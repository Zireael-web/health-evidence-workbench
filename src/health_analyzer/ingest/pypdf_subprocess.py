"""Bounded subprocess transport for production pypdf extraction.

The worker receives private bytes only over stdin.  On macOS it is always
launched inside a dedicated, narrower Seatbelt profile in addition to any
sandbox already applied to the parent process.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, replace
import json
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any, BinaryIO

from .models import BlockDraft, BlockKind
from .registry import ExtractorFailure


WORKER_PROTOCOL = "health-analyzer-pypdf-worker-v1"
MAX_WORKER_HEADER_BYTES = 64 * 1024
MAX_WORKER_INPUT_BYTES = 64 * 1024 * 1024
MAX_WORKER_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_WORKER_STDERR_BYTES = 1024 * 1024
MAX_WORKER_PASSWORD_BYTES = 4096
PROJECT_ROOT = Path(__file__).resolve().parents[3]
PDF_PARSER_PROFILE = PROJECT_ROOT / "policies" / "pdf-parser.sb"
SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
_GENERATED_PDF_PARSER_PROFILES: set[Path] = set()


@dataclass(frozen=True, slots=True)
class PypdfSubprocessLimits:
    """Parent- and worker-enforced bounds for the production PDF process."""

    timeout_seconds: float = 20.0
    cpu_seconds: int = 10
    max_address_space_bytes: int = 1024 * 1024 * 1024
    max_open_files: int = 32
    max_processes: int = 1
    max_input_bytes: int = MAX_WORKER_INPUT_BYTES
    max_output_bytes: int = 32 * 1024 * 1024
    max_stderr_bytes: int = 64 * 1024

    def __post_init__(self) -> None:
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
            or self.timeout_seconds > 300
        ):
            raise ValueError("timeout_seconds must be finite and in (0, 300]")
        object.__setattr__(self, "timeout_seconds", float(self.timeout_seconds))
        for name, upper in (
            ("cpu_seconds", 120),
            ("max_address_space_bytes", 16 * 1024 * 1024 * 1024),
            ("max_open_files", 256),
            ("max_processes", 1),
            ("max_input_bytes", MAX_WORKER_INPUT_BYTES),
            ("max_output_bytes", MAX_WORKER_OUTPUT_BYTES),
            ("max_stderr_bytes", MAX_WORKER_STDERR_BYTES),
        ):
            value = getattr(self, name)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 1
                or value > upper
            ):
                raise ValueError(f"{name} must be a positive integer <= {upper}")
        if self.max_address_space_bytes < 128 * 1024 * 1024:
            raise ValueError("max_address_space_bytes must be at least 128 MiB")
        if self.max_open_files < 8:
            raise ValueError("max_open_files must be at least 8")
        if self.max_output_bytes < 1024:
            raise ValueError("max_output_bytes must be at least 1024")
        if self.max_stderr_bytes < 1024:
            raise ValueError("max_stderr_bytes must be at least 1024")


_WORKER_FAILURES: dict[str, tuple[str, bool]] = {
    "pdf_empty_input": ("PDF input contains no bytes.", False),
    "pdf_input_size_limit_exceeded": (
        "PDF input exceeds the configured byte limit.",
        False,
    ),
    "pdf_empty_document": ("PDF contains no pages.", False),
    "pdf_page_limit_exceeded": (
        "PDF page count exceeds the configured limit.",
        False,
    ),
    "pdf_page_content_stream_limit_exceeded": (
        "A PDF page exceeds the configured content-stream byte limit.",
        False,
    ),
    "pdf_total_content_stream_limit_exceeded": (
        "PDF exceeds the cumulative content-stream byte limit.",
        False,
    ),
    "pdf_page_text_limit_exceeded": (
        "A PDF page exceeds the configured extracted-text byte limit.",
        False,
    ),
    "pdf_total_text_limit_exceeded": (
        "PDF exceeds the cumulative extracted-text byte limit.",
        False,
    ),
    "pdf_text_encoding_failed": (
        "Extracted PDF text could not be represented safely.",
        False,
    ),
    "pdf_ocr_required": (
        "PDF has no extractable native text and may require a separate OCR provider.",
        True,
    ),
    "pdf_text_extraction_failed": (
        "pypdf could not extract text from any PDF page.",
        True,
    ),
    "pdf_read_error": ("pypdf could not parse the PDF.", True),
    "pdf_encryption_status_error": (
        "PDF encryption status could not be determined.",
        False,
    ),
    "pdf_encrypted": (
        "PDF is encrypted and no password was provided.",
        False,
    ),
    "pdf_decryption_failed": (
        "PDF could not be decrypted with the provided password.",
        False,
    ),
    "pdf_page_index_error": ("PDF page index could not be read.", True),
    "pdf_content_stream_read_failed": (
        "A PDF page content stream could not be measured.",
        False,
    ),
    "pypdf_dependency_missing": (
        "pypdf is required for local PDF text extraction.",
        True,
    ),
    "pdf_worker_resource_limit_failed": (
        "PDF worker could not apply mandatory resource limits.",
        False,
    ),
    "pdf_worker_request_invalid": (
        "PDF worker rejected the bounded request protocol.",
        False,
    ),
    "pdf_worker_output_limit_exceeded": (
        "PDF worker output exceeds the configured byte limit.",
        False,
    ),
    "pdf_worker_failure": ("PDF extraction worker failed safely.", True),
}


def extract_pdf_in_subprocess(
    content: bytes,
    *,
    document_limits: Any,
    subprocess_limits: PypdfSubprocessLimits,
    password: str | bytes | None,
) -> tuple[BlockDraft, ...]:
    """Extract PDF blocks through the production worker protocol."""

    immutable_content = bytes(content)
    effective_input_limit = min(
        int(document_limits.max_input_bytes),
        subprocess_limits.max_input_bytes,
        MAX_WORKER_INPUT_BYTES,
    )
    if not immutable_content:
        raise ExtractorFailure(
            "pdf_empty_input",
            "PDF input contains no bytes.",
            recoverable=False,
        )
    if len(immutable_content) > effective_input_limit:
        raise ExtractorFailure(
            "pdf_input_size_limit_exceeded",
            "PDF input exceeds the configured byte limit.",
            recoverable=False,
        )

    header = {
        "protocol": WORKER_PROTOCOL,
        "input_length": len(immutable_content),
        "document_limits": {
            "max_input_bytes": int(document_limits.max_input_bytes),
            "max_pages": int(document_limits.max_pages),
            "max_page_content_stream_bytes": int(
                document_limits.max_page_content_stream_bytes
            ),
            "max_total_content_stream_bytes": int(
                document_limits.max_total_content_stream_bytes
            ),
            "max_page_extracted_text_bytes": int(
                document_limits.max_page_extracted_text_bytes
            ),
            "max_total_extracted_text_bytes": int(
                document_limits.max_total_extracted_text_bytes
            ),
        },
        "resource_limits": {
            "cpu_seconds": subprocess_limits.cpu_seconds,
            "max_address_space_bytes": subprocess_limits.max_address_space_bytes,
            "max_open_files": subprocess_limits.max_open_files,
            "max_processes": subprocess_limits.max_processes,
            "max_output_bytes": subprocess_limits.max_output_bytes,
        },
        "password": _encode_password(password),
    }
    encoded_header = json.dumps(
        header,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    if len(encoded_header) + 1 > MAX_WORKER_HEADER_BYTES:
        raise ExtractorFailure(
            "pdf_worker_request_invalid",
            "PDF worker request metadata exceeds the bounded protocol limit.",
            recoverable=False,
        )
    request = encoded_header + b"\n" + immutable_content
    command = _pdf_worker_command()
    try:
        response_bytes = _run_bounded_process(
            command,
            request,
            timeout_seconds=float(subprocess_limits.timeout_seconds),
            max_output_bytes=subprocess_limits.max_output_bytes,
            max_stderr_bytes=subprocess_limits.max_stderr_bytes,
        )
    finally:
        _release_pdf_worker_command(command)
    response = _decode_response(response_bytes, max_pages=int(document_limits.max_pages))
    if response[0] is not None:
        code = response[0]
        message, recoverable = _WORKER_FAILURES.get(
            code,
            _WORKER_FAILURES["pdf_worker_failure"],
        )
        if code not in _WORKER_FAILURES:
            code = "pdf_worker_failure"
        raise ExtractorFailure(code, message, recoverable=recoverable)

    blocks, address_space_limit_applied = response[1], response[2]
    if sys.platform == "darwin":
        isolation_note = (
            "pypdf extraction ran in a dedicated macOS Seatbelt sandbox nested "
            "inside any parent sandbox; state, handoff keys, Keychain, file writes, "
            "network access, and child-process creation were denied."
        )
    else:
        isolation_note = (
            "pypdf extraction ran in a separate resource-limited process; this "
            "platform build does not add a dedicated operating-system sandbox."
        )
    common_limitations = [
        isolation_note,
        "Bounded stdio, CPU, process-count, and file-descriptor limits were applied.",
        "pypdf stream-decoder allocation ceilings were lowered to the configured "
        "per-page content limit before parsing.",
    ]
    if not address_space_limit_applied:
        common_limitations.append(
            "A hard address-space RLIMIT was unavailable in this worker; on macOS "
            "RLIMIT_AS aliases advisory RLIMIT_RSS and may be rejected. Wall-clock, "
            "CPU, descriptor, input, and output bounds remained active."
        )
    return tuple(
        replace(block, limitations=(*block.limitations, *common_limitations))
        for block in blocks
    )


def _render_pdf_parser_profile() -> Path:
    """Render the portable Seatbelt template into a local ephemeral profile."""

    try:
        template = PDF_PARSER_PROFILE
        text = template.read_text(encoding="utf-8")
        if "__" not in text:
            return template
        python_environment_root = Path(sys.prefix).resolve()
        if not python_environment_root.is_dir() or python_environment_root.is_symlink():
            raise OSError("Python environment root is unavailable")
        python_executable = Path(sys.executable).resolve()
        python_executable_root = python_executable.parents[1]
        if (
            not python_executable.is_file()
            or not python_executable_root.is_dir()
            or python_executable_root.is_symlink()
        ):
            raise OSError("Python executable root is unavailable")
        rendered = (
            text.replace("__PROJECT_ROOT__", str(PROJECT_ROOT))
            .replace("__PYTHON_ENV_ROOT__", str(python_environment_root))
            .replace("__PYTHON_EXECUTABLE_ROOT__", str(python_executable_root))
        )
        if "__" in rendered:
            raise OSError("PDF parser profile contains an unresolved placeholder")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix="health-analyzer-pdf-",
            suffix=".sb",
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(rendered)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o600)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    except (OSError, UnicodeError) as exc:
        raise ExtractorFailure(
            "pdf_worker_sandbox_unavailable",
            "The mandatory macOS PDF parser sandbox is unavailable.",
            recoverable=False,
        ) from exc
    _GENERATED_PDF_PARSER_PROFILES.add(temporary)
    return temporary


def _release_pdf_worker_command(command: tuple[str, ...]) -> None:
    """Remove a generated policy after the corresponding worker terminates."""

    if len(command) < 3 or command[0] != str(SANDBOX_EXEC) or command[1] != "-f":
        return
    policy = Path(command[2])
    if policy not in _GENERATED_PDF_PARSER_PROFILES:
        return
    _GENERATED_PDF_PARSER_PROFILES.discard(policy)
    policy.unlink(missing_ok=True)


def _pdf_worker_command() -> tuple[str, ...]:
    """Build the fail-closed platform command for the untrusted PDF worker."""

    worker = (
        sys.executable,
        "-I",
        "-B",
        "-X",
        "utf8",
        "-m",
        "health_analyzer.ingest.pypdf_worker",
    )
    if sys.platform != "darwin":
        return worker
    if (
        not SANDBOX_EXEC.is_file()
        or not os.access(SANDBOX_EXEC, os.X_OK)
        or not PDF_PARSER_PROFILE.is_file()
        or PDF_PARSER_PROFILE.is_symlink()
    ):
        raise ExtractorFailure(
            "pdf_worker_sandbox_unavailable",
            "The mandatory macOS PDF parser sandbox is unavailable.",
            recoverable=False,
        )
    return (
        str(SANDBOX_EXEC),
        "-f",
        str(_render_pdf_parser_profile()),
        *worker,
    )


def _encode_password(password: str | bytes | None) -> dict[str, str]:
    if password is None:
        return {"kind": "none", "base64": ""}
    if isinstance(password, str):
        kind = "str"
        encoded = password.encode("utf-8")
    elif isinstance(password, bytes):
        kind = "bytes"
        encoded = password
    else:
        raise ExtractorFailure(
            "pdf_worker_request_invalid",
            "PDF password must be text or bytes.",
            recoverable=False,
        )
    if len(encoded) > MAX_WORKER_PASSWORD_BYTES:
        raise ExtractorFailure(
            "pdf_worker_request_invalid",
            "PDF password exceeds the bounded worker protocol limit.",
            recoverable=False,
        )
    return {
        "kind": kind,
        "base64": base64.b64encode(encoded).decode("ascii"),
    }


def _run_bounded_process(
    command: tuple[str, ...],
    request: bytes,
    *,
    timeout_seconds: float,
    max_output_bytes: int,
    max_stderr_bytes: int,
) -> bytes:
    """Run a child with concurrently bounded stdin/stdout/stderr pipes."""

    environment = {
        "HOME": "/private/var/empty",
        "PATH": os.defpath,
    }
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=Path("/"),
            env=environment,
            close_fds=True,
            start_new_session=True,
        )
    except (OSError, ValueError):
        raise ExtractorFailure(
            "pdf_worker_start_failed",
            "PDF extraction worker could not be started.",
            recoverable=True,
        ) from None

    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
    streams: tuple[BinaryIO, ...] = (
        process.stdin,
        process.stdout,
        process.stderr,
    )
    try:
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    except (OSError, ValueError):
        _kill_process_group(process)
        for stream in streams:
            try:
                stream.close()
            except OSError:
                pass
        selector.close()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            _kill_process_group(process)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        raise ExtractorFailure(
            "pdf_worker_start_failed",
            "PDF extraction worker pipes could not be initialized.",
            recoverable=True,
        ) from None

    request_offset = 0
    output = bytearray()
    stderr_size = 0
    deadline = time.monotonic() + timeout_seconds
    failure: ExtractorFailure | None = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = ExtractorFailure(
                    "pdf_worker_timeout",
                    "PDF extraction worker exceeded the wall-clock timeout.",
                    recoverable=False,
                )
                break
            try:
                events = selector.select(min(remaining, 0.05))
            except InterruptedError:
                continue
            except OSError:
                failure = ExtractorFailure(
                    "pdf_worker_process_failed",
                    "PDF extraction worker I/O failed safely.",
                    recoverable=True,
                )
                break
            if not events and process.poll() is not None:
                # A terminated child will make its pipes readable at EOF; loop
                # briefly so those EOF events are observed and unregistered.
                continue
            for key, _ in events:
                stream = key.fileobj
                if key.data == "stdin":
                    try:
                        written = os.write(
                            stream.fileno(),
                            request[request_offset : request_offset + 64 * 1024],
                        )
                    except OSError:
                        written = 0
                        request_offset = len(request)
                    request_offset += written
                    if request_offset >= len(request):
                        selector.unregister(stream)
                        stream.close()
                    continue

                try:
                    chunk = os.read(stream.fileno(), 64 * 1024)
                except BlockingIOError:
                    continue
                except OSError:
                    failure = ExtractorFailure(
                        "pdf_worker_process_failed",
                        "PDF extraction worker I/O failed safely.",
                        recoverable=True,
                    )
                    break
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                if key.data == "stdout":
                    output.extend(chunk)
                    if len(output) > max_output_bytes:
                        failure = ExtractorFailure(
                            "pdf_worker_output_limit_exceeded",
                            "PDF extraction worker output exceeds the configured byte limit.",
                            recoverable=False,
                        )
                        break
                else:
                    stderr_size += len(chunk)
                    if stderr_size > max_stderr_bytes:
                        failure = ExtractorFailure(
                            "pdf_worker_output_limit_exceeded",
                            "PDF extraction worker diagnostics exceed the configured byte limit.",
                            recoverable=False,
                        )
                        break
            if failure is not None:
                break
    finally:
        if failure is None and process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = ExtractorFailure(
                    "pdf_worker_timeout",
                    "PDF extraction worker exceeded the wall-clock timeout.",
                    recoverable=False,
                )
            else:
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    failure = ExtractorFailure(
                        "pdf_worker_timeout",
                        "PDF extraction worker exceeded the wall-clock timeout.",
                        recoverable=False,
                    )
        if failure is not None or process.poll() is None:
            _kill_process_group(process)
        for stream in streams:
            try:
                selector.unregister(stream)
            except (KeyError, ValueError):
                pass
            try:
                stream.close()
            except OSError:
                pass
        selector.close()
        if process.poll() is None:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                _kill_process_group(process)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    if failure is None:
                        failure = ExtractorFailure(
                            "pdf_worker_process_failed",
                            "PDF extraction worker could not be reaped safely.",
                            recoverable=True,
                        )

    if failure is not None:
        raise failure
    if process.returncode != 0:
        raise ExtractorFailure(
            "pdf_worker_process_failed",
            "PDF extraction worker exited before returning a valid result.",
            recoverable=True,
        )
    if not output:
        raise ExtractorFailure(
            "pdf_worker_protocol_error",
            "PDF extraction worker returned no protocol response.",
            recoverable=True,
        )
    return bytes(output)


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        try:
            process.kill()
        except ProcessLookupError:
            pass


def _decode_response(
    response_bytes: bytes,
    *,
    max_pages: int,
) -> tuple[str | None, tuple[BlockDraft, ...], bool]:
    try:
        payload = json.loads(response_bytes.decode("utf-8"))
        if not isinstance(payload, dict) or set(payload) != {
            "protocol",
            "ok",
            "result",
        }:
            raise ValueError("invalid response envelope")
        if payload["protocol"] != WORKER_PROTOCOL or not isinstance(payload["ok"], bool):
            raise ValueError("invalid response protocol")
        result = payload["result"]
        if not isinstance(result, dict):
            raise ValueError("invalid response result")
        if not payload["ok"]:
            if set(result) != {"code"} or not isinstance(result["code"], str):
                raise ValueError("invalid failure response")
            return result["code"], (), False
        if set(result) != {"address_space_limit_applied", "blocks"}:
            raise ValueError("invalid success response")
        address_applied = result["address_space_limit_applied"]
        raw_blocks = result["blocks"]
        if not isinstance(address_applied, bool) or not isinstance(raw_blocks, list):
            raise ValueError("invalid success fields")
        if not raw_blocks or len(raw_blocks) > max_pages:
            raise ValueError("invalid block count")
        blocks = tuple(_decode_block(item) for item in raw_blocks)
        return None, blocks, address_applied
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise ExtractorFailure(
            "pdf_worker_protocol_error",
            "PDF extraction worker returned an invalid bounded response.",
            recoverable=True,
        ) from None


def _decode_block(payload: Any) -> BlockDraft:
    expected = {
        "kind",
        "text",
        "rows",
        "payload_sha256",
        "page",
        "bbox",
        "line_start",
        "line_end",
        "confidence",
        "document_incomplete",
        "limitations",
    }
    if not isinstance(payload, dict) or set(payload) != expected:
        raise ValueError("invalid block")
    if not isinstance(payload["kind"], str):
        raise ValueError("invalid block kind")
    for name in ("text", "payload_sha256"):
        if payload[name] is not None and not isinstance(payload[name], str):
            raise ValueError("invalid block string")
    for name in ("page", "line_start", "line_end"):
        if payload[name] is not None and (
            not isinstance(payload[name], int) or isinstance(payload[name], bool)
        ):
            raise ValueError("invalid block integer")
    confidence = payload["confidence"]
    if confidence is not None and (
        not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not math.isfinite(confidence)
    ):
        raise ValueError("invalid block confidence")
    if not isinstance(payload["document_incomplete"], bool):
        raise ValueError("invalid incomplete marker")
    rows = payload["rows"]
    limitations = payload["limitations"]
    if (
        not isinstance(rows, list)
        or not all(
            isinstance(row, list) and all(isinstance(cell, str) for cell in row)
            for row in rows
        )
        or not isinstance(limitations, list)
        or not all(isinstance(item, str) for item in limitations)
    ):
        raise ValueError("invalid block collections")
    bbox = payload["bbox"]
    if bbox is not None:
        if (
            not isinstance(bbox, list)
            or len(bbox) != 4
            or not all(
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and math.isfinite(value)
                for value in bbox
            )
        ):
            raise ValueError("invalid bbox")
        bbox_value = tuple(bbox)
    else:
        bbox_value = None
    return BlockDraft(
        kind=BlockKind(payload["kind"]),
        text=payload["text"],
        rows=tuple(tuple(row) for row in rows),
        payload_sha256=payload["payload_sha256"],
        page=payload["page"],
        bbox=bbox_value,
        line_start=payload["line_start"],
        line_end=payload["line_end"],
        confidence=payload["confidence"],
        document_incomplete=payload["document_incomplete"],
        limitations=tuple(limitations),
    )


def serialize_block(block: BlockDraft) -> dict[str, Any]:
    """Serialize a trusted worker block into the strict parent protocol."""

    return {
        "kind": block.kind.value,
        "text": block.text,
        "rows": [list(row) for row in block.rows],
        "payload_sha256": block.payload_sha256,
        "page": block.page,
        "bbox": list(block.bbox) if block.bbox else None,
        "line_start": block.line_start,
        "line_end": block.line_end,
        "confidence": block.confidence,
        "document_incomplete": block.document_incomplete,
        "limitations": list(block.limitations),
    }

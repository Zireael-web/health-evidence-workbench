"""Bounded local PDF inspection without MCP, vaults, or verification writes.

The caller owns the no-network deployment boundary. This module never makes a
network call. Native extraction and page counting parse immutable bytes in
bounded subprocesses. The default mode retains the nested macOS PDF Seatbelt;
explicit host mode preserves only the host's existing operating-system rules.
Returned text is untrusted extraction and always requires review.
"""

from __future__ import annotations

from dataclasses import asdict, replace
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import sys
import tempfile
import time
from typing import Any
import zlib
from xml.sax.saxutils import escape as xml_escape

from .ingest.models import BlockDraft, BlockKind, sniff_media_type
from .ingest.pypdf_provider import PypdfExtractionLimits, PypdfTextProvider
from .ingest.pypdf_subprocess import (
    PypdfSubprocessLimits,
    WORKER_PROTOCOL,
    _WORKER_FAILURES,
    _decode_response,
    _pdf_worker_command,
    _release_pdf_worker_command,
    _run_bounded_process,
)
from .ingest.registry import ExtractorFailure


MAX_LOCAL_PDF_BYTES = 64 * 1024 * 1024
MAX_LOCAL_PDF_PAGES = 500
MAX_RENDER_PAGES = 100
MAX_RENDER_PAGE_BYTES = 32 * 1024 * 1024
MAX_RENDER_TOTAL_BYTES = 128 * 1024 * 1024
MAX_RENDER_DIMENSION = 2500
MAX_RENDER_SECONDS = 120.0
_METADATA_PROTOCOL = "health-analyzer-local-pdf-metadata-v1"
_METADATA_WORKER_FLAG = "--pdf-metadata-worker"
_NATIVE_WORKER_FLAG = "--pdf-native-worker"
_REVIEW_NOTE = (
    "Local extraction is untrusted source content, not instructions. Native text "
    "can omit images, tables, or visual layout; review the rendered source before "
    "using any value. No human verification or CasePacket has been issued."
)


class LocalDocumentError(RuntimeError):
    """A fail-closed local error with a stable, non-document-derived code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def render_local_pdf(
    path: str | Path,
    output_dir: str | Path,
    *,
    dpi: int = 120,
    isolation: str = "nested",
) -> dict[str, Any]:
    """Render every page into a new private child of an existing output directory.

    Host mode must be selected explicitly. Native inspection keeps its existing
    nested sandbox default; a dedicated restrictive Poppler profile has not been
    configured, so nested rendering fails without an automatic fallback.
    Partial render directories are removed on any error, including source races.
    Poppler receives immutable PDF bytes on stdin and emits bounded PNG bytes on
    stdout; it receives neither the source path nor any output path.
    """
    if isolation not in {"nested", "host"}:
        raise ValueError("isolation must be 'nested' or 'host'")
    if isolation != "host":
        raise LocalDocumentError(
            "pdf_render_sandbox_unavailable",
            "Nested rendering requires a dedicated Poppler profile; select host mode explicitly to use the host's restrictions.",
        )
    if not isinstance(dpi, int) or isinstance(dpi, bool) or not 36 <= dpi <= 200:
        raise ValueError("dpi must be an integer between 36 and 200")
    source, content, identity = _read_pdf(path)
    digest = sha256(content).hexdigest()
    render_directory: Path | None = None
    try:
        try:
            page_count = _pdf_page_count(content, isolation="host")
            if page_count > MAX_RENDER_PAGES:
                raise LocalDocumentError("pdf_render_page_limit_exceeded", "PDF has too many pages for bounded rendering.")
            executable = shutil.which("pdftoppm")
            if executable is None:
                raise LocalDocumentError("poppler_dependency_missing", "Local pdftoppm is required for PDF rendering.")
            parent = _absolute_source_path(output_dir)
            try:
                parent_fd = _open_directory(parent)
                os.close(parent_fd)
                render_directory = Path(tempfile.mkdtemp(prefix="local-pdf-render-", dir=parent))
            except OSError:
                raise LocalDocumentError("pdf_render_directory_unavailable", "The local render parent could not be used.") from None

            font_directory, font_config = _prepare_fontconfig(render_directory, Path(executable))
            pages: list[dict[str, Any]] = []
            total_bytes = 0
            deadline = time.monotonic() + MAX_RENDER_SECONDS
            for page_number in range(1, page_count + 1):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise LocalDocumentError("pdf_render_timeout", "PDF rendering exceeded its total time budget.")
                png = _run_bounded_process(
                    (
                        "/usr/bin/env", f"FONTCONFIG_FILE={font_config}",
                        f"XDG_CACHE_HOME={font_directory / 'cache'}",
                        executable, "-f", str(page_number), "-l", str(page_number),
                        "-singlefile", "-png", "-r", str(dpi),
                        "-scale-to", str(MAX_RENDER_DIMENSION), "-",
                    ),
                    content,
                    timeout_seconds=min(20.0, remaining),
                    max_output_bytes=min(MAX_RENDER_PAGE_BYTES, MAX_RENDER_TOTAL_BYTES - total_bytes),
                    max_stderr_bytes=64 * 1024,
                )
                total_bytes += len(png)
                _check_font_cache_budget(font_directory)
                if len(png) > MAX_RENDER_PAGE_BYTES or total_bytes > MAX_RENDER_TOTAL_BYTES:
                    raise LocalDocumentError("pdf_render_output_limit_exceeded", "PDF renders exceed the output byte budget.")
                width, height = _png_dimensions(png)
                image_path = render_directory / f"page-{page_number:04d}.png"
                try:
                    descriptor = os.open(image_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(descriptor, "wb") as output:
                        output.write(png)
                except OSError:
                    raise LocalDocumentError("pdf_render_write_failed", "A local page render could not be written exclusively.") from None
                pages.append({
                    "page": page_number,
                    "path": str(image_path),
                    "sha256": sha256(png).hexdigest(),
                    "byte_size": len(png),
                    "width": width,
                    "height": height,
                    "review_status": "needs_review",
                    "provenance": {"source_sha256": digest, "page": page_number, "method": "poppler_pdftoppm"},
                })
            shutil.rmtree(font_directory)
            expected_names = {f"page-{page_number:04d}.png" for page_number in range(1, page_count + 1)}
            if len(pages) != page_count or {item.name for item in render_directory.iterdir()} != expected_names:
                raise LocalDocumentError("pdf_render_page_count_mismatch", "PDF renders do not match the complete page inventory.")
            result = {
                "schema_version": "local-pdf-render-v1",
                "source_path": str(source),
                "sha256": digest,
                "page_count": page_count,
                "render_directory": str(render_directory),
                "dpi_requested": dpi,
                "maximum_dimension": MAX_RENDER_DIMENSION,
                "total_bytes": total_bytes,
                "pages": pages,
                "review_status": "needs_review",
                "isolation": {"mode": "host", "nested_seatbelt": False, "os_no_network_guarantee": False},
                "limitations": [
                    _REVIEW_NOTE,
                    "Rendering used time, output-byte, page-count, and image-size bounds under the host's existing restrictions; no additional OS network boundary is asserted.",
                ],
            }
        finally:
            _verify_unchanged(source, identity, digest)
    except BaseException as error:
        if render_directory is not None:
            # This uniquely named directory was created by this call. No source
            # or caller-owned output directory is ever removed.
            shutil.rmtree(render_directory)
        if isinstance(error, ExtractorFailure):
            raise LocalDocumentError(error.code, error.message) from None
        raise
    return result


def _prepare_fontconfig(render_directory: Path, executable: Path) -> tuple[Path, Path]:
    """Supply a local font config so relocated Poppler never uses build paths."""
    font_directory = render_directory / ".fontconfig"
    font_directory.mkdir(mode=0o700)
    cache = font_directory / "cache"
    cache.mkdir(mode=0o700)
    candidates = [
        Path("/System/Library/Fonts"), Path("/Library/Fonts"),
        Path("/usr/share/fonts"), Path("/usr/local/share/fonts"),
    ]
    if len(executable.parents) >= 3:
        candidates.append(executable.parents[2] / "native/poppler/poppler/fonts")
    directories = [path for path in candidates if path.is_dir()]
    config = font_directory / "fonts.conf"
    payload = (
        '<?xml version="1.0"?>\n<fontconfig>\n'
        + "".join(f"<dir>{xml_escape(str(path))}</dir>\n" for path in directories)
        + f"<cachedir>{xml_escape(str(cache))}</cachedir>\n"
        + "<config><rescan><int>0</int></rescan></config>\n</fontconfig>\n"
    )
    with config.open("x", encoding="utf-8") as output:
        output.write(payload)
    return font_directory, config


def _check_font_cache_budget(directory: Path) -> None:
    count = size = 0
    for parent, directories, files in os.walk(directory, followlinks=False):
        for name in (*directories, *files):
            item = Path(parent) / name
            info = os.lstat(item)
            count += 1
            if stat.S_ISLNK(info.st_mode) or count > 1024:
                raise LocalDocumentError("pdf_render_font_cache_limit_exceeded", "The local font cache exceeds its structural budget.")
            size += info.st_size
            if size > 16 * 1024 * 1024:
                raise LocalDocumentError("pdf_render_font_cache_limit_exceeded", "The local font cache exceeds its byte budget.")


def _png_dimensions(content: bytes) -> tuple[int, int]:
    """Validate the bounded PNG chunk structure and advertised pixel dimensions."""
    if not content.startswith(b"\x89PNG\r\n\x1a\n"):
        raise LocalDocumentError("pdf_render_invalid_png", "PDF renderer did not return a PNG image.")
    cursor = 8
    width = height = 0
    saw_data = False
    chunks = 0
    while cursor + 12 <= len(content):
        chunks += 1
        length = int.from_bytes(content[cursor:cursor + 4], "big")
        kind = content[cursor + 4:cursor + 8]
        end = cursor + 12 + length
        if chunks > 10_000 or end > len(content):
            break
        data = content[cursor + 8:cursor + 8 + length]
        checksum = int.from_bytes(content[cursor + 8 + length:end], "big")
        if zlib.crc32(kind + data) != checksum:
            break
        if chunks == 1:
            if kind != b"IHDR" or length != 13:
                break
            width, height = struct.unpack(">II", data[:8])
            if not 1 <= width <= MAX_RENDER_DIMENSION or not 1 <= height <= MAX_RENDER_DIMENSION:
                raise LocalDocumentError("pdf_render_pixel_limit_exceeded", "PDF render dimensions exceed the pixel limit.")
        elif kind == b"IHDR":
            break
        if kind == b"IDAT":
            saw_data = True
        if kind == b"IEND":
            if length == 0 and end == len(content) and saw_data:
                return width, height
            break
        cursor = end
    raise LocalDocumentError("pdf_render_invalid_png", "PDF renderer returned an incomplete or invalid PNG.")


def inspect_local_pdf(path: str | Path, *, isolation: str = "nested") -> dict[str, Any]:
    """Inspect a regular PDF, returning all pages as JSON-compatible values.

    Hard limits and source changes raise ``LocalDocumentError`` without returning
    a partial result. Pages without native text remain explicitly present with
    ``needs_visual_review``. ``extraction_complete`` describes native text page
    coverage only, never completeness of the visual/medical information.

    ``isolation='host'`` explicitly selects the bounded child process without
    the additional app-owned Seatbelt wrapper. It preserves the host's existing
    restrictions but does not provide an operating-system no-network guarantee.
    """

    if isolation not in {"nested", "host"}:
        raise ValueError("isolation must be 'nested' or 'host'")
    source, content, identity = _read_pdf(path)
    digest = sha256(content).hexdigest()
    try:
        page_count = _pdf_page_count(content, isolation=isolation)
        provider = PypdfTextProvider()
        failures: list[str] = []
        try:
            blocks = (
                provider.extract_pdf(content)
                if isolation == "nested"
                else _extract_host_text(content, provider)
            )
        except ExtractorFailure as error:
            if error.code not in {"pdf_ocr_required", "pdf_text_extraction_failed"}:
                raise
            blocks = ()
            failures.append(error.code)

        page_blocks: dict[int, Any] = {}
        text_bytes = 0
        for block in blocks:
            if (
                not isinstance(block.page, int)
                or isinstance(block.page, bool)
                or not 1 <= block.page <= page_count
                or block.page in page_blocks
                or block.kind != BlockKind.TEXT
                or not isinstance(block.text, str)
                or not block.text.strip()
            ):
                raise LocalDocumentError(
                    "pdf_page_provenance_invalid",
                    "PDF extractor returned inconsistent page provenance.",
                )
            try:
                size = len(block.text.encode("utf-8"))
            except UnicodeEncodeError:
                raise LocalDocumentError(
                    "pdf_text_encoding_failed", "PDF text is not valid UTF-8."
                ) from None
            text_bytes += size
            if (
                size > provider.limits.max_page_extracted_text_bytes
                or text_bytes > provider.limits.max_total_extracted_text_bytes
            ):
                raise LocalDocumentError(
                    "pdf_text_limit_exceeded", "PDF text exceeds the byte limit."
                )
            page_blocks[block.page] = block

        pages: list[dict[str, Any]] = []
        fingerprint = sha256(
            f"{provider.configuration_fingerprint}:{isolation}".encode("ascii")
        ).hexdigest()
        for page_number in range(1, page_count + 1):
            block = page_blocks.get(page_number)
            pages.append(
                {
                    "page": page_number,
                    "text": block.text if block is not None else None,
                    "extraction_status": (
                        "native_text" if block is not None else "needs_visual_review"
                    ),
                    "review_status": "needs_review",
                    "provenance": {
                        "source_path": str(source),
                        "source_sha256": digest,
                        "page": page_number,
                        "method": "native_pdf_text" if block is not None else None,
                        "extractor_id": provider.provider_id,
                        "extractor_version": provider.version,
                        "configuration_fingerprint": fingerprint,
                        "isolation_mode": isolation,
                        "line_start": block.line_start if block is not None else None,
                        "line_end": block.line_end if block is not None else None,
                    },
                    "limitations": (
                        list(block.limitations)
                        if block is not None
                        else [
                            "Native text was unavailable on this page. It may be "
                            "blank, image-only, or have a text extraction failure."
                        ]
                    ),
                }
            )
        complete = len(page_blocks) == page_count and not any(
            block.document_incomplete for block in blocks
        )
        return {
            "schema_version": "local-pdf-inspection-v1",
            "source_path": str(source),
            "sha256": digest,
            "byte_size": len(content),
            "page_count": page_count,
            "pages": pages,
            "extraction_complete": complete,
            "extraction_status": "complete" if complete else "needs_visual_review",
            "review_status": "needs_review",
            "isolation": {
                "mode": isolation,
                "nested_seatbelt": isolation == "nested" and sys.platform == "darwin",
                "resource_bounded_subprocess": True,
                "os_no_network_guarantee": isolation == "nested" and sys.platform == "darwin",
                "python_socket_audit_deny": isolation == "host",
            },
            "failures": failures,
            "limitations": [_REVIEW_NOTE],
        }
    except ExtractorFailure as error:
        raise LocalDocumentError(error.code, error.message) from None
    finally:
        # Reopen without following a replaced symlink. The digest catches a
        # content change even if a caller restores the original timestamps.
        _verify_unchanged(source, identity, digest)


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_pdf(path: str | Path) -> tuple[Path, bytes, tuple[int, ...]]:
    source = _absolute_source_path(path)
    if source.suffix.casefold() != ".pdf":
        raise LocalDocumentError(
            "pdf_extension_mismatch", "The local PDF source must have a .pdf extension."
        )
    content, identity = _read_regular_file(source)
    if sniff_media_type(content) != "application/pdf":
        raise LocalDocumentError(
            "pdf_signature_mismatch", "The file does not have a supported PDF signature."
        )
    return source, content, identity


def _absolute_source_path(path: str | Path) -> Path:
    raw = os.fspath(path)
    source = Path(raw)
    if "\x00" in raw or ".." in source.parts:
        raise LocalDocumentError("pdf_source_path_invalid", "PDF paths must not contain traversal or NUL.")
    return source if source.is_absolute() else Path.cwd() / source


def _open_directory(path: Path) -> int:
    """Traverse each original directory component without following symlinks."""
    if not all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC")):
        raise LocalDocumentError("pdf_nofollow_unavailable", "Local PDF access requires POSIX no-follow support.")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_regular_file(source: Path) -> tuple[bytes, tuple[int, ...]]:
    descriptor: int | None = None
    parent_descriptor: int | None = None
    current_parent_descriptor: int | None = None
    try:
        parent_descriptor = _open_directory(source.parent)
        parent_before = os.fstat(parent_descriptor)
        before_path = os.stat(source.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if not stat.S_ISREG(before_path.st_mode):
            raise LocalDocumentError(
                "pdf_not_regular_file", "The PDF source must be a regular non-symlink file."
            )
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(source.name, flags, dir_fd=parent_descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or _identity(before) != _identity(before_path):
            raise LocalDocumentError("pdf_source_changed", "The PDF source changed while opening.")
        if before.st_size > MAX_LOCAL_PDF_BYTES:
            raise LocalDocumentError("pdf_input_size_limit_exceeded", "PDF input exceeds 64 MiB.")
        content = bytearray()
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_LOCAL_PDF_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
            if len(content) > MAX_LOCAL_PDF_BYTES:
                raise LocalDocumentError("pdf_input_size_limit_exceeded", "PDF input exceeds 64 MiB.")
        after = os.fstat(descriptor)
        current_parent_descriptor = _open_directory(source.parent)
        parent_after = os.fstat(current_parent_descriptor)
        after_path = os.stat(source.name, dir_fd=current_parent_descriptor, follow_symlinks=False)
        if (
            _identity(before) != _identity(after)
            or _identity(after) != _identity(after_path)
            or len(content) != after.st_size
            or (parent_before.st_dev, parent_before.st_ino) != (parent_after.st_dev, parent_after.st_ino)
        ):
            raise LocalDocumentError("pdf_source_changed", "The PDF source changed during reading.")
        return bytes(content), (*_identity(after), parent_after.st_dev, parent_after.st_ino)
    except OSError:
        raise LocalDocumentError("pdf_source_unavailable", "The local PDF source could not be read.") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        if current_parent_descriptor is not None:
            os.close(current_parent_descriptor)


def _verify_unchanged(source: Path, identity: tuple[int, ...], digest: str) -> None:
    try:
        content, after = _read_regular_file(source)
    except LocalDocumentError:
        raise LocalDocumentError("pdf_source_changed", "The PDF source changed during processing.") from None
    if after != identity or sha256(content).hexdigest() != digest:
        raise LocalDocumentError("pdf_source_changed", "The PDF source changed during processing.")


def _metadata_worker_command(*, isolation: str = "nested") -> tuple[str, ...]:
    # Keep the existing mandatory platform sandbox exactly as configured; only
    # choose another code module within its existing runtime/code allowlist.
    if isolation == "host":
        return _host_worker_command(_METADATA_WORKER_FLAG)
    return (*_pdf_worker_command()[:-1], "health_analyzer.local_documents", _METADATA_WORKER_FLAG)


def _pdf_page_count(content: bytes, *, isolation: str = "nested") -> int:
    command = _metadata_worker_command(isolation=isolation)
    try:
        response = _run_bounded_process(
            command,
            str(len(content)).encode("ascii") + b"\n" + content,
            timeout_seconds=20,
            max_output_bytes=4096,
            max_stderr_bytes=64 * 1024,
        )
    finally:
        _release_pdf_worker_command(command)
    try:
        payload = json.loads(response)
        if not isinstance(payload, dict) or payload.get("protocol") != _METADATA_PROTOCOL:
            raise ValueError
        if set(payload) == {"protocol", "error"}:
            code = payload["error"]
            if code not in {
                "pdf_encrypted", "pdf_empty_document", "pdf_page_limit_exceeded",
                "pypdf_dependency_missing", "pdf_read_error", "pdf_worker_resource_limit_failed",
                "pdf_worker_request_invalid",
            }:
                raise ValueError
            raise LocalDocumentError(code, "The bounded PDF page-count worker could not inspect this document.")
        count = payload["page_count"]
        if (
            set(payload) != {"protocol", "page_count"}
            or not isinstance(count, int)
            or isinstance(count, bool)
            or not 1 <= count <= MAX_LOCAL_PDF_PAGES
        ):
            raise ValueError
        return count
    except (KeyError, TypeError, ValueError, UnicodeDecodeError):
        raise LocalDocumentError("pdf_metadata_response_invalid", "PDF page-count worker returned an invalid response.") from None


def _host_worker_command(flag: str) -> tuple[str, ...]:
    return (sys.executable, "-I", "-B", "-X", "utf8", "-m", "health_analyzer.local_documents", flag)


def _extract_host_text(content: bytes, provider: PypdfTextProvider) -> tuple[BlockDraft, ...]:
    """Use the existing worker protocol and resource limits without Seatbelt."""
    limits = provider.subprocess_limits
    resource_limits = {
        key: getattr(limits, key)
        for key in ("cpu_seconds", "max_address_space_bytes", "max_open_files", "max_processes", "max_output_bytes")
    }
    header = {
        "protocol": WORKER_PROTOCOL,
        "input_length": len(content),
        "document_limits": asdict(provider.limits),
        "resource_limits": resource_limits,
        "password": {"kind": "none", "base64": ""},
    }
    response = _run_bounded_process(
        _host_worker_command(_NATIVE_WORKER_FLAG),
        json.dumps(header, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n" + content,
        timeout_seconds=limits.timeout_seconds,
        max_output_bytes=limits.max_output_bytes,
        max_stderr_bytes=limits.max_stderr_bytes,
    )
    code, blocks, address_space_applied = _decode_response(response, max_pages=provider.limits.max_pages)
    if code is not None:
        message, recoverable = _WORKER_FAILURES.get(code, _WORKER_FAILURES["pdf_worker_failure"])
        raise ExtractorFailure(code if code in _WORKER_FAILURES else "pdf_worker_failure", message, recoverable=recoverable)
    notes = [
        "Native extraction ran in a resource-bounded child process under the host's "
        "existing restrictions. The additional application Seatbelt wrapper was "
        "explicitly disabled; no OS no-network guarantee is asserted.",
        "A Python socket audit deny hook was enabled as defense in depth; it is "
        "not an operating-system network boundary.",
    ]
    if not address_space_applied:
        notes.append("A hard address-space limit is unavailable on this platform; CPU, time, I/O, and decoder limits remained active.")
    return tuple(replace(block, limitations=(*block.limitations, *notes)) for block in blocks)


def _deny_python_sockets(event: str, args: tuple[Any, ...]) -> None:
    if event.startswith("socket."):
        raise PermissionError("Network operations are disabled in the local PDF worker.")


def _metadata_worker_main() -> int:
    # This branch executes only in the bounded subprocess with no source path.
    from .ingest.pypdf_provider import _default_reader_factory
    from .ingest.pypdf_worker import (
        _InvalidRequest,
        _MandatoryLimitFailure,
        _apply_resource_limits,
        _configure_pypdf_decode_limits,
        _read_exact_input,
    )

    response: dict[str, Any] = {"protocol": _METADATA_PROTOCOL}
    try:
        limits = PypdfSubprocessLimits()
        _apply_resource_limits({
            "cpu_seconds": limits.cpu_seconds,
            "max_address_space_bytes": limits.max_address_space_bytes,
            "max_open_files": limits.max_open_files,
            "max_processes": limits.max_processes,
            "max_output_bytes": 4096,
        })
        header = sys.stdin.buffer.readline(32)
        if not header.endswith(b"\n") or not header[:-1].isdigit():
            raise _InvalidRequest
        size = int(header)
        if not 1 <= size <= MAX_LOCAL_PDF_BYTES:
            raise _InvalidRequest
        content = _read_exact_input(size)
        _configure_pypdf_decode_limits(PypdfExtractionLimits())
        reader = _default_reader_factory(BytesIO(content))
        if reader.is_encrypted:
            response["error"] = "pdf_encrypted"
        else:
            count = len(reader.pages)
            if count < 1:
                response["error"] = "pdf_empty_document"
            elif count > MAX_LOCAL_PDF_PAGES:
                response["error"] = "pdf_page_limit_exceeded"
            else:
                response["page_count"] = count
    except _MandatoryLimitFailure:
        response["error"] = "pdf_worker_resource_limit_failed"
    except _InvalidRequest:
        response["error"] = "pdf_worker_request_invalid"
    except ExtractorFailure as error:
        response["error"] = (
            "pypdf_dependency_missing" if error.code == "pypdf_dependency_missing" else "pdf_read_error"
        )
    except BaseException:
        response["error"] = "pdf_read_error"
    sys.stdout.buffer.write(json.dumps(response, sort_keys=True).encode("ascii"))
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.addaudithook(_deny_python_sockets)
    if sys.argv[1:] == [_METADATA_WORKER_FLAG]:
        raise SystemExit(_metadata_worker_main())
    if sys.argv[1:] == [_NATIVE_WORKER_FLAG]:
        from .ingest.pypdf_worker import main

        raise SystemExit(main())
    raise SystemExit(2)

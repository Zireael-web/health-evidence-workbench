"""Private stdio worker for bounded native-text extraction with pypdf."""

from __future__ import annotations

import base64
import binascii
import json
import resource
import sys
from typing import Any

from .pypdf_provider import (
    PypdfExtractionLimits,
    PypdfTextProvider,
    _default_reader_factory,
)
from .pypdf_subprocess import (
    MAX_WORKER_HEADER_BYTES,
    MAX_WORKER_INPUT_BYTES,
    MAX_WORKER_OUTPUT_BYTES,
    MAX_WORKER_PASSWORD_BYTES,
    WORKER_PROTOCOL,
    serialize_block,
)
from .registry import ExtractorFailure


_MAX_WORKER_PAGES = 1000
_MAX_PAGE_CONTENT_BYTES = 128 * 1024 * 1024
_MAX_TOTAL_CONTENT_BYTES = 256 * 1024 * 1024
_MAX_PAGE_TEXT_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_TEXT_BYTES = 32 * 1024 * 1024


class _InvalidRequest(ValueError):
    pass


class _MandatoryLimitFailure(RuntimeError):
    pass


def main() -> int:
    output_limit = 1024
    try:
        header = _read_header()
        output_limit = _validated_int(
            header["resource_limits"],
            "max_output_bytes",
            minimum=1024,
            maximum=MAX_WORKER_OUTPUT_BYTES,
        )
        address_space_limit_applied = _apply_resource_limits(
            header["resource_limits"]
        )
        document_limits = _document_limits(header["document_limits"])
        _configure_pypdf_decode_limits(document_limits)
        input_length = _validated_int(
            header,
            "input_length",
            minimum=1,
            maximum=min(document_limits.max_input_bytes, MAX_WORKER_INPUT_BYTES),
        )
        password = _decode_password(header["password"])
        content = _read_exact_input(input_length)
        provider = PypdfTextProvider(
            limits=document_limits,
            reader_factory=_default_reader_factory,
            password=password,
        )
        blocks = provider.extract_pdf(content)
        return _emit(
            {
                "protocol": WORKER_PROTOCOL,
                "ok": True,
                "result": {
                    "address_space_limit_applied": address_space_limit_applied,
                    "blocks": [serialize_block(block) for block in blocks],
                },
            },
            output_limit=output_limit,
        )
    except _MandatoryLimitFailure:
        return _emit_failure(
            "pdf_worker_resource_limit_failed",
            output_limit=output_limit,
        )
    except _InvalidRequest:
        return _emit_failure(
            "pdf_worker_request_invalid",
            output_limit=output_limit,
        )
    except ExtractorFailure as error:
        return _emit_failure(error.code, output_limit=output_limit)
    except BaseException:
        # No exception type, path, parser detail, or document content crosses
        # the worker boundary.
        return _emit_failure("pdf_worker_failure", output_limit=output_limit)


def _read_header() -> dict[str, Any]:
    encoded = sys.stdin.buffer.readline(MAX_WORKER_HEADER_BYTES + 1)
    if not encoded or len(encoded) > MAX_WORKER_HEADER_BYTES or not encoded.endswith(b"\n"):
        raise _InvalidRequest
    try:
        payload = json.loads(encoded.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _InvalidRequest from None
    if not isinstance(payload, dict) or set(payload) != {
        "protocol",
        "input_length",
        "document_limits",
        "resource_limits",
        "password",
    }:
        raise _InvalidRequest
    if payload["protocol"] != WORKER_PROTOCOL:
        raise _InvalidRequest
    for name in ("document_limits", "resource_limits", "password"):
        if not isinstance(payload[name], dict):
            raise _InvalidRequest
    return payload


def _document_limits(payload: dict[str, Any]) -> PypdfExtractionLimits:
    expected = {
        "max_input_bytes",
        "max_pages",
        "max_page_content_stream_bytes",
        "max_total_content_stream_bytes",
        "max_page_extracted_text_bytes",
        "max_total_extracted_text_bytes",
    }
    if set(payload) != expected:
        raise _InvalidRequest
    values = {
        "max_input_bytes": _validated_int(
            payload,
            "max_input_bytes",
            minimum=1,
            maximum=MAX_WORKER_INPUT_BYTES,
        ),
        "max_pages": _validated_int(
            payload,
            "max_pages",
            minimum=1,
            maximum=_MAX_WORKER_PAGES,
        ),
        "max_page_content_stream_bytes": _validated_int(
            payload,
            "max_page_content_stream_bytes",
            minimum=1,
            maximum=_MAX_PAGE_CONTENT_BYTES,
        ),
        "max_total_content_stream_bytes": _validated_int(
            payload,
            "max_total_content_stream_bytes",
            minimum=1,
            maximum=_MAX_TOTAL_CONTENT_BYTES,
        ),
        "max_page_extracted_text_bytes": _validated_int(
            payload,
            "max_page_extracted_text_bytes",
            minimum=1,
            maximum=_MAX_PAGE_TEXT_BYTES,
        ),
        "max_total_extracted_text_bytes": _validated_int(
            payload,
            "max_total_extracted_text_bytes",
            minimum=1,
            maximum=_MAX_TOTAL_TEXT_BYTES,
        ),
    }
    return PypdfExtractionLimits(**values)


def _apply_resource_limits(payload: dict[str, Any]) -> bool:
    expected = {
        "cpu_seconds",
        "max_address_space_bytes",
        "max_open_files",
        "max_processes",
        "max_output_bytes",
    }
    if set(payload) != expected:
        raise _InvalidRequest
    cpu_seconds = _validated_int(
        payload,
        "cpu_seconds",
        minimum=1,
        maximum=120,
    )
    address_bytes = _validated_int(
        payload,
        "max_address_space_bytes",
        minimum=128 * 1024 * 1024,
        maximum=16 * 1024 * 1024 * 1024,
    )
    open_files = _validated_int(
        payload,
        "max_open_files",
        minimum=8,
        maximum=256,
    )
    max_processes = _validated_int(
        payload,
        "max_processes",
        minimum=1,
        maximum=1,
    )
    _validated_int(
        payload,
        "max_output_bytes",
        minimum=1024,
        maximum=MAX_WORKER_OUTPUT_BYTES,
    )

    try:
        _lower_limit(resource.RLIMIT_CPU, cpu_seconds, cpu_seconds + 1)
        _lower_limit(resource.RLIMIT_NOFILE, open_files, open_files)
        _lower_limit(resource.RLIMIT_NPROC, max_processes, max_processes)
    except (OSError, ValueError):
        raise _MandatoryLimitFailure from None

    try:
        _lower_limit(resource.RLIMIT_AS, address_bytes, address_bytes)
    except (OSError, ValueError):
        if sys.platform == "darwin":
            return False
        raise _MandatoryLimitFailure from None

    # Darwin exposes RLIMIT_AS as an alias of RLIMIT_RSS.  Even if the call is
    # accepted, Darwin documents this as a resident-set preference under
    # memory pressure, not a hard virtual-address-space ceiling.
    return sys.platform != "darwin"


def _configure_pypdf_decode_limits(limits: PypdfExtractionLimits) -> None:
    """Lower every pypdf stream-decoder ceiling before parsing untrusted bytes.

    The provider's post-decode length checks are semantic/cumulative checks, not
    allocation guards. pypdf 6.15 exposes bounded decoder globals; lowering them
    here ensures a compressed stream cannot allocate past the configured page
    ceiling before those checks run. The worker is single-use, so mutating these
    process-local limits cannot affect another document.
    """

    try:
        from pypdf import filters
    except ImportError:
        # Preserve the provider's structured dependency-missing result.
        return

    decoder_limit = min(
        limits.max_page_content_stream_bytes,
        limits.max_total_content_stream_bytes,
        75_000_000,
    )
    bounded_names = (
        "ZLIB_MAX_OUTPUT_LENGTH",
        "LZW_MAX_OUTPUT_LENGTH",
        "RUN_LENGTH_MAX_OUTPUT_LENGTH",
        "MAX_ARRAY_BASED_STREAM_OUTPUT_LENGTH",
        "JBIG2_MAX_OUTPUT_LENGTH",
    )
    try:
        for name in bounded_names:
            current = getattr(filters, name)
            if not isinstance(current, int) or isinstance(current, bool):
                raise TypeError(name)
            setattr(
                filters,
                name,
                decoder_limit if current <= 0 else min(current, decoder_limit),
            )
        declared_limit = getattr(filters, "MAX_DECLARED_STREAM_LENGTH")
        if not isinstance(declared_limit, int) or isinstance(declared_limit, bool):
            raise TypeError("MAX_DECLARED_STREAM_LENGTH")
        raw_stream_limit = min(limits.max_input_bytes, 75_000_000)
        filters.MAX_DECLARED_STREAM_LENGTH = (
            raw_stream_limit
            if declared_limit <= 0
            else min(declared_limit, raw_stream_limit)
        )
    except (AttributeError, TypeError, ValueError):
        raise _MandatoryLimitFailure from None


def _lower_limit(resource_id: int, requested_soft: int, requested_hard: int) -> None:
    current_soft, current_hard = resource.getrlimit(resource_id)
    target_hard = min(current_hard, requested_hard)
    target_soft = min(current_soft, requested_soft, target_hard)
    resource.setrlimit(resource_id, (target_soft, target_hard))


def _decode_password(payload: dict[str, Any]) -> str | bytes | None:
    if set(payload) != {"kind", "base64"}:
        raise _InvalidRequest
    kind = payload["kind"]
    encoded = payload["base64"]
    if kind not in {"none", "str", "bytes"} or not isinstance(encoded, str):
        raise _InvalidRequest
    try:
        value = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise _InvalidRequest from None
    if len(value) > MAX_WORKER_PASSWORD_BYTES:
        raise _InvalidRequest
    if kind == "none":
        if value:
            raise _InvalidRequest
        return None
    if kind == "bytes":
        return value
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        raise _InvalidRequest from None


def _read_exact_input(expected_size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = expected_size
    while remaining:
        chunk = sys.stdin.buffer.read(min(remaining, 64 * 1024))
        if not chunk:
            raise _InvalidRequest
        chunks.append(chunk)
        remaining -= len(chunk)
    if sys.stdin.buffer.read(1):
        raise _InvalidRequest
    return b"".join(chunks)


def _validated_int(
    payload: dict[str, Any],
    name: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    value = payload.get(name)
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        raise _InvalidRequest
    return value


def _emit_failure(code: str, *, output_limit: int) -> int:
    return _emit(
        {
            "protocol": WORKER_PROTOCOL,
            "ok": False,
            "result": {"code": code},
        },
        output_limit=output_limit,
    )


def _emit(payload: dict[str, Any], *, output_limit: int) -> int:
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError):
        encoded = _encoded_output_limit_failure()
    if len(encoded) > output_limit:
        encoded = _encoded_output_limit_failure()
    if len(encoded) > output_limit:
        return 1
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    return 0


def _encoded_output_limit_failure() -> bytes:
    return json.dumps(
        {
            "protocol": WORKER_PROTOCOL,
            "ok": False,
            "result": {"code": "pdf_worker_output_limit_exceeded"},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


if __name__ == "__main__":
    raise SystemExit(main())

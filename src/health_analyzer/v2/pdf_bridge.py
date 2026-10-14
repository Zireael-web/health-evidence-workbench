"""Byte-only document launch bridge supervised by the trusted bootstrap.

macOS refuses applying a second Seatbelt profile to an inherited sandboxed
process. The private runtime sends PDF/PNG/JPEG bytes to its existing bootstrap
parent. That parent starts the fixed bounded native PDF text parser under
its mandatory narrower profile. Images return pending visual transcription. Neither paths, commands, keys nor controls cross
this bridge. This is a separate parser sandbox, not stacked Seatbelt profiles.
"""
from __future__ import annotations

import json
import os
import re
import select
import stat
import threading
import time
from typing import Callable

from .common import V2Error, require

MAX_REQUEST = 64 * 1024 * 1024
MAX_RESPONSE = 32 * 1024 * 1024
# Bounds the byte-only native text extraction request.
RPC_TIMEOUT = 300.0
_ERROR_CODE = re.compile(r"[A-Za-z0-9_-]{1,160}\Z")
_runtime_client = None


def _validate_pipe(fd: int) -> None:
    require(type(fd) is int and fd > 2, "PDF_BRIDGE_INVALID", "A dedicated bootstrap pipe FD is required")
    try:
        require(stat.S_ISFIFO(os.fstat(fd).st_mode), "PDF_BRIDGE_INVALID", "PDF bridge must use anonymous pipe FDs")
        os.set_blocking(fd, False)
    except OSError as exc:
        raise V2Error("PDF_BRIDGE_INVALID", "PDF bridge descriptor is unavailable") from exc


def _wait(fd: int, *, writing: bool, deadline: float | None) -> None:
    while True:
        remaining = None if deadline is None else deadline - time.monotonic()
        require(remaining is None or remaining > 0, "PDF_BRIDGE_TIMEOUT", "PDF bridge request exceeded its deadline")
        try:
            read, write, _ = select.select([] if writing else [fd], [fd] if writing else [], [], remaining)
            require(bool(write if writing else read), "PDF_BRIDGE_TIMEOUT", "PDF bridge request exceeded its deadline")
            return
        except InterruptedError:
            continue
        except OSError as exc:
            raise V2Error("PDF_BRIDGE_IO_FAILED", "PDF bridge pipe failed") from exc


def _read_exact(fd: int, length: int, *, deadline: float | None,
                idle_header: bool = False) -> bytes | None:
    pieces = []
    consumed = 0
    while consumed < length:
        _wait(fd, writing=False, deadline=deadline)
        try:
            chunk = os.read(fd, min(65536, length - consumed))
        except BlockingIOError:
            continue
        except OSError as exc:
            raise V2Error("PDF_BRIDGE_IO_FAILED", "PDF bridge read failed") from exc
        if not chunk:
            if idle_header and consumed == 0:
                return None
            raise V2Error("PDF_BRIDGE_CLOSED", "PDF bridge closed before a complete frame")
        pieces.append(chunk)
        consumed += len(chunk)
        if idle_header and deadline is None:
            deadline = time.monotonic() + RPC_TIMEOUT
    return b"".join(pieces)


def _write_all(fd: int, data: bytes, *, deadline: float) -> None:
    offset = 0
    while offset < len(data):
        _wait(fd, writing=True, deadline=deadline)
        try:
            offset += os.write(fd, data[offset:offset + 65536])
        except BlockingIOError:
            continue
        except OSError as exc:
            raise V2Error("PDF_BRIDGE_IO_FAILED", "PDF bridge write failed") from exc


def _read_frame(fd: int, *, maximum: int, deadline: float | None,
                idle_header: bool = False) -> bytes | None:
    header = _read_exact(fd, 8, deadline=deadline, idle_header=idle_header)
    if header is None:
        return None
    size = int.from_bytes(header, "big")
    require(0 < size <= maximum, "PDF_BRIDGE_FRAME_INVALID", "PDF bridge frame exceeds its bound")
    if deadline is None:
        deadline = time.monotonic() + RPC_TIMEOUT
    return _read_exact(fd, size, deadline=deadline)


def _write_frame(fd: int, data: bytes, *, maximum: int, deadline: float) -> None:
    require(0 < len(data) <= maximum, "PDF_BRIDGE_FRAME_INVALID", "PDF bridge frame exceeds its bound")
    _write_all(fd, len(data).to_bytes(8, "big"), deadline=deadline)
    _write_all(fd, data, deadline=deadline)


class PdfBridgeBootstrap:
    """One byte-only broker thread in the existing launcher process.

    Callback injection is for synthetic tests only; production uses the fixed
    v2 bounded parser function. There is no transport field for a callback/path.
    """
    def __init__(self, extractor: Callable | None = None):
        self._request_read, self._request_write = os.pipe()
        self._response_read, self._response_write = os.pipe()
        for fd in (*self.client_fds, self._request_read, self._response_write):
            _validate_pipe(fd)
        self._extractor = extractor
        self._closed = False
        self._started = False
        self._thread = threading.Thread(target=self._serve, name="v2-pdf-launch-bridge", daemon=True)

    @property
    def client_fds(self) -> tuple[int, int]:
        return self._request_write, self._response_read

    def __enter__(self):
        self._started = True
        self._thread.start()
        return self

    def _serve(self) -> None:
        try:
            while True:
                content = _read_frame(self._request_read, maximum=MAX_REQUEST, deadline=None, idle_header=True)
                if content is None:
                    return
                try:
                    if self._extractor is None:
                        from .ingest import extract_document_native
                        extractor = extract_document_native
                    else:
                        extractor = self._extractor
                    blocks, limitations = extractor(content)
                    from health_analyzer.ingest.pypdf_subprocess import serialize_block
                    serialized = [item if isinstance(item, dict) else serialize_block(item) for item in blocks]
                    response = {"ok": True, "blocks": serialized, "limitations": limitations}
                except V2Error as exc:
                    response = {"ok": False, "code": exc.code if _ERROR_CODE.fullmatch(exc.code) else "PDF_EXTRACTION_FAILED"}
                except Exception:
                    response = {"ok": False, "code": "PDF_EXTRACTION_FAILED"}
                try:
                    payload = json.dumps(response, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
                except (TypeError, ValueError):
                    payload = b'{"ok":false,"code":"PDF_BRIDGE_PROTOCOL_ERROR"}'
                if len(payload) > MAX_RESPONSE:
                    payload = b'{"ok":false,"code":"PDF_BRIDGE_OUTPUT_LIMIT"}'
                _write_frame(self._response_write, payload, maximum=MAX_RESPONSE,
                             deadline=time.monotonic() + RPC_TIMEOUT)
        except (V2Error, OSError):
            # A broken/invalid framing channel closes. Runtime must not retry
            # through an unsandboxed local parser.
            return
        finally:
            for fd in (self._request_read, self._response_write):
                try:
                    os.close(fd)
                except OSError:
                    pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for fd in self.client_fds:
            try:
                os.close(fd)
            except OSError:
                pass
        # Normal runtime exit produces EOF immediately. A currently running
        # parser retains its independent CPU/wall/output bounds.
        if self._thread.is_alive():
            self._thread.join(timeout=2.0)
        if not self._started:
            for fd in (self._request_read, self._response_write):
                try:
                    os.close(fd)
                except OSError:
                    pass

    def __exit__(self, *exc):
        self.close()


class _PdfRuntimeClient:
    def __init__(self, request_fd: int, response_fd: int):
        require(request_fd != response_fd, "PDF_BRIDGE_INVALID", "Separate request and response pipes are required")
        _validate_pipe(request_fd)
        _validate_pipe(response_fd)
        self.request_fd, self.response_fd = request_fd, response_fd
        self.lock = threading.Lock()
        self.failed = False
        self.closed = False

    def extract(self, content: bytes) -> tuple[list[dict], list[str]]:
        require(isinstance(content, bytes) and 0 < len(content) <= MAX_REQUEST,
                "PDF_BRIDGE_INPUT_LIMIT", "PDF input must be bounded bytes")
        deadline = time.monotonic() + RPC_TIMEOUT
        require(self.lock.acquire(timeout=RPC_TIMEOUT), "PDF_BRIDGE_BUSY", "PDF bridge is serving another bounded request")
        try:
            require(not self.failed, "PDF_BRIDGE_CLOSED", "PDF launch bridge is unavailable")
            try:
                _write_frame(self.request_fd, content, maximum=MAX_REQUEST, deadline=deadline)
                data = _read_frame(self.response_fd, maximum=MAX_RESPONSE, deadline=deadline)
                require(data is not None, "PDF_BRIDGE_CLOSED", "PDF bridge returned no response")
                try:
                    response = json.loads(data)
                except (ValueError, UnicodeError) as exc:
                    raise V2Error("PDF_BRIDGE_PROTOCOL_ERROR", "PDF bridge returned invalid JSON") from exc
                require(isinstance(response, dict) and type(response.get("ok")) is bool,
                        "PDF_BRIDGE_PROTOCOL_ERROR", "PDF bridge response is invalid")
                if not response["ok"]:
                    require(set(response) == {"ok", "code"} and isinstance(response["code"], str)
                            and bool(_ERROR_CODE.fullmatch(response["code"])),
                            "PDF_BRIDGE_PROTOCOL_ERROR", "PDF bridge failure response is invalid")
                    # A valid parser failure does not damage the IPC stream.
                    raise _RemoteFailure(response["code"])
                require(set(response) == {"ok", "blocks", "limitations"},
                        "PDF_BRIDGE_PROTOCOL_ERROR", "PDF bridge response fields are invalid")
                require(isinstance(response["blocks"], list) and len(response["blocks"]) <= 500,
                        "PDF_BRIDGE_PROTOCOL_ERROR", "PDF bridge block count exceeds its bound")
                from health_analyzer.ingest.pypdf_subprocess import _decode_block, serialize_block
                try:
                    blocks = [_decode_ocr_page(item) if isinstance(item, dict) and item.get("source") == "vision_ocr"
                              else _decode_pdf_geometry_page(item) if isinstance(item, dict) and item.get("source") == "pdf_text"
                              else serialize_block(_decode_block(item)) for item in response["blocks"]]
                    _validate_document_blocks(blocks)
                except Exception as exc:
                    raise V2Error("PDF_BRIDGE_PROTOCOL_ERROR", "PDF bridge block validation failed") from exc
                limitations = response["limitations"]
                require(isinstance(limitations, list) and len(limitations) <= 100
                        and all(isinstance(item, str) and len(item) <= 4000 for item in limitations),
                        "PDF_BRIDGE_PROTOCOL_ERROR", "PDF bridge limitations are invalid")
                return blocks, limitations
            except _RemoteFailure as exc:
                raise V2Error(exc.code, "Mandatory bounded PDF parser reported a failure") from exc
            except V2Error:
                self.failed = True
                self.close()
                raise
        finally:
            self.lock.release()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.failed = True
        for fd in (self.request_fd, self.response_fd):
            try:
                os.close(fd)
            except OSError:
                pass


class _RemoteFailure(Exception):
    def __init__(self, code: str):
        self.code = code


def _validate_document_blocks(blocks: list[dict]) -> None:
    """Validate native pages and historical OCR payloads without execution."""
    from . import pdf_geometry, vision
    native_words = native_text = native_word_text = 0
    ocr_words = ocr_text = ocr_word_text = 0
    crop_passes = crop_pixels = 0
    seen_pages = set()
    for page in blocks:
        source = page.get("source")
        if source in {"pdf_text", "vision_ocr"}:
            require(page["page"] not in seen_pages, "PDF_BRIDGE_PROTOCOL_ERROR", "Document repeats a source page")
            seen_pages.add(page["page"])
        if source == "pdf_text":
            native_words += len(page["blocks"])
            native_text += len(page["text"].encode("utf-8"))
            native_word_text += sum(len(b["text"].encode("utf-8")) for b in page["blocks"])
        elif source == "vision_ocr":
            ocr_words += len(page["blocks"])
            ocr_text += len(page["text"].encode("utf-8"))
            ocr_word_text += sum(len(b["text"].encode("utf-8")) for b in page["blocks"])
            ocr_text += sum(len(candidate["text"].encode("utf-8"))
                            for block in page["blocks"] for candidate in block.get("candidates", []))
            receipt = page["metadata"].get("recognition", {})
            crop_passes += receipt.get("crop_passes", 0)
            crop_pixels += receipt.get("crop_pixels", 0)
    require(native_words <= pdf_geometry.MAX_WORDS and native_text <= pdf_geometry.MAX_TEXT and
            native_word_text <= pdf_geometry.MAX_TEXT, "PDF_BRIDGE_PROTOCOL_ERROR", "Native geometry document exceeds word/text bounds")
    require(ocr_words <= vision.MAX_BLOCKS and ocr_text <= vision.MAX_TEXT_BYTES and
            ocr_word_text <= vision.MAX_TEXT_BYTES and crop_passes <= vision.MAX_TOTAL_CROP_PASSES and
            crop_pixels <= vision.MAX_CROP_PIXELS,
            "PDF_BRIDGE_PROTOCOL_ERROR", "OCR document exceeds block/text/crop bounds")


def _decode_pdf_geometry_page(item: dict) -> dict:
    import copy
    from .pdf_geometry import PROTOCOL, decode_geometry
    page = copy.deepcopy(item)
    number = page.get("page")
    incomplete = page.pop("document_incomplete", False)
    require(type(number) is int and 1 <= number <= 500 and type(incomplete) is bool,
            "PDF_BRIDGE_PROTOCOL_ERROR", "Invalid native geometry page state")
    page["page"] = 1
    raw = json.dumps({"protocol": PROTOCOL, "ok": True, "pages": [page]}, ensure_ascii=False, allow_nan=False).encode()
    decoded = decode_geometry(raw)[0]
    decoded["page"] = number
    decoded["document_incomplete"] = incomplete
    return decoded


def _decode_ocr_page(item: dict) -> dict:
    """Validate historical OCR geometry only; this never invokes recognition."""
    import copy
    from .vision import PROTOCOL, _decode_response
    page = copy.deepcopy(item)
    number = page.get("page")
    require(type(number) is int and 1 <= number <= 500, "PDF_BRIDGE_PROTOCOL_ERROR", "OCR page is out of bounds")
    page["page"] = 1
    if isinstance(page.get("metadata"), dict):
        page["metadata"].pop("quality", None)
    payload = json.dumps({"protocol": PROTOCOL, "ok": True, "pages": [page]}, ensure_ascii=False, allow_nan=False).encode()
    decoded = _decode_response(payload, maximum=1)[0]
    decoded["page"] = number
    return decoded


def configure_runtime_bridge(request_fd: int, response_fd: int) -> None:
    global _runtime_client
    require(_runtime_client is None, "PDF_BRIDGE_INVALID", "PDF bridge can only be configured once per runtime")
    _runtime_client = _PdfRuntimeClient(request_fd, response_fd)


def close_runtime_bridge() -> None:
    global _runtime_client
    if _runtime_client is not None:
        _runtime_client.close()
        _runtime_client = None


def extract_via_bridge_if_configured(content: bytes) -> tuple[list[dict], list[str]] | None:
    if _runtime_client is None:
        return None
    return _runtime_client.extract(content)

"""Local, type-independent PDF text extraction through an optional pypdf runtime.

The provider accepts immutable bytes and never writes the document to disk.  It
does text extraction only: image-only pages are reported as requiring a
separate OCR provider and are never relabelled as recognized text.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from importlib.metadata import PackageNotFoundError, version as package_version
from io import BytesIO
from typing import Any, BinaryIO, ClassVar, Protocol

from .models import BlockDraft, BlockKind, ExtractionCapability, content_hash
from .pypdf_subprocess import (
    WORKER_PROTOCOL,
    PypdfSubprocessLimits,
    extract_pdf_in_subprocess,
)
from .registry import ExtractorFailure


class PDFPageLike(Protocol):
    def get_contents(self) -> Any: ...

    def extract_text(self, *args: Any, **kwargs: Any) -> str | None: ...


class PDFReaderLike(Protocol):
    is_encrypted: bool
    pages: Sequence[PDFPageLike]

    def decrypt(self, password: str | bytes) -> Any: ...


PDFReaderFactory = Callable[[BinaryIO], PDFReaderLike]


@dataclass(frozen=True, slots=True)
class PypdfExtractionLimits:
    """Bounds checked before pypdf performs page text extraction."""

    max_input_bytes: int = 64 * 1024 * 1024
    max_pages: int = 500
    max_page_content_stream_bytes: int = 32 * 1024 * 1024
    max_total_content_stream_bytes: int = 128 * 1024 * 1024
    max_page_extracted_text_bytes: int = 4 * 1024 * 1024
    max_total_extracted_text_bytes: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        for name in (
            "max_input_bytes",
            "max_pages",
            "max_page_content_stream_bytes",
            "max_total_content_stream_bytes",
            "max_page_extracted_text_bytes",
            "max_total_extracted_text_bytes",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True, slots=True)
class PypdfTextProvider:
    """Extract page text in a bounded worker, or in-process with an injected reader."""

    provider_id: ClassVar[str] = "pypdf-local-text"
    version: ClassVar[str] = "1.0"
    capabilities: ClassVar[frozenset[ExtractionCapability]] = frozenset(
        {ExtractionCapability.PDF, ExtractionCapability.NATIVE_TEXT}
    )
    limits: PypdfExtractionLimits = field(default_factory=PypdfExtractionLimits)
    subprocess_limits: PypdfSubprocessLimits = field(
        default_factory=PypdfSubprocessLimits
    )
    reader_factory: PDFReaderFactory | None = field(default=None, repr=False)
    password: str | bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.limits is None:
            object.__setattr__(self, "limits", PypdfExtractionLimits())
        if self.subprocess_limits is None:
            object.__setattr__(self, "subprocess_limits", PypdfSubprocessLimits())

    @property
    def configuration_fingerprint(self) -> str:
        if self.reader_factory is None:
            execution_mode = "sandbox-inherited-subprocess"
            reader_factory_id = "worker:pypdf.PdfReader(strict=False)"
            try:
                dependency_version = package_version("pypdf")
            except PackageNotFoundError:
                dependency_version = "not-installed"
        else:
            execution_mode = "in-process-injected-reader"
            reader_factory_id = ".".join(
                (
                    getattr(
                        self.reader_factory,
                        "__module__",
                        type(self.reader_factory).__module__,
                    ),
                    getattr(
                        self.reader_factory,
                        "__qualname__",
                        type(self.reader_factory).__qualname__,
                    ),
                )
            )
            dependency_version = "injected-reader-factory"
        return content_hash(
            {
                "provider_id": self.provider_id,
                "version": self.version,
                "limits": {
                    "max_input_bytes": self.limits.max_input_bytes,
                    "max_pages": self.limits.max_pages,
                    "max_page_content_stream_bytes": (
                        self.limits.max_page_content_stream_bytes
                    ),
                    "max_total_content_stream_bytes": (
                        self.limits.max_total_content_stream_bytes
                    ),
                    "max_page_extracted_text_bytes": (
                        self.limits.max_page_extracted_text_bytes
                    ),
                    "max_total_extracted_text_bytes": (
                        self.limits.max_total_extracted_text_bytes
                    ),
                },
                "execution_mode": execution_mode,
                "reader_factory": reader_factory_id,
                "pypdf_version": dependency_version,
                "worker_protocol": (
                    WORKER_PROTOCOL if self.reader_factory is None else None
                ),
                "subprocess_limits": (
                    {
                        "timeout_seconds": self.subprocess_limits.timeout_seconds,
                        "cpu_seconds": self.subprocess_limits.cpu_seconds,
                        "max_address_space_bytes": (
                            self.subprocess_limits.max_address_space_bytes
                        ),
                        "max_open_files": self.subprocess_limits.max_open_files,
                        "max_input_bytes": self.subprocess_limits.max_input_bytes,
                        "max_output_bytes": self.subprocess_limits.max_output_bytes,
                        "max_stderr_bytes": self.subprocess_limits.max_stderr_bytes,
                    }
                    if self.reader_factory is None
                    else None
                ),
                # Never derive or expose a reusable fingerprint of a credential.
                # The frozen provider guarantees the configured value cannot
                # change during the lifetime of this pipeline/cache.
                "password_configured": self.password is not None,
            }
        )

    def extract_pdf(self, content: bytes) -> tuple[BlockDraft, ...]:
        immutable_content = bytes(content)
        if not immutable_content:
            raise ExtractorFailure(
                "pdf_empty_input",
                "PDF input contains no bytes.",
                recoverable=False,
            )
        if len(immutable_content) > self.limits.max_input_bytes:
            raise ExtractorFailure(
                "pdf_input_size_limit_exceeded",
                "PDF input exceeds the configured byte limit.",
                recoverable=False,
            )

        if self.reader_factory is None:
            return extract_pdf_in_subprocess(
                immutable_content,
                document_limits=self.limits,
                subprocess_limits=self.subprocess_limits,
                password=self.password,
            )

        # Keep the stream alive for the full extraction because pypdf resolves
        # objects lazily from the seekable source.
        stream = BytesIO(immutable_content)
        reader = self._open_reader(stream)
        self._handle_encryption(reader)
        pages = self._pages(reader)
        page_count = len(pages)
        if page_count == 0:
            raise ExtractorFailure(
                "pdf_empty_document",
                "PDF contains no pages.",
                recoverable=False,
            )
        if page_count > self.limits.max_pages:
            raise ExtractorFailure(
                "pdf_page_limit_exceeded",
                "PDF page count exceeds the configured limit.",
                recoverable=False,
            )

        blocks: list[BlockDraft] = []
        pages_without_text: list[int] = []
        pages_with_extraction_errors: list[int] = []
        total_content_bytes = 0
        total_text_bytes = 0

        for page_number, page in enumerate(pages, start=1):
            content_bytes = self._content_stream_size(page, page_number)
            if content_bytes > self.limits.max_page_content_stream_bytes:
                raise ExtractorFailure(
                    "pdf_page_content_stream_limit_exceeded",
                    f"PDF page {page_number} exceeds the content-stream byte limit.",
                    recoverable=False,
                )
            total_content_bytes += content_bytes
            if total_content_bytes > self.limits.max_total_content_stream_bytes:
                raise ExtractorFailure(
                    "pdf_total_content_stream_limit_exceeded",
                    "PDF exceeds the cumulative content-stream byte limit.",
                    recoverable=False,
                )

            text, used_plain_fallback, extraction_failed = self._extract_page_text(page)
            if extraction_failed:
                pages_with_extraction_errors.append(page_number)
                continue
            if text is None or not text.strip():
                pages_without_text.append(page_number)
                continue

            try:
                text_size = len(text.encode("utf-8"))
            except UnicodeEncodeError as error:
                raise ExtractorFailure(
                    "pdf_text_encoding_failed",
                    "Extracted PDF text could not be represented safely.",
                    recoverable=False,
                ) from error
            if text_size > self.limits.max_page_extracted_text_bytes:
                raise ExtractorFailure(
                    "pdf_page_text_limit_exceeded",
                    f"PDF page {page_number} exceeds the extracted-text byte limit.",
                    recoverable=False,
                )
            total_text_bytes += text_size
            if total_text_bytes > self.limits.max_total_extracted_text_bytes:
                raise ExtractorFailure(
                    "pdf_total_text_limit_exceeded",
                    "PDF exceeds the cumulative extracted-text byte limit.",
                    recoverable=False,
                )

            limitations = [
                "pypdf extracts native PDF text without OCR; reading order and "
                "layout may differ from the rendered page."
            ]
            if used_plain_fallback:
                limitations.append(
                    "Layout extraction was unavailable or empty on this page; "
                    "plain text extraction fallback was used."
                )
            blocks.append(
                BlockDraft(
                    kind=BlockKind.TEXT,
                    text=text,
                    page=page_number,
                    line_start=1,
                    line_end=max(1, len(text.splitlines())),
                    confidence=None,
                    limitations=tuple(limitations),
                )
            )

        if not blocks:
            if pages_without_text:
                raise ExtractorFailure(
                    "pdf_ocr_required",
                    "PDF has no extractable text on its pages; it may be blank or "
                    "image-only and requires a separate OCR provider.",
                )
            raise ExtractorFailure(
                "pdf_text_extraction_failed",
                "pypdf could not extract text from any PDF page.",
            )

        document_limitations: list[str] = []
        if pages_without_text:
            document_limitations.append(
                "Pages with no extractable text were omitted: "
                f"{_format_pages(pages_without_text)}. OCR may be required for "
                "image-only content."
            )
        if pages_with_extraction_errors:
            document_limitations.append(
                "Pages where both layout and plain text extraction failed were "
                f"omitted: {_format_pages(pages_with_extraction_errors)}."
            )
        if document_limitations:
            blocks[0] = replace(
                blocks[0],
                document_incomplete=True,
                limitations=(*blocks[0].limitations, *document_limitations),
            )
        return tuple(blocks)

    def _open_reader(self, stream: BinaryIO) -> PDFReaderLike:
        factory = self.reader_factory or _default_reader_factory
        try:
            return factory(stream)
        except ExtractorFailure:
            raise
        except Exception as error:
            raise ExtractorFailure(
                "pdf_read_error",
                f"pypdf could not parse the PDF ({type(error).__name__}).",
            ) from error

    def _handle_encryption(self, reader: PDFReaderLike) -> None:
        try:
            encrypted = bool(reader.is_encrypted)
        except Exception as error:
            raise ExtractorFailure(
                "pdf_encryption_status_error",
                "PDF encryption status could not be determined.",
                recoverable=False,
            ) from error
        if not encrypted:
            return
        if self.password is None:
            raise ExtractorFailure(
                "pdf_encrypted",
                "PDF is encrypted and no password was provided.",
                recoverable=False,
            )
        try:
            decrypted = reader.decrypt(self.password)
        except Exception as error:
            raise ExtractorFailure(
                "pdf_decryption_failed",
                "PDF could not be decrypted with the provided password.",
                recoverable=False,
            ) from error
        if not decrypted:
            raise ExtractorFailure(
                "pdf_decryption_failed",
                "PDF could not be decrypted with the provided password.",
                recoverable=False,
            )

    @staticmethod
    def _pages(reader: PDFReaderLike) -> Sequence[PDFPageLike]:
        try:
            pages = reader.pages
            len(pages)
            return pages
        except Exception as error:
            raise ExtractorFailure(
                "pdf_page_index_error",
                "PDF page index could not be read.",
            ) from error

    @staticmethod
    def _content_stream_size(page: PDFPageLike, page_number: int) -> int:
        try:
            contents = page.get_contents()
            if contents is None:
                return 0
            data = contents.get_data()
            if not isinstance(data, (bytes, bytearray, memoryview)):
                raise TypeError("content stream did not return bytes")
            return len(data)
        except Exception as error:
            if _is_pypdf_limit_error(error):
                raise ExtractorFailure(
                    "pdf_page_content_stream_limit_exceeded",
                    f"PDF page {page_number} exceeds the content-stream byte limit.",
                    recoverable=False,
                ) from None
            raise ExtractorFailure(
                "pdf_content_stream_read_failed",
                f"PDF page {page_number} content stream could not be measured.",
                recoverable=False,
            ) from error

    @staticmethod
    def _extract_page_text(page: PDFPageLike) -> tuple[str | None, bool, bool]:
        try:
            layout_text = page.extract_text(
                extraction_mode="layout",
                layout_mode_space_vertically=False,
            )
            if layout_text is not None and not isinstance(layout_text, str):
                raise TypeError("layout extraction did not return text")
            if layout_text and layout_text.strip():
                return layout_text, False, False
        except Exception as error:
            if _is_pypdf_limit_error(error):
                raise ExtractorFailure(
                    "pdf_page_content_stream_limit_exceeded",
                    "PDF page extraction exceeded the content-stream byte limit.",
                    recoverable=False,
                ) from None

        try:
            plain_text = page.extract_text()
            if plain_text is not None and not isinstance(plain_text, str):
                raise TypeError("plain extraction did not return text")
            return plain_text, bool(plain_text and plain_text.strip()), False
        except Exception as error:
            if _is_pypdf_limit_error(error):
                raise ExtractorFailure(
                    "pdf_page_content_stream_limit_exceeded",
                    "PDF page extraction exceeded the content-stream byte limit.",
                    recoverable=False,
                ) from None
            return None, False, True


def _default_reader_factory(stream: BinaryIO) -> PDFReaderLike:
    try:
        from pypdf import PdfReader
    except ImportError as error:
        raise ExtractorFailure(
            "pypdf_dependency_missing",
            "pypdf is required for local PDF text extraction.",
        ) from error
    return PdfReader(stream, strict=False)


def _is_pypdf_limit_error(error: BaseException) -> bool:
    try:
        from pypdf.errors import LimitReachedError
    except ImportError:
        return False
    return isinstance(error, LimitReachedError)


def _format_pages(pages: list[int]) -> str:
    return ", ".join(str(page) for page in pages)

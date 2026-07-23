from __future__ import annotations

from io import BytesIO
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, BinaryIO
import zlib

import pytest

import health_analyzer.ingest.pypdf_subprocess as pypdf_subprocess
from health_analyzer.ingest.pypdf_worker import _configure_pypdf_decode_limits

from health_analyzer.ingest import (
    BlockKind,
    DocumentArtifact,
    ExtractionCapability,
    ExtractorFailure,
    ExtractorRegistry,
    IngestionPipeline,
    PDFProviderExtractor,
    PypdfExtractionLimits,
    PypdfSubprocessLimits,
    PypdfTextProvider,
    default_extractors,
)
from health_analyzer.ingest.pypdf_subprocess import (
    PDF_PARSER_PROFILE,
    PROJECT_ROOT,
    _pdf_worker_command,
    _release_pdf_worker_command,
    _render_pdf_parser_profile,
    _run_bounded_process,
)


class FakeContents:
    def __init__(self, size: int, events: list[str]) -> None:
        self.size = size
        self.events = events

    def get_data(self) -> bytes:
        self.events.append("content")
        return b"x" * self.size


class FakePage:
    def __init__(
        self,
        *,
        layout: str | None | Exception,
        plain: str | None | Exception = None,
        content_size: int = 1,
    ) -> None:
        self.layout = layout
        self.plain = layout if plain is None else plain
        self.content_size = content_size
        self.events: list[str] = []

    def get_contents(self) -> FakeContents:
        return FakeContents(self.content_size, self.events)

    def extract_text(self, *args: Any, **kwargs: Any) -> str | None:
        is_layout = kwargs.get("extraction_mode") == "layout"
        self.events.append("layout" if is_layout else "plain")
        value = self.layout if is_layout else self.plain
        if isinstance(value, Exception):
            raise value
        return value


class FakeReader:
    def __init__(
        self,
        pages: list[FakePage],
        *,
        encrypted: bool = False,
        decrypt_result: int = 1,
    ) -> None:
        self.pages = pages
        self.is_encrypted = encrypted
        self.decrypt_result = decrypt_result
        self.passwords: list[str | bytes] = []

    def decrypt(self, password: str | bytes) -> int:
        self.passwords.append(password)
        return self.decrypt_result


class RecordingReaderFactory:
    def __init__(self, reader: FakeReader) -> None:
        self.reader = reader
        self.streams: list[BinaryIO] = []
        self.process_ids: list[int] = []

    def __call__(self, stream: BinaryIO) -> FakeReader:
        self.process_ids.append(os.getpid())
        self.streams.append(stream)
        return self.reader


def _provider(
    pages: list[FakePage],
    *,
    limits: PypdfExtractionLimits | None = None,
    encrypted: bool = False,
    password: str | bytes | None = None,
    decrypt_result: int = 1,
) -> tuple[PypdfTextProvider, FakeReader, RecordingReaderFactory]:
    reader = FakeReader(
        pages,
        encrypted=encrypted,
        decrypt_result=decrypt_result,
    )
    factory = RecordingReaderFactory(reader)
    return (
        PypdfTextProvider(
            limits=limits,
            reader_factory=factory,
            password=password,
        ),
        reader,
        factory,
    )


def _failure_code(provider: PypdfTextProvider, content: bytes = b"%PDF-fake") -> str:
    with pytest.raises(ExtractorFailure) as raised:
        provider.extract_pdf(content)
    return raised.value.code


def _native_text_pdf(text: str) -> bytes:
    """Build a minimal deterministic PDF with one native Helvetica text run."""

    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode("ascii")
    objects = (
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        ),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
    )
    output = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = []
    for number, payload in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode("ascii"))
        output.extend(payload)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(output)


def _compressed_content_pdf(decoded_padding_bytes: int) -> bytes:
    decoded = (
        b"%" + b"x" * decoded_padding_bytes + b"\n"
        b"BT /F1 12 Tf 72 720 Td (bounded) Tj ET"
    )
    stream = zlib.compress(decoded, level=9)
    objects = (
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        ),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(stream)
        + stream
        + b"\nendstream",
    )
    output = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = []
    for number, payload in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode("ascii"))
        output.extend(payload)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(output)


def test_pdf_worker_uses_a_fixed_dedicated_seatbelt_profile_on_macos(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sandbox_exec = tmp_path / "sandbox-exec"
    sandbox_exec.write_text("#!/bin/sh\nexit 1\n")
    sandbox_exec.chmod(0o700)
    profile = tmp_path / "pdf-parser.sb"
    profile.write_text("(version 1)\n(deny default)\n")
    profile.chmod(0o600)
    monkeypatch.setattr(pypdf_subprocess.sys, "platform", "darwin")
    monkeypatch.setattr(pypdf_subprocess, "SANDBOX_EXEC", sandbox_exec)
    monkeypatch.setattr(pypdf_subprocess, "PDF_PARSER_PROFILE", profile)

    command = _pdf_worker_command()

    assert command[:3] == (str(sandbox_exec), "-f", str(profile))
    assert command[3:] == (
        sys.executable,
        "-I",
        "-B",
        "-X",
        "utf8",
        "-m",
        "health_analyzer.ingest.pypdf_worker",
    )


def test_pdf_worker_refuses_unsandboxed_macos_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(pypdf_subprocess.sys, "platform", "darwin")
    monkeypatch.setattr(
        pypdf_subprocess,
        "SANDBOX_EXEC",
        tmp_path / "missing-sandbox-exec",
    )
    monkeypatch.setattr(
        pypdf_subprocess,
        "PDF_PARSER_PROFILE",
        tmp_path / "missing-pdf-parser.sb",
    )

    with pytest.raises(ExtractorFailure) as failed:
        _pdf_worker_command()

    assert failed.value.code == "pdf_worker_sandbox_unavailable"
    assert failed.value.recoverable is False


def test_pdf_parser_policy_denies_handoff_keychain_and_network() -> None:
    assert PDF_PARSER_PROFILE == PROJECT_ROOT / "policies" / "pdf-parser.sb"
    profile = PDF_PARSER_PROFILE.read_text()
    state_root = str(PROJECT_ROOT / "state")
    handoff_root = str(PROJECT_ROOT / "state" / "handoff")

    assert "(deny default)" in profile
    assert "(deny file-read*" in profile
    assert "__PROJECT_ROOT__/state" in profile
    assert "__PROJECT_ROOT__" in profile
    assert "__PYTHON_ENV_ROOT__" in profile
    assert "__PYTHON_EXECUTABLE_ROOT__" in profile
    assert (
        "/usr/bin/security" not in profile
        or '(deny process-exec (literal "/usr/bin/security"))' in profile
    )
    assert "com.apple.securityd.general" in profile
    assert "com.apple.security.XPCKeychainSandboxCheck" in profile
    assert "(deny network*)" in profile
    assert "(allow network" not in profile
    assert "(allow process*)" not in profile
    assert "(deny process-fork)" in profile


@pytest.mark.skipif(
    sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").is_file(),
    reason="requires macOS Seatbelt",
)
def test_pdf_parser_seatbelt_probe_cannot_reach_sensitive_resources() -> None:
    probe_path = (
        PROJECT_ROOT
        / "state"
        / "handoff"
        / f".pdf-parser-seatbelt-probe-{os.getpid()}"
    )
    probe_program = f"""
import socket
import sys

violations = []
for path in (
    {str(PROJECT_ROOT / 'state' / 'handoff' / 'keys' / 'case-integrity-v1.bin')!r},
    '/path/to/local-resource',
):
    try:
        with open(path, 'rb'):
            pass
    except OSError:
        pass
    else:
        violations.append('sensitive-read')

try:
    with open({str(probe_path)!r}, 'xb'):
        pass
except OSError:
    pass
else:
    violations.append('handoff-write')

try:
    with socket.socket() as connection:
        connection.bind(('127.0.0.1', 0))
except OSError:
    pass
else:
    violations.append('network')

raise SystemExit(1 if violations else 0)
"""
    try:
        rendered_profile = _render_pdf_parser_profile()
        result = subprocess.run(
            (
                "/usr/bin/sandbox-exec",
                "-f",
                str(rendered_profile),
                sys.executable,
                "-I",
                "-B",
                "-X",
                "utf8",
                "-c",
                probe_program,
            ),
            cwd="/",
            env={"HOME": "/private/var/empty", "PATH": os.defpath},
            close_fds=True,
            capture_output=True,
            check=False,
            timeout=5,
        )
        assert result.returncode == 0, result.stderr.decode(errors="replace")
    finally:
        if "rendered_profile" in locals():
            _release_pdf_worker_command(
                (str(Path("/usr/bin/sandbox-exec")), "-f", str(rendered_profile))
            )
        probe_path.unlink(missing_ok=True)


def test_pypdf_provider_uses_bytesio_and_preserves_page_line_provenance() -> None:
    first = FakePage(layout="Heading\nValue", content_size=4)
    second = FakePage(layout="Second page", content_size=3)
    provider, _, factory = _provider([first, second])

    blocks = provider.extract_pdf(b"%PDF-synthetic")

    assert len(factory.streams) == 1
    assert isinstance(factory.streams[0], BytesIO)
    assert factory.streams[0].getvalue() == b"%PDF-synthetic"
    assert factory.process_ids == [os.getpid()]
    assert [block.kind for block in blocks] == [BlockKind.TEXT, BlockKind.TEXT]
    assert [block.page for block in blocks] == [1, 2]
    assert [(block.line_start, block.line_end) for block in blocks] == [(1, 2), (1, 1)]
    assert [block.text for block in blocks] == ["Heading\nValue", "Second page"]
    assert first.events == ["content", "layout"]
    assert second.events == ["content", "layout"]


def test_layout_extraction_falls_back_to_plain_text_per_page() -> None:
    page = FakePage(
        layout=TypeError("layout unsupported"),
        plain="plain fallback",
    )
    provider, _, _ = _provider([page])

    blocks = provider.extract_pdf(b"%PDF-synthetic")

    assert blocks[0].text == "plain fallback"
    assert page.events == ["content", "layout", "plain"]
    assert "plain text extraction fallback" in " ".join(blocks[0].limitations)


@pytest.mark.parametrize(
    ("limits", "pages", "content", "expected_code"),
    [
        (
            PypdfExtractionLimits(max_input_bytes=4),
            [FakePage(layout="text")],
            b"12345",
            "pdf_input_size_limit_exceeded",
        ),
        (
            PypdfExtractionLimits(max_pages=1),
            [FakePage(layout="one"), FakePage(layout="two")],
            b"%PDF",
            "pdf_page_limit_exceeded",
        ),
        (
            PypdfExtractionLimits(max_page_content_stream_bytes=3),
            [FakePage(layout="text", content_size=4)],
            b"%PDF",
            "pdf_page_content_stream_limit_exceeded",
        ),
        (
            PypdfExtractionLimits(
                max_page_content_stream_bytes=10,
                max_total_content_stream_bytes=5,
            ),
            [
                FakePage(layout="one", content_size=3),
                FakePage(layout="two", content_size=3),
            ],
            b"%PDF",
            "pdf_total_content_stream_limit_exceeded",
        ),
        (
            PypdfExtractionLimits(max_page_extracted_text_bytes=3),
            [FakePage(layout="text")],
            b"%PDF",
            "pdf_page_text_limit_exceeded",
        ),
        (
            PypdfExtractionLimits(
                max_page_extracted_text_bytes=10,
                max_total_extracted_text_bytes=5,
            ),
            [FakePage(layout="abc"), FakePage(layout="def")],
            b"%PDF",
            "pdf_total_text_limit_exceeded",
        ),
    ],
)
def test_pdf_safety_limits_are_structured_failures(
    limits: PypdfExtractionLimits,
    pages: list[FakePage],
    content: bytes,
    expected_code: str,
) -> None:
    provider, _, _ = _provider(pages, limits=limits)

    assert _failure_code(provider, content) == expected_code


def test_encrypted_pdf_requires_password_and_accepts_injected_password() -> None:
    locked, locked_reader, _ = _provider(
        [FakePage(layout="secret text")],
        encrypted=True,
    )
    unlocked, unlocked_reader, _ = _provider(
        [FakePage(layout="available text")],
        encrypted=True,
        password="synthetic-password",
    )

    assert _failure_code(locked) == "pdf_encrypted"
    assert not locked_reader.passwords
    assert unlocked.extract_pdf(b"%PDF-fake")[0].text == "available text"
    assert unlocked_reader.passwords == ["synthetic-password"]


def test_zero_page_and_image_only_pdf_have_distinct_structured_failures() -> None:
    empty, _, _ = _provider([])
    image_only, _, _ = _provider(
        [FakePage(layout="", plain="", content_size=20)]
    )

    assert _failure_code(empty) == "pdf_empty_document"
    assert _failure_code(image_only) == "pdf_ocr_required"


def test_image_only_pdf_does_not_invent_image_or_ocr_blocks() -> None:
    provider, _, _ = _provider([FakePage(layout="", plain="")])
    extractor = PDFProviderExtractor(provider)
    pipeline = IngestionPipeline(registry=ExtractorRegistry((extractor,)))
    artifact = DocumentArtifact.from_bytes(b"%PDF-fake", media_type="application/pdf")

    result = pipeline.ingest(
        artifact,
        required_capabilities=frozenset({ExtractionCapability.PDF}),
    )

    assert not result.blocks
    assert not result.candidates
    assert [failure.code for failure in result.failures] == ["pdf_ocr_required"]
    assert result.failures[0].recoverable is True


def test_partial_image_only_pdf_keeps_text_pages_and_records_ocr_limitation() -> None:
    provider, _, _ = _provider(
        [
            FakePage(layout="", plain=""),
            FakePage(layout="page two text"),
        ]
    )

    blocks = provider.extract_pdf(b"%PDF-fake")

    assert [block.page for block in blocks] == [2]
    assert "Pages with no extractable text were omitted: 1" in " ".join(
        blocks[0].limitations
    )
    assert "OCR may be required" in " ".join(blocks[0].limitations)
    assert blocks[0].document_incomplete is True


def test_provider_configuration_changes_registry_fingerprint() -> None:
    first = ExtractorRegistry(
        (
            PDFProviderExtractor(
                PypdfTextProvider(limits=PypdfExtractionLimits(max_pages=10))
            ),
        )
    ).freeze()
    second = ExtractorRegistry(
        (
            PDFProviderExtractor(
                PypdfTextProvider(limits=PypdfExtractionLimits(max_pages=20))
            ),
        )
    ).freeze()

    assert first.fingerprint != second.fingerprint


def test_pypdf_block_provenance_contains_runtime_configuration_fingerprint() -> None:
    provider, _, _ = _provider([FakePage(layout="synthetic text")])
    pipeline = IngestionPipeline(
        registry=ExtractorRegistry((PDFProviderExtractor(provider),))
    )
    artifact = DocumentArtifact.from_bytes(
        b"%PDF-synthetic",
        media_type="application/pdf",
    )

    block = pipeline.ingest(artifact).blocks[0]

    assert block.extractor_version.startswith("1.0+cfg.")
    assert len(block.extractor_version.removeprefix("1.0+cfg.")) == 16


def test_default_registry_advertises_local_pdf_and_native_text_capabilities() -> None:
    registry = ExtractorRegistry(default_extractors())
    artifact = DocumentArtifact.from_bytes(b"%PDF-fake", media_type="application/pdf")

    selected = registry.select(
        artifact,
        required_capabilities=frozenset(
            {ExtractionCapability.PDF, ExtractionCapability.NATIVE_TEXT}
        ),
    )

    assert [item.descriptor.extractor_id for item in selected] == [
        "pdf-provider:pypdf-local-text"
    ]


def test_default_provider_extracts_in_dedicated_sandboxed_subprocess() -> None:
    provider = PypdfTextProvider()

    blocks = provider.extract_pdf(_native_text_pdf("Hello worker"))

    assert [block.text for block in blocks] == ["Hello worker"]
    limitations = " ".join(blocks[0].limitations)
    if sys.platform == "darwin":
        assert "dedicated macOS Seatbelt sandbox" in limitations
        assert "state, handoff keys, Keychain" in limitations
        assert (
            "file writes, network access, and child-process creation were denied"
            in limitations
        )
    else:
        assert "separate resource-limited process" in limitations
        assert "does not add a dedicated operating-system sandbox" in limitations
    assert "Bounded stdio, CPU, process-count, and file-descriptor limits" in limitations
    if sys.platform == "darwin":
        assert "RLIMIT_AS aliases advisory RLIMIT_RSS" in limitations


def test_worker_lowers_pypdf_decoder_limits_before_decompression(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pypdf import filters
    from pypdf.errors import LimitReachedError

    bounded_names = (
        "ZLIB_MAX_OUTPUT_LENGTH",
        "LZW_MAX_OUTPUT_LENGTH",
        "RUN_LENGTH_MAX_OUTPUT_LENGTH",
        "MAX_ARRAY_BASED_STREAM_OUTPUT_LENGTH",
        "JBIG2_MAX_OUTPUT_LENGTH",
    )
    for name in (*bounded_names, "MAX_DECLARED_STREAM_LENGTH"):
        monkeypatch.setattr(filters, name, 75_000_000)
    limits = PypdfExtractionLimits(
        max_input_bytes=16_384,
        max_page_content_stream_bytes=4_096,
        max_total_content_stream_bytes=4_096,
    )

    _configure_pypdf_decode_limits(limits)

    assert all(getattr(filters, name) == 4_096 for name in bounded_names)
    assert filters.MAX_DECLARED_STREAM_LENGTH == 16_384
    with pytest.raises(LimitReachedError):
        filters.FlateDecode.decode(zlib.compress(b"x" * 8_192))


def test_worker_never_raises_an_existing_lower_decoder_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pypdf import filters

    monkeypatch.setattr(filters, "ZLIB_MAX_OUTPUT_LENGTH", 2_048)
    _configure_pypdf_decode_limits(
        PypdfExtractionLimits(
            max_page_content_stream_bytes=4_096,
            max_total_content_stream_bytes=4_096,
        )
    )

    assert filters.ZLIB_MAX_OUTPUT_LENGTH == 2_048


def test_compressed_pdf_stream_is_rejected_at_decoder_ceiling() -> None:
    provider = PypdfTextProvider(
        limits=PypdfExtractionLimits(
            max_input_bytes=1024 * 1024,
            max_page_content_stream_bytes=4_096,
            max_total_content_stream_bytes=4_096,
        )
    )

    assert _failure_code(
        provider,
        _compressed_content_pdf(64 * 1024),
    ) == "pdf_page_content_stream_limit_exceeded"


def test_default_worker_preserves_capabilities_and_provenance_fingerprint() -> None:
    first_provider = PypdfTextProvider()
    second_provider = PypdfTextProvider(
        subprocess_limits=PypdfSubprocessLimits(cpu_seconds=9)
    )
    first = PDFProviderExtractor(first_provider)
    second = PDFProviderExtractor(second_provider)

    assert first.descriptor.capabilities == second.descriptor.capabilities == frozenset(
        {ExtractionCapability.PDF, ExtractionCapability.NATIVE_TEXT}
    )
    assert first.descriptor.configuration_fingerprint
    assert first.descriptor.configuration_fingerprint != (
        second.descriptor.configuration_fingerprint
    )

    pipeline = IngestionPipeline(registry=ExtractorRegistry((first,)))
    artifact = DocumentArtifact.from_bytes(
        _native_text_pdf("Provenance"),
        media_type="application/pdf",
    )
    block = pipeline.ingest(artifact).blocks[0]
    assert block.extractor_id == "pdf-provider:pypdf-local-text"
    assert block.extractor_version.startswith("1.0+cfg.")


def test_worker_enforces_parent_side_input_and_child_output_bounds() -> None:
    pdf = _native_text_pdf("x" * 2000)
    input_bounded = PypdfTextProvider(
        subprocess_limits=PypdfSubprocessLimits(max_input_bytes=128)
    )
    output_bounded = PypdfTextProvider(
        subprocess_limits=PypdfSubprocessLimits(max_output_bytes=1024)
    )

    assert _failure_code(input_bounded, pdf) == "pdf_input_size_limit_exceeded"
    assert _failure_code(output_bounded, pdf) == "pdf_worker_output_limit_exceeded"


def test_bounded_process_times_out_and_caps_untrusted_output() -> None:
    with pytest.raises(ExtractorFailure) as timed_out:
        _run_bounded_process(
            (sys.executable, "-I", "-c", "import time; time.sleep(5)"),
            b"request",
            timeout_seconds=0.05,
            max_output_bytes=1024,
            max_stderr_bytes=1024,
        )
    assert timed_out.value.code == "pdf_worker_timeout"

    with pytest.raises(ExtractorFailure) as oversized:
        _run_bounded_process(
            (
                sys.executable,
                "-I",
                "-c",
                "import sys; sys.stdout.buffer.write(b\"x\" * 4096)",
            ),
            b"request",
            timeout_seconds=2,
            max_output_bytes=1024,
            max_stderr_bytes=1024,
        )
    assert oversized.value.code == "pdf_worker_output_limit_exceeded"


def test_worker_process_failure_does_not_echo_stderr_or_paths() -> None:
    secret = "/private/clinical/secret-patient.pdf"
    with pytest.raises(ExtractorFailure) as failed:
        _run_bounded_process(
            (
                sys.executable,
                "-I",
                "-c",
                f"import sys; sys.stderr.write({secret!r}); raise SystemExit(7)",
            ),
            b"request",
            timeout_seconds=2,
            max_output_bytes=1024,
            max_stderr_bytes=1024,
        )

    assert failed.value.code == "pdf_worker_process_failed"
    assert secret not in failed.value.message

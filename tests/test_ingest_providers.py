from __future__ import annotations

from health_analyzer.ingest import (
    BlockDraft,
    BlockKind,
    DocumentArtifact,
    ExtractionCapability,
    ExtractorRegistry,
    ImagePassthroughExtractor,
    IngestionPipeline,
    OCRProviderExtractor,
    PDFProviderExtractor,
)
from health_analyzer.contracts import VerificationStatus



class SyntheticPDFProvider:
    provider_id = "synthetic-pdf"
    version = "3.2"

    def extract_pdf(self, content: bytes) -> tuple[BlockDraft, ...]:
        assert content.startswith(b"%PDF")
        return (
            BlockDraft(
                kind=BlockKind.TEXT,
                text="field: provider-value",
                page=1,
                bbox=(10.0, 20.0, 100.0, 40.0),
                line_start=1,
                line_end=1,
                confidence=0.99,
            ),
        )


class SyntheticOCRProvider:
    provider_id = "synthetic-ocr"
    version = "2.0"

    def recognize(self, content: bytes, media_type: str) -> tuple[BlockDraft, ...]:
        assert content == b"synthetic-image"
        assert media_type == "image/png"
        return (
            BlockDraft(
                kind=BlockKind.OCR,
                text="label: recognized",
                page=1,
                bbox=(1.0, 2.0, 30.0, 12.0),
                line_start=1,
                line_end=1,
                confidence=0.83,
                limitations=("Synthetic OCR output requires human verification.",),
            ),
        )


def test_optional_pdf_provider_preserves_page_bbox_and_provider_identity() -> None:
    adapter = PDFProviderExtractor(SyntheticPDFProvider())
    pipeline = IngestionPipeline(registry=ExtractorRegistry((adapter,)))
    artifact = DocumentArtifact.from_bytes(b"%PDF-1.4 synthetic provider placeholder", media_type="application/pdf")

    result = pipeline.ingest(
        artifact,
        required_capabilities=frozenset({ExtractionCapability.PDF}),
    )

    assert not result.failures
    assert result.blocks[0].extractor_id == "pdf-provider:synthetic-pdf"
    assert result.blocks[0].extractor_version == "3.2"
    assert result.blocks[0].page == 1
    assert result.blocks[0].bbox == (10.0, 20.0, 100.0, 40.0)
    assert result.candidates[0].provenance[0].bbox == result.blocks[0].bbox
    assert result.candidates[0].verification is VerificationStatus.NEEDS_REVIEW
    assert "review-routing signal" in " ".join(result.candidates[0].limitations)


def test_registered_ocr_provider_is_disabled_before_recognition() -> None:
    class NeverCalled(SyntheticOCRProvider):
        def recognize(self, content, media_type):
            raise AssertionError("Local OCR provider must never be called")

    registry = ExtractorRegistry((ImagePassthroughExtractor(), OCRProviderExtractor(NeverCalled())))
    artifact = DocumentArtifact.from_bytes(b"synthetic-image", media_type="image/png")
    result = IngestionPipeline(registry=registry).ingest(
        artifact, required_capabilities=frozenset({ExtractionCapability.IMAGE, ExtractionCapability.OCR}))
    assert not result.blocks and not result.candidates
    assert [failure.code for failure in result.failures] == ["LOCAL_OCR_DISABLED"]
    assert result.failures[0].recoverable is False


def test_image_passthrough_indexes_bytes_without_inventing_text() -> None:
    artifact = DocumentArtifact.from_bytes(b"synthetic-image", media_type="image/png")
    pipeline = IngestionPipeline()

    result = pipeline.ingest(artifact)
    repeated = pipeline.ingest(artifact)

    assert result.blocks[0].kind is BlockKind.IMAGE
    assert result.blocks[0].payload_sha256 == artifact.content_sha256
    assert result.blocks[0].document_incomplete is True
    assert result.complete is False
    assert repeated.deduplicated is False
    assert pipeline.cache_entry_count == 0
    assert not result.candidates
    assert "local OCR is disabled" in " ".join(result.limitations)



def test_disabled_ocr_provider_never_falls_back_or_populates_cache() -> None:
    class NeverCalled(SyntheticOCRProvider):
        def recognize(self, content, media_type):
            raise AssertionError("Local OCR provider must never be called")

    pipeline = IngestionPipeline(registry=ExtractorRegistry(
        (OCRProviderExtractor(NeverCalled()), ImagePassthroughExtractor())))
    artifact = DocumentArtifact.from_bytes(b"synthetic-image", media_type="image/png")
    result = pipeline.ingest(artifact)
    repeated = pipeline.ingest(artifact)
    assert result.blocks == repeated.blocks == ()
    assert result.candidates == repeated.candidates == ()
    assert [failure.code for failure in result.failures] == ["LOCAL_OCR_DISABLED"]
    assert result.failures[0].recoverable is False
    assert result.complete is repeated.complete is False
    assert repeated.deduplicated is False
    assert pipeline.cache_entry_count == 0

from __future__ import annotations

from pathlib import Path

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


FIXTURES = Path(__file__).parents[1] / "fixtures" / "ingest"


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
    artifact = DocumentArtifact.from_path(FIXTURES / "provider-placeholder.pdf")

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


def test_optional_ocr_provider_wins_by_priority_and_marks_ocr_origin() -> None:
    adapter = OCRProviderExtractor(SyntheticOCRProvider())
    registry = ExtractorRegistry((ImagePassthroughExtractor(), adapter))
    pipeline = IngestionPipeline(registry=registry)
    artifact = DocumentArtifact.from_bytes(
        b"synthetic-image",
        media_type="image/png",
        source_name="synthetic.png",
    )

    result = pipeline.ingest(
        artifact,
        required_capabilities=frozenset(
            {ExtractionCapability.IMAGE, ExtractionCapability.OCR}
        ),
    )

    block = result.blocks[0]
    assert block.kind is BlockKind.OCR
    assert block.extractor_id == "ocr-provider:synthetic-ocr"
    assert block.confidence == 0.83
    assert result.candidates[0].confidence == 0.83
    assert result.candidates[0].verification is VerificationStatus.NEEDS_REVIEW
    assert "requires human verification" in " ".join(
        result.candidates[0].limitations
    )
    assert "review-routing signal" in " ".join(
        result.candidates[0].limitations
    )
    assert "requires human verification" in " ".join(result.limitations)


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
    assert "no OCR provider" in " ".join(result.limitations)


def test_ocr_provider_image_only_output_cannot_claim_complete_ingestion() -> None:
    class ImageOnlyOCRProvider:
        provider_id = "image-only-ocr"
        version = "1"

        def recognize(self, content: bytes, media_type: str) -> tuple[BlockDraft, ...]:
            return (
                BlockDraft(
                    kind=BlockKind.IMAGE,
                    payload_sha256="a" * 64,
                ),
            )

    pipeline = IngestionPipeline(
        registry=ExtractorRegistry((OCRProviderExtractor(ImageOnlyOCRProvider()),))
    )
    artifact = DocumentArtifact.from_bytes(b"image", media_type="image/png")

    result = pipeline.ingest(artifact)
    repeated = pipeline.ingest(artifact)

    assert result.blocks[0].kind is BlockKind.IMAGE
    assert result.blocks[0].document_incomplete is True
    assert result.complete is repeated.complete is False
    assert result.candidates == repeated.candidates == ()
    assert repeated.deduplicated is False
    assert pipeline.cache_entry_count == 0


def test_ocr_provider_cannot_mislabel_recognized_text_as_native_text() -> None:
    class InvalidOCRProvider:
        provider_id = "invalid-ocr"
        version = "1"

        def recognize(self, content: bytes, media_type: str) -> tuple[BlockDraft, ...]:
            return (BlockDraft(kind=BlockKind.TEXT, text="not-native"),)

    registry = ExtractorRegistry(
        (OCRProviderExtractor(InvalidOCRProvider()), ImagePassthroughExtractor())
    )
    artifact = DocumentArtifact.from_bytes(b"synthetic-image", media_type="image/png")

    result = IngestionPipeline(registry=registry).ingest(artifact)

    assert not result.blocks
    assert [failure.code for failure in result.failures] == ["invalid_ocr_block"]
    assert result.failures[0].recoverable is False

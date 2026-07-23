from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from health_analyzer.contracts import VerificationStatus
from health_analyzer.ingest import (
    DocumentArtifact,
    IngestionPipeline,
    InvalidReviewTransition,
    review_candidate,
)


def test_review_transition_is_immutable_and_audited() -> None:
    artifact = DocumentArtifact.from_bytes(b"field: value", media_type="text/plain")
    original = IngestionPipeline().ingest(artifact).candidates[0]

    verified = review_candidate(
        original,
        VerificationStatus.VERIFIED,
        reviewer_id="synthetic-reviewer",
        note="Source checked.",
        reviewed_at="2026-01-02T03:04:05+00:00",
    )

    assert original.verification is VerificationStatus.EXTRACTED
    assert not original.review_history
    assert verified.verification is VerificationStatus.VERIFIED
    assert len(verified.review_history) == 1
    event = verified.review_history[0]
    assert event.from_status is VerificationStatus.EXTRACTED
    assert event.to_status is VerificationStatus.VERIFIED
    assert event.reviewer_id == "synthetic-reviewer"
    with pytest.raises(FrozenInstanceError):
        verified.raw_value = "changed"  # type: ignore[misc]


def test_rejected_candidate_is_terminal_and_review_requires_identity() -> None:
    artifact = DocumentArtifact.from_bytes(b"statement", media_type="text/plain")
    candidate = IngestionPipeline().ingest(artifact).candidates[0]
    rejected = review_candidate(
        candidate,
        VerificationStatus.REJECTED,
        reviewer_id="synthetic-reviewer",
        reviewed_at="2026-01-02T03:04:05+00:00",
    )

    with pytest.raises(InvalidReviewTransition):
        review_candidate(
            rejected,
            VerificationStatus.VERIFIED,
            reviewer_id="synthetic-reviewer",
        )
    with pytest.raises(ValueError, match="reviewer_id"):
        review_candidate(
            candidate,
            VerificationStatus.NEEDS_REVIEW,
            reviewer_id=" ",
        )

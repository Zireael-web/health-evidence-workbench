"""Explicit immutable human-review state transitions."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

from health_analyzer.contracts import VerificationStatus

from .models import Candidate, ReviewEvent, deterministic_id


class InvalidReviewTransition(ValueError):
    pass


_ALLOWED = {
    VerificationStatus.EXTRACTED: frozenset(
        {
            VerificationStatus.NEEDS_REVIEW,
            VerificationStatus.VERIFIED,
            VerificationStatus.REJECTED,
        }
    ),
    VerificationStatus.NEEDS_REVIEW: frozenset(
        {VerificationStatus.VERIFIED, VerificationStatus.REJECTED}
    ),
    VerificationStatus.VERIFIED: frozenset({VerificationStatus.NEEDS_REVIEW}),
    VerificationStatus.REJECTED: frozenset(),
}


def review_candidate(
    candidate: Candidate,
    to_status: VerificationStatus,
    *,
    reviewer_id: str,
    note: str | None = None,
    reviewed_at: str | None = None,
) -> Candidate:
    if not reviewer_id.strip():
        raise ValueError("reviewer_id is required")
    if to_status not in _ALLOWED[candidate.verification]:
        raise InvalidReviewTransition(
            f"cannot transition {candidate.verification.value} to {to_status.value}"
        )
    timestamp = reviewed_at or datetime.now(timezone.utc).isoformat()
    sequence = len(candidate.review_history)
    event = ReviewEvent(
        event_id=deterministic_id(
            "rev",
            candidate.candidate_id,
            str(sequence),
            candidate.verification.value,
            to_status.value,
            reviewer_id,
            timestamp,
            note or "",
        ),
        from_status=candidate.verification,
        to_status=to_status,
        reviewer_id=reviewer_id,
        reviewed_at=timestamp,
        note=note,
    )
    return replace(
        candidate,
        verification=to_status,
        review_history=(*candidate.review_history, event),
    )

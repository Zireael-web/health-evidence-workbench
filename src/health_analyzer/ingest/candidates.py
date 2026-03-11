"""Generic field/statement candidate generation without domain semantics."""

from __future__ import annotations

import re

from health_analyzer.contracts import VerificationStatus

from .models import (
    BlockKind,
    Candidate,
    CandidateKind,
    CandidateProvenance,
    ExtractionBlock,
    InstructionFinding,
    content_hash,
    deterministic_id,
)
from .registry import ExtractorFailure


_KEY_VALUE = re.compile(r"^\s*(?P<key>[^:=\t]{1,160}?)\s*[:=]\s*(?P<value>.+?)\s*$")
_DETERMINISTIC_CONFIDENCE_EXTRACTORS = frozenset(
    {"stdlib-plain-text", "stdlib-csv"}
)


def _block_review_context(
    block: ExtractionBlock,
) -> tuple[tuple[str, ...], bool]:
    """Carry extractor uncertainty into every candidate made from a block.

    Confidence values are routing metadata, not proof of correctness.  The
    generic layer deliberately has no universal score threshold: any
    probabilistic output, every OCR block, and every incomplete block requires
    an explicit review decision before promotion.
    """

    limitations = list(block.limitations)
    needs_review = False
    if block.kind is BlockKind.OCR:
        needs_review = True
        limitations.append(
            "OCR-derived text requires explicit human verification against the source."
        )
    if block.document_incomplete:
        needs_review = True
        limitations.append(
            "The source block was marked incomplete by its extractor."
        )
    if (
        block.confidence is not None
        and block.extractor_id not in _DETERMINISTIC_CONFIDENCE_EXTRACTORS
    ):
        needs_review = True
        limitations.append(
            "Extractor confidence is a review-routing signal, not verification."
        )
    return tuple(dict.fromkeys(limitations)), needs_review


def _findings_for_span(
    findings: tuple[InstructionFinding, ...],
    line_start: int | None,
    line_end: int | None = None,
) -> tuple[InstructionFinding, ...]:
    if line_start is None:
        return findings
    resolved_end = line_end if line_end is not None else line_start
    return tuple(
        item
        for item in findings
        if item.line is None or line_start <= item.line <= resolved_end
    )


class GenericCandidateBuilder:
    def __init__(
        self,
        *,
        max_candidates: int = 20_000,
        max_candidate_bytes: int = 64 * 1024,
        max_total_candidate_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        for name, value in (
            ("max_candidates", max_candidates),
            ("max_candidate_bytes", max_candidate_bytes),
            ("max_total_candidate_bytes", max_total_candidate_bytes),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if max_candidates > 1_000_000:
            raise ValueError("max_candidates exceeds the supported safety ceiling")
        if max_candidate_bytes > 1024 * 1024:
            raise ValueError("max_candidate_bytes must not exceed 1 MiB")
        if max_total_candidate_bytes > 128 * 1024 * 1024:
            raise ValueError("max_total_candidate_bytes must not exceed 128 MiB")
        self.max_candidates = max_candidates
        self.max_candidate_bytes = max_candidate_bytes
        self.max_total_candidate_bytes = max_total_candidate_bytes

    def build(self, blocks: tuple[ExtractionBlock, ...]) -> tuple[Candidate, ...]:
        candidates: list[Candidate] = []
        budget = [0, 0]
        for block in blocks:
            if block.kind in (BlockKind.TEXT, BlockKind.OCR):
                generated = self._from_text(block, budget=budget)
            elif block.kind is BlockKind.TABLE:
                generated = self._from_table(block, budget=budget)
            else:
                generated = []
            candidates.extend(generated)
        return tuple(candidates)

    def _provenance(
        self,
        block: ExtractionBlock,
        *,
        line_start: int | None = None,
        line_end: int | None = None,
        row_index: int | None = None,
        column_index: int | None = None,
    ) -> CandidateProvenance:
        resolved_start = line_start if line_start is not None else block.line_start
        resolved_end = (
            line_end
            if line_start is not None
            else block.line_end
        )
        return CandidateProvenance(
            artifact_id=block.artifact_id,
            artifact_sha256=block.artifact_sha256,
            block_id=block.block_id,
            block_sha256=block.block_sha256,
            extractor_id=block.extractor_id,
            extractor_version=block.extractor_version,
            page=block.page,
            bbox=block.bbox,
            line_start=resolved_start,
            line_end=resolved_end,
            row_index=row_index,
            column_index=column_index,
        )

    def _candidate(
        self,
        block: ExtractionBlock,
        ordinal: int,
        *,
        kind: CandidateKind,
        raw_value: str,
        field_name: str | None,
        provenance: CandidateProvenance,
        findings: tuple[InstructionFinding, ...],
        budget: list[int],
        limitations: tuple[str, ...] = (),
        needs_review: bool = False,
    ) -> Candidate:
        candidate_bytes = len(raw_value.encode("utf-8"))
        if field_name is not None:
            candidate_bytes += len(field_name.encode("utf-8"))
        if candidate_bytes > self.max_candidate_bytes:
            raise ExtractorFailure(
                "candidate_value_size_limit_exceeded",
                "A candidate value and field name exceed the configured byte limit.",
                recoverable=False,
            )
        if budget[0] >= self.max_candidates:
            raise ExtractorFailure(
                "candidate_limit_exceeded",
                "Candidate count exceeds the configured limit.",
                recoverable=False,
            )
        if budget[1] + candidate_bytes > self.max_total_candidate_bytes:
            raise ExtractorFailure(
                "candidate_total_size_limit_exceeded",
                "Candidate output exceeds the configured cumulative byte limit.",
                recoverable=False,
            )
        budget[0] += 1
        budget[1] += candidate_bytes
        payload = {
            "kind": kind.value,
            "raw_value": raw_value,
            "field_name": field_name,
            "provenance": {
                "block_id": provenance.block_id,
                "line_start": provenance.line_start,
                "line_end": provenance.line_end,
                "row_index": provenance.row_index,
                "column_index": provenance.column_index,
            },
        }
        digest = content_hash(payload)
        candidate_id = deterministic_id(
            "cand",
            block.block_id,
            str(ordinal),
            digest,
        )
        return Candidate(
            candidate_id=candidate_id,
            candidate_sha256=digest,
            kind=kind,
            raw_value=raw_value,
            field_name=field_name,
            confidence=block.confidence,
            provenance=(provenance,),
            verification=(
                VerificationStatus.NEEDS_REVIEW
                if findings or needs_review
                else VerificationStatus.EXTRACTED
            ),
            instruction_findings=findings,
            limitations=limitations,
        )

    def _from_text(
        self,
        block: ExtractionBlock,
        *,
        budget: list[int],
    ) -> list[Candidate]:
        assert block.text is not None
        block_limitations, block_needs_review = _block_review_context(block)
        output: list[Candidate] = []
        for local_index, line_text in enumerate(block.text.splitlines()):
            if not line_text.strip():
                continue
            line = (block.line_start or 1) + local_index
            findings = _findings_for_span(block.instruction_findings, line)
            match = _KEY_VALUE.fullmatch(line_text)
            if match:
                kind = CandidateKind.FIELD
                field_name = match.group("key").strip()
                raw_value = match.group("value")
            else:
                kind = CandidateKind.STATEMENT
                field_name = None
                raw_value = line_text
            output.append(
                self._candidate(
                    block,
                    len(output),
                    kind=kind,
                    raw_value=raw_value,
                    field_name=field_name,
                    provenance=self._provenance(
                        block,
                        line_start=line,
                        line_end=line,
                    ),
                    findings=findings,
                    budget=budget,
                    limitations=block_limitations,
                    needs_review=block_needs_review,
                )
            )
        return output

    def _from_table(
        self,
        block: ExtractionBlock,
        *,
        budget: list[int],
    ) -> list[Candidate]:
        block_limitations, block_needs_review = _block_review_context(block)
        rows = block.rows
        width = max(len(row) for row in rows)
        first = rows[0]
        has_header = (
            len(rows) > 1
            and len(first) == width
            and all(cell.strip() for cell in first)
            and len({_header_key(cell) for cell in first}) == width
        )
        headers = first if has_header else tuple(f"column_{index + 1}" for index in range(width))
        data_start = 1 if has_header else 0
        row_spans = block.row_spans
        header_start, header_end = row_spans[0]
        header_findings = (
            _findings_for_span(
                block.instruction_findings,
                header_start,
                header_end,
            )
            if has_header
            else ()
        )
        output: list[Candidate] = []
        if has_header:
            for column_index, raw_value in enumerate(first, start=1):
                if raw_value == "":
                    continue
                output.append(
                    self._candidate(
                        block,
                        len(output),
                        kind=CandidateKind.FIELD,
                        raw_value=raw_value,
                        field_name=f"column_{column_index}",
                        provenance=self._provenance(
                            block,
                            line_start=header_start,
                            line_end=header_end,
                            row_index=1,
                            column_index=column_index,
                        ),
                        findings=header_findings,
                        budget=budget,
                        limitations=tuple(
                            dict.fromkeys(
                                (
                                    "First CSV row was inferred as a possible header and retained "
                                    "as a positional candidate; verify it before treating it as labels.",
                                    *block_limitations,
                                )
                            )
                        ),
                        needs_review=True,
                    )
                )
        for row_index, row in enumerate(rows[data_start:], start=data_start + 1):
            line_start, line_end = row_spans[row_index - 1]
            findings = tuple(
                dict.fromkeys(
                    (
                        *header_findings,
                        *_findings_for_span(
                            block.instruction_findings,
                            line_start,
                            line_end,
                        ),
                    )
                )
            )
            for column_index, raw_value in enumerate(row, start=1):
                if raw_value == "":
                    continue
                output.append(
                    self._candidate(
                        block,
                        len(output),
                        kind=CandidateKind.FIELD,
                        raw_value=raw_value,
                        field_name=headers[column_index - 1],
                        provenance=self._provenance(
                            block,
                            line_start=line_start,
                            line_end=line_end,
                            row_index=row_index,
                            column_index=column_index,
                        ),
                        findings=findings,
                        budget=budget,
                        limitations=tuple(
                            dict.fromkeys(
                                (
                                    (
                                        "Field name was inferred from a possible header in the first "
                                        "CSV row; verify the mapping."
                                        if has_header
                                        else "CSV had no unambiguous header; a positional "
                                        "field name was used."
                                    ),
                                    *block_limitations,
                                )
                            )
                        ),
                        needs_review=has_header or block_needs_review,
                    )
                )
        return output

def _header_key(value: str) -> str:
    return " ".join(value.casefold().split())

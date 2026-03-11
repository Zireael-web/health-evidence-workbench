"""Deterministic artifact -> blocks -> generic candidates pipeline."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from threading import Condition, RLock

from .candidates import GenericCandidateBuilder
from .extractors import default_extractors
from .models import (
    BlockDraft,
    Candidate,
    DocumentArtifact,
    ExtractionBlock,
    ExtractionCapability,
    ExtractionFailure,
    IngestionResult,
    content_hash,
    deterministic_id,
)
from .registry import Extractor, ExtractorFailure, ExtractorRegistry
from .security import InstructionDetector


INGESTION_PROCESSING_CONTRACT_VERSION = "2"


def _processing_fingerprint(
    registry: ExtractorRegistry,
    detector: InstructionDetector,
    candidate_builder: GenericCandidateBuilder,
) -> str:
    """Identify every policy that can change blocks or candidate safety state."""

    return content_hash(
        {
            "schema": "health-analyzer-ingestion-processing-profile-v2",
            "contract_version": INGESTION_PROCESSING_CONTRACT_VERSION,
            "registry_fingerprint": registry.fingerprint,
            "registry_descriptors": [
                {
                    "extractor_id": descriptor.extractor_id,
                    "version": descriptor.version,
                    "mime_types": list(descriptor.mime_types),
                    "capabilities": sorted(
                        capability.value for capability in descriptor.capabilities
                    ),
                    "priority": descriptor.priority,
                    "configuration_fingerprint": (
                        descriptor.configuration_fingerprint
                    ),
                }
                for descriptor in registry.descriptors()
            ],
            "instruction_patterns": [
                {
                    "pattern_id": pattern.pattern_id,
                    "category": pattern.category,
                    "severity": pattern.severity,
                    "description": pattern.description,
                    "expression": pattern.expression.pattern,
                    "flags": pattern.expression.flags,
                }
                for pattern in detector.patterns
            ],
            "candidate_builder": {
                "type": (
                    f"{type(candidate_builder).__module__}."
                    f"{type(candidate_builder).__qualname__}"
                ),
                "max_candidates": candidate_builder.max_candidates,
                "max_candidate_bytes": candidate_builder.max_candidate_bytes,
                "max_total_candidate_bytes": (
                    candidate_builder.max_total_candidate_bytes
                ),
            },
        }
    )


@dataclass(frozen=True, slots=True)
class _CachedExtraction:
    """Successful extraction data only; never retains DocumentArtifact bytes."""

    blocks: tuple[ExtractionBlock, ...]
    candidates: tuple[Candidate, ...]


@dataclass(slots=True)
class _InFlightExtraction:
    """One result shared only by callers that overlap the active extraction."""

    done: bool = False
    result: IngestionResult | None = None
    error: _InFlightError | None = None
    waiters: int = 0


@dataclass(frozen=True, slots=True)
class _InFlightError:
    """Ephemeral exception recipe; followers must not re-raise one object."""

    error_type: type[BaseException]
    args: tuple[object, ...]

    @classmethod
    def capture(cls, error: BaseException) -> _InFlightError:
        return cls(error_type=type(error), args=error.args)

    def recreate(self) -> BaseException:
        try:
            return self.error_type(*self.args)
        except Exception:
            return RuntimeError(
                f"Concurrent extraction failed with {self.error_type.__name__}."
            )


class IngestionPipeline:
    def __init__(
        self,
        *,
        registry: ExtractorRegistry | None = None,
        detector: InstructionDetector | None = None,
        candidate_builder: GenericCandidateBuilder | None = None,
        deduplicate: bool = True,
        cache_max_entries: int = 128,
    ) -> None:
        if not isinstance(cache_max_entries, int) or isinstance(cache_max_entries, bool):
            raise ValueError("cache_max_entries must be a positive integer")
        if cache_max_entries < 1:
            raise ValueError("cache_max_entries must be a positive integer")
        self.registry = (registry or ExtractorRegistry(default_extractors())).freeze()
        self.registry_fingerprint = self.registry.fingerprint
        self.detector = detector or InstructionDetector()
        self.candidate_builder = candidate_builder or GenericCandidateBuilder()
        self.processing_fingerprint = _processing_fingerprint(
            self.registry,
            self.detector,
            self.candidate_builder,
        )
        self.deduplicate = deduplicate
        self.cache_max_entries = cache_max_entries
        self._results: OrderedDict[
            tuple[str, str, str, tuple[str, ...], str],
            _CachedExtraction,
        ] = OrderedDict()
        self._condition = Condition(RLock())
        self._in_flight: dict[
            tuple[str, str, str, tuple[str, ...], str],
            _InFlightExtraction,
        ] = {}

    @property
    def cache_entry_count(self) -> int:
        with self._condition:
            return len(self._results)

    def ingest(
        self,
        artifact: DocumentArtifact,
        *,
        required_capabilities: frozenset[ExtractionCapability] = frozenset(),
        cache_scope: str = "default",
        force_reprocess: bool = False,
    ) -> IngestionResult:
        """Ingest one immutable artifact under the configured processing profile.

        ``force_reprocess=True`` bypasses both the successful-result LRU and
        single-flight sharing for this call. It deliberately does not replace
        the existing normal-cache entry; callers that persist forced attempts
        must give each attempt its own external processing-profile identity.
        """

        if not isinstance(cache_scope, str) or not cache_scope.strip():
            raise ValueError("cache_scope must be a non-empty string")
        if not isinstance(force_reprocess, bool):
            raise ValueError("force_reprocess must be a boolean")
        self._require_unchanged_processing_profile()
        capability_key = tuple(sorted(item.value for item in required_capabilities))
        cache_key = (
            cache_scope,
            artifact.content_sha256,
            artifact.media_type,
            capability_key,
            self.processing_fingerprint,
        )
        if force_reprocess or not self.deduplicate:
            result = self._ingest_uncached(
                artifact,
                required_capabilities=required_capabilities,
            )
            self._require_unchanged_processing_profile()
            return result

        with self._condition:
            cached = self._results.get(cache_key)
            if cached is not None:
                self._results.move_to_end(cache_key)
                return self._cached_result(artifact, cached)
            flight = self._in_flight.get(cache_key)
            if flight is None:
                flight = _InFlightExtraction()
                self._in_flight[cache_key] = flight
                leads_flight = True
            else:
                leads_flight = False

            if not leads_flight:
                flight.waiters += 1
                self._condition.notify_all()
                try:
                    while not flight.done:
                        self._condition.wait()
                    self._require_unchanged_processing_profile()
                    if flight.error is not None:
                        raise flight.error.recreate()
                    if flight.result is None:
                        raise RuntimeError(
                            "in-flight extraction ended without a result"
                        )
                    if flight.result.complete:
                        cached = self._results.get(cache_key)
                        if cached is None:
                            raise RuntimeError(
                                "complete in-flight extraction was not cached"
                            )
                        self._results.move_to_end(cache_key)
                        return self._cached_result(artifact, cached)
                    return self._shared_incomplete_result(artifact, flight.result)
                finally:
                    flight.waiters -= 1
                    self._condition.notify_all()

        result: IngestionResult | None = None
        error: _InFlightError | None = None
        try:
            produced = self._ingest_uncached(
                artifact,
                required_capabilities=required_capabilities,
            )
            self._require_unchanged_processing_profile()
            result = produced
            return produced
        except BaseException as caught:
            error = _InFlightError.capture(caught)
            raise
        finally:
            with self._condition:
                if result is not None and result.complete:
                    self._results[cache_key] = _CachedExtraction(
                        blocks=result.blocks,
                        candidates=result.candidates,
                    )
                    self._results.move_to_end(cache_key)
                    while len(self._results) > self.cache_max_entries:
                        self._results.popitem(last=False)
                flight.result = result
                flight.error = error
                flight.done = True
                if self._in_flight.get(cache_key) is flight:
                    self._in_flight.pop(cache_key)
                self._condition.notify_all()

    def _require_unchanged_processing_profile(self) -> None:
        current = _processing_fingerprint(
            self.registry,
            self.detector,
            self.candidate_builder,
        )
        if current != self.processing_fingerprint:
            raise RuntimeError(
                "ingestion processing configuration changed after initialization"
            )

    def _cached_result(
        self,
        artifact: DocumentArtifact,
        cached: _CachedExtraction,
    ) -> IngestionResult:
        return IngestionResult(
            artifact=artifact,
            blocks=cached.blocks,
            candidates=cached.candidates,
            failures=(),
            deduplicated=True,
            duplicate_of_artifact_id=artifact.artifact_id,
            limitations=tuple(
                dict.fromkeys(
                    (
                        *self._limitations(artifact, cached.blocks, []),
                        "Content hash was already ingested in this cache scope; "
                        "cached extraction reused.",
                    )
                )
            ),
            complete=True,
        )

    def _shared_incomplete_result(
        self,
        artifact: DocumentArtifact,
        result: IngestionResult,
    ) -> IngestionResult:
        if result.blocks:
            limitations = self._limitations(
                artifact,
                result.blocks,
                list(result.failures),
            )
        else:
            limitations = tuple(
                dict.fromkeys(
                    (*artifact.limitations, "No extractor produced usable blocks.")
                )
            )
        return IngestionResult(
            artifact=artifact,
            blocks=result.blocks,
            candidates=result.candidates,
            failures=result.failures,
            limitations=tuple(
                dict.fromkeys(
                    (
                        *limitations,
                        "A concurrent caller reused this in-flight extraction result; "
                        "the incomplete result was not retained in the cache.",
                    )
                )
            ),
            deduplicated=True,
            duplicate_of_artifact_id=artifact.artifact_id,
            complete=False,
        )

    def _ingest_uncached(
        self,
        artifact: DocumentArtifact,
        *,
        required_capabilities: frozenset[ExtractionCapability],
    ) -> IngestionResult:
        failures: list[ExtractionFailure] = []
        selected = self.registry.select(
            artifact,
            required_capabilities=required_capabilities,
        )
        if not selected:
            failures.append(
                self._failure(
                    artifact,
                    code="no_extractor",
                    message=f"No extractor registered for {artifact.media_type}.",
                )
            )

        result: IngestionResult | None = None
        for extractor in selected:
            try:
                drafts = tuple(extractor.extract(artifact))
                if not drafts:
                    raise ExtractorFailure(
                        "empty_extraction",
                        "Extractor returned no blocks.",
                    )
                blocks = self._finalize_blocks(artifact, drafts, extractor)
                candidates = self.candidate_builder.build(blocks)
                limitations = self._limitations(artifact, blocks, failures)
                result = IngestionResult(
                    artifact=artifact,
                    blocks=blocks,
                    candidates=candidates,
                    failures=tuple(failures),
                    limitations=limitations,
                    deduplicated=False,
                    duplicate_of_artifact_id=None,
                    complete=(
                        not failures
                        and not any(block.document_incomplete for block in blocks)
                    ),
                )
                break
            except ExtractorFailure as error:
                failures.append(
                    self._failure(
                        artifact,
                        code=error.code,
                        message=error.message,
                        extractor=extractor,
                        recoverable=error.recoverable,
                    )
                )
                if not error.recoverable:
                    break
            except Exception as error:  # provider isolation boundary
                failures.append(
                    self._failure(
                        artifact,
                        code="unexpected_extractor_failure",
                        message=f"Extractor failed with {type(error).__name__}.",
                        extractor=extractor,
                    )
                )

        if result is None:
            result = IngestionResult(
                artifact=artifact,
                blocks=(),
                candidates=(),
                failures=tuple(failures),
                limitations=tuple(
                    dict.fromkeys(
                        (*artifact.limitations, "No extractor produced usable blocks.")
                    )
                ),
                deduplicated=False,
                duplicate_of_artifact_id=None,
                complete=False,
            )

        return result

    def _finalize_blocks(
        self,
        artifact: DocumentArtifact,
        drafts: tuple[BlockDraft, ...],
        extractor: Extractor,
    ) -> tuple[ExtractionBlock, ...]:
        blocks: list[ExtractionBlock] = []
        descriptor = extractor.descriptor
        extractor_version = descriptor.version
        if descriptor.configuration_fingerprint:
            extractor_version = (
                f"{descriptor.version}+cfg."
                f"{descriptor.configuration_fingerprint[:16]}"
            )
        for ordinal, draft in enumerate(drafts):
            payload = {
                "kind": draft.kind.value,
                "text": draft.text,
                "rows": [list(row) for row in draft.rows],
                "payload_sha256": draft.payload_sha256,
                "page": draft.page,
                "bbox": list(draft.bbox) if draft.bbox else None,
                "line_start": draft.line_start,
                "line_end": draft.line_end,
            }
            block_sha256 = content_hash(payload)
            block_id = deterministic_id(
                "blk",
                artifact.artifact_id,
                str(ordinal),
                block_sha256,
                descriptor.extractor_id,
                extractor_version,
            )
            scannable_text = draft.text
            if scannable_text is None and draft.rows:
                scannable_text = "\n".join("\t".join(row) for row in draft.rows)
            findings = self.detector.scan(
                scannable_text or "",
                line_offset=(draft.line_start or 1) - 1,
            )
            blocks.append(
                ExtractionBlock(
                    block_id=block_id,
                    artifact_id=artifact.artifact_id,
                    artifact_sha256=artifact.content_sha256,
                    ordinal=ordinal,
                    kind=draft.kind,
                    block_sha256=block_sha256,
                    extractor_id=descriptor.extractor_id,
                    extractor_version=extractor_version,
                    text=draft.text,
                    rows=draft.rows,
                    payload_sha256=draft.payload_sha256,
                    page=draft.page,
                    bbox=draft.bbox,
                    line_start=draft.line_start,
                    line_end=draft.line_end,
                    confidence=draft.confidence,
                    document_incomplete=draft.document_incomplete,
                    instruction_findings=findings,
                    limitations=draft.limitations,
                )
            )
        return tuple(blocks)

    @staticmethod
    def _failure(
        artifact: DocumentArtifact,
        *,
        code: str,
        message: str,
        extractor: Extractor | None = None,
        recoverable: bool = True,
    ) -> ExtractionFailure:
        descriptor = extractor.descriptor if extractor else None
        return ExtractionFailure(
            failure_id=deterministic_id(
                "fail",
                artifact.artifact_id,
                descriptor.extractor_id if descriptor else "none",
                descriptor.version if descriptor else "none",
                code,
            ),
            code=code,
            message=message,
            extractor_id=descriptor.extractor_id if descriptor else None,
            extractor_version=descriptor.version if descriptor else None,
            recoverable=recoverable,
        )

    @staticmethod
    def _limitations(
        artifact: DocumentArtifact,
        blocks: tuple[ExtractionBlock, ...],
        failures: list[ExtractionFailure],
    ) -> tuple[str, ...]:
        values = list(artifact.limitations)
        for block in blocks:
            values.extend(block.limitations)
            if block.instruction_findings:
                values.append(
                    "Instruction-like content was retained as untrusted data and marked for review."
                )
        if failures:
            values.append("One or more extractors failed before a fallback succeeded.")
        return tuple(dict.fromkeys(values))

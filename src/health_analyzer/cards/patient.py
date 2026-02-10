"""A lossless view of one issued, verified CasePacket, never a whole history."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from ..contracts import CasePacket, Observation, Statement
from .validation import validated_case_snapshot


CONTEXT_CATEGORIES = (
    "medications", "supplements", "allergies", "conditions", "symptoms", "goals",
)
_LIMITATIONS = (
    "Это снимок выбранного CasePacket, а не полная история пациента. "
    "Полнота архива и актуальность записей не установлены.",
    "Дата создания пакета не является датой исследования или начала заболевания.",
    "Проверка записи означает сверку с источником, а не подтверждение диагноза. "
    "Пользовательские заметки и вычисления не являются фактами из заключения.",
    "Полнота исходных данных вычисления и правильность расчёта этой карточкой не проверяются.",
    "Наличие записи в разделе не подтверждает её актуальность или полноту. "
    "Отсутствие данных не означает отсутствие аллергий, заболеваний или лекарств.",
)


@dataclass(frozen=True, slots=True)
class PatientContext:
    category: str
    status: str
    record_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PatientCard:
    case_packet_id: str
    subject_id: str
    packet_created_at: str
    observations: tuple[Observation, ...]
    statements: tuple[Statement, ...]
    contexts: tuple[PatientContext, ...]
    source_count: int
    record_count: int
    limitations: tuple[str, ...]
    card_type: str = field(default="patient", init=False)
    schema_version: str = field(default="1.0", init=False)
    status: str = field(default="packet_snapshot", init=False)
    scope: str = field(default="selected_case_packet", init=False)
    archive_completeness: str = field(default="unknown", init=False)
    review_required: bool = field(default=True, init=False)


def build_patient_card(
    case_packet: CasePacket,
    *,
    context_bindings: Mapping[str, Sequence[str]] | None = None,
) -> PatientCard:
    """Bindings are operator categorization, not absence/currentness assertions.

    This pure builder does not authenticate issuance: MCP must load the packet
    by ID from its integrity-checked handoff store before calling it. No source
    files, archive pages, new model interpretations or medical inference enter
    the card. Dates, units, reference intervals and locators remain verbatim.
    """
    packet = validated_case_snapshot(case_packet)

    if context_bindings is None:
        context_bindings = {}
    if not isinstance(context_bindings, Mapping):
        raise ValueError("context_bindings must be an object")
    if any(key not in CONTEXT_CATEGORIES for key in context_bindings):
        raise ValueError("unsupported patient context category")
    known_ids = {
        *(observation.observation_id for observation in packet.observations),
        *(statement.statement_id for statement in packet.statements),
    }
    contexts = []
    total_bindings = 0
    for category in CONTEXT_CATEGORIES:
        ids = context_bindings.get(category, ())
        if not isinstance(ids, (list, tuple)):
            raise ValueError("context record_ids must be an array")
        total_bindings += len(ids)
        if total_bindings > 100:
            raise ValueError("at most 100 patient context references are allowed")
        if any(not isinstance(record_id, str) or record_id not in known_ids for record_id in ids):
            raise ValueError("context record ID is absent from the selected CasePacket")
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate context record ID")
        contexts.append(PatientContext(
            category=category,
            status="records_available_in_packet" if ids else "unknown",
            record_ids=tuple(ids),
        ))
    return PatientCard(
        case_packet_id=packet.packet_id,
        subject_id=packet.subject_id,
        packet_created_at=packet.created_at,
        observations=packet.observations,
        statements=packet.statements,
        contexts=tuple(contexts),
        source_count=len({
            locator.source_id
            for record in (*packet.observations, *packet.statements)
            for locator in record.provenance
        }),
        record_count=len(packet.observations) + len(packet.statements),
        limitations=(*packet.limitations, *_LIMITATIONS),
    )

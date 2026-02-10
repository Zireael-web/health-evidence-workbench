"""Deterministic, inert presentations of card view models.

This module performs no reads, writes, network requests, or clinical inference.
Every value from a card is rendered as text, never as markup, a URL, or an HTML
attribute.  Markdown and HTML have separate escaping paths.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from html import escape
import string
from typing import Any


_MARKDOWN_PUNCTUATION = frozenset(string.punctuation)


def _markdown_text(value: str) -> str:
    """Keep dynamic text inert, including GFM URLs and multiline injections.

    Character references are decoded only after Markdown structure is parsed.
    Encoding all ASCII punctuation also prevents bare URL/email autolinks.
    Only the line-break element is generated markup, with no dynamic content.
    """

    if not isinstance(value, str):
        raise TypeError("rendered text must be a string")
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    return "".join(
        "<br>" if character == "\n" else
        f"&#{ord(character)};"
        if character in _MARKDOWN_PUNCTUATION or character == "\t"
        else character
        for character in value
    )


def _html_text(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("rendered text must be a string")
    return escape(value, quote=True)


def _scalar(value: object) -> str:
    if value is None:
        return "Не указано"
    if type(value) is bool:
        return "Да" if value else "Нет"
    if isinstance(value, (str, int, float)):
        return str(value) if value != "" else "Пустое значение"
    raise ValueError("card scalar must be text, a number, a boolean, or null")


def _object(value: object, *, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) for key in value
    ):
        raise ValueError(f"{name} must be an object with string keys")
    return value


def _array(value: object, *, name: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be an array")
    return value


_LABELS = {
    "card_type": "Тип карточки", "schema_version": "Версия схемы",
    "card_id": "ID карточки", "case_packet_id": "ID пакета наблюдений",
    "subject_id": "Псевдоним профиля", "packet_created_at": "Дата сборки пакета",
    "evidence_packet_id": "ID пакета научных данных",
    "answer_bundle_id": "ID проекта ответа", "bundle_id": "ID проекта ответа",
    "scope": "Объём данных", "archive_completeness": "Полнота архива",
    "source_count": "Источников в пакете", "record_count": "Записей в пакете",
    "status": "Статус", "review_required": "Требуется проверка",
    "clinical_approval_obtained": "Клиническое одобрение получено",
    "observation_id": "ID наблюдения", "display": "Показатель",
    "raw_value": "Исходное значение", "original_unit": "Исходная единица",
    "normalized_value": "Нормализованное значение", "ucum_unit": "Единица UCUM",
    "code_system": "Система кодирования", "code": "Код",
    "comparator": "Знак сравнения", "specimen": "Биоматериал",
    "method": "Метод", "device": "Прибор", "observed_at": "Дата наблюдения",
    "reference_intervals": "Референсные интервалы лаборатории",
    "low": "Нижняя граница", "high": "Верхняя граница", "unit": "Единица",
    "label": "Метка", "population": "Популяция", "notes": "Примечания",
    "statement_id": "ID записи", "text": "Текст", "kind": "Тип записи",
    "statement_kind": "Тип утверждения", "support_ids": "ID оснований",
    "verification": "Проверка записи", "certainty": "Уверенность",
    "provenance": "Происхождение и место в источнике",
    "source_id": "ID источника", "sha256": "SHA-256 источника",
    "page": "Страница", "locator": "Указатель в источнике",
    "bbox": "Координаты фрагмента", "line_start": "Первая строка",
    "line_end": "Последняя строка", "char_start": "Первый символ",
    "char_end": "Последний символ", "excerpt": "Фрагмент источника", "category": "Категория",
    "record_ids": "Связанные записи", "message": "Пояснение",
    "intent": "Заявленная цель", "risk_envelope": "Заявленная цель и подтверждение",
    "clinician_confirmation_required": "Требуется подтверждение врача",
    "claim_id": "ID утверждения", "conflicts_with": "Конфликтующие утверждения",
    "caveats": "Оговорки", "question": "Вопрос", "source_kind": "Тип источника",
    "source_evidence_id": "ID научного источника",
    "source_snapshot_sha256": "SHA-256 снимка источника",
    "claim_type": "Тип научного утверждения", "review_receipt_id": "ID проверки",
    "reviewed_at": "Дата проверки", "reviewer_id": "Автор проверки",
    "outcome": "Исход", "effect": "Эффект",
    "native_grade_system": "Исходная система оценки доказательств",
    "native_grade": "Исходная оценка доказательств", "limitations": "Ограничения",
    "evidence_id": "ID научного источника", "title": "Название",
    "source_type": "Тип публикации", "url": "Адрес источника (текст)",
    "published_at": "Дата публикации", "retrieved_at": "Дата получения",
    "organization": "Организация", "jurisdiction": "Юрисдикция",
    "identifiers": "Идентификаторы", "study_design": "Дизайн исследования",
    "source_grade": "Оценка источника", "raw_grade": "Исходная оценка",
    "supersedes": "Заменяемые записи", "content_hash": "Хеш содержимого",
    "option_id": "ID варианта", "label_claim_id": "ID названия варианта",
    "benefit_claim_ids": "Польза", "harm_claim_ids": "Риски",
    "dose_claim_ids": "Дозировка", "duration_claim_ids": "Длительность",
    "monitoring_claim_ids": "Контроль", "alternative_claim_ids": "Альтернативы",
    "applicability_claim_ids": "Применимость", "uncertainty_claim_ids": "Неопределённость",
    "passed": "Структурная проверка пройдена", "issues": "Замечания аудита",
    "audited_at": "Дата аудита", "structural_traceability_passed": "Связи с основаниями проверены",
    "bundle_sha256": "SHA-256 проекта ответа", "severity": "Уровень замечания",
}

_KINDS = {
    "source_fact": "Факт из источника", "user_note": "Сообщено пользователем",
    "calculated": "Расчёт", "external_evidence": "Научные данные",
    "inference": "Вывод", "guideline_recommendation": "Рекомендация руководства",
}
_CATEGORIES = {
    "medications": "Лекарства", "supplements": "Добавки", "allergies": "Аллергии",
    "conditions": "Состояния и диагнозы", "symptoms": "Симптомы", "goals": "Цели",
    "measurements": "Измерения", "previous_treatments": "Предыдущее лечение",
    "preferences": "Предпочтения",
    "pregnancy": "Беременность", "renal_function": "Функция почек",
    "liver_function": "Функция печени", "age": "Возраст",
}
_STATES = {
    "patient": "Карточка пациента", "decision": "Карточка решения",
    "packet_snapshot": "Снимок выбранного пакета", "selected_case_packet": "Выбранный CasePacket",
    "unknown": "Неизвестно", "records_available_in_packet": "Есть записи в выбранном пакете",
    "not_assessed": "Не оценено", "research_needed": "Нужны научные данные",
    "draft": "Черновик", "blocked_clinician_confirmation": "Требуется подтверждение врача",
    "extracted": "Извлечено; проверка не завершена", "needs_review": "Ожидает проверки",
    "verified": "Проверена запись", "rejected": "Отклонено",
    "legacy_unspecified": "Цель не указана", "education": "Общее объяснение",
    "personal_context": "Объяснение с личным контекстом", "clinical_action": "Клиническое действие",
    "urgent_assessment": "Оценка срочности",
}
_FIELD_ORDER = {key: index for index, key in enumerate(_LABELS)}


def _items(record: Mapping[str, Any]) -> list[tuple[str, Any]]:
    """Mapping insertion order is not part of the visible card contract."""

    return sorted(record.items(), key=lambda item: (_FIELD_ORDER.get(item[0], len(_FIELD_ORDER)), item[0]))


def _value_text(value: object, *, field: str = "", kind: str = "") -> str:
    text = _scalar(value)
    if not isinstance(value, str):
        return text
    if field in {"kind", "statement_kind"}:
        translated = _KINDS.get(value)
    elif field == "category":
        translated = _CATEGORIES.get(value)
    elif field in {"status", "verification", "scope", "archive_completeness", "intent", "card_type"}:
        translated = _STATES.get(value)
        if value == "verified" and kind == "user_note":
            translated = "Проверена запись сообщения пользователя"
        elif value == "verified" and kind == "calculated":
            translated = "Проверена запись расчёта"
        elif value == "verified" and kind == "source_fact":
            translated = "Проверена запись факта из источника"
    else:
        translated = None
    return f"{translated} ({value})" if translated else text


@dataclass(frozen=True)
class _Section:
    title: str
    value: object
    description: str = ""


@dataclass(frozen=True)
class _Document:
    title: str
    subtitle: str
    status: str
    sections: tuple[_Section, ...]


def _selected(card: Mapping[str, Any], fields: Sequence[str]) -> dict[str, Any]:
    return {field: card.get(field) for field in fields}


def _record_sections(records: object, *, heading: str) -> list[_Section]:
    result: list[_Section] = []
    for index, item in enumerate(_array(records, name=heading), 1):
        record = _object(item, name=heading)
        label = record.get("display") or record.get("claim_id") or record.get("statement_id")
        title = f"{heading} {index}" + (f" · {_scalar(label)}" if label else "")
        result.append(_Section(title, record))
    if not result:
        result.append(_Section(heading, "В выбранном пакете записей нет. Это не означает отсутствие состояния."))
    return result


def _patient_document(card: Mapping[str, Any]) -> _Document:
    metadata = (
        "card_type", "schema_version", "status", "case_packet_id", "subject_id",
        "packet_created_at", "scope", "archive_completeness", "source_count",
        "record_count", "review_required",
    )
    sections = [
        _Section("О снимке данных", _selected(card, metadata),
                 "Дата сборки пакета не является датой анализа. Полнота архива не установлена."),
        _Section("Контекст", card.get("contexts", []),
                 "Неизвестно не означает «нет». Наличие записи не подтверждает её актуальность или полную оценку категории."),
    ]
    sections.extend(_record_sections(card.get("observations", []), heading="Наблюдение"))
    statements = _array(card.get("statements", []), name="statements")
    groups = (
        ("source_fact", "Факт из источника"),
        ("user_note", "Сообщение пользователя"),
        ("calculated", "Расчёт"),
    )
    for kind, title in groups:
        records = [record for record in statements if _object(record, name="statement").get("kind") == kind]
        sections.extend(_record_sections(records, heading=title))
    other = [record for record in statements if record.get("kind") not in {kind for kind, _ in groups}]
    if other:
        sections.append(_Section("Записи с другим типом", other, "Тип этих записей не распознан карточкой."))
    sections.append(_Section("Ограничения", card.get("limitations", [])))
    known = set(metadata) | {"contexts", "observations", "statements", "limitations"}
    extra = {key: value for key, value in card.items() if key not in known}
    if extra:
        sections.append(_Section("Дополнительные поля", extra))
    return _Document("Карточка пациента", "Наблюдения и контекст из выбранного пакета",
                     _value_text(card.get("status"), field="status"), tuple(sections))


def _decision_document(card: Mapping[str, Any]) -> _Document:
    metadata = (
        "card_type", "schema_version", "card_id", "status", "case_packet_id",
        "evidence_packet_id", "answer_bundle_id", "risk_envelope", "review_required",
        "clinical_approval_obtained",
    )
    claims = _array(card.get("claims", []), name="claims")
    claim_by_id: dict[str, Mapping[str, Any]] = {}
    for claim in claims:
        record = _object(claim, name="claim")
        claim_id = record.get("claim_id")
        if not isinstance(claim_id, str) or claim_id in claim_by_id:
            raise ValueError("decision claim identifiers must be unique text")
        claim_by_id[claim_id] = record
    sections = [
        _Section("Вопрос", card.get("question")),
        _Section("Статус решения", _selected(card, metadata),
                 "Все варианты остаются черновиками. Карточка не устанавливает предпочтительный вариант и не подтверждает назначение."),
        _Section("Недостающий контекст", card.get("missing_context", []),
                 "Категории не оценены; пустой список не подтверждает полноту клинического контекста."),
        _Section("Что ещё требуется исследовать", card.get("research_gaps", [])),
    ]
    options = _array(card.get("options", []), name="options")
    if not options:
        sections.append(_Section("Варианты", "Варианты не сформированы."))
    for index, item in enumerate(options, 1):
        option = _object(item, name="option")
        label_id = option.get("label_claim_id")
        label_claim = claim_by_id.get(label_id) if isinstance(label_id, str) else None
        title = f"Вариант {index} · Черновик"
        if label_claim:
            title += " · " + _scalar(label_claim.get("text"))
        option_values: dict[str, Any] = {}
        for key, value in option.items():
            if key.endswith("_claim_ids"):
                expanded = []
                for claim_id in _array(value, name=key):
                    if not isinstance(claim_id, str):
                        raise ValueError("option claim identifiers must be text")
                    expanded.append(claim_by_id.get(claim_id) or {
                        "claim_id": claim_id, "message": "Утверждение отсутствует в карточке; основание не разрешено.",
                    })
                option_values[key] = expanded
            else:
                option_values[key] = value
        sections.append(_Section(title, option_values))
    sections.extend(_record_sections(claims, heading="Утверждение"))
    for key, title, description in (
        ("case_observations", "Наблюдения, на которые ссылается проект", "Исходные значения, единицы и даты сохранены отдельно от выводов."),
        ("case_statements", "Записи контекста, на которые ссылается проект", "Факты, сообщения пользователя и расчёты сохраняют исходный тип."),
        ("reviewed_evidence_claims", "Проверенные утверждения научных источников", "Проверка записи не доказывает применимость к отдельному человеку."),
        ("evidence_items", "Библиографические записи источников", "Метаданные публикации сами по себе не являются основанием медицинского утверждения."),
    ):
        sections.append(_Section(title, card.get(key, []), description))
    sections.extend((
        _Section("Структурный аудит", card.get("audit"),
                 "Аудит проверяет структуру и связи с основаниями. Он не подтверждает смысловую корректность, применимость или клиническую безопасность."),
        _Section("Ограничения", card.get("limitations", [])),
    ))
    known = set(metadata) | {
        "question", "options", "claims", "case_observations", "case_statements",
        "reviewed_evidence_claims", "evidence_items", "missing_context", "research_gaps",
        "limitations", "audit",
    }
    extra = {key: value for key, value in card.items() if key not in known}
    if extra:
        sections.append(_Section("Дополнительные поля", extra))
    return _Document("Карточка решения", "Варианты, основания и недостающий контекст",
                     _value_text(card.get("status"), field="status"), tuple(sections))


def _document(card: Mapping[str, Any]) -> _Document:
    card = _object(card, name="card")
    if card.get("schema_version") != "1.0":
        raise ValueError("unsupported card schema_version")
    if card.get("card_type") == "patient":
        return _patient_document(card)
    if card.get("card_type") == "decision":
        return _decision_document(card)
    raise ValueError("unsupported card_type")


def _markdown_value(value: object, *, indent: int = 0, field: str = "", kind: str = "") -> str:
    prefix = " " * indent
    if isinstance(value, Mapping):
        record = _object(value, name="card value")
        kind = str(record.get("kind") or record.get("statement_kind") or kind)
        rows = []
        for key, item in _items(record):
            label = _markdown_text(_LABELS.get(key, key))
            if isinstance(item, (Mapping, list, tuple)) and item:
                rows.append(f"{prefix}- {label}:\n\n{_markdown_value(item, indent=indent + 4, field=key, kind=kind)}")
            else:
                rendered = _markdown_value(item, field=key, kind=kind)
                rows.append(f"{prefix}- {label}: {rendered}")
        return "\n\n".join(rows) if rows else "Не указано"
    if isinstance(value, (list, tuple)):
        rows = []
        for index, item in enumerate(value, 1):
            if isinstance(item, (Mapping, list, tuple)):
                rows.append(f"{prefix}- Запись {index}:\n\n{_markdown_value(item, indent=indent + 4, field=field, kind=kind)}")
            else:
                rows.append(f"{prefix}- {_markdown_text(_value_text(item, field=field, kind=kind))}")
        return "\n\n".join(rows) if rows else "Не указано"
    return _markdown_text(_value_text(value, field=field, kind=kind))


def render_card_markdown(card: Mapping[str, Any]) -> str:
    """Render a complete card for a chat/MCP response, without external links."""

    document = _document(card)
    parts = [f"# {document.title}", document.subtitle, _markdown_text(document.status)]
    for section in document.sections:
        parts.append("## " + _markdown_text(section.title))
        if section.description:
            parts.append(section.description)
        parts.append(_markdown_value(section.value))
    return "\n\n".join(parts) + "\n"


def _html_value(value: object, *, field: str = "", kind: str = "") -> str:
    if isinstance(value, Mapping):
        record = _object(value, name="card value")
        kind = str(record.get("kind") or record.get("statement_kind") or kind)
        rows = [
            "<div class=\"field\"><dt>" + _html_text(_LABELS.get(key, key)) + "</dt><dd>"
            + _html_value(item, field=key, kind=kind) + "</dd></div>"
            for key, item in _items(record)
        ]
        return "<dl>" + "".join(rows) + "</dl>" if rows else "<span>Не указано</span>"
    if isinstance(value, (list, tuple)):
        rows = ["<li>" + _html_value(item, field=field, kind=kind) + "</li>" for item in value]
        return "<ol>" + "".join(rows) + "</ol>" if rows else "<span>Не указано</span>"
    return "<span>" + _html_text(_value_text(value, field=field, kind=kind)) + "</span>"


def _html_context_summary(contexts: object) -> str:
    cards = []
    for item in _array(contexts, name="contexts"):
        context = _object(item, name="context")
        cards.append(
            '<div class="context-item"><h3>'
            + _html_text(_summary_text(context.get("category"), field="category"))
            + '</h3><p>' + _html_text(_summary_text(context.get("status"), field="status"))
            + "</p></div>"
        )
    return '<div class="context-grid">' + "".join(cards) + "</div>" if cards else '<p>Контекст не оценён.</p>'


def _summary_text(value: object, *, field: str = "", kind: str = "") -> str:
    """Internal enum spellings stay available in the complete disclosure."""

    text = _value_text(value, field=field, kind=kind)
    suffix = f" ({value})"
    if text != _scalar(value) and text.endswith(suffix):
        return text[:-len(suffix)]
    return text


def _html_patient_summary(card: Mapping[str, Any]) -> str:
    observations = []
    for item in _array(card.get("observations", []), name="observations"):
        record = _object(item, name="observation")
        observations.append(
            '<article class="observation-summary"><div><h3>'
            + _html_text(_scalar(record.get("display")))
            + '</h3><p class="observation-date">Дата наблюдения: '
            + _html_text(_scalar(record.get("observed_at"))) + "</p></div>"
            + '<div class="measurement"><strong>' + _html_text(_scalar(record.get("raw_value")))
            + '</strong><span>' + _html_text(_scalar(record.get("original_unit"))) + "</span></div>"
            + '<p class="record-state">'
            + _html_text(_summary_text(record.get("verification"), field="verification"))
            + "</p></article>"
        )
    observation_html = "".join(observations) or '<p>В выбранном пакете наблюдений нет.</p>'
    return (
        '<section class="section"><h2>Наблюдения</h2>'
        '<p class="description">Исходные значения из выбранного пакета. '
        'Дата наблюдения относится к записи, дата сборки пакета — к снимку данных.</p>'
        + '<div class="observation-list">' + observation_html + "</div></section>"
        '<section class="section"><h2>Контекст</h2>'
        '<p class="description">Неизвестно не означает «нет». Наличие записи '
        'не подтверждает её актуальность или полноту оценки.</p>'
        + _html_context_summary(card.get("contexts", [])) + "</section>"
    )


_OPTION_SUMMARY_FIELDS = (
    "benefit_claim_ids", "harm_claim_ids", "dose_claim_ids", "duration_claim_ids",
    "monitoring_claim_ids", "alternative_claim_ids", "applicability_claim_ids",
    "uncertainty_claim_ids",
)


def _html_decision_summary(card: Mapping[str, Any]) -> str:
    claims = {
        record["claim_id"]: record
        for record in (_object(item, name="claim") for item in _array(card.get("claims", []), name="claims"))
    }
    options = []
    for index, item in enumerate(_array(card.get("options", []), name="options"), 1):
        option = _object(item, name="option")
        label = claims.get(option.get("label_claim_id"))
        title = _scalar(label.get("text")) if label else f"Вариант {index}"
        fields = []
        for key in _OPTION_SUMMARY_FIELDS:
            texts = []
            for claim_id in _array(option.get(key, []), name=key):
                claim = claims.get(claim_id)
                if claim:
                    texts.append(
                        '<li><p class="claim-text">' + _html_text(_scalar(claim.get("text")))
                        + '</p><p class="claim-state">'
                        + _html_text(_summary_text(claim.get("kind"), field="kind")) + " · "
                        + _html_text(_summary_text(claim.get("status"), field="status", kind=str(claim.get("kind", ""))))
                        + "</p></li>"
                    )
                else:
                    texts.append('<li><p>Нет подтвержденных данных</p></li>')
            content = '<ul class="claim-list">' + "".join(texts) + "</ul>" if texts else '<p class="empty-field">Нет подтвержденных данных</p>'
            fields.append('<div class="option-field"><h4>' + _html_text(_LABELS[key]) + "</h4>" + content + "</div>")
        options.append(
            '<article class="option-summary"><div class="option-heading"><span class="draft-label">Черновик</span>'
            + '<h3>' + _html_text(title) + "</h3></div>" + "".join(fields) + "</article>"
        )
    options_html = '<div class="option-grid">' + "".join(options) + "</div>" if options else '<p>Варианты не сформированы.</p>'
    return (
        '<section class="section question-section"><h2>Вопрос</h2><p class="question">'
        + _html_text(_scalar(card.get("question"))) + '</p><p class="approval-state">'
        'Клиническое одобрение получено: ' + _html_text(_scalar(card.get("clinical_approval_obtained")))
        + '</p><p class="description">Все варианты остаются черновиками для проверки. '
        'Карточка не устанавливает предпочтительный вариант.</p></section>'
        '<section class="section"><h2>Варианты</h2>' + options_html + "</section>"
        '<section class="section"><h2>Недостающий контекст</h2>'
        '<p class="description">Категории не оценены; пустой список не подтверждает полноту клинического контекста.</p>'
        + _html_context_summary(card.get("missing_context", [])) + "</section>"
        '<section class="section"><h2>Что ещё требуется исследовать</h2>'
        + _html_value(card.get("research_gaps", [])) + "</section>"
    )


_STYLE = """
:root{color-scheme:light;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#26372f;background:#f4f3ee}
*{box-sizing:border-box}body{margin:0;padding:32px 20px 64px}main{max-width:1020px;margin:auto}
header{border-radius:24px;background:#203d34;color:#fafbf8;padding:32px;margin-bottom:24px}
h1{font-size:32px;font-weight:650;margin:0 0 10px}header p{color:#d6e2d9;margin:0 0 18px}
.badge{display:inline-block;border:1px solid #8caa99;border-radius:24px;padding:8px 14px;font-size:14px}
.sections{display:grid;gap:18px}.section{background:#fff;border:1px solid #dfe4dc;border-radius:18px;padding:24px;min-width:0}
h2{font-size:19px;line-height:1.4;margin:0 0 16px;overflow-wrap:anywhere;white-space:pre-wrap}
h3{font-size:16px;line-height:1.5;margin:0;overflow-wrap:anywhere;white-space:pre-wrap}h4{font-size:13px;margin:0 0 7px;color:#566b60}
p{overflow-wrap:anywhere;white-space:pre-wrap;line-height:1.6}
.description{color:#68746d;font-size:14px;line-height:1.6;margin:0 0 16px}
.observation-summary{display:grid;grid-template-columns:minmax(0,1fr) minmax(130px,auto);gap:8px 18px;border-top:1px solid #edf0e9;padding:18px 0}
.observation-summary:first-child{border-top:0;padding-top:0}.observation-date{font-size:13px;color:#65736b;margin:6px 0 0}
.measurement{display:flex;align-items:baseline;justify-content:flex-end;gap:8px;flex-wrap:wrap;min-width:0}.measurement strong{font-size:28px;font-weight:650;overflow-wrap:anywhere;white-space:pre-wrap}
.measurement span{font-size:14px;color:#65736b}.record-state{grid-column:1/-1;font-size:12px;color:#65736b;margin:0}
.context-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.context-item{background:#f6f8f4;border:1px solid #e6ebe1;border-radius:12px;padding:14px}
.context-item h3{font-size:14px}.context-item p{font-size:12px;margin:6px 0 0;color:#65736b}
.question{font-size:20px;margin:0 0 14px}.approval-state{padding:10px 14px;border-left:3px solid #b79a5b;background:#fbf7eb;font-size:14px}
.option-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr));gap:16px;align-items:start}
.option-summary{min-width:0;border:1px solid #dfe4dc;border-radius:14px;padding:20px}.option-heading{padding-bottom:16px}.option-heading h3{margin-top:10px}
.draft-label{font-size:12px;color:#6d612f;background:#f6f1df;padding:5px 9px;border-radius:20px}
.option-field{border-top:1px solid #edf0e9;padding:14px 0 0;margin-top:14px}.option-field:first-of-type{margin-top:0}
.claim-list{margin:0;padding-left:19px}.claim-text{font-size:14px;margin:0}.claim-state{font-size:11px;color:#65736b;margin:5px 0 0}.empty-field{font-size:13px;color:#778077;margin:0}
.limitations{background:#fbfaf4;border-color:#e5e0cb}.full-records-heading{margin:16px 0 0}.detail-section{padding:0}
summary{cursor:pointer;padding:20px 24px;line-height:1.5;font-size:15px;font-weight:600;overflow-wrap:anywhere;white-space:pre-wrap}
summary::marker{color:#778e7f}summary:focus-visible{outline:2px solid #3a7059;outline-offset:3px;border-radius:14px}.detail-body{padding:0 24px 24px}
dl{margin:0}.field{display:grid;grid-template-columns:minmax(140px,29%) minmax(0,1fr);gap:16px;border-top:1px solid #edf0e9;padding:10px 0}
.field:first-child{border-top:0}dt{color:#65736b;font-size:13px;line-height:1.5}dd{margin:0;min-width:0;line-height:1.5}
span,dt{overflow-wrap:anywhere;white-space:pre-wrap}ol{margin:0;padding-left:22px}li{padding:4px 0}li+li{margin-top:6px}
dd dl .field{grid-template-columns:minmax(100px,34%) minmax(0,1fr)}footer{color:#65736b;font-size:12px;margin-top:22px}
@media(max-width:640px){body{padding:16px 10px 32px}header,.section{padding:20px}h1{font-size:26px}.field,dd dl .field{grid-template-columns:1fr;gap:5px}.context-grid,.option-grid{grid-template-columns:1fr}.observation-summary{grid-template-columns:1fr}.measurement{justify-content:flex-start}.detail-section{padding:0}summary{padding:18px 20px}.detail-body{padding:0 20px 20px}}
@media print{body{background:#fff;padding:0}header{background:#fff;color:#26372f;border:1px solid #dfe4dc}header p{color:#65736b}.section{break-inside:avoid}.badge{border-color:#65736b}}
""".strip()


def render_card_html(card: Mapping[str, Any]) -> str:
    """Return a standalone read-only HTML preview; callers control local export.

    No card data enters attributes, styles, links, scripts, or requests.  The
    content security policy also prevents a preview from loading resources.
    """

    document = _document(card)
    summary = _html_patient_summary(card) if card["card_type"] == "patient" else _html_decision_summary(card)
    visible_limits = (
        '<section class="section limitations"><h2>Ограничения</h2>'
        + _html_value(card.get("limitations", [])) + "</section>"
    )
    sections = []
    for section in document.sections:
        description = (
            '<p class="description">' + _html_text(section.description) + "</p>"
            if section.description else ""
        )
        sections.append('<section class="section detail-section"><details><summary>' + _html_text(section.title)
                        + '</summary><div class="detail-body">' + description + _html_value(section.value)
                        + "</div></details></section>")
    return (
        '<!doctype html>\n<html lang="ru"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
        "<title>" + _html_text(document.title) + "</title><style>" + _STYLE + "</style>"
        '</head><body><main><header><h1>' + _html_text(document.title) + "</h1><p>"
        + _html_text(document.subtitle) + '</p><div class="badge">'
        + _html_text(_summary_text(card.get("status"), field="status")) + '</div></header><div class="sections">'
        + summary + visible_limits + '<h2 class="full-records-heading">Все поля карточки и основания</h2>'
        + '<p class="description">Раскройте раздел, чтобы проверить полные записи, метаданные и происхождение.</p>'
        + "".join(sections) + "</div><footer>Локальное представление · требуется проверка</footer>"
        "</main></body></html>\n"
    )

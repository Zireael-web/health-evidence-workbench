"""Only synthetic values belong in presentation tests."""

from html import unescape
from html.parser import HTMLParser

import pytest

from health_analyzer.cards.rendering import (
    _html_text, _markdown_text, render_card_html, render_card_markdown,
)


def test_markdown_dynamic_text_cannot_create_markup_or_autolinks() -> None:
    hostile = (
        '[click](https://example.invalid/) ![image](file:///tmp/synthetic)\n'
        '# Forged heading\n<script>alert("synthetic")</script>\n'
        '`code` **verified** <details open>\n'
        'https://example.invalid/ synthetic@example.invalid &copy;'
    )
    rendered = _markdown_text(hostile)

    assert "https://" not in rendered
    assert "[click]" not in rendered
    assert "<script>" not in rendered
    assert "<details" not in rendered
    assert "**verified**" not in rendered
    assert "\n" not in rendered
    assert unescape(rendered.replace("<br>", "\n")) == hostile


def test_html_dynamic_text_is_only_text_without_loss() -> None:
    hostile = '<img src="https://example.invalid/" onerror="alert(1)"> & \'raw\'\n'
    rendered = _html_text(hostile)

    assert "<img" not in rendered
    assert unescape(rendered) == hostile


def test_escaping_keeps_long_values_complete() -> None:
    value = "Синтетическое значение " * 2000 + "КОНЕЦ"
    assert _markdown_text(value).endswith("КОНЕЦ")
    assert _html_text(value).endswith("КОНЕЦ")


@pytest.mark.parametrize("value", [None, [], {}, 7])
def test_escaping_rejects_non_text(value: object) -> None:
    with pytest.raises(TypeError):
        _markdown_text(value)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        _html_text(value)  # type: ignore[arg-type]


def _patient_card() -> dict:
    from health_analyzer.cards.patient import build_patient_card
    from health_analyzer.contracts import to_dict
    from health_analyzer.packets import build_case_packet

    subject_id = "subj_" + "1" * 32
    provenance = [{"source_id": "synthetic_source", "sha256": "a" * 64, "page": 2,
                   "locator": "synthetic row 7"}]
    records = [{"record_type": "observation", "payload": {
        "observation_id": "synthetic_observation", "subject_id": subject_id,
        "display": "Синтетический показатель", "raw_value": "12.40",
        "original_unit": "ng/mL", "normalized_value": "12.4", "ucum_unit": "ug/L",
        "observed_at": "2025-02-03", "method": "synthetic_method",
        "reference_intervals": [{"low": "1.00", "high": "20.00", "unit": "ng/mL"}],
        "verification": "verified", "provenance": provenance, "notes": ["synthetic_note"],
    }}]
    for kind in ("source_fact", "user_note", "calculated"):
        records.append({"record_type": "statement", "payload": {
            "statement_id": "synthetic_" + kind, "subject_id": subject_id,
            "text": "synthetic record " + kind, "kind": kind,
            "verification": "verified", "provenance": provenance,
        }})
    packet = build_case_packet(subject_id=subject_id, records=records,
                               created_at="2026-08-01T12:00:00+00:00")
    return to_dict(build_patient_card(packet, context_bindings={"goals": ["synthetic_user_note"]}))


def _decision_card() -> dict:
    return {
        "card_type": "decision", "schema_version": "1.0", "card_id": "synthetic_card",
        "question": "Синтетический вопрос", "status": "draft", "case_packet_id": None,
        "evidence_packet_id": "synthetic_evidence", "answer_bundle_id": "synthetic_bundle",
        "risk_envelope": {"intent": "personal_context", "clinician_confirmation_required": False},
        "options": [{"option_id": "synthetic_option", "label_claim_id": "synthetic_claim",
                     "benefit_claim_ids": ["synthetic_claim"], "harm_claim_ids": [],
                     "status": "draft"}],
        "claims": [{"claim_id": "synthetic_claim", "text": "Синтетическое утверждение",
                    "kind": "external_evidence", "status": "verified", "certainty": "uncertain",
                    "support_ids": ["synthetic_support"], "conflicts_with": [], "caveats": []}],
        "case_observations": [], "case_statements": [], "reviewed_evidence_claims": [],
        "evidence_items": [{"evidence_id": "synthetic_source", "url": "https://example.invalid/"}],
        "missing_context": [{"category": "allergies", "status": "not_assessed",
                             "message": "Синтетический контекст не оценён."}],
        "research_gaps": ["Синтетический пробел"], "limitations": ["Синтетическое ограничение"],
        "audit": {"passed": True, "structural_traceability_passed": True, "issues": []},
        "review_required": True, "clinical_approval_obtained": False,
    }


def test_patient_builder_contract_preserves_values_dates_units_and_provenance() -> None:
    card = _patient_card()
    markdown = unescape(render_card_markdown(card))
    html = unescape(render_card_html(card))
    for rendered in (markdown, html):
        for expected in ("12.40", "12.4", "ng/mL", "ug/L", "2025-02-03",
                         "2026-08-01T12:00:00+00:00", "1.00", "20.00",
                         "synthetic row 7", "a" * 64, "synthetic_note", "synthetic_method"):
            assert expected in rendered
        assert "Дата сборки пакета" in rendered
        assert "Дата наблюдения" in rendered
        assert "Проверена запись сообщения пользователя" in rendered
        assert "Проверена запись расчёта" in rendered
        assert "Проверена запись факта из источника" in rendered
        assert "Неизвестно (unknown)" in rendered
        assert "Есть записи в выбранном пакете" in rendered
        assert "не подтверждает её актуальность" in rendered


def test_decision_keeps_draft_review_limits_and_exact_support_records_visible() -> None:
    card = _decision_card()
    for rendered in (unescape(render_card_markdown(card)), unescape(render_card_html(card))):
        assert "Вариант 1 · Черновик · Синтетическое утверждение" in rendered
        assert "synthetic_support" in rendered
        assert "Не оценено (not_assessed)" in rendered
        assert "не подтверждает смысловую корректность" in rendered
        assert "Метаданные публикации сами по себе" in rendered
        assert "Клиническое одобрение получено" in rendered
        assert "Синтетический пробел" in rendered


def test_decision_builder_contract_renders_research_and_blocked_states() -> None:
    from health_analyzer.cards.decision import DecisionContext, build_decision_card
    from health_analyzer.contracts import RiskEnvelope, RiskIntent, to_dict

    for intent, expected in ((RiskIntent.PERSONAL_CONTEXT, "Нужны научные данные"),
                             (RiskIntent.CLINICAL_ACTION, "Требуется подтверждение врача")):
        card = build_decision_card(
            question="Синтетический вопрос",
            risk_envelope=RiskEnvelope(intent=intent,
                                      clinician_confirmation_required=intent is RiskIntent.CLINICAL_ACTION),
            required_context=(DecisionContext.PREFERENCES, DecisionContext.PREVIOUS_TREATMENTS),
        )
        for rendered in (render_card_markdown(to_dict(card)), render_card_html(to_dict(card))):
            assert expected in rendered
            assert "Предпочтения" in rendered
            assert "Предыдущее лечение" in rendered
            assert "Варианты не сформированы" in rendered


class _MarkupInspector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.attributes: list[tuple[str, str | None]] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attributes.extend(attrs)

    def handle_data(self, data: str) -> None:
        self.text.append(data)


class _DisclosureInspector(_MarkupInspector):
    def __init__(self) -> None:
        super().__init__()
        self.details_depth = 0
        self.visible: list[str] = []
        self.disclosed: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        super().handle_starttag(tag, attrs)
        if tag == "details":
            self.details_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "details":
            self.details_depth -= 1

    def handle_data(self, data: str) -> None:
        super().handle_data(data)
        (self.disclosed if self.details_depth else self.visible).append(data)


def test_complete_card_html_has_no_dynamic_attributes_or_resource_elements() -> None:
    card = _decision_card()
    hostile = '<img src="https://example.invalid/synthetic-canary" onerror="alert(1)">'
    card["question"] = hostile
    card["claims"][0]["text"] = hostile
    card["extra<field>"] = {"untrusted-key": hostile}
    inspector = _MarkupInspector()
    inspector.feed(render_card_html(card))

    assert not ({"script", "a", "img", "iframe", "form", "link", "object", "embed", "svg"} & set(inspector.tags))
    assert all("synthetic" not in (value or "") for _, value in inspector.attributes)
    assert all(not name.startswith("on") and name not in {"src", "href", "srcdoc"} for name, _ in inspector.attributes)
    assert hostile in "".join(inspector.text)
    assert "extra<field>" in "".join(inspector.text)


def test_patient_html_compact_summary_coexists_with_complete_disclosures() -> None:
    inspector = _DisclosureInspector()
    inspector.feed(render_card_html(_patient_card()))
    visible = "".join(inspector.visible)
    disclosed = "".join(inspector.disclosed)

    for value in ("Синтетический показатель", "12.40", "ng/mL", "2025-02-03",
                  "Проверена запись", "Лекарства", "Неизвестно", "Ограничения"):
        assert value in visible
    assert "Дата сборки пакета" not in visible
    assert "2026-08-01T12:00:00+00:00" in disclosed
    assert "synthetic row 7" in disclosed
    assert "a" * 64 not in visible
    assert "a" * 64 in disclosed
    assert "12.40" in disclosed
    assert "ng/mL" in disclosed
    assert "(medications)" not in visible
    assert "(medications)" in disclosed
    assert inspector.tags.count("summary") == inspector.tags.count("details")
    assert not any(name == "open" for name, _ in inspector.attributes)


def test_decision_html_shows_comparison_fields_and_limits_without_disclosure() -> None:
    card = _decision_card()
    card["options"].append({"option_id": "synthetic_empty", "status": "draft"})
    inspector = _DisclosureInspector()
    inspector.feed(render_card_html(card))
    visible = "".join(inspector.visible)
    disclosed = "".join(inspector.disclosed)

    for value in ("Синтетический вопрос", "Синтетическое утверждение", "Черновик", "Вариант 2",
                  "Польза", "Риски", "Дозировка", "Длительность", "Контроль", "Альтернативы",
                  "Применимость", "Неопределённость", "Нет подтвержденных данных",
                  "Клиническое одобрение получено: Нет", "Синтетическое ограничение"):
        assert value in visible
    assert ("class", "option-grid") in inspector.attributes
    assert inspector.attributes.count(("class", "option-summary")) == 2
    assert "synthetic_support" not in visible
    assert "synthetic_support" in disclosed
    assert "Структурный аудит" in disclosed
    assert "Синтетическое утверждение" in disclosed


def test_html_summary_layout_has_narrow_screen_rules_without_clipping() -> None:
    rendered = render_card_html(_decision_card())
    assert "@media(max-width:640px)" in rendered
    assert ".context-grid,.option-grid{grid-template-columns:1fr}" in rendered
    assert "grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr))" in rendered
    assert "overflow-wrap:anywhere" in rendered
    assert "text-overflow:ellipsis" not in rendered
    assert "line-clamp" not in rendered
    assert "max-height" not in rendered


def test_full_card_rendering_never_truncates_records_or_large_values() -> None:
    card = _patient_card()
    long_text = "Синтетический текст " * 2000 + "ПОСЛЕДНИЙ_СИМВОЛ"
    card["observations"][0]["notes"].append(long_text)
    for index in range(30):
        card["statements"].append({"statement_id": f"synthetic_extra_{index}",
                                   "kind": "user_note", "text": f"полная запись {index}",
                                   "verification": "needs_review"})
    for rendered in (unescape(render_card_markdown(card)), unescape(render_card_html(card))):
        assert long_text in rendered
        assert "полная запись 29" in rendered
        assert "Ожидает проверки" in rendered


def test_rendering_is_deterministic_independent_of_mapping_key_order() -> None:
    card = _patient_card()
    reordered = {key: value for key, value in reversed(tuple(card.items()))}
    reordered["observations"] = [dict(reversed(tuple(item.items()))) for item in card["observations"]]
    assert render_card_markdown(card) == render_card_markdown(reordered)
    assert render_card_html(card) == render_card_html(reordered)


@pytest.mark.parametrize("card", [{}, {"card_type": "other", "schema_version": "1.0"},
                                  {"card_type": "patient", "schema_version": "9.9"}])
def test_renderer_rejects_unknown_card_contracts(card: dict) -> None:
    with pytest.raises(ValueError):
        render_card_markdown(card)
    with pytest.raises(ValueError):
        render_card_html(card)

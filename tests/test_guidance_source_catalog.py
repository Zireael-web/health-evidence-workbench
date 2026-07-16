from __future__ import annotations

import json
from pathlib import Path

import pytest

from health_analyzer.cli import main
from health_analyzer.guidance import (
    DEFAULT_GUIDANCE_SOURCE_CATALOG,
    GuidanceRiskLevel,
    GuidanceSourceCatalog,
)
from health_analyzer.privacy import PrivacyViolation


def test_bundled_catalog_is_strict_and_contains_official_portals() -> None:
    catalog = GuidanceSourceCatalog.load()

    assert len(catalog.sources) == 20
    assert tuple(source.source_id for source in catalog.sources) == tuple(
        sorted(source.source_id for source in catalog.sources)
    )
    assert {
        "cardiology",
        "cosmetics",
        "dermatology",
        "infectious-disease",
        "laboratory-medicine",
        "medicines",
        "nephrology",
        "prevention",
        "respiratory",
        "rheumatology",
        "sport",
    }.issubset(catalog.domains)


def test_information_plan_uses_live_sources_without_forcing_registry_import() -> None:
    plan = GuidanceSourceCatalog.load().plan(
        question="What current cardiovascular guidance addresses exercise?",
        domains=("cardiology",),
        jurisdictions=("GLOBAL",),
        risk_level=GuidanceRiskLevel.INFORMATION,
    )

    assert [source.source_id for source in plan.sources] == ["who", "esc", "acc-aha"]
    assert plan.source_review_passes == 1
    assert plan.requires_registry_snapshot is False
    assert plan.requires_clinician_confirmation is False
    assert "Chrome" in plan.browser_policy


def test_user_facing_domain_aliases_expand_to_canonical_domains() -> None:
    catalog = GuidanceSourceCatalog.load()

    beauty = catalog.plan(
        question="Which current sources address cosmetic and skin safety?",
        domains=("beauty",),
        jurisdictions=("EU",),
    )
    labs = catalog.plan(
        question="Which current sources govern laboratory interpretation?",
        domains=("labs",),
        jurisdictions=("GLOBAL",),
    )

    assert beauty.domains == ("cosmetics", "dermatology")
    assert "sccs" in {source.source_id for source in beauty.sources}
    assert labs.domains == ("laboratory-medicine",)
    assert {"clsi", "ifcc", "iso-medical-laboratories"}.issubset(
        {source.source_id for source in labs.sources}
    )


def test_jurisdiction_alias_uses_existing_registry_contract() -> None:
    plan = GuidanceSourceCatalog.load().plan(
        question="Which current US medicine sources apply?",
        domains=("medicines",),
        jurisdictions=("USA",),
    )

    assert plan.jurisdictions == ("US",)
    assert "fda" in {source.source_id for source in plan.sources}


def test_single_source_set_cover_prefers_profile_and_national_authority() -> None:
    plan = GuidanceSourceCatalog.load().plan(
        question="Which US cardiovascular guidance applies?",
        domains=("cardiology",),
        jurisdictions=("US",),
        max_sources=1,
    )

    assert [source.source_id for source in plan.sources] == ["acc-aha"]
    assert plan.uncovered_scopes == ()


def test_source_limit_fails_when_two_profile_domains_require_two_issuers() -> None:
    with pytest.raises(ValueError, match="too small"):
        GuidanceSourceCatalog.load().plan(
            question="Which sources cover cardiovascular and skin guidance?",
            domains=("cardiology", "dermatology"),
            jurisdictions=("GLOBAL",),
            max_sources=1,
        )


def test_missing_national_profile_scope_is_explicit_without_blocking_global_source() -> None:
    plan = GuidanceSourceCatalog.load().plan(
        question="Which US nephrology guidance applies?",
        domains=("nephrology",),
        jurisdictions=("US",),
    )

    assert "kdigo" in {source.source_id for source in plan.sources}
    assert plan.unmapped_jurisdictions == ()
    assert plan.uncovered_scopes == ("nephrology@US",)
    assert any("domain-jurisdiction" in check for check in plan.required_checks)


def test_unknown_jurisdiction_requires_competent_authority_discovery() -> None:
    plan = GuidanceSourceCatalog.load().plan(
        question="Which Russian cardiovascular guidance applies?",
        domains=("cardiology",),
        jurisdictions=("RU",),
    )

    assert plan.unmapped_jurisdictions == ("RU",)
    assert plan.uncovered_scopes == ("cardiology@RU",)
    assert any("national authority" in check for check in plan.required_checks)


@pytest.mark.parametrize(
    ("risk_level", "clinician_confirmation"),
    (
        (GuidanceRiskLevel.PERSONAL_CONTEXT, False),
        (GuidanceRiskLevel.CLINICAL_ACTION, True),
    ),
)
def test_personal_and_actionable_plans_require_audited_snapshot(
    risk_level: GuidanceRiskLevel,
    clinician_confirmation: bool,
) -> None:
    plan = GuidanceSourceCatalog.load().plan(
        question="Which official sources govern a synthetic personal decision?",
        domains=("cosmetics",),
        jurisdictions=("EU",),
        risk_level=risk_level,
    )

    assert [source.source_id for source in plan.sources] == ["sccs", "who"]
    assert plan.source_review_passes == 2
    assert plan.requires_registry_snapshot is True
    assert plan.requires_clinician_confirmation is clinician_confirmation


def test_unmapped_domain_uses_broad_authorities_and_requires_issuer_review() -> None:
    catalog = GuidanceSourceCatalog.load()

    plan = catalog.plan(
        question="Which current official sources cover a new specialty topic?",
        domains=("new-specialty",),
    )

    assert plan.unmapped_domains == ("new-specialty",)
    assert [source.source_id for source in plan.sources] == ["who"]
    assert plan.required_checks[0].startswith("identify and verify")


def test_empty_match_fails_closed() -> None:
    catalog = GuidanceSourceCatalog.load()

    sccs_only = GuidanceSourceCatalog(
        (next(source for source in catalog.sources if source.source_id == "sccs"),)
    )
    with pytest.raises(ValueError, match="no official guidance source"):
        sccs_only.plan(
            question="Synthetic question",
            domains=("cosmetics",),
            jurisdictions=("GB-ENG",),
        )


def test_catalog_rejects_unallowlisted_index_host(tmp_path: Path) -> None:
    payload = json.loads(DEFAULT_GUIDANCE_SOURCE_CATALOG.read_text())
    payload["sources"][0]["index_url"] = "https://example.test/guidelines"
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(payload))

    with pytest.raises(ValueError, match="canonical HTTPS"):
        GuidanceSourceCatalog.load(path)


def test_catalog_rejects_duplicate_source_id(tmp_path: Path) -> None:
    payload = json.loads(DEFAULT_GUIDANCE_SOURCE_CATALOG.read_text())
    payload["sources"][1]["source_id"] = payload["sources"][0]["source_id"]
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(payload))

    with pytest.raises(ValueError, match="sorted by source_id|unique"):
        GuidanceSourceCatalog.load(path)


def test_catalog_rejects_duplicate_json_keys_and_boolean_integers(
    tmp_path: Path,
) -> None:
    duplicate = tmp_path / "duplicate-key.json"
    duplicate.write_text(
        '{"schema_version":"1.0","schema_version":"1.0","sources":[]}'
    )
    with pytest.raises(ValueError, match="duplicate JSON key"):
        GuidanceSourceCatalog.load(duplicate)

    payload = json.loads(DEFAULT_GUIDANCE_SOURCE_CATALOG.read_text())
    payload["sources"][0]["priority"] = True
    invalid_bool = tmp_path / "boolean-priority.json"
    invalid_bool.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="priority"):
        GuidanceSourceCatalog.load(invalid_bool)


def test_guidance_plan_cli_applies_the_public_privacy_gate() -> None:
    with pytest.raises(PrivacyViolation):
        main(
            [
                "guidance-plan",
                "Patient: Smith John asks about exercise",
                "--domain",
                "cardiology",
                "--risk-level",
                "information",
            ]
        )


def test_guidance_plan_cli_requires_explicit_risk_level() -> None:
    with pytest.raises(SystemExit):
        main(
            [
                "guidance-plan",
                "Which current cardiovascular guidance applies?",
                "--domain",
                "cardiology",
            ]
        )

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SKILLS = ROOT / "plugins" / "health-analyzer-v2" / "skills"


def test_v2_plugin_contains_exactly_three_short_discoverable_skills():
    expected = {"health-records", "health-research", "health-review"}
    assert {p.parent.name for p in SKILLS.glob("*/SKILL.md")} == expected
    for name in expected:
        body = (SKILLS / name / "SKILL.md").read_text()
        assert body.startswith(f"---\nname: {name}\ndescription: ")
        assert len(body.splitlines()) < 100


def test_skills_describe_actual_trust_and_runtime_limits():
    records = (SKILLS / "health-records" / "SKILL.md").read_text()
    research = (SKILLS / "health-research" / "SKILL.md").read_text()
    review = (SKILLS / "health-review" / "SKILL.md").read_text()
    assert "snapshot ID/hash" in records and "attested" in records
    assert "provider_unavailable" in research and "model_reported" in research
    assert "public evidence drafts only" in review and "structural report is not medical validation" in review

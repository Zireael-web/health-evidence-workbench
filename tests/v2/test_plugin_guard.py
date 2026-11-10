import json
from pathlib import Path
import re
import subprocess
import sys

import pytest

PLUGIN = Path(__file__).resolve().parents[2] / "plugins/health-analyzer-v2"
GUARD = PLUGIN / "hooks/public_guard.py"
PUBLIC = "mcp__health_analyzer_v2_public_research__plan_search"


def execute(value, *, raw=False):
    data = value if raw else json.dumps(value)
    result = subprocess.run([sys.executable, "-I", "-B", str(GUARD)], input=data,
                            capture_output=True, text=True, timeout=3)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout) if result.stdout else None


def event(tool_input, tool=PUBLIC):
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input}


@pytest.mark.parametrize("input", [
    {"request": {"question": "Patient name: Synthetic Test Person"}},
    {"request": {"question": "Contact synthetic@example.invalid"}},
    {"request": {"question": "Пациент: Синтетический Пациент"}},
    {"request": {"question": "Phone +7 777 123 45 67"}},
    {"request": {"question": "/Users/synthetic/Documents/report.pdf"}},
    {"request": {"question": "file:///home/synthetic/report.pdf"}},
    {"request": {"question": "%252FUsers%252Fsynthetic%252Freport.pdf"}},
    {"request": {"question": "C:\\Users\\synthetic\\report.pdf"}},
    {"request": {"question": "General topic", "patient_id": "synthetic-patient"}},
    {"draft": {"case_selection": {"subject_id": "synthetic-subject"}}},
    {"request": {"question": "DOB: 2000-01-01"}},
    {"draft": {"claims": [{"support_ids": ["revision_" + "a" * 32]}]}},
    {"request": {"question": "Inspect observation_" + "b" * 64}},
    {"request": {"question": "extraction_" + "a" * 64}},
])
def test_obvious_identifiers_are_explicitly_denied_without_echo(input):
    result = execute(event(input))
    decision = result["hookSpecificOutput"]
    assert decision["hookEventName"] == "PreToolUse"
    assert decision["permissionDecision"] == "deny"
    assert "Synthetic Test Person" not in json.dumps(result)
    assert "example.invalid" not in json.dumps(result)


@pytest.mark.parametrize("input", [
    {"request": {"question": "Vitamin D effects on mortality in adults", "population": "Adults"}},
    {"source": {"url": "https://example.invalid/library/study", "title": "Synthetic public study"}},
    {"source_id": "source_" + "0" * 32},
    {"plan_id": "plan_" + "a" * 32},
    {"review_id": "review_" + "a" * 32},
    {"draft_id": "draft_" + "a" * 32},
    {"request": {"question": "Diabetes in patients aged 50 to 60"}},
    {"finding": {"publication_date": "2025-01-01", "excerpt": "Synthetic population event risk 10.5 percent"}},
])
def test_public_questions_ids_dates_and_public_url_are_allowed(input):
    assert execute(event(input)) is None


def test_non_v2_tools_and_private_surface_are_not_intercepted():
    unsafe = {"patient_name": "Synthetic Person", "file_path": "/Users/synthetic/report.pdf"}
    assert execute(event(unsafe, "mcp__health_analyzer_v2_private_data__prepare_import")) is None
    assert execute(event(unsafe, "mcp__other__plan_search")) is None


def test_malformed_and_oversized_matched_events_produce_supported_denial():
    assert execute("not JSON", raw=True)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert execute("x" * (2 * 1024 * 1024 + 1), raw=True)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert execute({"tool_name": PUBLIC})["hookSpecificOutput"]["permissionDecision"] == "deny"
    decision = execute(event({"draft": {"claims": [{"text": "a" * 32769}]}}))["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    assert "claim batches" in decision["permissionDecisionReason"]
    assert "private identifiers" not in decision["permissionDecisionReason"]


def test_public_draft_total_size_is_not_mistaken_for_oversized_scalar():
    draft = {"claims": [{"claim_id": f"claim_{index}", "text": "a" * 1000,
                          "support_ids": ["finding_" + "a" * 32]} for index in range(80)]}
    assert len(json.dumps(draft)) > 32768
    assert execute(event({"draft": draft})) is None


def test_hook_never_reads_transcript_or_other_event_metadata(tmp_path):
    transcript = tmp_path / "synthetic-transcript.json"
    transcript.write_text("patient_name: Synthetic Person; synthetic@example.invalid")
    value = event({"request": {"question": "Public scientific question"}})
    value.update(transcript_path=str(transcript), cwd="/Users/synthetic/private", session_id="synthetic-session")
    assert execute(value) is None


def test_manifest_exactly_three_skills_public_only_transport_and_namespaced_hook():
    manifest = json.loads((PLUGIN / ".codex-plugin/plugin.json").read_text())
    assert manifest["skills"] == "./skills/"
    assert manifest["mcpServers"] == "./.mcp.json"
    assert manifest["hooks"] == "./hooks/hooks.json"
    assert {p.parent.name for p in (PLUGIN / "skills").glob("*/SKILL.md")} == {
        "health-records", "health-research", "health-review"}
    servers = json.loads((PLUGIN / ".mcp.json").read_text())["mcpServers"]
    assert set(servers) == {"health-analyzer-v2-public-research"}
    assert "private-data" not in json.dumps(servers)
    config = json.loads((PLUGIN / "hooks/hooks.json").read_text())
    matcher = config["hooks"]["PreToolUse"][0]["matcher"]
    assert re.fullmatch(matcher, PUBLIC)
    assert re.fullmatch(matcher, "mcp__plugin_health_analyzer_v2_health_analyzer_v2_public_research__fetch_source_abstract")
    assert not re.fullmatch(matcher, "mcp__health_analyzer_v2_private_data__prepare_import")
    assert not re.fullmatch(matcher, "mcp__other__plan_search")

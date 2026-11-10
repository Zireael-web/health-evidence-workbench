"""Actual offline CLI source binding; no model/provider or real personal data."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from health_analyzer.v2.exercise_scope import create_synthetic_exercise


def run_public_cli_chain(root):
    """Caller supplies a new artificial exercise; all state stays below it."""
    create_synthetic_exercise(root)
    stage = Path(__file__).resolve().parents[2]
    launcher = stage / "scripts/ha-v2"
    config = root / "synthetic-config.json"
    receipts = []
    init = [sys.executable, "-I", "-B", str(launcher), "--config", str(config), "init",
            "--data-root", str(root / "data"), "--isolation", "macos_enforced"]
    initialized = subprocess.run(init, capture_output=True, text=True, timeout=60)
    assert initialized.returncode == 0, initialized.stderr
    receipts.append({"transport": "actual_cli", "operation": "init", "isolation": "macos_enforced",
                     "result": json.loads(initialized.stdout)})

    def call(tool, arguments, *, expect_success=True):
        path = root / f"request-{len(receipts):02d}-{tool}.json"
        path.write_text(json.dumps(arguments, ensure_ascii=False)); path.chmod(0o600)
        result = subprocess.run([sys.executable, "-I", "-B", str(launcher), "--config", str(config),
            "call", "--zone", "public-research", "--tool", tool, "--arguments-file", str(path)],
            capture_output=True, text=True, timeout=45)
        assert (result.returncode == 0) == expect_success, result.stderr or result.stdout
        parsed = json.loads(result.stdout or result.stderr)
        receipts.append({"transport": "actual_cli", "tool": tool, "arguments": arguments,
                         "returncode": result.returncode, "result": parsed})
        return parsed

    source = call("register_source", {"source": {
        "title": "SYNTHETIC FICTIONAL comparison guidance", "url": "https://synthetic.example.invalid/comparison-guidance",
        "issuer": "Fictional fixture issuer", "publication_date": "2040-01-01"}})
    access = call("record_source_access", {"source_id": source["source_id"], "access": {
        "checked_url": source["url"], "availability": "available", "text_extent": "selected_sections",
        "inspected_scope": "SYNTHETIC fixture paragraph 1", "locators": ["Fixture paragraph 1"]}})
    text = "SYNTHETIC FICTIONAL SOURCE: retain the printed reference interval separately for each observation."
    finding = call("record_finding", {"finding": {"source_id": source["source_id"], "access_id": access["access_id"],
        "kind": "recommendation", "statement": text, "excerpt": text, "locator": "Fixture paragraph 1"}})
    draft = {"intent": "education", "depth": "quick", "claims": [{"claim_id": "synthetic-claim-1",
        "type": "source_finding", "text": text, "support_ids": [finding["finding_id"]]}],
        "limitations": ["Fictional source and deterministic engineering draft; no actual model or clinical validation."]}
    reviewed = call("review_answer", {"draft": draft})
    assert reviewed["release_state"] == "needs_revision"
    assert reviewed["medical_validation"] == "not_provided"
    assert any(c["check"] == "structural" and c["status"] == "ok" for c in reviewed["checks"])
    assert any(c["check"] == "source_alignment" and c["status"] == "not_checked" for c in reviewed["checks"])
    assert reviewed["claim_readiness"][0]["semantic_alignment"] == "not_checked_by_backend"
    unsupported = {**draft, "claims": [{**draft["claims"][0], "support_ids": [source["source_id"]]}]}
    rejected = call("review_answer", {"draft": unsupported})
    assert rejected["release_state"] == "needs_revision"
    assert any(c["check"] == "structural" and c["status"] == "issue" for c in rejected["checks"])
    return {"scope": "fully_synthetic_offline", "receipts": receipts, "public_draft": draft,
            "structural_review": reviewed, "unsupported_metadata_review": rejected,
            "actual_model_calls": 0, "provider_calls": 0, "network_calls": 0,
            "semantic_review": "not_performed", "personal_review_resolver": "unavailable",
            "real_human_or_clinical_confirmation": False}


@pytest.mark.skipif(sys.platform != "darwin", reason="This acceptance requires the actual macOS enforced CLI")
def test_actual_offline_public_cli_source_supported_draft_keeps_semantic_gate_open(tmp_path):
    report = run_public_cli_chain(tmp_path / "synthetic-offline-cli")
    assert len(report["receipts"]) == 6
    assert report["actual_model_calls"] == 0

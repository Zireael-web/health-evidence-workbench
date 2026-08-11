from __future__ import annotations

import json

from evals import EvalStatus, run_evals

SECURITY_SCENARIOS = (
    "phi-in-public-query",
    "prompt-injection-in-document",
    "path-traversal-and-symlink",
    "cross-patient-join",
    "unsupported-unit-conversion",
    "missing-provenance",
)


def _by_id(summary: dict[str, object]) -> dict[str, dict[str, object]]:
    results = summary["results"]
    assert isinstance(results, list)
    return {str(result["scenario_id"]): result for result in results}


def test_security_controls_fail_closed_and_report_contract_gaps() -> None:
    summary = run_evals(SECURITY_SCENARIOS)
    results = _by_id(summary)

    assert summary["passed"] is True
    assert results["phi-in-public-query"]["status"] == EvalStatus.PASS.value
    assert results["prompt-injection-in-document"]["status"] == EvalStatus.PASS.value
    assert results["path-traversal-and-symlink"]["status"] == EvalStatus.PASS.value
    assert results["cross-patient-join"]["status"] == EvalStatus.PASS.value
    assert results["unsupported-unit-conversion"]["status"] == EvalStatus.PASS.value

    provenance = results["missing-provenance"]
    assert provenance["status"] in {EvalStatus.PASS.value, EvalStatus.GAP.value}
    if provenance["status"] == EvalStatus.GAP.value:
        assert provenance["gap_id"] == "CASE_PACKET_PROVENANCE_NOT_REQUIRED"


def test_security_summary_never_echoes_synthetic_identifier_or_injection_text() -> None:
    encoded = json.dumps(run_evals(SECURITY_SCENARIOS), ensure_ascii=False)

    assert "synthetic.record@example.invalid" not in encoded
    assert "Ignore all previous instructions" not in encoded

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from evals import SCENARIOS, EvalStatus, run_evals

ROOT = Path(__file__).resolve().parents[1]


def _by_id(summary: dict[str, object]) -> dict[str, dict[str, object]]:
    results = summary["results"]
    assert isinstance(results, list)
    return {str(result["scenario_id"]): result for result in results}


def test_full_eval_suite_covers_required_end_to_end_scenarios() -> None:
    summary = run_evals()
    results = _by_id(summary)

    assert summary["schema_version"] == "1.0"
    assert summary["suite_id"] == "health-analyzer-red-team"
    datetime.fromisoformat(str(summary["generated_at"]))
    assert summary["passed"] is True
    assert summary["counts"]["fail"] == 0
    assert summary["counts"]["total"] == len(SCENARIOS) == 10

    for scenario_id in (
        "guidance-lifecycle",
        "unsupported-and-overstated-claim",
        "abpm-two-night-readings",
    ):
        assert results[scenario_id]["status"] == EvalStatus.PASS.value

    fallback = results["unknown-document-generic-fallback"]
    assert fallback["status"] in {EvalStatus.PASS.value, EvalStatus.GAP.value}
    if fallback["status"] == EvalStatus.GAP.value:
        assert str(fallback["gap_id"]).startswith("GENERIC_DOCUMENT_FALLBACK_")


def test_eval_runner_writes_the_same_machine_json_summary(tmp_path: Path) -> None:
    output = tmp_path / "eval-summary.json"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "evals.run",
            "--output",
            str(output),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    stdout_summary = json.loads(completed.stdout)
    file_summary = json.loads(output.read_text(encoding="utf-8"))
    assert stdout_summary == file_summary
    assert stdout_summary["counts"]["total"] == 10
    assert stdout_summary["counts"]["fail"] == 0

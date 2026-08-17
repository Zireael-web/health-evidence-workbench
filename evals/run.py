"""Command-line entry point for the red-team evaluation suite."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scenarios import SCENARIOS, run_evals


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run black-box health-analyzer security and safety evaluations."
    )
    parser.add_argument(
        "--scenario",
        action="append",
        dest="scenario_ids",
        help="Run one scenario ID; repeat to select multiple scenarios.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Also write the JSON summary to this path.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return a non-zero exit code for known gaps as well as failures.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List scenario IDs as JSON without running them.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.list:
        payload = {
            "schema_version": "1.0",
            "scenarios": [
                {
                    "scenario_id": scenario.scenario_id,
                    "title": scenario.title,
                    "category": scenario.category,
                }
                for scenario in SCENARIOS
            ],
        }
        encoded = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        print(encoded)
        return 0

    try:
        summary = run_evals(args.scenario_ids)
    except ValueError as error:
        _parser().error(str(error))
    encoded = json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True)
    print(encoded)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded + "\n", encoding="utf-8")
    if args.strict:
        return 0 if summary["strict_passed"] else 1
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

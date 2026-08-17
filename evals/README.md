# Red-team and clinical-safety evals

The suite calls the project's public Python APIs as a black box. It never
changes the core implementation. Implemented controls report `pass`, unexpected
regressions report `fail`, and missing enforceable contracts report `gap` with a
stable `gap_id`.

Run the complete suite and print a machine-readable JSON summary:

```bash
PYTHONPATH=src uv run --no-project python -m evals.run
```

Write the same summary to a file:

```bash
PYTHONPATH=src uv run --no-project python -m evals.run \
  --output state/evals/red-team-summary.json
```

By default, known gaps do not make the process fail; control regressions do.
Use `--strict` in a release gate to make both `gap` and `fail` return exit code
1. Use repeated `--scenario ID` flags to run a subset, or `--list` to discover
the available IDs.

All test inputs are synthetic. No real patient names, identifiers, documents,
or health measurements belong in this directory.

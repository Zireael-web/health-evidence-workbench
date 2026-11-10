# Synthetic A06/A09 comparison and correction gates

This bounded exercise uses artificial typed rows and artificial CSV files.
It does not establish native PDF/image acceptance, clinical validity, OCR
accuracy, user identity, human review, or a hard operating-system isolation
boundary. All attestations are simulated and explicitly contain `SYNTHETIC`
markers. Runtime `conversation_attested` is tested as an attributed contract
branch; no person confirmed these records.

## Frozen matrix and result

`work/corrections/matrix.json` was written and hashed before the first runtime
call. `freeze.json` records zero preceding runtime calls. Its SHA-256 is
`7af20091ac767b7ed152ec2668f371bfbbb2f621fed00a1fab65d783d2b5ff99`.
The test asserts that its field coverage equals the actual `RecordsService`
allowlist derived from `ROW_FIELDS`, so a newly allowed field cannot silently
escape this matrix.

The final targeted run passed **62 tests, zero failures/errors/skips** in
17.186 seconds: 60 service/matrix cases and two transport tests. Each actual
transport made 104 scoped calls through a fresh explicit artificial deployment
configuration. The actual CLI uses subprocess `ha-v2 call`; the actual MCP test
initializes an SDK stdio client, lists the private tools, and calls them over
stdio. Neither is a mocked transport. Bootstrap passes keys through inherited
FDs; tests do not read transport key files or put raw keys in argv, environment,
evidence, or logs. No external requests or model calls are made.

## A09 typed corrections

Twenty-seven accepted correction cases cover every one of the 16 permitted
fields:

| Fields | Frozen cases |
| --- | --- |
| `analyte_raw`, `analyte_key`, `mapping_status` | spelling, different identity, proposed mapping |
| `measurement_property`, `subtype`, `loinc` | separate literal typed proposals |
| `result` | exact comma scalar, censored inequality, qualitative, semiquantitative, explicit cancellation |
| `unit_raw`, `unit_code` | original unit and separate literal proposed code |
| `clinical_time` | performed datetime/timezone, reported date, month, year, bounded interval/inclusivity, explicit unknown |
| `reference_intervals` | all bounds/inclusivity/context/text fields, reference kind, explicit absence |
| `specimen`, `method`, `device`, `lab_flag_raw` | typed replacement literals |
| `missing_reasons` | explicit unknown specimen and absent time/reference |

Fifteen rejected cases cover source-anchor/panel/extraction/status rewrites,
caller assurance, nonexistent row notes, unresolved text, blank no-result,
mismatched/float Decimal, ambiguous mapping, fabricated date precision and
reversed references. Notes are separately recorded as `user_note` context
events and do not alter laboratory revisions.

Every accepted service correction retains the exact signed previous payload
and MAC, old object content, all original source anchors, source hash and
supersession link. Idempotent replay returns the same result without additional
writes. CLI/MCP read back the original revisions exactly after stripping only
the documented query projection fields; their correction responses retain
the complete frozen anchor dictionary. CSV has no device column, so its
initial explicit typed proposal fixes the missing device anchor as `null`,
without an invented source locator.

Wrong-subject operations, a valid first/invalid second review decision, unshown
rows, stale review, stale correction attestation, source-check failure and
idempotency conflict are rejected. Service failures preserve the complete
signed inventory; actual transport failures preserve queried history and
coverage. Source-check failure is exercised at the service boundary; transport
source checks run against preserved artificial originals.

## A06 comparison

The positive pair preserves `(5.4, 3.9-5.5)` and `(5.6, 4.2-6.2)` as separate
result/reference pairs. The exact same-unit Decimal delta is `0.2`, ordered by
collection date. Fourteen negatives through each transport include mismatched
analyte/specimen/method/property/subtype, unknown mapping/specimen/method/unit,
unsupported unit conversion despite an apparent proposed unit code,
reported/month time, differing result scale and explicit invalid specimen.
These become exclusions or contextual rows with recorded reasons and no
numeric delta. Censored bounds retain their inequality and are not imputed as
exact numbers at the service boundary.

Parsed CSV fields remain `proposed` after a review that corrects only mapping.
That observed behavior is saved in `proposed-fields-observation.json`; the
comparison is contextual with known reason codes. The positive transport
fixture explicitly corrects unit, time, specimen and method before comparison.
It therefore proves the typed correction/comparison path, without claiming
that accepting raw native proposals alone establishes comparability.

## Evidence and reproduction

- `work/corrections/result-summary.json`: counts, scope, transport hashes.
- `work/corrections/pytest.xml`: final JUnit result.
- `work/corrections/evidence/actual-cli.json`: all 104 CLI requests/results.
- `work/corrections/evidence/actual-stdio-mcp.json`: all 104 MCP requests/results.
- `work/corrections/evidence/service-*.json`: scoped service requests/results and
  immutable/atomic invariants.

From the staged repository, run:

```sh
SYNTHETIC_CHAIN_EVIDENCE_DIR="$PWD/work/corrections/evidence" PYTHONPATH=src \
  /path/to/health-evidence-workbench/.venv/bin/python -m pytest \
  tests/v2/test_chain_corrections.py --basetemp=work/corrections/pytest-verified \
  --junitxml=work/corrections/pytest.xml -q
```

The generated `pytest-*` deployments are disposable synthetic working state,
including test-generated key files; the frozen matrix, traces, result summary
and JUnit XML are the review evidence. No production configuration, real
archive, private database, legacy state, source/core implementation or user
settings were accessed or changed by this exercise.

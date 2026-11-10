# A16 private transport and bounded synthetic recovery

A16 adds five tools to the existing `private-data` runtime. The CLI and stdio
MCP use the same service implementations; the public runtime surface is unchanged.

| Tool | Store mode used by CLI | Service result |
| --- | --- | --- |
| `get_case_selection` | read only | verified minimal private context and current freshness |
| `create_private_calculation` | writable | immutable calculation receipt and current freshness |
| `get_private_calculation` | read only | immutable receipt and current freshness |
| `prepare_private_answer` | writable | immutable private review report |
| `get_private_answer_review` | read only | immutable report, original draft, and current freshness |

Only the three new GETs extend `READONLY_PRIVATE_TOOLS`. Creation stays writable.
Existing MCP registration enforces `additionalProperties: false` at the outer
argument object. The private services validate nested draft, claim, assertion,
selection, calculation, and report contracts. Callers cannot supply a clinician
confirmation, review assurance, replacement numeric result, or calculation formula.
No new server, HTTP transport, model invocation, or release authority is added.

## Recovery graph validation

`SyntheticRecovery` accepts the exact new private kinds and schema versions:

| Kind | Schema | Payload identity |
| --- | --- | --- |
| `case_selection` | `health-analyzer.case-selection/2.0` | `selection_id` |
| `private_calculation` | `health-analyzer.private-calculation/2.0` | `calculation_id` |
| `private_answer_draft` | `health-analyzer.private-answer-draft/2.0` | `draft_id` |
| `private_answer_review` | `health-analyzer.private-answer-review/2.0` | `review_id` |

Recovery first authenticates the entire inventory and scopes. It then invokes
the same pure frozen-graph validators used by the private services. A valid HMAC
alone cannot establish that a case hash, frozen observation, source binding,
numeric result, report body, or retry response is consistent. A private draft
must have exactly one atomically saved review report. Calculation retry links
must resolve to the exact receipt ID and hash. Answer retry responses must equal
the original report and resolve to its original draft and request hash.

The case validator binds saved observations to actual immutable revisions,
source versions, extraction drafts, frozen review snapshots, decisions, and
confirmation/correction events. Calculation validation runs the production
comparator over those original frozen operands and checks its numeric output.
It does not replace old operands with the current projection after a correction.

Historical receipts and reports remain recoverable after a correction. Their
GETs return their unchanged bodies with separate `stale` freshness. A new
preparation using the stale case is rejected. Recovery does not turn a historical
artifact into a current medical claim.

## Acceptance evidence

`tests/v2/test_a16_transport_recovery.py` exercises one artificial CSV containing
two rows, through actual packaged CLI and MCP subprocesses:

1. Create a new owned synthetic deployment and import/review the artificial rows.
2. Create a case selection, numeric receipt, and private report through MCP.
3. Reject unknown outer arguments and a nested caller confirmation field.
4. Receive the complete report ACK, SIGKILL only the owned MCP process group,
   retrieve the three new GETs through CLI, and restart MCP to retry the exact
   calculation/report requests.
5. Verify that the CLI GETs preserve main/WAL/journal byte hashes and do not
   claim a current source-byte check.
6. Deny private preparation in the public runtime and deny an opaque private
   report ID in the existing public review adapter; the public object inventory
   remains empty.
7. Back up and restore the synthetic private database; retry responses retain
   the original receipt/report IDs and bodies without duplicate artifacts.
8. Correct a selected observation, then back up and restore again; the original
   report survives with stale freshness and rejects a new preparation.

Additional tests establish a valid baseline recovery before introducing
synthetically signed corruption: a wrong case hash, a rehashed frozen row,
an unsupported case field, a rehashed wrong numeric result, a wrong calculation
retry hash, and a rehashed inconsistent report body. Every malformed graph fails
before a bundle is published.

Actual transport receipts contain JSON CLI results and MCP request/response
messages. Synthetic recovery is exercised through its internal bounded service,
which has no CLI or MCP recovery entry point. This distinction is recorded in
the acceptance summary; recovery is not described as an actual recovery transport.

The harness uses explicit `host` isolation and records `host_logical_only`. It
provides an actual stdio/CLI test, not a new OS isolation proof. All attribution
decisions are conspicuously simulated; none is evidence of real human confirmation.
The test neither repeats the existing native/OCR source proof nor opens an
installed production deployment.

## Running the bounded check

Run offline with the existing runtime, from this stage:

```sh
env VIRTUAL_ENV=/path/to/health-evidence-workbench/.venv \
  PYTHONPATH="$PWD/src" UV_CACHE_DIR="$PWD/work/uv-cache" \
  PYTHONDONTWRITEBYTECODE=1 \
  uv run --active --no-sync --offline python -B -m pytest -p no:cacheprovider \
  tests/v2/test_a16_transport_recovery.py tests/v2/test_runtime.py \
  tests/v2/test_synthetic_recovery.py
```

Optionally set `HA_A16_TRANSPORT_OUTPUT` to a new, nonexistent exercise path
whose parent already exists. The test creates its own marker/config/state/test
keys and saves receipts there. It rejects adoption of an existing exercise.
Keys stay outside recovery bundles and are never placed in argv or receipts.

The final retained 2026-10-15 run is
`work/a16-owned-transport-recovery-proof-20261015-final/`. Its `receipts/summary.json`
distinguishes actual CLI/MCP from the internal recovery-service exercise. There
are 10 actual CLI receipts and two MCP wire logs (`ack` and `retry`). The owned
ACK process receipt records return code `-9` after the fully received private
report ACK. The first verified backup inventory contains one case, one private
calculation, one private answer draft, one private answer report, and their
three total retry records including the original simulated row acceptance.
Both recovery bundles contain only `manifest.json` and `private.sqlite3`.
The targeted A16/runtime/existing synthetic recovery command above passed
27 tests in 5.54 seconds. The summary binds the six implementation modules to
SHA-256 hashes and the test verifies they stay unchanged during this proof.
The XML receipt is `work/a16-transport-final-20261015.xml`. Earlier development
runs remain separate evidence, including the 2026-10-14 `-frozen` pass whose
module hashes predate the last case-graph and answer-getter repairs. The
2026-10-14 `-final` development attempt failed before summary receipt creation
on a coverage-contract incompatibility which the calculation owner fixed
before the later passing runs. All decisions and inputs in this evidence are
artificial.

The existing recovery restrictions remain: owned synthetic paths only, hard
object/byte bounds, exact supported SQLite schema, plaintext synthetic snapshots,
explicit test keys, and no replacement of existing targets. Bundles include no
original source-file bytes. Original-file availability and full production
recovery are not validated or claimed.

# Bounded synthetic production transport exercise

> Historical engineering exercise. Local OCR has since been disabled. Current
> PDF/image workflows use native PDF text and explicit model transcription; see
> [document intake](document-intake.md) and [records skill](../../plugins/health-analyzer-v2/skills/health-records/SKILL.md).

This is an explicitly artificial engineering exercise. Every source, subject,
decision, mapping and stored result is fictional. It does not issue medical
confirmation, evaluate general model quality, activate a plugin, or accept a
whole release. No existing deployment/configuration, archive, database, key,
model setting or other chat is opened or changed.

The opt-in test `tests/v2/test_production_chain_transport.py` creates a new owned
namespace under `work/transport`, copies only the Python package into an
installation layout without checkout scripts, and invokes its packaged entry
with `-I -B` and an explicit freshly initialized `macos_enforced` configuration.
Source bindings contain exact frozen PDF/PNG copies, without oracle files.
The freeze is checked before and after the exercise.

The harness performs real packaged CLI calls and real newline-framed stdio MCP
initialize/list/tools/call exchanges. It retains exact request/response objects,
CLI stdout/stderr/exit code, frozen review snapshots, source hashes, extraction
issues, provider limitations, native helper hashes, and snapshots of only its
owned descendant processes. The production byte bridge and mandatory native
parser profiles are used; no parser/model/service callbacks are mocked.

Raw recognition is scored against frozen independently authored labels before
any review, deliberately injected persistence edit or separately authored model visual
proposal. Applicable fields are reported separately; controls and duplicate
proposals remain explicit. Golden labels never repair source proposals.
Unsupported/ambiguous typed fields remain deferred.

To exercise the confirmed branch, the harness submits an openly fake fixture
attestation whose exact excerpt is `SYNTHETIC SIMULATED fixture decision; no real
human/patient confirmation`. The service records its ordinary attributed
`conversation_attested`/`user_confirmed` classes in these synthetic records.
Those labels describe the tested adapter branch, not an actual human or medical
decision. A separate subject without attestation must remain `model_checked`,
with assurance `none`, contextual history, an empty case selection and rejection
of explicit selection of its unconfirmed revision.

The crash check waits for actual stdio tool acknowledgements for commit and
correction, then SIGKILLs only the owned bootstrap/service process group. After
restart, the exact original request and idempotency key are replayed through
both stdio and CLI. Exact original acknowledgements and history without extra
revisions are required. The deliberately injected numeric edit is restored from
the frozen actual raw candidate, rather than from oracle labels.

## Recorded first attempt

`work/transport/run-01` used frozen bundle
`7fc3d63ad41686114fc43b974d94e077b72b763199217c821c72986e123e1b10`.
Actual native PDF imports yielded zero typed drafts for both native reports;
PNG yielded seven drafts, and image-only PDF yielded zero. The process receipts
show actual local native PDF geometry workers, trusted Swift helper compilation
and Apple Vision helper processes. The run failed at native `empty_review`
before any simulated confirmation or crash check. All import issue objects and
28-row raw field scores are retained; 229 individual field errors were recorded.
The fixture hashes remained unchanged. This attempt supplies a concrete layout
failure receipt, not an acceptance claim.

## Completed final installed-code exercise

`work/transport/run-03` is the final bounded receipt. The selected actual
production-chain test passed in 72.49 seconds. Its installed `layout.py` and
`records.py` bytes match the final stage code. `run-02` also passed, but its
installation preceded the final colon-only metadata alias safeguard; it is
retained as an intermediate code snapshot, not the final-code receipt.

The final native reports each yielded eight typed proposals: seven subject rows
and one printed control. The simulation rejected the controls, retained
unsupported/ambiguous rows as deferred, and never used oracle values to fill
them. A root source-model visual annotation of one image-only PDF row was
posted through actual `submit_visual` after the raw score. Its Latin/Cyrillic
method glyph uncertainty remains an unknown typed method. All its assertions
and approximate regions are root model proposals, not a blind evaluator or
human field review. The remaining raster source gaps remain unresolved.

Raw recognition still has 91 detailed field errors against the immutable
28-row denominator. Twenty rows match the expected analyte/result kind/raw,
reference, specimen, method and source locator fields; numeric Decimal checks
match 12 of 16 applicable rows. These field counts do not establish overall
recognition quality. The receipt explicitly reports control proposals and
unmatched proposals, and claims no overall recognition acceptance. PNG unknown
collection dates remain unknown rather than becoming the printed report date;
the oracle's `unknown` role versus the proposed `collected` role is separately
visible in the raw errors.

The synthetic confirmed branch retains 11 current revisions and one historic
revision from the deliberately injected edit, with ten deferred proposals.
Actual case selection contains the same 11 current synthetic revisions.
Two invented same-unit/date comparisons compute deltas `0.7` and `-1.2`;
the third refuses arithmetic for the differently printed `10⁹/л` and `10^9/л`
under the existing identical-raw-unit policy. No conversion or imputation is
silently introduced. The no-attestation branch separately verifies
`model_checked`/`none`, contextual history and an empty case selection.

Actual commit and correction tool ACKs were each received over stdio before an
owned process-group SIGKILL (recorded exit `-9`). Fresh stdio processes and CLI
replayed the identical requests and returned exactly the original ACKs.
Final history retained one correction lineage, without duplicate revisions.
The successful exercise is bounded A02/A23 transport and history evidence;
A01 source accuracy remains partial because the raw field gaps remain.

Final receipt map:

- `work/transport/run-03/acceptance-summary.json`: bounded status and counts.
- `work/transport/run-03/raw-recognition-score.json`: every frozen expected row,
  actual draft and field-specific error before reviews or model submission.
- `work/transport/run-03/documents.json`, `import-issues/`, `frozen-review/`:
  actual source imports, unresolved issues and frozen source-bound snapshots.
- `work/transport/run-03/cli/`, `mcp/`, `requests/`, `results/`: actual entrypoint
  commands, wire exchanges, errors, process ownership and exit receipts.
- `work/transport/run-03/ack-commit-replay.json` and
  `ack-correction-replay.json`: exact ACK equality after crash/restart.
- `work/transport/run-03/history-final.json`, `comparisons.json` and
  `case-selection.json`: saved revisions, source-specific values and selection.
- `work/transport/run-03/no-attestation-boundary.json`: actual weaker-assurance
  branch and explicit rejection of unconfirmed revision selection.
- `work/transport/run-03/isolation-provider-receipt.json`: installed-code,
  native helper and policy hashes; offline native parser limitations.
- `work/transport/run-03/pytest-result.json`: the selected test result.

## Invocation

Use a new output name on every recognition run; never reuse a runtime namespace:

```sh
HA_SYNTHETIC_CHAIN_OUTPUT="$PWD/work/transport/run-NEW" \
VIRTUAL_ENV=/path/to/health-evidence-workbench/.venv \
UV_CACHE_DIR="$PWD/work/uv-cache" PYTHONPATH="$PWD/src" \
PYTHONDONTWRITEBYTECODE=1 \
uv run --active --no-sync --offline python -B -m pytest -p no:cacheprovider \
  tests/v2/test_production_chain_transport.py
```

An optional `HA_SYNTHETIC_CHAIN_VISUAL_TEMPLATE` identifies a separately authored
synthetic source visual proposal under the stage's `work` directory. It must
declare `synthetic_only:true`, `golden_rows_used:false` and
an accurate `review_kind` (`root_model_visual_proposal` for a root annotation,
or `independent_model_visual_proposal` only when that independence exists).
The root's visual annotation is not a blind model evaluation. Its source text and normalized
anchors are submitted through actual `submit_visual` only after raw scoring;
the actual version/hash bindings are attached by the harness. Coverage remains
partial with an unknown source count. Such proposals stay separately labeled
`model_proposed`; the production backend makes no model call.

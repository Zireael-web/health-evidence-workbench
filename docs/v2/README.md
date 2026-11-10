# Health Analyzer v2: records and history increment

This parallel implementation adds a new, explicitly configured namespace. No
legacy stores, records, keys, clinical archives or active plugin registration
are migrated or replaced. A new deployment starts empty. Existing project code
continues to work through its existing entrypoints.

## Architecture

The core uses standard-library Python and SQLite, with optional existing MCP
and pypdf dependencies. There are two stdio processes and two marked stores:

| Component | Responsibility |
|---|---|
| `contracts.py` | One typed whole-row laboratory contract and source anchors |
| `records.py` | Reviews, immutable revisions, clinical/event history, comparisons and exports |
| `private_cases.py` | Exact selected-case graph, confirmation/correction lineage and separate current freshness |
| `private_calculations.py` / `private_answers.py` | Backend Decimal receipts and immutable private draft/review artifacts; no semantic or medical validation |
| `ingest.py` / `layout.py` | Bounded intake and source-bound native text/table proposals |
| `vision.py` | Disabled local OCR entrypoints and pure historical payload validation |
| `document_io.py` / `attachments.py` | Explicit selected-file intake, full transcripts and source-bound PDF/image views |
| `originals.py` | Separate immutable byte copies with subject scope and SHA-256 verification |
| `import_issues.py` | Append-only decisions about incomplete or ambiguous source rows |
| `common.py` | Canonical JSON, scoped immutable SQLite objects and domain HMAC |
| `configuration.py` | New namespace initialization, strict bindings and independent domain keys |
| `runtime.py` | Thin `private-data` and `public-research` stdio surfaces |
| `cli.py` / `entry.py` | Shared-service CLI, trusted bootstrap, policy and inactive deployment assets |
| `research.py` / `review.py` | Public evidence records and structural review with honest model attestations |

HMAC protects stored identity/payload integrity. It does not authenticate a
human or prove medical correctness. Source availability is a separate event
projection and never silently deletes confirmed history. The shared cloud
conversation is not made confidential from itself by naming a subagent.

## Three skills

- `health-records`: import, whole-row review, corrections, history and comparisons.
- `health-research`: public research and personalized explanation in the main
  conversation, with only a minimal deidentified question sent publicly.
- `health-review`: structural and substantive review as separate operations;
  independent model review for material/personal claims when required.

They are under `plugins/health-analyzer-v2/skills`. They are not an obligatory
chain and this increment does not automatically install/activate the plugin.
See [runtime setup](runtime.md) for optional registration and its gates.

## Whole-row records and history

A laboratory row preserves original analyte, tagged result, unit, clinical
time/role/precision, printed references, specimen/method/flags and anchors.
Numeric values use Decimal strings. Inequalities and qualitative/no-result
values remain their own types. Native extraction is a proposal, not acceptance.

Frozen previews show complete rows and source fragments. The main conversation
must display them before recording an actual user decision. Conversation
attestation contains the exact preview ID/hash and decision; the backend trusts
the orchestrator's attribution, not an invented human-authentication token.
No attestation leaves a model-only revision in contextual history. Caller
operator/migration assurance fields are rejected.

Corrections are new immutable revisions. Current accepted records and proposed
corrections are separate. Clinical time and `recorded_as_of` are distinct.
Duplicate/supersedes relations need an explicit decision and compatible unique
row matches; unresolved/ambiguous relations remain visible. A fresh commit checks
the exact saved original, when present. Archive drift is reported separately.
Older records without a saved original still check the current archive bytes.
An already accepted observation remains in history if its source becomes unavailable.

Comparisons return included/contextual/excluded rows and reasons. Current
implementation computes same-unit Decimal deltas only when analyte, specimen,
method, field certainty and clinical ordering support them. Censored values,
zero baselines, timezone ambiguity and two date-only draws on the same day do
not receive fabricated percentages. JSON exports include full lineage; CSV is
an explicitly incomplete table projection with formula escaping.

## Intake limits and capabilities

- `prepare_import` uses approved root IDs and relative paths. `prepare_attachment`
  accepts one explicitly selected absolute file without changing archive bindings.
  Neither intake follows source symlinks.
- Each file ≤64 MiB; batch ≤128 MiB and ≤100 explicit files.
- At most 1000 whole rows per extraction; review pages default25, maximum100.
  Hard limits reject the whole operation rather than silently truncate records.
- UTF-8 CSV/TXT with recognized explicit headers and delimiter; native PDF fixed
  columns and native PDF text geometry. Unknown
  layouts and unsupported cells remain issues needing visual review. Prior
  result columns remain source alternatives until their dates/units are verified.
- Native PDF text uses a resource-bounded worker and mandatory dedicated Seatbelt
  on macOS. The private runtime passes only bytes to a relay in the existing
  trusted bootstrap; the relay launches the fixed parser. macOS rejects stacked
  Seatbelt application, so this is a separate narrower parser sandbox. The
  relay has the bootstrap's host permissions, accepts no path/command/key
  parameters, makes no network calls and adds no permanent MCP process.
  A bridge failure never falls back to parsing without the mandatory profile.
  PNG/JPEG and scanned PDF pages require model transcription in the dialogue.
  Local OCR is disabled, including fallback and direct legacy OCR adapters.
  Native text and missing-page inventory remain on mixed PDFs. `submit_visual`
  supplies unverified whole-row model proposals without calling a model backend.
- Native-text previews have a shared256 KiB response budget with a visible
  truncation marker. Preview truncation and source extraction coverage differ.
- Store list queries are bounded at10000 objects per kind/subject. This is a
  first-increment capacity, not an unlimited archive indexing service.

## Originals and unresolved source rows

New imports preserve exact source bytes in `private/originals`, separated by
subject and content hash. Blob files are owner-only read-only; manifests are
immutable signed objects. Every read/commit verifies type, ownership, size and
SHA-256. A corrupt saved copy is not repaired from a changed archive path.
`get_source_version` shows saved-copy status and archive status separately.
No existing records receive automatic saved-copy backfills. A failed database
transaction may leave an unreferenced copy; intake never deletes source bytes.

`list_import_issues` paginates raw source text/cells, anchors, reason codes and
alternatives. Long source spans retain complete ordered linked fragments; a
coarsened anchor names a real source line range, not a fabricated precise cell.
`resolve_import_issue` records defer/discard/propose decisions and never confirms
an observation. Proposals must match the issue's source result cell or row and
the displayed extraction selection. Whole-page unresolved layouts use
`submit_visual`; one row cannot silently resolve the whole page.

The same saved input reuses recognition unless `force_reextract=true`. Extraction
selection is append-only, so an A→B→A sequence invalidates a preview made before
B. Whole-row human review remains necessary for accepted history. OCR confidence
is a recognition heuristic and does not validate clinical values or identities.

## Remaining work

This increment does not migrate legacy records, implement unit conversions,
guarantee handwritten/complex table recognition, or authenticate
local human presence. Public source access is model-attested; metadata-only
citations do not support substantive effects. Personal explanation/review is
model orchestration, not a hidden local medical-model service.

Public research defaults to `provider_unavailable`; a bounded PubMed adapter can
be explicitly configured, while native Codex public browsing can supply
honestly attributed inspected source records through the skills. The preparation
helper configures PubMed but does not verify live network access.
See [research contracts](research.md). Model quality evals and all final-release
criteria in the approved TЗ remain distinct from deterministic code tests.

Private drafts can now resolve exact selected source facts, user notes and
backend calculation receipts without sending them to public research. See
[private answer resolution](private-answer-resolution.md),
[calculation receipts](private-calculations.md) and
[private transport/recovery](a16-transport-recovery.md). The persisted structural
report remains `needs_revision`; substantive model/medical/human review is
separate. Existing snapshots and history are not rewritten or migrated.

An active rollout requires separately reviewed new configuration/bindings,
doctor gates, installed plugin checks and a pilot on explicitly selected new
documents. No deployment readiness follows merely from passing unit tests.

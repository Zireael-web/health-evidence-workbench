# Owned synthetic origin migration exercise

`health_analyzer.v2.migration` implements the A18 mechanism for the artificial
`health-analyzer.synthetic-legacy/1` schema. It does not read a real legacy schema,
real keys, production configurations or archives. It has no CLI/MCP/runtime
surface, implicit input, automatic deployment discovery, or production record
write. Passing these tests does not close release A18 or establish compatibility
with actual legacy contracts. Real inventory, migration, reconciliation and
cutover remain separate work requiring an authorized scope.

## Explicit API

```python
from health_analyzer.v2.exercise_scope import create_synthetic_exercise
from health_analyzer.v2.migration import (
    SyntheticLegacyFixture, SyntheticLegacyAdapter, OriginRegistry, CONTEXT_RULE,
)

# Parent exists; exercise itself must be new. Paths must stay inside this root.
create_synthetic_exercise(exercise_root)
source = SyntheticLegacyFixture.create(
    exercise_root, source_path, artificial_records, explicit_test_key,
    snapshot_id="synthetic-generation-1", store_id="synthetic-store-1",
)
snapshot = SyntheticLegacyAdapter(exercise_root, source, explicit_test_key).read()
registry = OriginRegistry(exercise_root, new_target_path, explicit_v2_test_key)
report = registry.import_snapshot(snapshot)  # preserved_only is the default
registry.reconcile(snapshot, run_id=report["run_id"])
registry.payload_bytes(snapshot.records[0].origin_id)  # exact original bytes
registry.close()
```

An artificial record is `{"legacy_id": str, "kind": str, "scope":
{"subject_id": str, ...}, "payload": bytes | dict}`. The factory canonicalizes a
caller-provided dict exactly once while creating the fixture; bytes supplied to
the factory are never canonicalized. The reader and registry preserve those
original payload bytes, exact legacy ID, kind, scope bytes, signature and key ID.
Unknown payload extensions, statuses, assurance and all old timestamps remain in
the exact raw payload. Migration audit timestamps occupy separate fields.

The `SourceSnapshot` object is an internal local adapter result, not an MCP or
CLI input schema and not a bearer credential. Registry import rereads its explicit
owned source and compares the result before writing; caller-supplied flags cannot
replace that read. This is an in-process trusted test harness boundary, not a
security boundary against callers that can alter code or possess the test keys.

The marker and owner/link checks prevent accidental use of ordinary paths. They
cannot prove that supplied data is fictitious, authenticate a human or defend
against a malicious process running as the same OS owner. The caller remains
responsible for supplying artificial data and keys. Nothing in a valid HMAC
establishes medical correctness or human review.

## Source and hash boundaries

The only physical source schema is created by `SyntheticLegacyFixture`: one
signed `synthetic_identity` row and bounded `synthetic_records` rows. The identity
binds the exercise ID, factory ID, snapshot/store IDs, logical schema, test key ID
and sealed declaration. The source must be a closed SQLite file in rollback
journal format, with no WAL, SHM or journal sidecar. A WAL header is rejected even
if its sidecars have disappeared. This adapter intentionally does not back up a
live source. It never opens a source with `immutable=1`, runs a checkpoint, invokes
a legacy constructor or changes legacy durability settings.

Reads use explicit `mode=ro`, `query_only=ON` and one read transaction. A bounded
main-file SHA-256 before and after reading detects changed sealed bytes. Its hash
scope is `sealed_sqlite_main_file_bytes_no_sidecars`, distinct from each record's
`raw_payload_sha256`. Backup of the newly created v2 registry uses the separate
synthetic recovery module, which reads committed WAL through SQLite's backup API.

The supplied test key verifies the fixture identity and each exact-byte row HMAC.
Unknown logical schema, wrong key, altered identity or altered row signatures
block ordinary import. With explicit `read(salvage=True)`, affected origins are
captured once and quarantined with exact bytes and failure reasons. Foreign
physical schema, another exercise identity, duplicate origin, resource overflow
or changed source fails the whole batch; no silent truncation or skip is returned.
Malformed JSON and duplicate JSON keys can be preserved in quarantine, without
claiming a trusted parsed representation.

## Immutable target and reconciliation

The target is an owned v2 `SignedStore` in `private-data`. Origins include source
snapshot ID, store ID, kind, full scope and exact legacy ID. Same origin with the
same exact bytes/bindings is idempotent; conflicting bytes/bindings cause an error
and rollback the entire batch. Different legacy IDs or scopes with equal values
remain distinct. A retry creates no extra capture, disposition or run.

Each origin has one immutable `legacy_records`, `legacy_mapping` and
`migration_disposition` entry. Original payload bytes use signed 1 MiB chunks so
a 2 MiB raw payload fits the v2 signed JSON object cap; chunk references belong to
one captured origin. `quarantine` references that existing origin rather than
counting a second source record. `migration_run` records the sealed source hash,
raw fixture identity bytes/signature, software/mapping version, origin set,
partition digest and reconciliation group references.

Reconciliation verifies exact source/captured/disposition set equality and the
complete disjoint partition `trusted_projected | preserved_only | quarantined`.
It checks source/captured counts and origin/payload digests grouped by subject,
store, kind and original status. It rejects extra/missing dispositions, duplicate
stored identity aliases, orphan projections, multiple projection links and
cross-subject links, including projections in otherwise unknown subject scopes.
The fixed context rule permits at most one projection per origin and requires its
exact deterministic origin/rule ID and mapping version. It compares exact raw bytes
and all captured bindings, not just aggregate counts. Explicit run reconciliation
and repeat import recompute every run field and verify the exact persisted group
set and payloads, including counts, original statuses and payload hashes; signed
but semantically altered run/group data fails. All registry records and group
reports are integrity checked by `SignedStore`.

Limits fail closed: source count 10,000, raw payload 2 MiB, scope 64 KiB,
aggregate raw payload plus scopes 64 MiB, source SQLite file 128 MiB and registry
inventory 100,000 objects/256 MiB signed JSON. The entire target import,
reconciliation and run commit is one transaction. A late failure leaves no partial
capture or acknowledgement. Success returns only after the outer commit.

## Conservative projections

Valid origins are `preserved_only` unless the caller explicitly selects the fixed
`legacy-context/1` rule with `projection_rules=[CONTEXT_RULE]`. That rule supports
only structurally valid `user_note` and `calculation` fixture kinds. The former
stays `user_note`; the latter becomes a synthetic `calculated` projection with
`measurement=false`. They retain their legacy payload/status/assurance without
invented clinical timestamps. `trusted_projected` means only fixture HMAC plus
rule-specific structural support; `human_validated=false`,
`medical_validated=false` and new `confirmation_assurance=none` remain explicit.

Raw field confirmations, rich observations, source facts, packets and scientific
claims receive no trusted projection from this adapter. It never creates
production observations or user confirmations. A legacy raw date/unit/reference
confirmation therefore cannot become a fully confirmed typed row. Invalid source
integrity always yields quarantine when salvage is selected. A new mapping rule
or repaired legacy status requires a separate future design; retry never upgrades
an existing immutable disposition.

## Evidence

`tests/v2/test_synthetic_migration.py` exercises exact noncanonical bytes, unknown
statuses/extensions and literal old dates; distinct IDs/scopes; HMAC/key/schema
failures; cross-subject payloads; full 2 MiB chunks; count/byte limits; duplicate
origins; retry and conflict; late transaction rollback; orphan/subject/partition
corruption; foreign physical schema; symlink/hardlink/out-of-scope paths; WAL
header/sidecars; ambiguous JSON; projection assurance tampering; multiple distinct
projection aliases; and re-signed run metadata/count/source-identity or referenced
group count/hash/status tampering, missing/extra groups and false-count retry. Only
artificial fixtures and explicit test keys are used. The local synthetic summary
lives under `work/migration/`; it contains no real legacy data.

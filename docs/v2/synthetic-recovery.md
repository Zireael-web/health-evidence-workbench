# Bounded synthetic recovery exercise

`health_analyzer.v2.recovery` implements a module-only mechanism for the owned
artificial part of A19/A23. It does not complete W6/W8, activate a runtime,
introduce backup/migration/cutover CLI or MCP tools, grant real private access,
or demonstrate real production recovery readiness. No real database, legacy
schema, credential, archive, deployment configuration or network is used.

This is a **plaintext synthetic exercise**. Keys are deliberately named
`TestKey` objects supplied by the fixture caller in memory, outside the bundle.
The bundle records key IDs and SHA-256 fingerprints, never raw keys. `material`
is excluded from `TestKey` repr. The SIGKILL test transmits its artificial key
through an inherited pipe descriptor; argv and environment contain no key
material. Real encrypted containers and recovery credential escrow are not
implemented or validated. Loss of the caller's test keys prevents recovery.

## Explicit API and path boundary

The caller creates a fresh exercise with
`exercise_scope.create_synthetic_exercise(root)`. The directory must remain
owned, mode `0700`, and contain its private scope marker. Every source,
destination, snapshot, sidecar and build path must be beneath that exercise.
Inputs must be owned regular files, mode `0600` or `0400`, with one hard link;
inner directories must be owned and `0700`. Outside paths, parent escapes,
symlinks, foreign owners and hard links are rejected before database access.
The marker does not prove caller data is fictitious or isolate a malicious
process running under the same OS identity.

```python
from health_analyzer.v2.exercise_scope import create_synthetic_exercise
from health_analyzer.v2.recovery import TestKey, SyntheticStore, SyntheticRecovery

# All arguments are explicit caller-created artificial fixtures.
create_synthetic_exercise(fresh_exercise_root)
key = TestKey("test_private", artificial_key_bytes)
recovery = SyntheticRecovery(fresh_exercise_root, test_keys={key.key_id: key})
stores = [SyntheticStore("private", artificial_v2_db, "private-data", key.key_id)]
manifest = recovery.create_backup(new_bundle, stores, source_generation="fixture_generation")
recovery.verify_bundle(new_bundle, expected_generation="fixture_generation")
restored = recovery.restore_bundle(new_bundle, new_empty_staging)
view = recovery.read_recovery_view(stores)
rollback = recovery.reconstruct_rollback(
    new_bundle, stores, another_new_staging, source_generation="after_cutover")
```

The example names are required caller parameters, not deployment defaults.
Production service-created stores are exercised only with artificial CSVs and
explicitly simulated conversation evidence. That evidence keeps its normal
`conversation_attested` attribution; it does not establish a real human
confirmation. The synthetic legacy origin registry's eight explicit schemas
are recognized as v2 objects; no real legacy source format is recognized.
Recovery checks those objects' HMAC, schema, immutable ID and envelope scope;
the origin registry owns its deeper origin/disposition reconciliation.

## WAL and generation evidence

Backup uses SQLite's backup API from a normal `mode=ro` source connection.
The read transaction verifies the exact supported v2 SQLite schema, identity
HMAC and every object's envelope HMAC, canonical payload, domain, subject and
supported schema. Typed row anchors, source hashes, revision chains, review
snapshots, decisions, original manifests and idempotent result references are
checked. Unknown schemas or object kinds fail closed. Snapshot inventories
are compared with the same source read transaction before publication.

No source PRAGMA, checkpoint, journal-mode change, repair, immutable object
read, archive operation or writer shutdown is performed by recovery. Only the
fresh owned destination is converted to a sealed SQLite main file. Reading an
active WAL source therefore includes its latest committed objects, including
the final acknowledged commit. Copying a main `.sqlite3` file alone would not
provide this guarantee and is not used.

A fully closed WAL-mode database may have no WAL/SHM files. SQLite's ordinary
read-only connection can create empty sidecars in this situation. Recovery
rejects it with `RECOVERY_DORMANT_WAL` before connecting. The fixture caller may
keep its own quiesced writer open, preserve a crash's existing WAL/SHM, or
explicitly seal its own artificial store with `journal_mode=DELETE` before
closing. Recovery never performs that source operation.

Main, WAL and rollback-journal file presence, byte lengths and SHA-256 hashes
are compared before/after the entire source set. SQLite's shared-memory lock
file is path-validated but its transient lock bytes are not part of durable
data evidence. Changes in source bytes prevent publication.

The manifest binds the explicit caller generation label, exercise ID,
code/schema versions, store domains, key fingerprints, source byte hashes,
object counts by kind, per-object envelope hashes and MACs, complete inventory
hash and latest event objects. The committed watermark is the last immutable
object's SQLite `rowid`: an insertion-order witness, **not** a SQLite LSN or a
cross-store transaction ID. v2 has no separate persistent commit LSN, and the
module does not claim one.

Multiple domains require `synthetic_quiesced=True`, an explicit assertion that
the caller has stopped its own artificial fixture writers. Separate SQLite
backups do not constitute one cross-store atomic transaction. The manifest
states this explicitly. All stores and paths are preflighted, and aggregate
limits apply to the full source set, object inventory and bundle. Defaults are
8 stores, 10,000 objects and 64 MiB; callers may lower these caps. No cap
failure returns a partial successful inventory or restore.

## Publication, restore and rollback

Destination names must be absent; existing directories or databases are never
replaced, including empty directories. Snapshots are constructed and verified
in a new private build directory. Publication reserves the destination with
exclusive `mkdir`, moves verified snapshots and publishes the fsynced complete
manifest last. This is atomic publication of bundle validity, not an atomic
directory rename. An interruption can leave a private incomplete directory;
it has no accepted publication manifest, fails verification and cannot be
restored. Recovery does not erase or reuse it automatically.

Restore first authenticates the complete canonical manifest under all bound
test keys, then verifies filenames, all snapshot byte hashes, exact supported
SQLite schema, every object HMAC and scope, counts, immutable inventory and
committed watermark. It uses fresh owned staging paths only. No arbitrary
unarchive path is accepted and foreign databases are never initialized.
Tampered, truncated, incomplete, wrong-exercise, wrong-domain, wrong-key,
unknown-code or unknown-schema bundles fail closed before a successful target
is published. A corrupt second store cannot publish a successful first store.

Rollback offers a verified read-only recovery view of the current data, then
creates a new staging reconstruction. Every old base object must still exist
with the same immutable ID, payload, scope, MAC and insertion position. The
base inventory must be an exact prefix of the current complete inventory.
Deleted old objects and conflicting IDs fail; neither is excused as a delta.
After this proof, the base-plus-current-object union equals the current
verified snapshot. Reconstructing that snapshot preserves every payload,
status, source link, timestamp, correction, context event and stored retry
result exactly, while avoiding unrelated duplicates.

The report's `read_only_rollback_reconstruction` describes the recovery mode;
it does not activate old code or an inadequate legacy writer and is not an OS
write-protection claim. A corrected compatible v2 fixture writer can later
open the new staging explicitly. Unknown schema/code fails and keeps the
current source available through compatible read-only recovery. An old backup
is never overlaid on a newer store; no lossy reverse import is performed.

Original bytes are **not included**. Signed source links/manifests are preserved
and checked against document versions, but physical-original availability is
not validated by backup/restore. Tests that inspect saved synthetic originals
supply their still-present fixture path explicitly. Neither that existing
fixture nor a previously recorded availability event proves physical-source
recovery from the bundle.

## Verified synthetic evidence

`tests/v2/test_synthetic_recovery.py` executes a real subprocess using production
`ImportService` and `RecordsService`. After a base backup it imports an owned
artificial CSV, acknowledges a new typed acceptance, acknowledges a correction,
records a context event and sends its successful response while WAL is open.
The parent forcibly sends SIGKILL, verifies the process exit signal, and reads
and backs up the still-committed WAL without a writable source reopen.

Restore and rollback retain the exact accepted revision, corrected revision,
source anchors, recorded timestamps, status and context event. A new staging
fixture writer repeats both acceptance and correction with their original
idempotency keys and receives the **same complete result and event/revision
IDs**, with exactly two total review events and one correction event. The
base history remains present; the post-cutover record remains a distinct
collection and creates no unrelated duplicate. Source main/WAL/journal hashes
and presence remain unchanged throughout recovery.

Additional tests cover unsafe paths before any SQLite open, hard links and
sidecar symlinks, foreign schema/journal bytes, unknown object/code schema,
key mismatch, manifest/object tampering, truncation, incomplete publication,
multi-domain quiescence, aggregate count/byte caps, corrupt second domain,
destination conflicts, missing base objects, conflicting same IDs, bad subject
scope, bad typed source links, dormant WAL rejection and a concurrent artificial
fixture writer invalidating publication. Test failures do not produce a
successful partial restore.

Run only this bounded suite with the existing offline test environment:

```sh
VIRTUAL_ENV=/path/to/health-evidence-workbench/.venv \
UV_CACHE_DIR=work/uv-cache PYTHONPATH=src \
uv run --active --no-sync --offline python -B -m pytest tests/v2/test_synthetic_recovery.py
```

This evidence validates the module's owned synthetic mechanism. It does not
establish production A19/A23 acceptance, encrypted recovery, credential escrow,
real original availability, real clinical correctness or a deployment cutover.

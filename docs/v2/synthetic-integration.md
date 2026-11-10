# Synthetic migration and recovery integration

This bounded exercise adds module-only primitives for artificial A18/A19/A23
checks. It adds no CLI, MCP, runtime, configuration, credential or archive
binding. Exactly three user skills and the existing public/private runtime
surfaces remain unchanged.

`test_synthetic_migration_recovery_integration.py` uses five fictional origins
across two fictional subjects, including exact noncanonical raw payloads,
unknown legacy status/assurance, optional note/calculation projections and a
deliberately corrupted test signature. Both preservation-only and explicit
context-projection modes run through the real origin registry, WAL-aware
backup, restore and rollback reconstruction.

After the base snapshot, real ImportService/RecordsService code accepts an
artificial CSV row under a clearly simulated conversation attestation, creates
an immutable correction and records a separate subject context event. Both
restore and rollback must preserve the exact origin inventory, complete
disjoint dispositions, payload bytes, source bindings, current/historical
typed records and context event. Deeper OriginRegistry reconciliation is
rerun against the unchanged owned fixture. Original acceptance and correction
requests must return the identical stored response, without duplicate events.

The recovery suite separately executes a real subprocess and SIGKILL after
its acknowledged synthetic writes. The independent suite compares that
committed WAL inventory with a sealed main-file-only copy to establish why
copying the main file is inadequate. None of these tests is a real patient
decision, actual legacy compatibility test or clinical validation.

Recovery bundles are plaintext synthetic fixtures; explicit test keys remain
outside them. Original bytes are excluded. Physical original recovery,
encrypted bundles, credential custody, real source preflight, production
quiescence, deployment cutover and actual migration remain unimplemented or
unverified. See synthetic-migration.md and synthetic-recovery.md for the
specific path, generation, schema and publication limits.

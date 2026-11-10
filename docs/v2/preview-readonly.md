# Reading a saved frozen preview

`RecordsService.get_review_snapshot(subject_id, snapshot_id)` reads an existing
signed review snapshot. It returns `snapshot` unchanged and a separate
`verification` object: method `signed_store_hmac`, UTC `checked_at`, `state`
(`current` or `stale`), stable `reasons`, the frozen `snapshot_sha256`,
`source_bytes_checked: false`, and `clinical_validation: not_provided`.

The HMAC, canonical snapshot digest, subject, source version, extraction and
immutable draft rows are checked before returning the preview. One consistent
SQLite read transaction compares the current extraction/run selection,
displayed-row review tokens and observation revision tokens. An A→B→A selection
still makes an older preview stale. A stale preview remains readable for
inspection; use a newly prepared preview for any later decision.

State freshness does not validate source pixels, source bytes, medical meaning,
or a human decision. Source-byte availability/integrity is a separate
`get_source_version` check. Snapshot reading never calls the source checker,
creates a preview, writes a review decision, or updates availability events.

`SignedStore(..., readonly=True)` requires an existing regular v2 database. It
does not provision a missing store or migrate a foreign database. An immutable
identity-only preflight prevents accidental recovery of a foreign hot journal.
Objects use normal SQLite `mode=ro`, not `immutable=1`, so acknowledged committed
WAL rows remain visible. Read transactions use `BEGIN`; object writes raise
`STORE_READ_ONLY`. The connection sets `query_only` and does not set writing
journal/synchronous PRAGMAs or request a checkpoint. Closing it leaves database
and existing WAL bytes unchanged. Normal SQLite read locking may use its SHM
sidecar; no SQLite durability guarantee is inferred from a copied main DB alone.

The private runtime exposes `get_review_snapshot`. The public runtime exposes
neither snapshot nor source-version reads. `open_services(..., readonly=True)`
permits only the two private tools `get_review_snapshot` and `get_source_version`.
Existing default MCP runtime behavior is preserved.

The existing CLI `call --zone private-data --tool get_review_snapshot` (or
`get_source_version`) automatically opens that limited read-only service. It is
not a read-only `serve` mode. Arguments still come from a bounded JSON file;
the trusted bootstrap reads only the selected new deployment key and passes it
through an anonymous FD. Readonly enforced launch writes the policy into
only a fresh temporary directory, removed after the call. The policy
uses the same reviewed permission grants. Existing bootstrap profiles/native
artifacts and configuration are not written, and readonly calls neither accept
nor start a PDF bridge. Every other enforced private operation still requires
its existing mandatory bridge. This grants no new host access, changes no key
modes, and performs no plugin install or manifest migration.

These capabilities are tested with synthetic deployments only. They do not
authorize reading any real source, old key/store, production archive binding,
or accepting any real row.

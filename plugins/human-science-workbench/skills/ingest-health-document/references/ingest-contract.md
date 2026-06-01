# Private ingest contract

## Receipt-backed fields in the current generic path

- identity: server-generated `observation_id`, opaque server-derived
  `subject_id`, confirmed display/field name;
- source value: exact confirmed `raw_value`;
- provenance: source ID, SHA-256, and available page/region/line/table locator;
- review: `verified` status plus receipt-level reviewer label and note.

The schema can represent original unit, comparator, specimen, method, device,
observed time, reference intervals, codes, and optional normalized value. The
generic candidate/receipt path does not automatically split or associate those
fields. Preserve them as exact source candidates and limitations until a
reviewed receipt-bound extension exists; never infer them from nearby layout.

Each configured private root is exactly one subject. The server derives the
subject from the opaque `root_id`; subdirectories do not create patient scopes.
Review receipts are HMAC integrity bindings stored in plaintext SQLite.
`reviewer_id` is an audit label, not authentication or proof of human presence.

`build_case_packet` uses a separate case-integrity key under
`state/handoff/keys/` to HMAC-bind packet kind, packet ID, and canonical payload
hash in the handoff database. The key is outside that SQLite database and is
not the review-receipt key. The binding is tamper detection under key secrecy,
not encryption, a signature, remote attestation, or same-account isolation.

## Archive discovery and longitudinal views

`list_private_archives` exposes configured roots only as opaque `root_id` and
derived `subject_id` pairs. `sync_private_archive` discovers files server-side;
callers do not supply names or relative paths. It records a keyed processing
receipt bound to root, subject, opaque source ID, artifact SHA-256, extractor
profile SHA-256, media type, timestamp, and bounded summary. An unchanged file
under the same profile is skipped. Any invalid processing-receipt binding is a
hard integrity failure. The first page publishes an immutable vault snapshot;
its opaque continuation cursor HMAC-binds the snapshot/offset plus the initial
capability profile and reprocessing policy. Omitted continuation options are
recovered from that cursor, while an explicit mismatch fails closed.

Archive synchronization registers extracted candidates but does not verify
them. Its document status reports occurrence-aware unreviewed, verified, and
rejected counts. `list_extraction_candidates` is the exact private review queue
and keeps independently reviewed source/profile occurrences distinct inside
`review_occurrences`. A content-addressed candidate with top-level `mixed`
state has both reviewed and unreviewed occurrences, appears in both filters,
and must never be treated as one globally reviewed fact. Its top-level receipt
list is aggregate metadata; downstream selection must use the receipt on the
exact chosen occurrence.
`list_verified_health_records` returns only HMAC-verified review receipts and
user-note receipts. Its chronology is receipt chronology, not inferred
specimen/event chronology. Roots remain separate in every view.

## Source-version batch review

`preview_document_review` is the only source for a document review snapshot.
The private server derives the subject and binds the snapshot HMAC to one root,
source, and source version, including the artifact and processing-profile
digests, ordered candidate IDs, exact candidate payload/provenance, review
state, findings, and limitations. Snapshot creation is an append to the private
review store, not a fact-verification step; it changes neither the immutable
source nor the verified ledger. A snapshot contains at most 100 candidates.
The operator-facing Codex UI must display every returned row; display aliases
such as `R01` are not ledger identifiers.

After explicit human confirmation, `commit_document_review` accepts the exact
returned batch ID, matching root/source/artifact/profile scope, reviewer audit
label, and row decisions. The batch ID plus canonical request is the
idempotency contract. Supported decisions are exact acceptance, correction,
and rejection. Correction preserves the immutable original and stores the
confirmed correction plus reason separately. Rejection is durable, emits no
verified record, and is excluded from `build_case_packet` inputs.

An accept-all default applies only to clean `extracted` rows without findings
or limitations. `needs_review`, OCR/model-vision text, inferred CSV/header/table
association, any limited candidate, and instruction-like content require an
explicit decision. Confidence can order or sample review work but cannot prove
accuracy. A missing critical field is checked independently of the confidence
of fields that were extracted.

The commit has transaction, not non-atomic batch, semantics. Before any write,
the server verifies snapshot HMAC and exact current membership/state, then
rejects mixed root/subject/source/version, unknown or undisplayed candidates,
stale snapshots, incomplete required decisions, and conflicting replays of the
same batch. Any failure leaves every row unchanged. An exact replay returns the
original result.

These contracts are informed by, but do not implement, FHIR R4 4.0.1. A
document/report maps conceptually to
[`DocumentReference`](https://hl7.org/fhir/R4/documentreference.html) and
[`DiagnosticReport`](https://hl7.org/fhir/R4/diagnosticreport.html), separately
interpretable result rows to
[`Observation`](https://hl7.org/fhir/R4/observation.html), and review/version
events to [`Provenance`](https://hl7.org/fhir/R4/provenance.html). The local
atomic rule follows FHIR transaction rather than batch semantics
([FHIR REST](https://hl7.org/fhir/R4/http.html#transaction)). No local object is
therefore a conformant FHIR resource. Domain assembly of laboratory rows and
radiology findings remains a separate, future source-bound layer.

## Codex visual review

The `private-ingest` role may read the source archive directly but read-only and
without network access. Use Codex `view_image` for local photographs. Render a
PDF locally to temporary PNG pages before visual inspection when scans, graphs,
tables, handwriting, or layout matter. This uses model vision rather than a
separate OCR service.

A visually transcribed value is still `needs_review`: record the source
SHA-256, image or PDF page, region when available, exact visible wording, and
ambiguity. It is not automatically present in the extraction ledger and must
not be described as receipt-backed or included in a `CasePacket` unless a
source-bound review extension has registered and confirmed it. Delete temporary
renders after review; never alter the archive original.

## External attachment intake

The private MCP accepts only an allowlisted `root_id` and an in-root relative
path; it does not upload or stage arbitrary attachments. A Full Access root
Codex task may perform a preceding local-only intake when the operator
explicitly requests adding the named file to an unambiguously selected
single-subject root. Existing archive files remain immutable. The intake must
hash the regular non-symlink source, create a new destination exclusively and
atomically, preserve the source, reject overwrite, and verify the copied
SHA-256 before calling private ingestion. This exception never grants archive
write access to `private-ingest` or the private MCP.

## User-note receipt

Use `record_user_note` only for explicitly confirmed context that is absent from
the source document. It derives the same root-bound subject and HMAC-binds the
exact text, root/subject, caller-supplied `recorder_id`, timestamp, provenance
marker, and emitted `user_note` statement. It cannot become `source_fact`.
`recorder_id` is audit text, not authentication; the note is plaintext in
SQLite. Include its `note_rcpt_...` ID in `build_case_packet` alongside source
receipts when relevant.

## Verification status

| Status | Meaning |
| --- | --- |
| `extracted` | parser output, not yet reviewed |
| `needs_review` | ambiguity or possible mismatch is known |
| `verified` | reconciled with the immutable source |
| `rejected` | extraction was incorrect and must not be used |

## Hard caps

| Stage | Default |
| --- | --- |
| CSV | 16 MiB input; 20,000 rows; 256 columns; 32 KiB per UTF-8 cell; 1,000,000 cells after rectangular padding |
| candidates | 20,000; 64 KiB per raw-value-plus-field; 16 MiB cumulative |
| archive | 20,000 files; 4 GiB tree; 64 MiB per file; 500 files per synchronization call |
| private review/history page | 100 candidates or records |
| archive processing summary | 64 KiB canonical JSON per source/profile receipt |
| document review snapshot | 100 fully displayed candidates; accept-all never reaches outside it |
| `build_case_packet` input | 100 unique receipt IDs |
| reviewed record batch | 8 MiB canonical JSON |

CSV/candidate violations return no blocks or candidates and create no cache
entry. Receipt-count or reviewed-batch violations issue no `CasePacket`.
Optional profiles cannot relax these failures.

## Fail-closed conditions

- source hash is unavailable or changes during processing;
- a CSV, candidate, receipt-count, or reviewed-batch hard cap is exceeded;
- result cannot be tied to a page/region or exact text span;
- unit, comparator, date, or table column cannot be resolved;
- private-zone processing is unavailable;
- a required step would use a networked service.

The packet may record limitations instead of forcing completeness. Missing is
preferable to plausible-looking fabrication.

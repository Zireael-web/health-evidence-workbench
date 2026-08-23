# Type-independent ingestion and optional domain profiles

The workbench does not implement one parser per laboratory test or examination.
Every supported source passes the same three layers:

1. **Artifact layer** — bytes read from an allowlisted source, detected media
   type, SHA-256, size, and extraction limitations. The source remains in place.
2. **Extraction layer** — ordered text/table/image blocks with extractor version
   and page/line/table provenance where the provider supplies it.
3. **Candidate/review layer** — generic `key: value`, table-cell, or narrative
   candidates that retain exact source text and provenance until review.

This makes medical *type* independent from ingestion. A new analyte, report
title, vendor, or examination does not require a dedicated parser when its
bytes are already extractable by the text, CSV, or native-text PDF provider. It
does not make every file format automatically parseable: an unsupported binary
format needs another generic provider. An image or image-only PDF still
produces an `ocr_required` deterministic-pipeline limitation, but the private
Codex agent can inspect local images and rendered PDF pages directly. Its
transcription remains unverified until source-bound review.
On macOS the native-PDF subprocess is additionally confined by a mandatory
nested Seatbelt; without it extraction fails closed. Non-macOS has only the
resource-limited subprocess, not equivalent built-in OS isolation.

## What the generic path currently records

For a reviewed field candidate, the receipt-backed MVP emits an observation
with the server-derived subject ID, confirmed display/field label, exact raw
value, verification status, and source locator. For a reviewed narrative
candidate it emits an exact `source_fact` statement. CSV header associations
are inferred candidates and must be confirmed together with the exact value.
Context absent from the document can enter through `record_user_note`, which
creates a separate HMAC-bound `user_note` statement tied to the root-derived
subject. It is never treated as extracted source content.

The `Observation` schema also has fields for unit, comparator, specimen,
method/device, time, reference intervals, codes, and normalized values. Their
presence in the schema is not automatic extraction. Generic candidate building
does not semantically split or associate those concepts; they remain in source
text/cells unless an explicit reviewed extension safely binds them. Do not claim
that a rich field was populated merely because the same document mentions it.

Unknown fields stay as raw candidates with `needs_review`; the system does not
guess a medical code, unit conversion, reference population, or interpretation.
The HMAC receipt binds a candidate and its emitted minimal record. It does not
authenticate the reviewer or encrypt the SQLite ledger.

The generic path is bounded independently of medical type. CSV structure and
bytes, candidate count/bytes, receipt count, and reviewed CasePacket batch bytes
have fixed defaults documented in `docs/operations.md`. Exceeding any hard cap
produces no partial extraction or packet; a domain profile cannot relax that
failure behavior.

Archive-wide ingestion does not add type-specific dispatch. The private server
walks an opaque single-subject root, applies this same generic pipeline to each
supported file, records a keyed source/profile processing receipt, and skips
unchanged files on later runs. Extracted candidates remain a review queue;
only exact human-reviewed receipts appear in the longitudinal verified view.

After review, `build_case_packet` issues the generic packet through the same
type-independent handoff. A separate case-integrity key under
`state/handoff/keys/` HMAC-binds packet kind, ID, and canonical payload hash;
the key is outside the handoff SQLite database and is distinct from the review
receipt key. This protects integrity only while the key remains secret and does
not create encryption, a signature, or a hard same-account boundary.

## When a domain profile is justified

A profile is an optional validator/calculator, not an ingestion dependency. Add
one only when an external standard defines domain-specific computation or
adequacy rules that cannot be represented safely by generic thresholds. For
example, ABPM may have guideline-specific minimum awake/asleep measurement
counts and a defined dipping calculation.

The MVP exposes deterministic normalization and ABPM adequacy helpers, but
their output is not automatically appended to the receipt-backed `CasePacket`.
`calculated` is a contract category, not a current automatic review-receipt
path. A future calculated-statement extension must preserve its input support
IDs, formula/rule version, units, assumptions, applicability, and limitations;
it must not overwrite the report's source conclusion.

`normalize_lab_observation` accepts an allowlisted `root_id`, never a
caller-selected `subject_id`; the private server derives the keyed pseudonym.
Its source ID, digest, and locator remain caller-supplied provenance, not a
vault lookup or source-authenticity proof. The response therefore explicitly
marks itself `unverified`, `receipt_backed=false`,
`vault_source_authenticity_verified=false`, and
`case_packet_eligible=false`. It accepts chronology only as an ISO 8601 date or
a timezone-aware date-time and keeps separately supplied source wording in
`observed_at_raw`. Threshold bounds must be finite, bounded `Decimal` values.
LOINC candidates bind the pinned catalog and full entry snapshot (axes,
aliases, display, code, and version); code/version equality alone cannot be
confirmed.

`assess_abpm_adequacy` is a read-only, unverified, non-receipt-backed
calculation and cannot enter a `CasePacket` automatically. Supplying only
`monitor_removed_at` never creates a `source_fact`. A report assertion requires
the explicit `monitor_removal_kind=source_fact`, exact assertion text containing
the same `HH:MM`, and report source ID/SHA-256 provenance; that provenance is
still caller supplied and does not authenticate report bytes. An
operator-reported removal requires `monitor_removal_kind=user_note`, the same
single-subject `root_id`, and a `note_rcpt_...` produced by `record_user_note`.
The ledger must verify that receipt's HMAC/root/subject binding, exact note text,
and the presence of the supplied `HH:MM` in that text. The verified note can
constrain the calculation as `user_note`; the calculation itself remains
unverified and ineligible for automatic packet inclusion.

Each profile must declare:

- stable profile/rule version;
- authoritative public source and applicable date/jurisdiction;
- required input fields and unit constraints;
- explicit insufficient/unknown behavior;
- generated statement kind `calculated` or `inference`;
- tests for missing, conflicting, and boundary data;
- how its result becomes reviewable and receipt-bound, if it may enter a
  `CasePacket`.

Do not create profiles merely to recognize a report title, vendor layout, or a
new analyte. Those belong in generic extraction configuration or terminology
mapping and must not fork the privacy workflow.

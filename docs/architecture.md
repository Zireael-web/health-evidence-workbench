# Architecture and trust model

## Data flow

```text
immutable source archive
        |
        v
PRIVATE_INGEST (network off, one configured root = one subject)
        | HMAC-bound, issued minimal CasePacket
        v
OFFLINE_SYNTHESIS (network off, no raw archive)
        ^
        | HMAC-bound EvidencePacket 1.3 with reviewed study/guidance claims
PUBLIC_RESEARCH metadata discovery (network allowed, no archive access)
        |
        v
SOURCE_REVIEW (fresh de-identified task, live WebSearch, no claim issuance)
        |
        v
PUBLIC_RESEARCH reviewed-claim issuance
        | issued EvidencePacket ID
        v
AUDIT (read-only, network off, public handoff only)

OFFLINE_SYNTHESIS / AUDIT -> REVIEW_EXPORT
                               (logical operator stage, not a runtime zone)
```

The four MCP processes are the implemented runtime boundaries. macOS Seatbelt
wrappers give private, synthesis, and audit no network, while public can use
outbound network but cannot read configured archives or private/synthesis
state. Audit has no writable state and can read only the issued public handoff
plus its evidence-integrity key. The public Python clients additionally
restrict requests and redirects to their allowlisted metadata hosts. Seatbelt
itself permits general outbound traffic in the public process; the host
allowlist is therefore an application control, not a kernel-level destination
allowlist.

Private, synthesis, and audit MCP entry points accept stdio only; every shipped
wrapper pins stdio, including public. Within the project, `hsw-isolated` grants
shell reads only to explicit runtime/code/docs/test/config paths, not the
project root, and explicitly denies private/input/output roots, `state`, `.env`,
and `.git`. The Codex Desktop parent and `private-ingest` use
`hsw-private-vision`: read-only archive, temporary local PDF renders, and no
shell network. Codex reapplies that live parent mode to subagents, so the
single-task workflow does not claim filesystem isolation between roles. Its
Codex vision is the visual data plane; the private MCP remains the
structured/receipt data plane.

Zone wrappers start from an empty environment, use zone-local temp/cache
directories, and pass only the variables needed by that zone. Project custom
agents narrow their MCP tools and host capabilities. Prompts, hooks, agent names,
and the `REVIEW_EXPORT` enum are policy aids, not security boundaries.
Each custom agent explicitly disables the plugin-provided full public MCP and
uses its own zone-scoped MCP allowlist; public agents may still retain the
plugin's reviewed skills and DLP hook.

## Orchestration is not strict isolation

A root Codex task running in this repository is not automatically assigned one
of the custom-agent permission profiles. It may coordinate subagents and receive
their outputs in shared task context. Private MCP tool responses, including
extracted text and candidates, are visible to the Codex model environment that
invoked them. Running all roles as subagents of one task therefore does not
provide strict information-flow isolation, even though their MCP child
processes have different OS restrictions.

For a strict deployment, run private, public, synthesis, and audit as separate
user-owned tasks/processes and preferably separate OS identities or containers;
keep export review as an explicit operator action. Transfer only reviewed,
minimal, de-identified packets through an authenticated handoff. The local MVP
uses separate append-only SQLite handoff stores: private
and public issue their packet types, while synthesis opens both stores read-only
and exposes `load_synthesis_packets` for one issued ID of each kind before
drafting; it never accepts caller-supplied packet JSON. Audit opens only
the public handoff read-only. Every canonical payload is bound to its packet ID,
kind, and payload SHA-256 with a packet-kind-specific HMAC key stored under
`state/handoff/keys/`, outside SQLite. Issuer wrappers bootstrap their own key;
synthesis validates both keys and audit validates the evidence key before
startup. This detects database tampering while the relevant key remains secret,
but supplies no encryption, digital signature, remote attestation, or hard
tenant boundary. A same-OS-account process that can bypass the wrappers and read
the keys is outside this integrity model.

Public update monitoring reads a prior issued packet through
`load_public_evidence_baseline`. The tool accepts one exact EvidencePacket ID,
verifies the handoff HMAC/canonical binding, and applies whole-payload
bounds/direct checks plus scoped semantic checks before returning the canonical
comparison-only baseline. Expired guidance carries typed stale status and must
be rechecked/reissued before current support. It accepts no caller-authored
packet JSON; ordinary synthesis/audit/current-support loaders remain fail-closed.

The project `audit-review` role now has a dedicated read-only, no-network audit
MCP server for public-only claims. `load_audit_evidence_packet` exposes one
HMAC/canonical-verified issued packet by exact ID after whole-payload bounds and
direct-identifier checks; strict semantic checks cover only its question,
reviewed-claim prose/provenance/limitations, and packet limitations, not
bibliographic metadata. `audit_public_claims` performs the structural audit.
Neither tool retrieves, writes packets, or accepts replacement packet JSON.
Complete case-plus-evidence bundle audits run in synthesis. `REVIEW_EXPORT` is
still only a logical workflow state:
there is no export approval service, authenticated reviewer session, or
publication gate. An operator remains responsible for the final export.

## Contracts and current representation

- `CasePacket`: opaque server-derived subject ID, reviewed observations/source
  statements, source hashes, limitations, and provenance locators. The generic
  receipt path currently emits an observation's display label, exact raw value,
  verification state, and provenance, or an exact `source_fact` statement. The
  schema can represent units, comparators, reference intervals, specimen,
  method, device, and calculated statements, but generic extraction does not
  automatically parse or associate those fields. A separate `record_user_note`
  path HMAC-binds an explicitly supplied note as `user_note`; it never promotes
  it to `source_fact`. `build_case_packet` accepts at most 100 receipt IDs and
  rejects a canonical reviewed-record batch above 8 MiB. Its packet ID binds
  the complete canonical packet payload (including record contents,
  limitations, creation time, and schema version); handoff issuance verifies
  that binding again. Receipt-order differences are canonicalized before ID
  derivation.
- Private document-review contracts: `preview_document_review` persists an
  HMAC-bound snapshot for one root, server-derived subject, source, and source
  version. The binding covers the artifact and processing profile, ordered
  candidate identities, exact displayed values and provenance, current review
  state, limitations, and findings. `commit_document_review` accepts only that
  batch ID and its matching source/artifact/profile scope. The batch ID plus
  canonical request is the idempotency contract. It applies explicit `accept`, `edit`, and
  `reject` decisions plus an optional safe-row accept-all default in one SQLite
  transaction. An edit retains the exact original and stores the reviewed
  correction separately; a rejection is durable and can never be selected for
  a `CasePacket`. A changed candidate set or state, mismatched root, subject,
  source/version, unknown or undisplayed row, invalid HMAC, or conflicting
  replay of the same batch aborts the whole commit. An exact retry returns the prior
  result.
- Archive pagination publishes an immutable Vault snapshot and wraps its
  subject/snapshot/offset cursor in a second HMAC binding that also fixes the
  extraction capabilities/profile and reprocessing policy. A continuation can
  therefore inherit those options safely, while cross-snapshot or changed-policy
  reuse fails closed. Synchronization reports review state per exact
  source/profile occurrence rather than treating a content-addressed candidate
  as globally reviewed.
- `EgressCasePacket` schema 1.0: a local preview derived only from an issued
  `CasePacket` ID. Every invocation replaces packet, subject, observation, and
  statement identifiers with fresh packet-local references; drops provenance,
  source hashes, paths, facilities, locations, and exact calendar dates; and
  expresses supported observation dates only as days relative to the latest
  observation. Its canonical JSON hash covers the exact proposed outbound
  `payload`; the accompanying redaction summary contains categories and counts,
  never removed values. Construction performs no send, network, or persistence
  action and still requires visual review for identifiers missed by heuristics.
- `EvidencePacket` schema 1.3: a de-identified question, bibliographic
  `EvidenceItem` records, and a separate `reviewed_claims` array.
  PubMed/Crossref items are metadata snapshots, not article content, and their
  IDs cannot support substantive claims. Each search returns an HMAC-bound
  retrieval receipt for the exact
  server query, its exact credential-free execution descriptor, and ordered
  metadata results. The descriptor records the endpoint, method, effective
  server parameters, and client version while explicitly omitting credential
  parameters. For PubMed it binds the ESearch request and ESummary v2 request,
  including whether ESummary ran, its ordered IDs, joined `id`, and `version`.
  A study finding, effect, or harm requires source inspection
  outside the bundled metadata client, register an exact candidate with source
  document hash, locator, and excerpt, and exactly confirm it through
  `review_evidence_claim_candidate`. Exact separate-review confirmation includes the
  question, retrieval receipt as source root, semantic `EvidenceItem` snapshot, claim
  fields, provenance, and limitations. The semantic snapshot contains every
  item field except the local `retrieved_at` timestamp. `store_evidence` accepts
  retrieval receipts plus optional `evidence_claim_receipt_ids`, verifies their
  question, source item snapshot, and retrieval binding, and emits the verified
  claims in `reviewed_claims`. It does not retrieve the source or record a
  complete screening/exclusion log. Guidance uses a distinct mandatory path:
  `plan_guidance_discovery`, live source review, lazy snapshot import when the
  risk path requires it, `resolve_guidance`, `register_guidance_claim_candidate` for every selected
  effective recommendation, exact separate `review_guidance_claim_candidate`
  confirmation of its question, recommendation/source root, semantic snapshot
  (excluding only `retrieved_at`), wording, provenance, native grade, and
  limitations, then `store_guidance_evidence` with both `recommendation_ids` and the exactly
  covering `evidence_claim_receipt_ids`. Registry HMAC verification is local
  integrity only and never substitutes for that review. Every issued CasePacket
  or EvidencePacket is capped at 8 MiB of canonical JSON at the handoff boundary.
  One explicit `risk_level` is bound unchanged across discovery, audited import,
  candidate registration, and packet storage. Registration and storage expose
  no default, so omission or silent downgrade is a schema error.
  Every public, synthesis, and audit handoff read rechecks the typed
  `source_review_valid_until` against the trusted current clock. Expired
  guidance packets fail closed and must be rechecked/reissued. Clinical-action
  issuance is blocked until a typed clinician-confirmation receipt exists.
  The runtime enforces exact equality between imported and requested risk, but
  it does not infer clinical intent from prose. A caller that mislabels an
  actionable request as personal context is outside this control; personal
  packets therefore carry no clinical-action authorization.
- `AnswerBundle`: typed claims with support IDs that must resolve into the
  supplied packets.

### FHIR-informed boundaries, not FHIR conformance

FHIR R4 4.0.1 (TC1) was used as a design reference; it is not the current FHIR
release, and this workbench does not emit validated FHIR resources or claim
FHIR compliance. Its separation of a report or panel in
[`DiagnosticReport`](https://hl7.org/fhir/R4/diagnosticreport.html) from
individual results in
[`Observation`](https://hl7.org/fhir/R4/observation.html) informs the planned
clinical layer: independently interpretable results stay separate and may be
linked through `result`/`hasMember`, while `Observation.component` is reserved
for inseparable subresults. `presentedForm` is analogous to retaining the whole
immutable report, not to replacing structured reviewed values.

The local source/version history likewise follows the concepts, not the wire
format, of
[`DocumentReference`](https://hl7.org/fhir/R4/documentreference.html)
current/superseded status and `relatesTo` replacement/appending, and of
version-specific targets, activity, recorded time, agent, revision, and
derivation in
[`Provenance`](https://hl7.org/fhir/R4/provenance.html). A correction therefore
creates reviewed state tied to a version instead of overwriting the original;
FHIR report statuses such as `amended` and `corrected` informed that choice.
FHIR [history](https://hl7.org/fhir/R4/http.html#history) availability itself
depends on the server's CapabilityStatement; the workbench's local history is
its own contract.

FHIR REST distinguishes a non-atomic `batch` from an atomic `transaction`
([official transaction documentation](https://hl7.org/fhir/R4/http.html#transaction)).
Despite the user-facing name "batch review", `commit_document_review`
deliberately has transaction semantics: every selected decision succeeds or
none does. Official AWS Textract and Azure Document Intelligence guidance also
informed the confidence rule: confidence is only a review-routing signal,
thresholds depend on the use case, critical missing fields need their own
checks, and some high-confidence output still needs sampling
([AWS](https://docs.aws.amazon.com/textract/latest/dg/textract-best-practices.html),
[Azure](https://learn.microsoft.com/en-us/azure/ai-services/document-intelligence/concept/accuracy-confidence?view=doc-intel-4.0.0)).
Those cloud products are not used by the private runtime; private source bytes
remain in the no-network zone.

The schema distinguishes `source_fact`, `user_note`, `calculated`,
`external_evidence`, `inference`, and `guideline_recommendation`. Source fields,
source narrative, and user notes have receipt-backed private paths. Calculated
statements do not yet have an automatic receipt-backed path.

Private deterministic helpers do not bypass those paths. Laboratory
normalization accepts only an allowlisted root and derives its pseudonymous
subject server-side, but its supplied source locator is not checked against the
vault or review ledger. Its output is explicitly unverified,
non-receipt-backed, source-authenticity-unverified, and CasePacket-ineligible.
The ABPM helper likewise emits only an unverified calculation. It accepts a
monitor-removal `source_fact` only with an explicit kind, exact time-bearing
text, and report provenance; it accepts a `user_note` only by loading and
verifying the exact root/subject-bound `record_user_note` receipt and matching
its text/time. Neither route converts the ABPM calculation into a reviewed
CasePacket record.

## Implemented controls

1. Selected archive files are opened through a no-follow descriptor walk,
   read with a size cap, hashed, and left in place.
   Archive-wide requests enumerate the allowlisted root inside the private
   server and incrementally process bounded pages without caller-supplied file
   paths. Keyed source/profile receipts skip unchanged content. Extracted
   candidates and verified longitudinal records remain separate views.
2. Each configured `root_id` represents exactly one subject. The server derives
   the keyed subject ID from that opaque root; nested folders are report
   categories and never new subject boundaries.
3. Public queries pass deterministic identifier, path, instruction-pattern,
   length, and structure checks before clients run. Returned remote metadata is
   checked again before receipt registration or tool output; a DLP/instruction
   hit fails the call after retrieval without emitting the metadata. Publication
   bounds must be supplied together and span whole months: first day for
   `date_from`, last calendar day for `date_to`.
4. Review receipts HMAC-bind the root scope, server-derived subject, candidate,
   exact field/value or statement, artifact hash, provenance, reviewer label,
   timestamp, and emitted record. Document snapshots additionally bind one
   source/version and every displayed row in order. Their commits recheck that
   exact scope and current undecided state under one transaction; safe-row
   accept-all never covers `needs_review`, OCR/table association, limitations,
   or instruction-like content without an explicit row decision. User-note
   receipts bind the root/subject, exact note, recorder label, timestamp,
   provenance marker, and emitted `user_note`. Packet construction rejects an
   invalid binding and excludes durable rejections.
5. MCP filesystem/network policy and explicit tool lists reduce accidental
   cross-zone access.
6. Private/public packet issuers write separate handoff stores. Per-kind keys
   outside SQLite HMAC-bind packet kind, packet ID, and canonical payload hash.
   Synthesis opens both stores read-only; audit opens only the public store.
   Readers reject unknown IDs, wrong packet kinds, non-canonical payloads,
   payload-hash mismatches, and invalid HMACs.
7. Public retrieval receipts HMAC-bind exact queries, credential-free exact
   execution descriptors, and ordered metadata results before evidence-packet
   construction. The ledger recomputes the descriptor, verifies PubMed items
   came from the recorded ESummary ID set, and rejects a mismatch.
8. Public evidence-claim receipts bind a registered candidate, retrieval
   receipt, exact metadata snapshot, source-document hash, locator/excerpt,
   claim fields, reviewer attribution, and timestamp. Review requires every
   confirmed material field, including question, source root, semantic item
   snapshot, provenance, and limitations, to equal the candidate. The semantic
   item snapshot excludes only `retrieved_at`. Guidance candidates similarly
   freeze one effective recommendation; human guidance review exactly confirms its
   wording, provenance, native grade, population/effect fields, limitations,
   question, source root, and semantic snapshot. Guidance issuance requires
   receipt IDs that exactly cover the selected recommendation IDs.
9. Project private/public/source-review agents use `approval_policy = "never"`
   and MCP approval mode `approve` over explicit, zone-specific tool allowlists.
   This permits non-interactive Full Access sessions without removing the
   private no-network and public no-archive process boundaries. Pre-approval is
   execution authorization only; exact human content confirmation remains a
   separate receipt contract. Plugin-only use elsewhere inherits host policy.
10. The structural answer audit rejects metadata-item IDs used as substantive
   support, missing/unknown support IDs, duplicate IDs, rejected claims,
   rejected or unverified case/evidence support, evidence claim-kind mismatches,
   invalid certainty, and bad conflict references. Case-backed `source_fact`, `user_note`, and
   `calculated` claims require support of exactly the same statement kind, so
   relabeling a note or calculation as a source fact cannot pass.
11. On macOS the untrusted PDF worker always runs in a dedicated Seatbelt nested
    inside the parent sandbox. Missing `sandbox-exec` or `pdf-parser.sb` fails
    closed; the child cannot read state/handoff/Keychain, write files, use the
    network, or fork. Non-macOS runs only the bounded subprocess and has no
    equivalent built-in OS sandbox.
12. Default CSV caps are 16 MiB input, 20,000 rows, 256 columns, 32 KiB per
    UTF-8 cell, and 1,000,000 cells after rectangular padding. Candidate caps
    are 20,000 records, 64 KiB per value-plus-field, and 16 MiB cumulatively.
    Any hard-cap failure discards blocks/candidates and does not cache a partial
    result.
13. Guidance imports and resolved output pass the public instruction/privacy
    gate. Free-text fields additionally pass quasi-identifier checks before the
    first fixture write and again on resolve, while explicitly typed IDs,
    dates, hashes, and URLs keep typed treatment. Each stored document,
    relation, and recommendation has an HMAC receipt verified whenever it is
    read. A registry-manifest HMAC binds the ordered receipt inventory and
    requires its record keys to equal the actual registry keys; adding or
    deleting either stored rows or receipts fails closed. These HMACs detect
    local registry tampering; they do not constitute source review.
14. `load_synthesis_packets` loads exactly one issued CasePacket and one issued
    EvidencePacket from the read-only HMAC-verified handoffs and returns no
    caller-authored replacement. Its bounded output gate runs before packet
    contents reach the synthesis agent.
15. Before synthesis strictly decodes a caller-provided mapping into a typed
    `AnswerBundle`, a bounded structural/text input gate rejects more than
    20,000 traversed nodes or 250,000 counted text characters. This offline
    bound performs no public identifier or instruction-pattern DLP and an
    overflow fails without running the claim audit.
16. The audit-only packet loader accepts one issued evidence packet ID, verifies
    the read-only HMAC/canonical binding, applies whole-payload bounds/direct
    checks, and applies stricter quasi-identifier checks only to the packet
    question, reviewed-claim prose/provenance/limitations, and packet
    limitations. Bibliographic metadata remains outside the quasi-ID pass.

## Controls that remain procedural

- The privacy gate is regex/structure based. It can miss identifiers or flag
  benign dates/text and is not a statistical or regulatory de-identification
  method. Its remote-metadata check is a fail-closed output gate, not proof that
  metadata is harmless or that prompt injection is impossible. It detects
  labelled US phone formats but does not reject arbitrary Title Case pairs
  merely because they are capitalized. Unlabelled lowercase names and names
  without a recognized surname suffix may escape. A human must inspect every
  cross-zone payload and every registry import.
- `reviewer_id` is an audit label supplied by the caller. It does not
  authenticate a person or prove that a human was present. HMAC protects record
  integrity under the local key, not reviewer identity. A Codex tool approval
  confirms that a user allowed that call; it is not clinical verification of
  every field or proof of the `reviewer_id` identity.
- Exact candidate confirmation and a valid evidence-claim receipt establish
  local integrity and traceability, not that the source entails the claim, the
  source is authentic, the reviewer is who the label says, or the claim is
  clinically applicable.
- The answer audit is structural. It does not read an article, prove that a
  source semantically entails a claim, validate effect size, assess population
  applicability, detect a retraction, or establish that guidance is current.
  Those checks require source-level review.
- `resolve_guidance` resolves only records already loaded into the local lazy
  cache. `plan_guidance_discovery` and the fresh live source-review stage handle
  official-source discovery and version verification on demand; the orchestrator
  imports only exact snapshots required for personal, clinical-action, or
  monitoring paths. Per-row and registry-manifest
  HMAC verification detects changed, added, or deleted rows/receipts under key
  secrecy; it is not source review, does not create a reviewed claim, does not
  authenticate the publisher, and does not defend against a same-account
  process that can read the adjacent key and rewrite the database, receipts,
  and manifest.
- Numeric/unit interpretation, terminology mapping, reference-interval use,
  and domain calculations require explicit validated logic and human review;
  the generic extractor does not infer them.
- The document batch surface reviews registered candidates; it does not yet
  assemble a laboratory name, value, unit, interval, method, and specimen into
  one domain record, nor a radiology report into structured findings and a
  conclusion. That source-bound domain assembly is the next layer and must not
  be inferred from neighbouring generic table cells.

## Storage and residual risk

Runtime stores use SQLite and ordinary files. Private directories/databases are
permission-restricted and receipt/packet rows are HMAC-bound, but SQLite content
is not encrypted at rest. Packet keys live outside their handoff databases under
`state/handoff/keys/`; the guidance key similarly lives beside its database.
They still share the same OS-account security domain.
Full-disk or volume encryption, backup encryption, access control, retention,
and secure disposal are deployment responsibilities.

The system does not make a consumer laptop HIPAA/GDPR compliant, verify OCR
clinically, authenticate the operator, or replace clinician review. All local
processes still run under one macOS account in the default setup. Consult
`docs/operations.md` for deployment canaries and the retention procedure.

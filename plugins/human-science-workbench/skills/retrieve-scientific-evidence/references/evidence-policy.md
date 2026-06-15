# Public evidence policy

## Source order

Use the most applicable source, not merely the highest label:

1. current official guideline, regulator, or public-health authority;
2. systematic review or meta-analysis with an inspectable method;
3. pivotal randomized or controlled study;
4. applicable observational evidence;
5. mechanistic, diagnostic-accuracy, or expert-consensus evidence when the
   question requires it.

Secondary summaries can orient a search but should not carry a clinical claim
when the primary or official source is available.

## Metadata item fields in the bundled clients

- stable ID, reported title, direct URL, source type;
- publication metadata and retrieval date;
- publisher/journal metadata and DOI/PMID where returned;
- hash of the returned metadata record.

The metadata hash is not a hash of an abstract or full source. Design labels may
come from publication-type metadata, but population, effect, uncertainty,
source grade, recommendation wording, and applicability require inspected
source content. Add them only through a reviewed source-level workflow and keep
the issuer's native grade separate from reviewer appraisal.

`EvidencePacket` schema 1.3 keeps metadata snapshots in `items` and
source-level support in `reviewed_claims`. An `items[].evidence_id` is a
discovery/source-identity handle and is rejected as support for a substantive
answer claim.

## Reviewed claim path

For a source-inspected study finding, effect, or harm:

1. `register_evidence_claim_candidate` binds the transcription to one verified
   retrieval receipt and metadata snapshot plus the source-document SHA-256,
   exact locator/excerpt, and structured claim fields.
2. `review_evidence_claim_candidate` requires a separately attributed exact
   confirmation of the question, retrieval receipt as source root, source
   evidence ID, semantic `EvidenceItem` snapshot, claim fields, provenance, and
   limitations, then emits a tamper-evident receipt. The reviewer may be a
   human or an independent Codex pass; the receipt authenticates neither. The
   semantic snapshot includes every item field except local `retrieved_at`.
   `reviewer_id` is an attribution label, not authentication.
3. `store_evidence` receives the retrieval IDs and
   `evidence_claim_receipt_ids`, rechecks their question, source receipt, and
   item-snapshot bindings, and places the resulting verified records in
   `reviewed_claims`.

Use only the reviewed claim's `claim_id` as downstream substantive support. The
candidate ID, receipt ID, and metadata item ID are not support IDs. This path
does not fetch or retain source content, authenticate the reviewer/source, or
prove entailment, quality, applicability, or clinical safety.

Reviewed guidance follows a distinct path: `plan_guidance_discovery` selects
validated official portals, a separate live-web role inspects the current
document, and only the exact source snapshot needed for an audited answer is
loaded into the lazy registry cache. Informational answers may remain
live-cited without registry import. `resolve_guidance` selects the effective
cached scope. Registry row/manifest HMACs provide local integrity only; they
are not source review. For every selected effective recommendation,
`register_guidance_claim_candidate` freezes its descriptor and
`review_guidance_claim_candidate` requires a separate exact confirmation of
the question, recommendation/source root, source evidence ID, semantic
`EvidenceItem` snapshot, verbatim text, provenance, native grade,
population/effect fields, and limitations. The semantic snapshot excludes only
`retrieved_at`. `store_guidance_evidence` must then receive both the selected
`recommendation_ids` and `evidence_claim_receipt_ids` that exactly cover them;
only this path issues `guideline_recommendation` reviewed claims. It does not
prove publisher authenticity, currentness, entailment, applicability, or
reviewer identity. Clinical-action research may proceed, but packet issuance
must stop with `needs_clinician_confirmation` until a typed clinician receipt
is implemented.
The `risk_level` selected at discovery is immutable workflow state: pass the
same value to audited import, every guidance registration, and guidance
storage. Omission or silent upgrade/downgrade is invalid.

## Reproducibility log

Record database, exact query, date/time, filters, result count, screening rule,
included IDs, excluded IDs with reasons, and inaccessible material. The MVP
HMAC-binds each server query, its exact credential-free execution descriptor,
and ordered metadata result set in a retrieval receipt. The descriptor records
the endpoint, HTTP method, effective server parameters, and client version; API
keys and contact-email parameters are deliberately omitted. PubMed uses a v2
descriptor containing ESearch plus ESummary v2, whether ESummary executed, its
ordered IDs, joined `id`, and `version=2.0`; stored PubMed items must belong to
that recorded ID set. `store_evidence`
recomputes that descriptor, reconstructs only from receipt IDs, and embeds the
query plus descriptor, execution time, and result IDs in
`EvidencePacket.search_log`. Reviewed source-level claims provided by valid
review receipts are stored separately in `EvidencePacket.reviewed_claims`. The
search log does not represent the manual
screening/exclusion or source-review part of this log. Keep those fields in a
separate reviewed artifact; without them, label the search
metadata-reproducible but screening-incomplete.

Publication filters are omitted together or supplied together and are
month-granular: `date_from` is the first day and `date_to` the last calendar day
of their months. Before a
successful result is registered or returned, normalize the remote metadata and
pass it through the deterministic identifier, path, instruction-pattern,
length, and structure gate. A refusal happens after network retrieval and
prevents tool output and receipt persistence; it is a fail-closed heuristic,
not complete DLP, de-identification, or prompt-injection protection. It catches
labelled US phone formats but does not block arbitrary Title Case pairs solely
for capitalization. Unlabelled lowercase or non-suffix personal names may
require human detection before public use.

The issued `EvidencePacket` has a separate evidence-integrity HMAC binding over
packet kind, packet ID, and canonical payload hash. Its key lives under
`state/handoff/keys/`, outside the handoff SQLite database, and is distinct from
the retrieval-ledger key. This is tamper detection under key secrecy, not
encryption, signing, remote attestation, or same-account isolation.

## Stop conditions

Stop and report a gap when source identity cannot be verified, only a snippet
is available for a detailed claim, guidance is superseded without an active
replacement, the question cannot be de-identified adequately, or remote
metadata is refused by the output gate.

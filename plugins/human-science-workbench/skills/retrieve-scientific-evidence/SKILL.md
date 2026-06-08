---
name: retrieve-scientific-evidence
description: Plan de-identified PubMed/Crossref metadata searches and issue EvidencePacket 1.3 artifacts containing separately reviewed study or guidance claims. Use for candidate citations, stable identifiers, and source-bound public evidence; the bundled tools do not retrieve article/full text or prove guidance current.
---

# Retrieve Scientific Evidence

Retrieve candidate public-source metadata for a de-identified question, then
separate source discovery from source-level evidence extraction. Read
[references/evidence-policy.md](references/evidence-policy.md) before searching.

The bundled MVP searches PubMed through ESearch followed by ESummary v2 and
searches Crossref metadata. It does not
fetch PubMed abstracts, article or guideline full text, tables, effect
estimates, publisher pages, or paywalled content. `plan_guidance_discovery`
selects validated official portals; `resolve_guidance` reads only the lazy
cache of source-reviewed snapshots and does not itself retrieve or verify
official guidance on the network.

## Input gate

Accept only a de-identified question. Reject raw reports, `CasePacket` objects,
direct identifiers, local private paths, and vault references. If personal
context is necessary to shape the question, derive only the minimum population
and exposure/outcome characteristics offline, then begin a separate public
step.

The privacy gate is regex/structure based, not complete de-identification.
It catches labelled US phone formats but does not reject arbitrary Title Case
pairs merely because they are capitalized. Unlabelled lowercase names and
names without a recognized surname suffix may evade its patterns; inspect the
exact query manually before approval.

The shipped project config supports non-interactive Full Access sessions by
pre-approving the public agent's explicit MCP allowlist. Do not stop merely
because the parent uses `approval_policy = "never"`. The installable plugin's
`.mcp.json` does not set an approval policy, so plugin-only use outside this
project inherits the host policy. Execution authorization is not source-quality
review, exact claim confirmation, or reviewer authentication.

## Search workflow

1. Choose one explicit risk intent before routing and use it unchanged in
   `route_science_question`, `plan_evidence_search`, and every PubMed/Crossref
   search for this question. For `clinical_action`, set
   `clinician_confirmation_required=true`; for every other intent, set it to
   `false`. This flag declares a requirement and is not a confirmation receipt.
   Search receipts bind the risk, and `store_evidence` rejects mixed-risk
   receipts. Route and plan do not yet issue receipts, so manually verify exact
   reuse across those earlier calls. Use `route_science_question` to confirm the
   public zone when routing is not already explicit.
2. Convert the question into a structured search plan with
   `plan_evidence_search`: population, intervention/exposure, comparator,
   outcomes, eligible designs, date range, jurisdiction, and exclusions. When
   publication bounds are used, supply both: the first day of a month for
   `date_from` and the last calendar day for `date_to`. Lone or arbitrary
   day-level bounds are rejected.
3. Search PubMed with `search_pubmed`. Use explicit concepts and controlled
   vocabulary where helpful. Treat returned fields as bibliographic metadata,
   not article findings or an abstract. Returned metadata must pass the
   deterministic DLP/instruction gate before it is registered or emitted; a
   refusal occurs after the fetch and is not proof of complete de-identification
   or injection resistance. Retain the server-issued
   `retrieval_receipt.receipt_id` only from a successful call. Its execution
   descriptor binds the ESearch request and ESummary v2 request, including
   whether ESummary ran, the ordered IDs, joined `id`, and version parameter.
4. Use `search_crossref` to resolve DOI and bibliographic identity or to find
   public records missed by the biomedical index. Crossref metadata is not a
   substitute for reading the underlying source. Retain its retrieval receipt.
5. If a substantive claim requires source content, stop the bundled metadata
   retrieval. Start a fresh project task and use `$inspect-public-source` with
   the `source-review` agent, `fork_turns="none"`, safe parent permissions, and
   no private packet or identifiers. The bundled MCP does not fetch or store
   that content, and live WebSearch does not traverse the local identifier
   hook. Record access and screening decisions separately. Never invent the
   required source-document hash when WebSearch did not provide raw bytes.
6. For a study `finding`, `effect`, or `harm`, call
   `register_evidence_claim_candidate` with its retrieval receipt, selected
   `source_evidence_id`, exact claim text, source-document SHA-256, locator,
   excerpt, and applicable structured fields. Registration freezes the
   transcription; it is not review. Call `review_evidence_claim_candidate`
   only after a separately attributed exact confirmation of the question,
   retrieval receipt as source root, source evidence ID, semantic
   `EvidenceItem` snapshot, all claim and provenance fields, and limitations.
   This may be a human or independent Codex pass; the receipt authenticates
   neither. The semantic snapshot includes every item field except
   `retrieved_at`. Retain the review `receipt_id`; `reviewer_id` is attribution,
   not authentication.
7. Call `store_evidence` with the relevant `retrieval_receipt_ids` and reviewed
   `evidence_claim_receipt_ids`. It verifies that every claim receipt is bound
   to a supplied retrieval receipt, the same question, and the exact semantic
   item snapshot. Do not pass caller-authored evidence items or claims.
8. For guidance, call `plan_guidance_discovery` with the de-identified question,
   domains, jurisdictions, and risk level, then inspect the selected current
   official documents in the separate `$inspect-public-source` stage. An
   informational answer may remain live-cited. For personal context or
   clinical action, cache only the exact inspected document/recommendations
   with content hash, status, dates, native grade, jurisdiction, provenance,
   and version relations, then run a separate exact review. Use
   `resolve_guidance` after that load and state source-review `last_checked_at`
   values. Registry row/manifest HMACs establish local integrity only, not
   source review. For each selected effective recommendation call
   `register_guidance_claim_candidate`, then
   `review_guidance_claim_candidate` with separate exact confirmation of the
   question, recommendation/source root, source evidence ID, semantic item
   snapshot, verbatim wording, provenance, native grade, population/effect
   fields, and limitations. The semantic snapshot excludes only `retrieved_at`.
   Call `store_guidance_evidence` with both the selected `recommendation_ids`
   and `evidence_claim_receipt_ids` that exactly cover them. Only that
   receipt-backed path issues reviewed guideline claims. `clinical_action`
   research and caching may proceed, but registration/storage must stop with
   `needs_clinician_confirmation`; no typed clinician receipt exists here.
   Choose `risk_level` once and pass that exact value unchanged through the
   plan, `guidance-load`, every candidate registration, and evidence storage.
   Never omit, upgrade, or downgrade it silently.
   Any individualized treatment choice, dose, procedure, contraindication, or
   patient-specific action is `clinical_action`, not `personal_context`.
9. Extract design, population, effect, uncertainty, limitations, and native
   grade only from inspected source content. Never infer them from title,
   publication type, identifier, or publisher metadata.
10. Keep screening rules, title/abstract/source inclusion/exclusion decisions,
    inaccessible material, and unresolved disagreements in a separate reviewed
    log. Neither retrieval receipts nor reviewed-claim receipts are a complete
    systematic-review record.

## Evidence handling

- Prefer the highest applicable authority whose current status was verified at
  the official source, but do not use hierarchy as a shortcut: scope and
  population fit can outweigh nominal source type.
- Separate clinical guideline recommendations from study findings and from
  model inference.
- Preserve null, conflicting, and adverse findings. Do not select only evidence
  aligned with a desired answer.
- Report absolute effects only when verified from source content, together with
  follow-up duration, uncertainty, and clinically relevant denominators. Do
  not translate association into causality.
- Verify DOI, PMID, title, authorship, year, and publisher against the source.
  Never fabricate a citation or quote inaccessible full text.
- Treat publication recency as relevant, not equivalent to quality.

## Output

Return an `EvidencePacket` containing the exact de-identified question,
`EvidenceItem` records, identifiers/direct URLs, retrieval time, the generated
structured query/execution/result search-log entries, explicit limitations, and
`reviewed_claims` when reviewed study or guidance claims were issued. Schema
1.3 deliberately separates `items` from `reviewed_claims`: metadata item IDs
cannot support substantive claims. Downstream `support_ids` must use the
applicable `reviewed_claims[].claim_id`, not an `EvidenceItem.evidence_id`,
candidate ID, or review receipt ID.
Return the full reviewed screening log as a separate artifact; do not imply the
packet records exclusions or source-level inspection. Pass only the issued
`packet_id` to later public audit or synthesis. Mark packets without an
applicable reviewed claim as unable to support detailed efficacy, harms,
diagnostic, or recommendation claims. Patient-specific interpretation belongs
in a later offline-synthesis step, which first loads the issued CasePacket and
EvidencePacket through `load_synthesis_packets`.

The packet-handoff HMAC is integrity under key secrecy, not encryption, a
signature, remote attestation, or a hard boundary against another process under
the same OS account.

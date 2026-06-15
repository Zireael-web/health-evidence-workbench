---
name: synthesize-personal-context
description: Combine a minimal verified CasePacket with a public EvidencePacket offline while keeping facts, calculations, recommendations, and inferences distinct. Use for personalized explanations, clinician briefs, or AnswerBundle creation after private and public work are complete.
---

# Synthesize Personal Context

Join verified case facts to public evidence only in the offline-synthesis zone.
The goal is a traceable claim ledger, not an authoritative-looking narrative
that hides how conclusions were formed. Read
[references/claim-ledger.md](references/claim-ledger.md) before drafting.

## Input gate

Require:

- an issued minimal `CasePacket` ID whose used observations/statements are
  `verified`;
- an issued de-identified `EvidencePacket` 1.3 ID with source identities,
  `reviewed_claims`, and search limits;
- a precise question defining the decision and intended audience.

Reject unnecessary direct identifiers, raw documents, private vault paths,
unverified observations, and evidence snippets without source identity. Do not
browse, retrieve, or call public search tools during synthesis. If evidence is
missing, emit a de-identified research question for a separate public run.

Inspect evidence depth before synthesis. PubMed/Crossref results from the
bundled clients are bibliographic metadata only. `EvidenceItem.evidence_id`
values cannot support substantive claims. Study findings, effects, and harms
must resolve to verified `reviewed_claims` created by the candidate/exact-review
receipt flow. Guideline recommendations must resolve to reviewed claims created
only after `resolve_guidance`, per-recommendation candidate registration, exact
separately attributed confirmation of wording, native grade, provenance,
limitations, source root, risk binding, and semantic item snapshot (which
excludes only `retrieved_at`), and
`store_guidance_evidence` issuance with exactly covering review receipts.
Registry HMACs establish local integrity only;
they are neither source review nor substantive support. A reviewer label may
identify a human or independent Codex pass but authenticates neither. This
Clinical-action study packets may reach synthesis, but the confirmation-required
flag is not a confirmation receipt: the resulting AnswerBundle remains a
draft and cannot pass final audit. Clinical-action guidance issuance remains
blocked until a typed clinician-confirmation receipt is available.

The synthesis server accepts packet IDs and loads only packets issued into the
private/public handoff stores; callers cannot submit replacement packet JSON.
Packet-kind-specific HMAC keys under `state/handoff/keys/`, outside SQLite, bind
each packet kind, ID, and canonical payload hash. The synthesis wrapper validates
both existing keys and opens the stores read-only. This detects tampering while
the keys remain secret; it is not encryption, a digital signature, remote
attestation, or a hard boundary from another process running as the same OS
account. In a strict cross-host deployment, use an authenticated
operator-controlled handoff and do not rely on shared parent-task context.

## Synthesis workflow

1. Call `load_synthesis_packets` with exactly one issued CasePacket ID and one
   issued EvidencePacket ID before drafting. Use only the returned canonical,
   bounded packet contents; never accept replacement packet JSON.
2. Select only case fields needed for the question. Record omitted context that
   could materially change interpretation.
3. Build atomic candidate claims. One claim should express one proposition that
   can be supported or rejected independently.
4. Assign the correct kind: `source_fact`, `user_note`, `calculated`,
   `external_evidence`, `guideline_recommendation`, or `inference`.
5. Attach `support_ids` to every claim. Source facts point to verified case
   records of exactly the same kind; the same exact-kind rule applies to
   `user_note` and `calculated`. Evidence claims point only to a verified
   `reviewed_claims[].claim_id` of the same statement kind; metadata item,
   candidate, and receipt IDs are invalid support. Inferences point to both the
   relevant verified case record and reviewed evidence claim. Never relabel a
   note, calculation, external-evidence claim, or guideline recommendation to
   bypass kind checks.
6. Set calibrated certainty and list caveats. Add `conflicts_with` links for
   inconsistent observations, studies, or recommendations; do not resolve a
   conflict by omission.
7. Test applicability: population, setting, jurisdiction, method, timeframe,
   baseline risk, outcome definition, and evidence date.
8. Exclude every candidate claim already marked `rejected`; that status is a
   hard audit failure even when support otherwise resolves.
9. Run `audit_answer_bundle` when available. Fix its structural failures,
   including metadata-only evidence support, rejected/unverified support, and
   exact case/evidence kind mismatches;
   preserve legitimate uncertainty and disagreement. The tool applies only a
   bounded structural/text input gate before strict typed decoding; treat an
   oversized-input refusal as a boundary failure, not as an audit result. It
   does not run public identifier/instruction DLP at this offline boundary. The
   tool also does not verify semantic entailment, citation truth, population
   applicability, or clinical safety, so record those review layers separately.
10. Create an `AnswerBundle` 1.1 with `review_required=true`, the exact same
   `risk_envelope` as its EvidencePacket, packet IDs, limitations, and only
   claims that survive support review.

## Writing rules

- Lead with what the verified records actually show, then explain what public
  evidence says, then label the case-specific inference.
- Do not convert population-level relative effects into an individual's
  probability without a validated model and required inputs.
- Do not infer causality from timing, correlation, or one abnormal result.
- Do not silently choose among conflicting guidelines. Explain the applicable
  scope and why a recommendation may or may not transfer.
- Medication, diagnosis, and urgent-care statements require particularly tight
  support and appropriate human review. Never issue an unsupported dose change
  or claim clinical clearance.

## Output modes

For a structured output, return the `AnswerBundle` and claim ledger. For a
clinician brief, use: question; verified case facts; relevant public evidence;
case-specific inferences; conflicts/limitations; and focused questions for the
clinician. Keep support IDs inline so every material statement remains
traceable. A structural audit pass means only that the support graph satisfies
coded rules; it is not clinical clearance or a complete evidence audit.

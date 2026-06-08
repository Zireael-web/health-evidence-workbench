---
name: monitor-evidence-updates
description: Define or run public-only metadata update checks and route changed study or guidance claims through EvidencePacket 1.3 review paths. Use when a prior public packet needs a delta; the MVP does not create recurring automation or fetch source content.
---

# Monitor Evidence Updates

Monitor public evidence without carrying private case material into the update
process. The result is a versioned delta and review trigger, not an automatic
change to a medical conclusion. Read
[references/update-ledger.md](references/update-ledger.md) before comparing runs.

The bundled clients compare bibliographic metadata, not abstracts/full text.
Their content hashes cover returned metadata records. `resolve_guidance` reads
only the lazy cache and cannot discover publisher changes;
`plan_guidance_discovery` selects the official portals for a fresh live check.

## Input gate

Accept a de-identified question, the exact ID of a prior issued public
`EvidencePacket`, exact baseline queries, included identifiers, guideline
versions, and last successful check. Reject caller-supplied replacement packet
JSON, `CasePacket` data, direct identifiers, local private paths, and vault
references.

## Monitoring workflow

1. Call `load_public_evidence_baseline` with the exact prior issued packet ID
   before classifying any delta. Use only its bounded, direct/semantic-gated,
   HMAC/canonical-verified comparison payload and typed baseline status. A
   stale baseline may define the delta but cannot support a current claim until
   the official source is rechecked and a packet reissued.
2. Define the monitored decision, source set, jurisdiction, eligible designs,
   query strings, cadence, and materiality criteria.
3. Re-run the baseline plan through `plan_evidence_search`, `search_pubmed`, and
   `search_crossref`. Keep each server-issued retrieval receipt. The resulting
   packet preserves the exact server query, credential-free exact execution
   descriptor, execution time, and result IDs. PubMed binds ESearch and ESummary
   v2, including ordered summary IDs and version. Publication bounds must be
   omitted together or supplied together as whole months: first day for
   `date_from`, last calendar day for `date_to`. Keep API/tool changes, refused
   remote-metadata calls, and manual screening decisions in a separate reviewed
   run log.
4. Call `plan_guidance_discovery` and, through a separately approved public-only
   source-review process, check the selected official publishers for guideline
   updates, focused revisions, corrections, withdrawals, retractions, and
   replacement documents. Encode only inspected changes with `guidance-load`,
   then use `resolve_guidance` to apply the registered relations. Registry HMAC
   verification is local integrity, not source review. When selected effective
   recommendations must support downstream claims, register one guidance
   candidate per recommendation, perform a separately attributed exact
   `review_guidance_claim_candidate` confirmation of wording, native grade,
   provenance, limitations, source root, and semantic item snapshot, then call
   `store_guidance_evidence` with the selected IDs and exactly covering review
   receipts.
   Preserve the exact planned/imported `risk_level` in every registration and
   storage call; never omit, upgrade, or downgrade it silently.
5. Compare stable identifiers and metadata hashes. Classify only what metadata
   establishes as new/changed/unchanged; reserve `corrected`, `retracted`,
   `superseding`, and `superseded` for status verified at an authoritative
   source.
6. Screen new or changed sources against the original eligibility rules. Do
   not treat every new citation as a material evidence change.
7. Assess impact on each supported claim: no impact, confidence only,
   qualification needed, recommendation changed, or prior claim invalidated.
   Metadata item IDs alone cannot establish a substantive impact. If a new or
   changed study finding/effect/harm must become support, register its exact
   source-bound candidate, then use `review_evidence_claim_candidate` for a
   separately attributed exact confirmation of the question, retrieval receipt
   as source root, semantic item snapshot, claim/provenance fields, and
   limitations. The
   semantic snapshot excludes only `retrieved_at`. Retain the review receipt.
8. Call `store_evidence` with issued retrieval receipts and any applicable
   `evidence_claim_receipt_ids`. Produce a separate update ledger linked to the
   prior/current packet IDs, reviewed claim IDs, and source-review record.

## Monitoring rules

- Never silently broaden a query. Version and explain every search-plan change.
- Distinguish a publisher metadata edit from a substantive recommendation or
  result change.
- Preserve retractions, corrections, and negative evidence in the ledger.
- A new guideline does not automatically supersede another jurisdiction's
  guidance.
- Failed or partial checks do not advance `last_successful_check`.
- Treat a remote metadata DLP/instruction-gate refusal as a failed source check;
  do not copy the refused content into another output path.
- Do not modify an `AnswerBundle` automatically. Trigger offline synthesis and
  human review when the delta is material; synthesis first loads the newly
  issued packet pair through `load_synthesis_packets`.

## Output

Return the baseline and current run IDs, as-of time, exact queries, source
coverage, item-level delta, affected claim IDs, materiality rationale, failures,
and next action. If the user requested only a monitor specification, define the
same fields and cadence without claiming that a recurring automation has been
created. If only metadata checks ran, label content/retraction/guidance status
`not_verified` rather than inferring it from a title or changed metadata hash.

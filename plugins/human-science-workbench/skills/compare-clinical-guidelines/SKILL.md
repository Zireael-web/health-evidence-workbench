---
name: compare-clinical-guidelines
description: Discover and compare current clinical guidelines by population, jurisdiction, date, recommendation strength, and evidence basis. Use for live international comparisons or after on-demand source-reviewed snapshots are cached locally; registry HMAC integrity is not source review.
---

# Compare Clinical Guidelines

Build a source-faithful comparison of applicable recommendations without
collapsing differences in population, jurisdiction, or grading system. Read
[references/guideline-comparison.md](references/guideline-comparison.md) before
normalizing recommendations.

Use `plan_guidance_discovery` to select official issuer portals before live
inspection. The bundled `resolve_guidance` tool queries the local SQLite cache
only; it does not visit publishers, download full guidelines, detect new
versions, or authenticate cached records. Treat “current” in the cache as
“effective according to integrity-checked records as of `last_checked_at`.”

Registry imports and resolved output pass the deterministic public
privacy/instruction gate. Each document, relation, and recommendation also has
an HMAC integrity receipt verified whenever it is read. A registry-manifest
HMAC binds the complete receipt inventory to the actual record keys, so added
or deleted rows/receipts fail closed. This is local integrity only, not source
review. Neither control authenticates the publisher or creates a same-account
security boundary.

## Scope gate

Start from a de-identified question. Define condition or decision, target
population, setting, intervention/exposure, outcome, jurisdiction, and the
as-of date. Do not use private case facts in the public comparison.

## Comparison workflow

1. Call `plan_guidance_discovery` with domains, jurisdictions, and risk level.
   Start with its validated official portals and add another issuer only after
   verifying its canonical identity. Execute every `required_checks` item:
   resolve `unmapped_domains` through a canonical specialist issuer,
   `unmapped_jurisdictions` through the competent national authority, and each
   `uncovered_scopes` domain@jurisdiction pair through a profile authority for
   that exact scope. Gaps require explicit follow-up, not a claim of coverage.
2. In the fresh public-only `source-review` stage, inspect the official
   guideline, focused update,
   correction, withdrawal, and implementation note. Record stable URL, exact
   title, version, publication/update date, and access date.
3. For a one-off informational comparison, cite the inspected official sources
   directly and skip registry import. For personal context, clinical action, or
   monitoring, have the orchestrator encode only the selected documents,
   recommendations, native grades, and version relations and load that lazy
   snapshot with `guidance-load`. Inspect the
   payload for identifiers and instruction-like text first. The regex gate
   catches labelled US phone formats but does not block arbitrary Title Case
   pairs solely for capitalization; it can miss unlabelled lowercase or
   non-suffix names.
4. Use `resolve_guidance` to apply dates, jurisdiction, full supersession, and
   partial updates represented in that registry. Stop on any integrity-receipt
   failure. Compare its result with the inspected official sources before
   relying on it.
5. When recommendations must support downstream claims, call
   `register_guidance_claim_candidate` once for each selected effective
   recommendation. Registration freezes the registry descriptor and is not
   review. Then call `review_guidance_claim_candidate` only after a separate
   exact confirmation of the question, recommendation ID as source root, source
   evidence ID, semantic `EvidenceItem` snapshot, verbatim wording, provenance,
   native grade, population/effect fields, and limitations. The semantic
   snapshot includes every item field except `retrieved_at`. Finally call
   `store_guidance_evidence` with the same topic/as-of/jurisdiction,
   `recommendation_ids`, and `evidence_claim_receipt_ids` that exactly cover
   those recommendations. Attribute whether the reviewer was a human or an
   independent Codex pass; the receipt does not authenticate either. Use the
   issued guideline `reviewed_claims` IDs downstream, not document, candidate,
   or receipt IDs.
   Choose `risk_level` once and pass the exact same value through discovery,
   `guidance-load`, registration, and storage; never omit or silently change it.
6. Extract each relevant recommendation faithfully: target population,
   trigger/threshold, action, exceptions, recommendation strength, evidence
   certainty, and page/section locator.
7. Preserve the issuer's native grading system and wording. Add a separate
   normalized comparison label only when its mapping is explicit and lossless
   enough for the stated purpose.
8. Compare rows on the same decision axis. Explain whether a disagreement
   arises from evidence date, population, outcome priorities, resource model,
   jurisdiction, grading method, or true interpretation conflict.
9. Store only public metadata/structured records in the MVP stores. Keep the
   complete source-review and screening log separately. The EvidencePacket
   preserves selected registry-bound recommendation claims and its issuance
   log, not a complete guideline-review record.

## Comparison rules

- Never call guidance current solely because its publication date is recent;
  check updates, withdrawals, and living-guideline status at the
  official publisher.
- Do not equate `strong`, `recommended`, class/level codes, and GRADE certainty
  across organizations without documenting the mapping.
- Separate screening, diagnosis, treatment, monitoring, and referral
  recommendations. Similar numeric thresholds may serve different decisions.
- Preserve minority or conditional recommendations when material.
- State when local availability, cost, legal context, or resource assumptions
  limit portability.

## Output

Return a matrix with one row per recommendation and columns for organization,
jurisdiction, version/date, population/setting, decision, threshold/action,
exceptions, native strength and evidence grade, locator, and status. Follow it
with agreements, material conflicts, reasoned explanations, unresolved gaps,
the exact as-of date, and each record's source-review `last_checked_at`.
Do not describe the comparison as current beyond the oldest material check date
and do not choose a patient-specific action in this public step.

`store_guidance_evidence` verifies local registry scope and requires exact
review-receipt coverage for every selected recommendation. Registry HMACs alone
do not count as review and cannot issue substantive support. The live stage
fetches guidance separately from this MCP; neither the cache nor review receipts
authenticate the publisher/reviewer or establish semantic entailment or
applicability. Do not make an automatic patient-specific clinical recommendation.

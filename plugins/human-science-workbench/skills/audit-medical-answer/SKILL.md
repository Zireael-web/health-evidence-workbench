---
name: audit-medical-answer
description: Run the built-in structural claim/support audit and organize separate source-level and human safety review of a medical or human-science answer. Use before sharing an AnswerBundle or evidence-grounded response; the bundled audit does not prove semantic entailment, applicability, citation truth, or clinical safety.
---

# Audit Medical Answer

Review the answer as an adversarial, read-only artifact. Do not improve weak
claims by inventing support or silently rewriting the conclusion. Read
[references/audit-checklist.md](references/audit-checklist.md) before grading.

Use the `audit-review` project agent when available. For public-only claim
audits, first call `load_audit_evidence_packet` with the issued evidence packet
ID to inspect its bounded public contents, then call `audit_public_claims` with
the same ID. For a complete offline `AnswerBundle`, use the synthesis-zone
`audit_answer_bundle` with issued case/evidence packet IDs. The servers load
canonical packet payloads from their handoff stores rather than accepting
caller replacements. Do not grant either tool more data than its zone contract
allows. The installable public plugin does not expose the project-local audit
loader; when `audit-review` is unavailable, run only the public structural tool
and mark packet inspection, semantic, citation, applicability, privacy, and
safety layers `not_verified` as applicable.

The synthesis tool runs only a bounded structural/text input gate before strict
typed `AnswerBundle` decoding. More than 20,000 traversed nodes or 250,000
counted text characters is a hard input refusal, not a claim-audit finding.
This offline bound performs no public identifier or instruction-pattern DLP.

Both MCP audit tools are deterministic structural validators. They check packet
references, duplicate/unknown support IDs, exact case claim/support-kind
matching, EvidencePacket 1.3 reviewed-claim verification/kind matching,
metadata-only support IDs, rejected claims, certainty rules, and conflict
links. They reject type laundering such as a `user_note` or `calculated` record
relabeled as `source_fact`, or reviewed external evidence relabeled as a
guideline recommendation. They do not retrieve or read
sources, compare claim meaning with source meaning, validate an effect estimate,
assess population fit, detect retractions, or establish that guidance is
current. Do not report a structural pass as a semantic, medical, or safety pass.

For a substantive guideline claim, registry row/manifest HMAC verification is
only local integrity and never counts as source review. Require a guideline
`reviewed_claims` record issued after per-recommendation candidate registration,
separately attributed exact confirmation of wording, native grade, provenance,
limitations, source root, risk binding, and semantic item snapshot (which
excludes only `retrieved_at`), and exact receipt coverage at
`store_guidance_evidence`. That exact pass may be human or an independent Codex
pass; even then the
receipt-backed path does not authenticate
the reviewer or prove entailment.

`audit-review` starts the separate `audit` MCP through `run-audit-mcp`. The
wrapper permits no network or writes and exposes only
`load_audit_evidence_packet` and `audit_public_claims`, with read-only access to
the issued public handoff and its evidence-integrity key. The loader applies
whole-payload bounds/direct checks and stricter quasi-identifier checks to the
question, reviewed-claim prose/provenance/limitations, and packet limitations;
bibliographic metadata is excluded from that stricter pass. This is independent
public-claim checking, not an export service:
`review_export` still has no authenticated reviewer or publication gate.

## Audit sequence

1. **Boundary audit:** verify that public artifacts contain no direct
   identifiers, raw private documents, local paths, vault references, or
   unnecessary case detail.
2. **Artifact audit:** confirm schema version, packet IDs, immutable source
   hashes where applicable, `reviewed_claims` provenance/receipt fields,
   verification statuses, and explicit limitations. For guidance, do not accept
   a registry HMAC as the review receipt.
3. **Structural claim audit:** call the appropriate MCP audit and record its
   exact coded findings. A resolved support ID proves only that the record is
   present in the supplied packet. Treat `metadata_only_support`,
   `rejected_claim`, rejected/unverified case or reviewed-evidence support,
   `case_support_kind_mismatch`, and `evidence_support_kind_mismatch` as hard
   failures; never repair a mismatch by relabeling a note, calculation, source
   fact, external-evidence claim, or guideline recommendation.
4. **Semantic/source audit:** only when inspected source content is available,
   split prose into atomic claims and have a reviewer compare each whole claim,
   including magnitude and population, with the cited passage. Metadata-only
   PubMed/Crossref metadata records cannot pass this check for detailed claims.
   A study or guidance reviewed-claim receipt records exact local confirmation
   but still does not establish source entailment or reviewer identity.
5. **Citation audit:** independently verify title, DOI/PMID, publisher, date,
   version, locator, retraction/correction, and supersession at authoritative
   sources. The MCP audit does not do this.
6. **Applicability audit:** have a reviewer compare population, setting,
   jurisdiction, method, timeframe, intervention/exposure, outcome, and baseline
   risk. The MCP audit does not do this.
7. **Reasoning audit:** flag association presented as causation, reference
   interval presented as diagnosis, relative effect presented without baseline,
   hidden calculation, cherry-picking, and resolution of conflict by omission.
8. **Safety audit:** flag diagnosis or medication directives beyond support,
   missed urgent red flags, false reassurance, and failure to request human
   review where consequences are material.

## Severity

- `critical`: privacy boundary breach, fabricated source, dangerous unsupported
  directive, or false reassurance in a potentially urgent situation;
- `high`: material claim lacks support, wrong/superseded guidance, or evidence
  is inapplicable enough to change the conclusion;
- `medium`: incomplete uncertainty, conflict, locator, search log, or contextual
  qualification that weakens auditability;
- `low`: clarity or traceability defect unlikely to change the conclusion.

Any critical finding fails the artifact. High findings require correction and
re-audit. Medium findings remain visible in limitations if they cannot be
resolved.

## Output

Return a table with finding ID, severity, exact claim/artifact location,
support inspected, failure type, consequence, and concrete remediation. Then
report checks passed, unresolved evidence gaps, privacy status, and disposition:
`fail`, `revise_and_reaudit`, or `ready_for_human_review`.

`ready_for_human_review` is not clinical clearance. Do not add new clinical
claims during the audit; route evidence gaps back to a separate public search.
Label structural, semantic, citation, applicability, and safety review statuses
separately. If only the built-in audit ran, semantic/citation/applicability and
safety remain `not_verified`.

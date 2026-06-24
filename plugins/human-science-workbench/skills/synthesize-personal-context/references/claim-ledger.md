# Claim-ledger contract

Each material sentence maps to one atomic claim:

```json
{
  "claim_id": "CL-7",
  "text": "Calibrated proposition",
  "kind": "inference",
  "support_ids": ["OBS-2", "EV-9"],
  "certainty": "moderate",
  "conflicts_with": ["CL-5"],
  "caveats": ["population differs in age range"],
  "status": "needs_review"
}
```

## Invariants

- No claim without support IDs.
- A `source_fact`, `user_note`, or `calculated` claim is supported by verified
  case material of exactly the same kind. A type mismatch is a hard failure;
  never relabel a user note or calculation as a source fact.
- An external-evidence claim is supported only by a verified
  `EvidencePacket.reviewed_claims[].claim_id` whose kind is
  `external_evidence`. A bibliographic `EvidenceItem.evidence_id`, candidate ID,
  or review receipt ID is not substantive support.
- A guideline recommendation uses a reviewed claim issued by
  `store_guidance_evidence` only after exact guidance-candidate review receipts
  cover every selected recommendation ID. That reviewed claim preserves issuer,
  scope, date, locator, native grade, and limitations. A registry row or its
  HMAC receipt is integrity metadata, not human review or substantive support.
- An inference cites both the relevant verified case fact and a verified
  reviewed evidence claim.
- Certainty reflects the weakest material link: source verification,
  evidence quality, applicability, or inference strength.
- Conflict and missingness are explicit; absence is never encoded as normal.
- A claim with status `rejected` cannot pass even when all support IDs resolve.

Delete a claim that cannot pass these invariants. Do not repair it with more
confident prose.

## Enforcement boundary

Before strictly decoding the caller mapping as an `AnswerBundle`, the synthesis
tool runs `PrivacyGate.assert_bounded_payload` over the wrapped bundle. More
than 20,000 traversed nodes or 250,000 counted text characters is a hard refusal
and produces no claim-audit report. This bounded offline-input check performs no
public identifier or instruction-pattern DLP; those semantics would wrongly
reject legitimate opaque packet/support IDs and de-identified case claims.

The current MCP audit resolves IDs, checks verification and claim/support kinds,
rejects bibliographic item IDs as `metadata_only_support`, rejects every
rejected claim, and applies coded certainty/conflict rules. Exact kind matching
for case-backed and reviewed-evidence claims prevents type laundering. Every
`inference` requires both verified case support and verified reviewed-evidence
support. The tool still does not inspect source meaning; exact claim review and
support resolution do not prove semantic entailment or applicability, which
remain separate human/source-level review results.

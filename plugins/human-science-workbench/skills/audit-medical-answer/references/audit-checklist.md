# Medical-answer audit checklist

## Fail immediately

- private identifier or source material appears in a public artifact;
- a citation is fabricated, materially misidentified, retracted without
  disclosure, or cannot support the attributed statement;
- a critical observation is unverified or has no provenance;
- diagnosis, medication change, or urgent-care reassurance exceeds support;
- a material claim has no support IDs;
- a substantive evidence claim uses an `EvidenceItem.evidence_id`, candidate
  ID, or review receipt ID instead of a verified `reviewed_claims[].claim_id`;
- a guideline claim is treated as reviewed solely because the registry row or
  manifest has a valid HMAC, without the exact guidance-candidate review path;
- any claim is already marked `rejected`, or relies on rejected/unverified case
  support;
- a case-backed `source_fact`, `user_note`, or `calculated` claim is supported
  by a case record of another kind.

## Check every claim

1. Is its kind correct, and does every case support have exactly that kind for
   `source_fact`, `user_note`, or `calculated`? Do not launder types by
   relabeling a note or calculation.
2. Does each support ID resolve to the stated artifact and exact kind? For
   external evidence or guideline recommendations, does it resolve to a
   verified EvidencePacket 1.3 reviewed claim rather than bibliographic
   metadata? For guidance, was it issued from exact review receipts covering
   the selected recommendation IDs, rather than directly from registry
   integrity metadata?
3. Has an independent source-level reviewer established that the support
   entails the whole claim, including magnitude and population? A built-in
   structural pass, registry HMAC, or reviewed-claim receipt is not evidence
   for entailment or reviewer identity.
4. Is certainty no stronger than verification, evidence, and applicability?
5. Are conflicts, adverse findings, and limitations visible?
6. Is source wording clearly separated from inference?

## Disposition contract

`fail` for any critical finding. `revise_and_reaudit` for unresolved high
findings. `ready_for_human_review` only when remaining findings are documented
and do not undermine the answer's material claims. Never label an artifact
clinically approved.

Record which layers actually ran: `structural`, `semantic_source`, `citation`,
`applicability`, `privacy`, and `safety`. The MCP tool implements only the
structural layer. The project-local packet loader adds bounded deterministic
identifier/instruction gates and makes the public packet inspectable, but it
does not automate semantic, citation, applicability, or safety review. Mark
every unperformed layer `not_verified`; never infer it from a support-ID pass.

# Optional ingestion domain profiles

A domain profile augments the generic ingestion contract; it is not another
skill, trust zone, parser authority, or clinical workflow.

In the current MVP, normalization/ABPM helpers return deterministic results but
do not automatically create HMAC review receipts or append `calculated`
statements to a `CasePacket`. Treat receipt-backed calculated output as a future
extension, not an existing generic capability.

`normalize_lab_observation` takes an allowlisted root and derives the subject;
its caller-supplied source locator is not authenticated against vault bytes.
Honor its explicit unverified/non-receipt/CasePacket-ineligible status. For
ABPM monitor removal, supplying a time alone is invalid. Select `source_fact`
only with exact time-bearing report text and report provenance. Select
`user_note` only with the matching root-bound `note_rcpt_...` from
`record_user_note`; the helper verifies receipt integrity, exact text, and the
same `HH:MM`. In either case the adequacy calculation remains unverified and
cannot be appended automatically.

## Compact profile shape

```yaml
profile_id: "abpm-summary"
version: "1"
applies_when: "deterministic format/signature rule"
expected_fields: ["recording duration", "valid awake count", "valid asleep count"]
normalizers: ["allowlisted unit or timestamp conversion"]
quality_checks: ["nighttime sufficiency can be assessed only with night data"]
prohibited_inferences: ["do not invent dipping status"]
```

## Invariants

- Generic source hashing, provenance, raw values, and verification remain
  mandatory.
- Profile matching must be explicit and reviewable; confidence-based guessing
  does not authorize specialized extraction.
- A future receipt-bound profile may add fields and validation but cannot delete
  source detail, overwrite raw values, call the network, or change trust zones.
- A profile cannot promote `extracted` or `needs_review` to `verified`.
- A profile never supplies diagnosis, treatment, or patient-specific risk.
- Unknown or partial formats fall back to generic ingestion with limitations.

ABPM, Holter, laboratory, imaging, and discharge-summary profiles all follow
this same contract. Add a new profile only when it contributes deterministic
field mapping or validation that the generic workflow cannot express clearly.

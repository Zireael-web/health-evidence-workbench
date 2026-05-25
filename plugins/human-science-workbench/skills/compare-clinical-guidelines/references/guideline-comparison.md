# Guideline comparison schema

Use one row per distinct recommendation:

Populate the row from an inspected official source. A live informational
comparison need not be imported; personal-context, clinical-action, and
monitoring paths also require its integrity-checked lazy-cache record.
`resolve_guidance` computes status from loaded dates and relations; it does not
verify publisher truth or discover missing updates. Registry HMAC verification
is not source review. When a row must become
downstream support, register the selected effective recommendation with
`register_guidance_claim_candidate`, then use
`review_guidance_claim_candidate` for exact separate-review confirmation of the question,
recommendation/source root, semantic `EvidenceItem` snapshot, verbatim wording,
provenance, native grade, and limitations. The semantic snapshot excludes only
`retrieved_at`. Pass the selected `recommendation_ids` and exactly covering
`evidence_claim_receipt_ids` to `store_guidance_evidence`; only then does it
issue EvidencePacket 1.3 reviewed claims. Use those claim IDs, not guideline
document, candidate, or receipt IDs. Issuance does not prove currentness,
entailment, applicability, or reviewer identity.
Bind one explicit `risk_level` unchanged across discovery, audited import,
registration, and storage. Never rely on a default or silently change it.

## Registry integrity boundary

Insertion and resolved output pass the public regex/structure and
instruction-pattern gate. This is heuristic: it catches labelled US phone
formats but deliberately permits arbitrary Title Case pairs without stronger
name signals; unlabelled lowercase or non-suffix names and novel prompt
injection can require human detection. The SQLite store writes an HMAC receipt
for every document, relation, and recommendation and verifies it on each read.
A manifest HMAC binds the ordered `(kind, ID, receipt HMAC)` inventory and
requires those keys to equal the actual record keys, detecting added or deleted
rows and receipts. The 32-byte key is stored beside the database, outside
SQLite; missing receipts, changed rows, unsafe keys, and HMAC mismatches fail
closed. This detects local edits only while the key remains secret. It does not
constitute source review, prove official-source authenticity, encrypt the
registry, or protect against a same-account process able to read the key and
rewrite rows, receipts, and the manifest.

| Field | Requirement |
| --- | --- |
| issuer | official organization name |
| jurisdiction | country/region and care setting |
| document | exact title, version, URL, dates, source-review `last_checked_at` |
| status | registry-computed current, partly superseded, superseded, withdrawn, uncertain |
| population | inclusion and material exclusion criteria |
| decision | screening, diagnosis, treatment, monitoring, or referral |
| trigger | threshold, risk band, timing, or clinical condition |
| action | recommendation in source-faithful paraphrase |
| exceptions | contraindications, alternatives, shared-decision conditions |
| native grade | issuer's recommendation strength and evidence certainty |
| locator | page, section, table, or recommendation number |

Do not create a universal score across grading systems. If a compact comparison
label is necessary, retain native grades and document the mapping and lost
information. Treat absent guidance as `not addressed`, not as a recommendation
against the action.

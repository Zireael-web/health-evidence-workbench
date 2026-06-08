# Evidence update ledger

## Run fields

- monitor ID, de-identified question, baseline/current packet IDs;
- exact queries, credential-free execution descriptors, sources, filters,
  jurisdictions and eligibility rules;
- started, completed and last-successful timestamps;
- result counts, failures, partial coverage and tool/version changes.

Load the baseline by exact issued ID through `load_public_evidence_baseline`
before comparing runs. The loader verifies the handoff HMAC/canonical binding
and applies the public output gates. An expired guidance packet is returned
only with typed stale/comparison-only status and cannot support a current claim
until source recheck/reissue. Never reconstruct the baseline from caller-supplied
packet JSON.

The MVP `EvidencePacket` stores structured entries for the exact server query,
exact credential-free execution descriptor, execution time, source, and result
IDs reconstructed from HMAC-bound retrieval receipts. The descriptor contains
the effective endpoint/method/parameters and client version, not credential
parameters. Keep manual screening, remote-metadata gate failures, tool changes,
and claim impact in a separate reviewed artifact. PubMed descriptors bind
ESearch and ESummary v2, including ordered IDs and version. Publication filters
must be omitted together or use first-of-month `date_from` and last-of-month
`date_to` boundaries. PubMed/Crossref hashes represent metadata payloads, not
source text.

Schema 1.3 also carries `reviewed_claims` when exact study-claim review receipts
or exact guidance-candidate review receipts covering selected recommendations
were issued. Registry HMAC integrity alone is not review. Track deltas by
reviewed claim ID and semantic source-snapshot binding; that snapshot excludes
only local `retrieved_at`. A bibliographic item ID or metadata-hash change is
not substantive claim support, and a review receipt does not prove entailment,
applicability, or reviewer identity.

## Item delta

For each stable identifier record old/new metadata or content hash and classify:

`new`, `metadata_changed`, `corrected`, `retracted`, `superseding`,
`superseded`, `unchanged`, or `unresolved_identity`.

Use content/status labels only after authoritative source-level review. A
metadata difference alone supports `metadata_changed`, not `corrected`,
`retracted`, or a substantive recommendation change.

## Claim impact

| Impact | Meaning |
| --- | --- |
| `none` | no material change to support |
| `confidence_only` | certainty may change, proposition remains |
| `qualify` | caveat or population limit must be added |
| `recommendation_changed` | applicable guidance changed |
| `invalidate` | prior material claim no longer has adequate support |

Only the last four states trigger re-synthesis; the final three require an
explicit independent review. Clinical-action packet issuance is blocked with
`needs_clinician_confirmation` until a typed clinician receipt exists. A failed
check never implies that no update exists.
For guidance, preserve one explicit `risk_level` unchanged from discovery and
audited import through candidate registration and evidence storage.

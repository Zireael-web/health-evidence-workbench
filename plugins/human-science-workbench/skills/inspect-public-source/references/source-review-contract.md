# Public source-review contract

## Input

- one minimal de-identified scientific question;
- optional PMID, DOI, registry ID, official-document ID, retrieval receipt/item
  ID, or public URL;
- explicit claim type and source content needed to assess it.

Private facts, raw reports, CasePackets, direct identifiers, local paths, vault
references, and inherited private task history are prohibited.

## Required record

| Field | Requirement |
| --- | --- |
| question | de-identified and scoped |
| source identity | title, issuer/authors, publication venue, stable IDs |
| access | inspected URL, UTC access date, full text/abstract/metadata/snippet |
| status | current, corrected, retracted, withdrawn, superseded, or not verified |
| version/scope | publication/effective dates, jurisdiction, population, setting |
| locator | page, section, table, figure, supplement, or recommendation number |
| content | source wording/paraphrase kept distinct from reviewer inference |
| quantitative fields | measure, numerator/denominator, follow-up, uncertainty |
| quality limits | design, bias/applicability limits, conflicts, inaccessible material |
| integrity | raw-source SHA-256 or exactly `not_computed` |
| risk path | information, personal context, or clinical action |
| disposition | live citation ready, registry snapshot ready, browser fallback needed, needs more access, or rejected |

Web citations establish which public page was inspected. They do not replace a
raw-document hash, prove the page unchanged, authenticate the reviewer, or make
the extracted proposition true. Informational answers may cite the live record
directly and label its access date. Personal-context and clinical-action claims
require an exact source snapshot plus a separate second-pass comparison of
every material field through the receipt-backed public MCP workflow. The
reviewer may be an identified human or a separately attributed Codex review;
the receipt authenticates neither. Clinical-action packet issuance remains
blocked until a typed clinician-confirmation receipt exists.

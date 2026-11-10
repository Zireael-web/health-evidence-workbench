# Private answer resolution (A16)

`PrivateAnswerService` prepares a bounded private draft against one immutable
case selection. It reads only the private records store and selected backend
calculation receipts. It performs no network access, model call, formula
evaluation, clinical authorization, or public evidence lookup.

The service API is:

```python
service = PrivateAnswerService(records, calculations=None)
report = service.prepare_private_answer(
    subject_id, selection_id, selection_sha256, draft, idempotency_key
)
result = service.get_private_answer_review(subject_id, review_id)
# result = {"report": frozen_report, "draft": frozen_draft,
#           "freshness": current_case_freshness}
```

Creation requires a current selection of this subject and the exact selection
hash. Historical or stale selections cannot produce a new answer artifact.
The case resolver establishes freshness from one signed database snapshot;
it does not check live source bytes and reports `source_bytes_checked: false`.

## Caller draft

Only `claims` and optional `intent` are accepted. Intent is
`personal_interpretation` (the default) or `clinical_action`. A draft contains
1–100 claims, has unique bounded claim IDs, and is limited to 256 KiB of
canonical JSON, with a maximum JSON nesting depth of 20 and 10,000 values.
Every claim has exactly these fields:

```json
{
  "claim_id": "FAKE_EXAMPLE",
  "type": "source_fact",
  "text": "Unchecked draft prose about a FAKE result",
  "support_id": "revision_0123456789abcdef0123456789abcdef",
  "assertion": {
    "field": "result",
    "expected_value": {
      "kind": "numeric_censored",
      "raw": "<0.01",
      "decimal": "0.01",
      "operator": "<"
    }
  }
}
```

Unknown fields and wrong types fail closed, including nested assertion fields.
There is no caller parameter for reported checks, formula, numeric result,
denominator, assurance, release state, clinician confirmation, or review mode.

| Claim type | Exact support | Allowed assertion |
| --- | --- | --- |
| `source_fact` | Selected trusted `observation_revision` | One complete allowed top-level typed row field and its exact `expected_value` |
| `user_note` | Selected `context_event` whose `kind` and `fact_status` both equal `user_note` | One complete `text`, `fields`, `event_type`, or `effective_time` value |
| `calculated` | Backend `private_calculation` receipt bound to this selection ID and hash | Exact `receipt_sha256` and receipt metric, `delta` or `percent_change` |

Allowed source fields are `analyte_raw`, `analyte_key`, `mapping_status`,
`measurement_property`, `subtype`, `loinc`, `result`, `unit_raw`, `unit_code`,
`clinical_time`, `reference_intervals`, `specimen`, `method`, `device`,
`lab_flag_raw`, and `panel_key`. A path such as `result.decimal` is not accepted.
Canonical JSON equality preserves types and every field of a censored result,
time value, reference list, or note object. A bare decimal cannot replace a
tagged result. `review_corrected` field origin remains explicit and is never
reported as literal printed proof.

Unreviewed `source_statement` events cannot become user notes. Laboratory
revisions cannot become notes, and notes cannot become laboratory source
facts. Note resolution does not depend on the result kind of any selected
laboratory row. Calculations are checked against the immutable receipt's full
revision input manifest and actual backend comparator; caller prose cannot
change the computed value or denominator.

## Assurance and storage

Exact field resolution checks the structured assertion. It does not compare
the meaning of claim `text` with that field. Even unrelated prose may pass the
structural assertion while remaining semantically unchecked. Every report is
therefore `needs_revision`, with `semantic_validation`, `medical_validation`,
and `human_validation` all `not_provided`. These artifacts do not authorize
clinical action or establish a note's clinical truth.

The private store atomically saves two immutable objects, with explicit kinds
and separate schemas:

| Store kind | Schema | Identity and links |
| --- | --- | --- |
| `private_answer_draft` | `health-analyzer.private-answer-draft/2.0` | `draft_id`, `review_id`, subject, selection ID/hash, draft hash |
| `private_answer_review` | `health-analyzer.private-answer-review/2.0` | `review_id`, `draft_id`, subject, selection ID/hash, draft and report hashes |

All new IDs, including the existing `idempotency` kind's ACK ID, use
`case_<32–64 lowercase hexadecimal characters>`. The existing public input
guard rejects this private identifier pattern. No new public adapter or
public storage permission is introduced.

Draft, report and original full ACK are committed in the same transaction.
The selected case is revalidated immediately before persistence. A failure
rolls back every answer write. An exact idempotency retry returns the original
report even after a correction or source freshness change; a different request
under that key is rejected. The getter returns the original bodies plus a
separate current freshness assessment and never rewrites either artifact.
It verifies the report body's review ID and subject against the requested
identity before resolving the graph, so a valid report cannot be retrieved
under a different report's store envelope.

`validate_private_answer_artifacts(draft, report, lookup)` and
`validate_private_answer_idempotency(payload, lookup)` replay the frozen
selection, exact-kind supports, calculation receipts and backend report body.
These pure recovery validators make no current freshness or source byte
checks, so valid historical artifacts remain recoverable. A rehashed report
with a promoted release or assurance is still rejected.

The targeted tests use newly created temporary FAKE namespaces and explicitly
SIMULATED decisions. They exercise the production records, case and calculation
resolvers; their passing status does not establish real human identity,
semantic review, medical validity, or deployment readiness.

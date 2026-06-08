# Laboratory interpretation checklist

## Required before interpretation

- verified raw value, original unit, comparator and source locator;
- laboratory reference interval and applicable population;
- specimen and collection date/time;
- method/device when it changes comparability;
- relevant prior values and collection conditions;
- exact `EvidencePacket.reviewed_claims[].claim_id` support of the matching
  statement kind for diagnostic, prognostic, or action-threshold claims.

Do not infer these fields from the generic candidate layout. The current
receipt-backed generic observation contains display, exact raw value,
verification, and provenance; optional unit/context fields must be explicitly
present in a verified record. Metadata-only PubMed/Crossref item IDs, candidate
IDs, and review receipt IDs establish no substantive support and cannot replace
a reviewed claim ID.

## Keep these concepts separate

| Concept | Meaning |
| --- | --- |
| reference interval | distribution selected by the laboratory |
| decision limit | threshold linked to a defined clinical decision |
| critical value | result requiring urgent communication under a policy |
| biological variation | expected within/between-person variation |
| analytical uncertainty | method and measurement uncertainty |

Do not replace one concept with another. A source flag supports the statement
that the laboratory marked a result, not a diagnosis.

## Claim pattern

```text
[source_fact] OBS-12: raw value and printed interval
[external_evidence] evclaim_<opaque>: meaning of an applicable decision threshold
[inference] CL-3: calibrated interpretation supported by OBS-12 + evclaim_<opaque>
```

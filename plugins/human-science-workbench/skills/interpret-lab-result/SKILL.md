---
name: interpret-lab-result
description: Interpret verified laboratory observations while preserving units, reference intervals, method, trend, and uncertainty. Use after private extraction and verification when the user needs an evidence-aware explanation, not for raw OCR or unverified values.
---

# Interpret Lab Result

Interpret only verified observations in the offline-synthesis zone. Keep the
source result, the laboratory's flag, clinical context, external evidence, and
your inference as separate layers. Read
[references/lab-interpretation.md](references/lab-interpretation.md) first.

This is an optional post-ingest interpretation profile, not a replacement for
the generic `$ingest-health-document` workflow and not a template to clone for
every analyte or report type.

## Input gate

Require the original analyte name, raw value, unit, comparator, source reference
interval, specimen, collection time, and verification status. Method/device,
fasting state, medication timing, age/sex/pregnancy context, and prior values
may be essential depending on the test.

The generic receipt-backed ingest path currently guarantees only confirmed
display/field label, exact raw value, verification, and provenance. Treat unit,
interval, specimen, method/device, and time as unavailable unless a reviewed
receipt-bound extension or separately verified case record actually contains
them; proximity in the document is not an association.

Stop and return to `$ingest-health-document` when the value, decimal, unit,
identity, interval, specimen, or date is ambiguous. Do not interpret a
normalized value when its conversion is not deterministic and documented.

## Interpretation workflow

1. **Source fact:** reproduce the raw result, unit, interval, flag, time, and
   provenance ID exactly.
2. **Analytical validity:** note sample quality, method limitations,
   interference, biological variation, and whether a repeat is needed to
   establish persistence. Mention only limitations supported for this test.
3. **Reference comparison:** state whether the value is inside, outside, or not
   comparable with the printed interval. A reference interval is not
   automatically a diagnostic or treatment threshold.
4. **Trend:** compare like with like: same analyte, unit, method where relevant,
   and comparable physiological context. Report absolute and relative change
   only when both inputs are verified.
5. **Clinical meaning:** list plausible interpretations in calibrated language.
   Substantive evidence support must be an exact
   `EvidencePacket.reviewed_claims[].claim_id` whose `statement_kind` matches
   the supported `external_evidence` or `guideline_recommendation` claim. An
   inference must cite that reviewed claim plus the relevant verified case
   record. PubMed/Crossref `EvidenceItem.evidence_id`, candidate IDs, and review
   receipt IDs are invalid support and cannot support a biomarker interpretation.
   Separate common from serious possibilities without claiming that the result
   establishes a diagnosis.
6. **Actionable discussion:** identify what additional context, repeat test, or
   clinician question would discriminate among interpretations. Do not direct a
   medication change.
7. Build supported `Claim` records and carry them into an `AnswerBundle` with
   `review_required=true` when a formal output is requested.

The built-in answer audit checks the support graph and coded claim rules only.
Have a source-level reviewer verify semantic entailment, applicability, and
safety before relying on the interpretation.

## Special cases

- For calculated indices, identify the formula, input IDs, assumptions, and
  population limitations; type the result as `calculated`.
- For qualitative or censored results (`detected`, `<x`, `>x`), preserve the
  comparator and do not invent a numeric point estimate.
- For method-dependent biomarkers, do not combine results across methods
  without an authoritative conversion.
- For reference intervals stratified by age, sex, pregnancy, specimen, or
  timing, use only the applicable interval and state the basis.
- For a possible critical value or severe current symptoms, prioritize prompt
  local clinical assessment using the source laboratory's critical-value policy
  or an applicable authoritative source; do not rely on a generic universal
  threshold.

## Output

Use four labeled sections: verified result, contextual comparison, supported
interpretation, and questions/next checks. Cite observation IDs and exact
`reviewed_claims[].claim_id` values next to each factual or interpretive
statement. End with limitations specific
to missing context, source quality, and evidence fit, not a generic disclaimer.

---
name: health-review
description: Review medical or human-science drafts for source alignment, numerical accuracy, applicability and relevant safety context. Use for personal interpretations, clinical-action drafts, material numbers, conflicting evidence or broad research; a structural report is not medical validation.
---

# Health review

Match the review to the draft. A narrow educational answer may self-check.
Dispatch an independent agent for personal interpretations, clinical action,
material quantitative claims, contradictions or broad research. Material numbers
change the main conclusion, benefit/harm, dose, risk or diagnostic decision.
Give the reviewer the minimal draft and available sources/context. Independent
agent review is model review, never human/clinician confirmation.

## Check claims

Check atomic claims separately; retain the draft's intent and claim types.
For each relevant check record `ok`, `issue`, `not_checked` or `not_applicable`,
the claim coverage, severity, source/locator, reason and needed correction:

- **Structural:** exact-kind support resolution and provenance. Bibliographic
  IDs do not substitute for substantive findings or confirmed observations.
- **Source alignment:** reread the accessible key passages and compare the claim
  with the actual population, comparator, outcome, follow-up, magnitude/CI, harms
  and limitations. Record the amount actually read.
- **Citation identity/status:** verify the source identity and material updates,
  corrections, withdrawals or retractions where relevant.
- **Applicability:** distinguish general evidence from its fit to this person.
- **Numeric:** printed figures, units, denominator, censoring, conversions,
  formula and rounding; do not treat a displayed formula as calculated proof.
- **Reasoning:** separate association/causation, clinical/surrogate/preclinical
  outcomes, inferences and contradiction handling.
- **Safety context:** relevant age/special states, conditions, medication,
  allergies, kidney/liver function, contraindications and urgent symptoms.
  Mark each necessary field known/unknown/not applicable and explain its impact;
  do not require an irrelevant full questionnaire.
- **Privacy:** inspect the actual public payload; heuristic guards do not prove
  anonymization.

The v2 `review_answer` tool accepts **public evidence drafts only**. It checks
schemas and finding lineage locally and stores separately attributed model
checks. Do not send a CaseSelection, personal lab table or private notes to it.
For personal drafts, use the existing private-data runtime when available:

1. Read `get_case_selection` with the exact subject, selection ID and hash. Use
   only its selected observations and context. Inspect the separate freshness;
   new artifacts require a current selection. An old clinical collection date
   alone does not make a current observation stale. Cached source availability
   and database freshness do not establish a live source-byte check.
2. Bind `source_fact` to a selected confirmed revision and an exact complete
   allowed row field. Preserve tagged results, censoring, units, references and
   corrected-field origin. Bind `user_note` only to a selected event explicitly
   typed as a user note; an unreviewed source statement is not a note or fact.
3. For a calculated claim, request `create_private_calculation` using exactly
   two selected comparable revisions and `delta` or `percent_change`. Use the
   returned receipt ID, hash and metric. The backend runs the production Decimal
   comparator; caller formulas and replacement results are not accepted.
4. Save the bounded draft with `prepare_private_answer`. Each claim supplies
   its ID, type, text, exact support ID and structured assertion. Read an existing
   artifact with `get_private_answer_review`; its original draft/report remain
   immutable and current freshness is returned separately. An exact acknowledged
   retry preserves its original result even after a correction; a stale case
   cannot support a new preparation.

The private backend checks the saved case graph, exact kinds, field assertions
and calculation receipts. It does not establish that prose follows from a field,
that a corrected value was literally printed, or that a clinical conclusion is
appropriate. Its report always remains `needs_revision`, with semantic, medical
and human validation `not_provided`. Perform the substantive checks above
separately and retain their coverage; never promote or overwrite that report.
If the private tools are unavailable, review the personal synthesis in the
private-context conversation and state that persisted backend resolution was
not performed. Do not fabricate a successful backend case check.

## Release

Use `ready_with_limits` only after the checks required for the claims are
complete with no unresolved material issue. Use `needs_revision` for unsupported
material claims or absent required review. Correct the draft and re-review its
new version; never relabel support to pass a validator.

Clinical-action research may be `draft_for_discussion` after substantive source
review and the relevant safety checklist. This does not authorize unsupported
personal treatment commands. A real clinician review needs documented provenance;
no boolean, reviewer ID or second model supplies it.

If the reviewer is unavailable, omit or narrow the unchecked material claim and
state the remaining coverage. Preserve urgent response priority: `urgent_redirect`
records the branch, not validation of emergency medical instructions.

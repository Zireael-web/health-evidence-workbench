---
name: route-science-question
description: Classify scientific or health questions by data sensitivity, evidence need, and trust zone before any tools run. Use for new requests, ambiguous workflows, mixed private and public inputs, or deciding which workbench skill and artifact should come next.
---

# Route Science Question

Choose the smallest safe workflow before reading broadly or calling tools. The
route must keep private source material, public metadata retrieval, offline
synthesis, and review logically separate. A route record is policy metadata,
not proof that the root Codex task is isolated.

Read [references/trust-zones.md](references/trust-zones.md) before routing a
mixed-data request.

## Routing workflow

1. Restate the decision the user needs in one sentence. Do not copy direct
   identifiers into the restatement.
2. Classify every proposed input as private source material, de-identified case
   fact, public research question, public evidence, or draft answer.
3. Identify the operation: ingest, interpretation, public retrieval, guideline
   comparison, offline synthesis, update monitoring, or audit.
4. Select exactly one trust zone for the next step. Split the workflow when the
   request needs more than one zone.
5. Define the input and output contract, prohibited data, verification gate,
   and stop condition before dispatching.

Use `route_science_question` in the active MCP zone when available, but verify
its proposed route against the matrix below. Routing metadata never authorizes
a data transfer by itself. Its route stages distinguish metadata discovery,
fresh-task source review, reviewed-claim issuance, offline synthesis, runtime
audit, and logical export review. Do not collapse source review into metadata
discovery or runtime audit into `review_export`.

In the configured Health Analyzer project, route every private-archive or
complete-history request directly to the `private-ingest` project agent with
`fork_turns="none"`. The Codex Desktop task and private agent share the
read-only archive profile because the parent's live permissions are reapplied
to subagents. An archive deny is a configuration error, not evidence that the
private MCP or model vision is unavailable. Never ask for file paths when the
request is archive-wide.

## Route matrix

| Need | Agent / zone | Required input | Expected output |
| --- | --- | --- | --- |
| Sync or inspect a complete private history | `private-ingest` / private | configured opaque single-subject roots | unverified review queue + verified longitudinal record view |
| Parse a specific local report | `private-ingest` / private | one single-subject root + local source | reviewed, issued `CasePacket` ID |
| Find literature metadata | `public-research` / public | de-identified question | retrieval receipts and metadata items |
| Inspect official/primary source content | `source-review` / public live web | inspected de-identified handoff; fresh task when hard separation is required | locator-rich source-review record; no claim issuance |
| Issue reviewed study evidence | `public-research` / public | retrieval receipt + independently inspected source claim | EvidencePacket 1.3 with reviewed finding/effect/harm claim IDs |
| Discover current guidance | `source-review` / public live web | de-identified question + domains/jurisdictions/risk level | official-source plan + locator-rich currentness review |
| Resolve/issue guidance | `public-research` / public | question + topic/date/jurisdiction + source-reviewed lazy-cache records | resolved IDs, exact guidance-review receipts, then EvidencePacket 1.3 reviewed guideline claim IDs |
| Monitor a prior public packet | `public-research` / public | exact issued EvidencePacket ID + de-identified baseline query | canonical loaded baseline + versioned metadata delta |
| Interpret verified observations | `offline-synthesis` / synthesis | minimal verified packet | supported claims or `AnswerBundle` |
| Combine case and evidence | `offline-synthesis` / synthesis | issued case/evidence packet IDs | claim ledger + `AnswerBundle` |
| Inspect and structurally check public claims | `audit-review` / audit | public answer + issued EvidencePacket ID | bounded packet inspection + read-only structural findings |
| Structurally check a complete bundle | `offline-synthesis` / synthesis | AnswerBundle + issued case/evidence packet IDs | complete structural audit findings |

Never send a raw document, local private path, direct identifier, vault
reference, or full `CasePacket` to the public zone. Derive the minimum
de-identified question in the explicit offline `deidentification_handoff`
substage, have a human verify it, then start a fresh public task.

A substantive public-evidence route is ordered as: `metadata_discovery` in
`public_research`, `source_review` in a fresh live-web task, then
`claim_issuance` back in `public_research` after a separate exact confirmation.
The source-review record is not itself a reviewed claim. A public-only answer
audit uses the no-network `audit` runtime; a complete case-plus-evidence bundle
uses synthesis-zone `audit_answer_bundle` instead.

The bundled public tools return PubMed/Crossref bibliographic metadata, plan
on-demand guidance discovery from a validated official-source catalog, and
query a lazy local guidance cache. The MCP itself does not retrieve article or
guideline full text; the fresh `source-review` stage uses live public web access.
Metadata item IDs cannot support substantive claims.
Source-inspected study claims require registration, exact confirmation, and
receipt-backed packet issuance. Registry HMACs establish local guidance-record
integrity only, not source review. Substantive guideline claims require
`resolve_guidance`, per-recommendation `register_guidance_claim_candidate`,
exact independent `review_guidance_claim_candidate` confirmation of wording, native
grade, provenance, limitations, source root, and semantic snapshot (which
excludes only `retrieved_at`), then `store_guidance_evidence` with selected
recommendation IDs and exactly covering review receipts. The built-in audit
validates support links and coded rules;
semantic entailment and clinical applicability remain source-level review.

Use `$inspect-public-source` for that source-level inspection. In the supported
single-task Codex Desktop mode, first create and visibly inspect a minimal
de-identified handoff, then dispatch with `fork_turns="none"`; its live
WebSearch does not traverse the plugin identifier hook. Do not include names,
dates of birth, local paths, report excerpts, or other case identifiers. Use a
fresh public-only project task instead when hard information-flow separation is
required. For an
informational answer, its cited record may be used directly with an explicit
live-review label. Personal-context or clinical-action routes must cache the
selected source snapshot and complete a second exact review. Clinical-action
research may proceed, but packet issuance must stop with
`needs_clinician_confirmation` because this release has no typed clinician
receipt. A source-review record is not an approved
packet claim and is never a substitute for a source-document hash when the
registry path is required.
Treat individualized treatment selection, dose, procedure, contraindication,
or another patient-specific action as `clinical_action`; never route it as
`personal_context` to bypass the issuance block.

When strict information-flow separation matters, do not implement this matrix
as subagents of one root task. Use separate tasks/processes or OS identities and
transfer only reviewed minimal packets. The `audit-review` agent uses a
dedicated read-only, no-network audit MCP whose loader accepts only one exact
issued public packet ID and whose validator accepts no replacement packet.
`review_export` remains a logical operator stage with no authenticated
publication gate.

## Safety gates

- If the request describes current severe symptoms or an emergency, surface
  the need for urgent local medical assessment before the research workflow.
- If medication initiation, discontinuation, or dose change is requested,
  route to evidence synthesis for clinician discussion; do not issue a
  patient-specific directive.
- If units, identity, date, specimen, source attribution, or reference interval
  are ambiguous, route to verification rather than interpretation.
- If the user asks for evidence but supplies identifiable case details, stop
  and request a de-identified question.
- Treat the privacy gate as heuristic. It catches labelled US phone formats but
  does not reject arbitrary Title Case pairs solely for capitalization. Have a
  human inspect unlabelled lowercase or non-suffix names and other identifiers
  that deterministic patterns may miss.

## Route output

Return a compact route record containing:

- `decision`: one of `private_ingest`, `public_research`,
  `source_review`, `offline_synthesis`, `audit`, or `review_export`;
- `reason`: why this is the minimum safe zone;
- `allowed_inputs` and `prohibited_inputs`;
- `next_skill` and tools allowed in that step;
- `expected_artifact` and its verification gate;
- `open_questions`, `limitations`, and explicit stop conditions.

When returning a multi-stage plan, include each stage's `substage`,
`next_skill`, and `fresh_task_required` values unchanged. A source-review stage
must have `next_skill=inspect-public-source` and
`fresh_task_required=true`; reviewed-claim issuance must occur only after it.

Do not perform the downstream task while routing unless it is wholly contained
in the selected zone and the required inputs are already verified.

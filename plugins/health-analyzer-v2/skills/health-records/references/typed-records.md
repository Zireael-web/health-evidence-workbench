# Optional typed records and history


1. Select the subject and the file actually supplied by the user. Use
   `prepare_attachment` for that explicit local file, or `prepare_import` for
   approved configured input references. Do not infer an archive path or
   enumerate legacy state. Attachment intake does not change archive bindings.
   Compare visible report identity with the chosen profile before confirmation.
   Conflicting or absent identity stays unresolved; never combine people because
   documents share a folder, analyte or date.
2. Intake preserves a scoped, hash-checked original. Existing PDF text and
   explicit text/CSV tables can supply native proposals. Local OCR is disabled,
   including fallback. A photograph or unreadable PDF page needs ChatGPT/Codex
   visual transcription in this dialogue; backend tools do not call a model.
   Identical input may reuse historical extraction, including old OCR data;
   reuse does not mean a new recognition or review occurred.
3. For PDF viewing, use `prepare_document_view` and open its verified `.pdf`
   copy in the native file panel. `get_document_view` is read-only. For model
   inspection, `render_document_pages` produces source-bound PNG pages in an
   explicit host deployment. An enforced runtime returns a limitation and the
   native PDF view instead of retrying outside its policy. Source pixels and
   original bytes remain separate from any transcription.
4. Save the complete page-by-page model transcription with `save_document_text`
   (`model_vision` or `manual_transcription`) before or alongside typed proposals.
   Keep uncertain readings explicit; do not replace them with plausible values.
   `get_document_text` retrieves the saved text without the short import-preview
   truncation. A saved full supplied transcript does not prove that every source
   page was read or every value is correct. Preserve older transcripts.
5. Read `get_review_snapshot` and `get_source_version` before visual review. Use the saved version
   when an archive occurrence has changed or disappeared; report archive drift.
   A damaged saved copy blocks review and must never be silently replaced with
   current bytes. Older records without saved originals keep their prior source
   behavior; this workflow does not backfill them automatically.
6. Read `list_import_issues` alongside the typed rows. It retains missing or
   unsupported cells, prior columns and historical recognition warnings.
   Alternatives are hypotheses. Visually inspect the necessary saved fragments
   and use `submit_visual` for whole unresolved pages, or
   `resolve_import_issue(action="propose")` for a source-bound row. Bind a row
   proposal to the displayed `current_run_id`, `current_selection_token` and
   latest event; it creates an unreviewed draft, not a confirmation. Preserve
   unresolved rows with `defer`; record `discard` only with a clear stated
   decision. Neither action deletes the source or its issue history.
   A blank result is uncertainty, not an explicit no-result report. Preserve
   merged unit/reference cells and narrative references as ambiguous until
   source review separates or explains them. Check header/date/cell intersections
   in transposed tables; keep dates, methods and specimens within their section.
   Visually transcribe photographs from the verified saved original in Codex
   and use `submit_visual` for whole rows. Resolve disagreements against pixels and retain
   doubts; model agreement does not become human confirmation.
   Native PDF boxes locate the text layer, including possibly invisible text.
   Check material values and dates against rendered pixels. Old extraction may
   retain OCR readings and alternatives; do not rerun OCR. Historical recognition
   receipts and confidence do not establish correct Cyrillic, decimal
   separators, micro prefixes or exponents. `unit_code` is proposed notation beside
   `unit_raw`, without value conversion. Conflicting prefixes, unknown units and
   uncertain glyphs need source review and explicit correction; do not repair text
   by choosing a clinically plausible spelling.
7. Preserve analyte wording, result kind (`<`/`>` and qualitative values included),
   original unit, clinical date and its role/precision, laboratory reference,
   flags, specimen, method and per-field source anchors. Missing fields remain
   null with a reason. A date of import is not a date of collection. Keep user
   notes and calculated values separate from source observations.
8. Prepare frozen review pages of whole rows; show values and source fragments
   together. Explain critical uncertainty before requesting a decision. One
   explicit user decision may confirm the displayed panel. Bind decisions to
   the returned snapshot ID/hash; correct, reject or defer individual rows.
9. Commit only the actual user decisions. Conversation provenance is attested,
   not authenticated; a model self-check or invented reviewer ID is not human
   confirmation. Do not request an operator/migration assurance flag.

Use the returned coverage to state what was extracted, pending or not inspected.
Visual proposals keep expected count unknown; caller counts do not prove coverage.
Page limits are not document limits. Do not report a complete archive or panel
when source coverage is unknown. Historical confidence is a heuristic; source
warnings stay visible. Review conflicts or a changed
extraction selection require a new frozen preview. Returning to an earlier
extraction does not resurrect a stale preview. Verification uses the exact saved
byte version; its integrity and the current archive path are separate checks.

## Optional: typed history and comparisons

Query existing records before importing the same archive again. Use clinical
time for the timeline and `recorded_as_of` for what the system knew at a point in
time. An unknown date remains contextual. Corrections create new revisions; keep
old revisions visible in history. A renamed file or unavailable source does not
delete a confirmed observation.

Do not infer that two reports are duplicate or that a newer file supersedes an
older clinical result. Record an explicit relation only with a stated basis and
user decision. Unresolved conflicts remain visible.

Use `compare_observations` and present `included`, `contextual_only`, exclusions,
coverage and source availability. Do not join unknown/incompatible methods,
specimens or analytes into a trend. Censored values are bounds, not exact points;
normality uses each result's own reference and does not establish diagnosis.
Retain conversion rule, source revisions and rounding for derived numbers.

For a typed-record explanation, select a minimal saved case context and use
`health-research` in the main conversation. Private context is never an argument
to the public MCP. This skill does not migrate legacy records or delete sources.
For a file-only explanation, use the saved text and matching original as above;
no private MCP or typed case selection is required.

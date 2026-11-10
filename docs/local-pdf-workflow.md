# Local PDF workflow (no MCP required)

This is an explicit alternative for a user-authorized local report intake when
the app's MCP connection is unavailable. It does not read Keychain, `.env`, a
vault, or the old private state, and it does not change host access restrictions.
It does not issue a CasePacket, medical verification receipt, or clinical clearance.

## Simple folder workflow with model text

For the ordinary document task, keep a PDF and its complete model-transcribed
UTF-8 text together in the person's explicitly selected existing folder. A
selected ChatGPT/Library attachment must first be materialized to its actual
host path with the current Library tools; the local PDF API cannot download an
attachment ID. File permissions remain those of the current executor.

1. Copy the selected PDF with `copy_authorized_pdf(source, archive_root)` from
   `health_analyzer.local_intake`; retain the returned path and SHA-256. This
   helper does no PDF decoding, OCR, network, database or Keychain work.
2. Open that preserved PDF in the native file panel. ChatGPT/Codex reads all
   actual page images, with the existing bounded renderer when available.
   Respect decoder sandbox failures; no OCR or silent unsandboxed retry.
3. Write the full model transcription, page separators and explicit doubts to
   a private UTF-8 staging file. Publish it next to the preserved PDF:

   ```sh
   /path/to/health-evidence-workbench/.venv/bin/python -I -B /path/to/health-evidence-workbench/scripts/ha-local save-text /selected/person/report.pdf --text-file /private/staging/model-text.txt --expected-sha256 <preserved-pdf-sha256>
   ```

   The source entry loads code relative to its own location and works outside
   the repository directory. It uses the existing interpreter without an
   environment install.
   This creates `/selected/person/report.txt` without altering the PDF.
   The PDF hash must still match. UTF-8 whitespace and trailing text are kept
   byte for byte, up to 8 MiB. An identical retry succeeds unchanged; different
   existing text is a conflict, never a replacement or new version. No local
   parser or OCR is invoked by `save-text`; it saves only supplied model text.
4. Search/read the saved TXT and its matching original using ordinary file
   tools. Answer in the conversation with current primary sources/guidelines
   and relevant uncertainty. Public searches receive only a minimal question,
   never the original report, private paths or identifiers.

The commands are for the assistant, not user setup. The existing typed-record
pipeline remains optional. This simple path creates no records/history store,
review receipt, migration or background audit. Saving all supplied text does not
prove that every page was correctly read; model text remains unverified.

## One-report workflow

1. A private document agent inspects identity locally and resolves the intended
   single-patient archive. Never infer a patient root from a similar filename.
2. Inspect the PDF in bounded child processes. Every page must be represented,
   including pages without native text. Render and visually check tables and
   image-only content. A text extraction result is not a verified lab result.
3. Only for an explicitly authorized intake, copy the exact inspected bytes to
   the confirmed archive. The source and existing archive files are unchanged.
4. Save a separate new extraction/review artifact outside source control. Keep
   printed dates, units, references, page locators, source SHA-256, ambiguous
   readings, and machine versus model-visual review status.
5. Compare only compatible same-patient observations. Keep date-of-birth or other
   identity conflicts visible; do not silently merge them. Public research gets
   a minimal de-identified question, never original documents or identifying text.

Example commands use fictional paths and do not require the user to run them:

```sh
uv run health-analyzer local-pdf inspect /absolute/report.pdf --output /absolute/new/extraction.json
uv run health-analyzer local-pdf ingest /absolute/report.pdf --archive-root /absolute/confirmed-patient --output /absolute/new/intake.json
uv run health-analyzer local-pdf render /absolute/report.pdf --isolation host --render-parent /absolute/review --output /absolute/new/pages.json
```

## Explicit host mode

The default preserves the nested parser sandbox on macOS. Select `--isolation
host` in advance only for an expressly authorized standalone operation under
the caller's existing permissions. Some managed desktop environments cannot
start an additional `sandbox-exec` process and return `sandbox_apply: Operation
not permitted` before reading a PDF. Such a denial stops the affected operation;
do not retry it outside that sandbox or change permissions to make it succeed.

The separately selected host mode uses the same bounded PDF worker protocol, CPU/memory/time/input/text
limits and page provenance. It keeps existing host permissions; it does not
remove a host file-access denial. It makes no network requests. Its Python socket
guard is defense in depth, **not an OS-enforced network sandbox**. The output
records this distinction. Existing MCP extraction never silently falls back.

## Intake and completeness guarantees

- Only regular, non-symlink PDFs, at most 64 MiB, are accepted.
- The intake is bound to the inspected SHA-256, uses no-replace atomic
  publication, and verifies the resulting digest. A byte-identical existing
  destination is an idempotent success; different existing bytes are a conflict.
- Hard limits fail without a partial extraction result. Missing native text is
  retained as `needs_visual_review`; all extracted values remain `needs_review`.
- `extraction_complete` means native-text page coverage, not complete visual
  transcription, medical correctness, or a finding that every result is normal.
- Rendering creates a fresh private child directory and an exact page inventory.
  The standalone renderer requires explicit host mode; it does not silently
  reuse the text parser's more restrictive profile, which permits no image writes.
- CLI JSON output is new-file-only with mode 0600. If saving a derived artifact
  fails after a successful intake, the source archive copy remains; retrying
  that exact intake is idempotent. No rollback deletes patient records.

The private document agent performs the subsequent visual/value review; a
medical explanation must name unresolved data and evidence limitations. A
standalone local artifact is not an issued or HMAC-verified workbench packet.

# Local PDF workflow (no MCP required)

This is an explicit alternative for a user-authorized local report intake when
the app's MCP connection is unavailable. It does not read Keychain, `.env`, a
vault, or the old private state, and it does not change host access restrictions.
It does not issue a CasePacket, medical verification receipt, or clinical clearance.

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

The default preserves the nested parser sandbox on macOS. Some managed desktop
environments cannot start an additional `sandbox-exec` process and return
`sandbox_apply: Operation not permitted` before reading a PDF. If the user has
authorized this local fallback, the agent may select `--isolation host` itself.
There is no need to ask the user to repair MCP or change their app settings.

Host mode uses the same bounded PDF worker protocol, CPU/memory/time/input/text
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

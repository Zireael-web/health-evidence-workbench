# Security and privacy

## Reporting a vulnerability

Do not disclose exploitable details, credentials, health records, screenshots
of local archives, or personal identifiers in a public issue, discussion, pull
request, or commit.

If the repository host provides private vulnerability reporting, use that
channel. Otherwise, open a minimal redacted issue requesting a private reporting
path from the maintainers. Do not attach the sensitive material to that issue.

## Before publishing a change

1. Confirm that only synthetic fixtures are included.
2. Check the staged file list with `git diff --cached --name-only`.
3. Search staged content for local paths, credentials, and identifiers.
4. Ensure runtime state, archives, exports, `.env` files, keys, and databases
   remain outside version control.

Example local scan:

```bash
rg -n -i '/path/to/local-resource KEY|gh[pousr]_\w+|github_pat_|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}' \
  --glob '!*.lock' --glob '!.git/**' .
```

Treat a clean pattern scan as a useful check, not proof of anonymization.
Review filenames, image metadata, binary documents, Git history, and the
repository account/profile separately.

## Security boundaries and limits

- Private/local and public/networked roles are designed to be separate, but a
  shared task, host account, or process is not a hard confidentiality boundary.
- HMAC-backed receipts provide tamper-evidence for selected local data. They do
  not encrypt records or prove the truth, clinical relevance, or currentness of
  a source.
- The project is not a medical device and does not provide medical advice.

# Contributing

Thanks for improving Human Science Workbench.

## Ground rules

- Never add real health records, screenshots, local exports, credentials, or
  personally identifying information.
- Use clearly fictional, documented synthetic fixtures only.
- Keep paths portable. Derive a repository path at runtime or use a documented
  `/path/to/...` placeholder in examples.
- Preserve the distinction between metadata discovery, source review, data
  integrity, and clinical decision-making.
- Do not describe the software as diagnostic, therapeutic, or clinically
  validated.

## Suggested workflow

1. Create a focused branch.
2. Add or update tests for behavior changes.
3. Run `uv run pytest`.
4. Run the privacy checks in [`SECURITY.md`](SECURITY.md).
5. Review every staged filename and diff before opening a pull request.

## Documentation changes

Keep examples generic and use fictional data. State important limitations near
the relevant feature instead of relying on a disclaimer elsewhere.

## Licensing

The repository metadata is currently proprietary. Do not assume that a public
repository grants permission to redistribute or relicense the code.

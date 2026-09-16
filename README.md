![Health Evidence Workbench — illustrated project overview](docs/assets/cover.svg)

# Health Evidence Workbench

[Quick start](#quick-start) · [Features](#what-it-contains) · [Privacy model](#privacy-model) · [Documentation](docs/architecture.md)

**Python 3.11+ · Local-first · MCP**

Local-first research and developer tooling for evidence-oriented human-science
workflows in Codex. It separates local document handling from public metadata
research and records structured provenance instead of presenting an automated
clinical conclusion.

> **Not medical advice or a medical device.** This MVP does not diagnose,
> prescribe, triage emergencies, establish clinical validity, or replace a
> qualified clinician.

## What it contains

- PubMed and Crossref bibliographic-metadata clients;
- a catalog-driven workflow for inspecting official guidance and primary
  sources;
- local, read-only document-ingestion primitives and synthetic fixtures;
- typed `CasePacket` and `EvidencePacket` handoff contracts;
- structural claim-to-support auditing and review-ledger helpers;
- optional laboratory and ambulatory-monitoring utilities;
- Codex skills, a public MCP server, and example patient/decision-card views
  using fictional data only.

## Privacy model

This public repository deliberately contains **no real PHI, medical source
documents, local runtime databases, credentials, or user-specific paths**.
Private archives belong outside the clone; all runtime state must remain local
and is ignored by Git. Before committing, inspect the exact staged files rather
than relying only on `.gitignore`.

The project uses logical trust zones:

| Zone | Intended role | Network | Raw private records |
| --- | --- | --- | --- |
| `public` | Metadata and source discovery | Allowed | Forbidden |
| `private` | Explicit local review | Forbidden | Allowed locally |
| `synthesis` | Packet-based offline assembly | Forbidden | Forbidden |
| `audit` | Read-only structural validation | Forbidden | Forbidden |

These boundaries are defense in depth, not a guarantee of anonymity or tenant
isolation. A shared process, task, or operating-system account can still carry
information across a boundary.

## Quick start

Requirements: Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --extra dev --extra mcp --extra documents
uv run pytest
uv run health-analyzer --help
```

Copy `.env.example` into a local, ignored configuration file only when needed.
Use placeholder paths such as `/path/to/private-archives`; never commit a
real archive path, patient identifier, API key, or pseudonymization key.
To use the bundled MCP configuration, set `HEALTH_ANALYZER_PROJECT_ROOT` in
your local environment to the absolute path of this clone. The placeholder is
intentional: a portable public config must not embed an operator's path.

The macOS public-MCP wrapper is integrity-pinned. Rebuild the pin after a
reviewed runtime change:

```bash
scripts/update-runtime-manifest
scripts/run-public-mcp --expected-runtime-manifest-sha256 \
  115a0ec00a0a5f4ee3ebace26e0c48a8f650c10377619dd9279b71e630f5b109
```

The wrapper is intentionally conservative and expects a local macOS runtime.
For portable development, use the CLI and tests above. See
[`docs/architecture.md`](docs/architecture.md),
[`docs/operations.md`](docs/operations.md), and
[`docs/local-pdf-workflow.md`](docs/local-pdf-workflow.md) for workflow detail.

## Important limits

- Bibliographic metadata is not full-text evidence and does not by itself
  support a medical claim.
- A source or guideline cache can become stale; currentness and applicability
  require source-level review.
- HMAC receipts support local tamper detection only. They are **not**
  encryption, a digital signature, reviewer authentication, source
  verification, or clinical review.
- De-identification checks are heuristic. Human review is still required before
  any public transfer.
- Synthetic examples demonstrate data flow, not complete clinical coverage or
  a recommendation.

## Contributing and security

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before submitting a change. Privacy,
credential, and vulnerability reporting guidance is in
[`SECURITY.md`](SECURITY.md). Do not place sensitive material in public issues,
pull requests, fixtures, logs, or screenshots.

## License

The project metadata currently declares the work **Proprietary**. Public
visibility does not grant a reuse license; see the repository owner for any
licensing decision.

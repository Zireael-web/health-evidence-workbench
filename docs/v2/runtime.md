# Parallel v2 runtime

This increment creates a new deployment alongside legacy code. It does not
read, migrate, delete or write a legacy store, archive, credential or active
plugin configuration. The CLI and stdio MCP transports use the same services.
There is no HTTP endpoint, automatic plugin activation or migration command.

## New namespace

Choose an absent or empty data root and a configuration path outside it:

```sh
python3 -I -B scripts/ha-v2 --config /absolute/new/config.json init \
  --data-root /absolute/new/v2-data --isolation host
```

The configuration parent must already exist. `host` is an explicit development
mode with logical service separation. It does not deny filesystem/network
access to the process. Use `--isolation macos_enforced` for a fail-closed macOS
Seatbelt launcher. This implementation has not established deployment readiness
until the listed doctor and PDF/plugin checks have passed on the intended host.
Do not silently fall back from enforced isolation to host mode.

```text
v2-data/
  .health-analyzer-v2.json
  private/private.sqlite3
  private/tmp/
  private/originals/  # created only by explicit new intake
  public/public.sqlite3
  public/tmp/
  keys/private-data.key
  keys/public-research.key
  bootstrap/
  bootstrap/native/  # trusted compiled helper; private child cannot replace it
```

Initialization creates independent random 32-byte keys and marked v2 SQLite
stores. Existing nonempty roots/configurations are rejected. A failed init may
leave an incomplete new namespace for explicit inspection; it never cleans up
arbitrary user files. JSON configuration is strict and contains deployment ID,
data root, isolation mode and explicit archive-to-subject bindings. Relative
paths resolve against the configuration file. Archive roots and data roots
cannot overlap, nor may archive bindings overlap each other or traverse
symlinks. Configuration cannot be created inside an archive. Bounded readers
open files without following symlinks and without blocking on FIFOs before
validating that they are regular files. No default live archive is supplied.
Data/archive roots cannot overlap shared package, interpreter or approved system
runtime read roots. The configuration itself cannot reside inside shared
runtime code/libraries. This prevents library grants from exposing private
sources, databases or domain keys to the public process/PDF worker.

An optional `--archive-bindings /absolute/bindings.json` file contains:

```json
{"demo":{"path":"/absolute/synthetic/archive","subject_id":"subject_demo"}}
```

Register the subject through `register_subject` before importing its documents.

## Service CLI and two stdio surfaces

```sh
python3 -I -B scripts/ha-v2 --config /absolute/new/config.json call \
  --zone private-data --tool query_history --arguments-file /absolute/request.json
python3 -I -B scripts/ha-v2 --config /absolute/new/config.json serve \
  --zone private-data --transport stdio
python3 -I -B scripts/ha-v2 --config /absolute/new/config.json serve \
  --zone public-research --transport stdio
```

Core calls need Python 3.11+ and standard library only. `serve` additionally
needs the optional `mcp` extra in the **selected interpreter**. Use that
interpreter explicitly; a copied/relocated console-script shebang is not used.
The repository launcher derives its code root from its own location and
injects only the `src` directory under `python -I -B`. Bootstrap subsequently
launches the packaged `health_analyzer/v2/entry.py`, which derives its library
directory from its own path. An installed noneditable package does not need
checkout `scripts/` files. Generated registration uses that packaged entry.

Private tools: `register_subject`, `prepare_import`, `submit_visual`,
`prepare_review`, `commit_review`, `query_history`, `correct_observation`,
`set_document_relation`, `compare_observations`, `select_case_context`,
`record_context_event`, `export_history`, `refresh_source_status`,
`get_source_version`, `list_import_issues`, `resolve_import_issue`.
History is a persisted projection, not an implicit filesystem scan.
`refresh_source_status` performs bounded source checks and records availability
as of that check; a caller cannot submit an arbitrary availability boolean.
Caller-supplied `register_document` hashes and extraction
registration are not a transport surface. The source checker is wired into
review commits. Model callers cannot select `operation_context=operator` or
`migration`, or upgrade an attestation to authenticated human provenance.

Public tools: `plan_search`, `execute_search`, `get_search_results`,
`register_source`, `record_source_access`, `fetch_source_abstract`,
`record_finding`, `build_dossier`, `review_answer`. No provider is enabled by
default; without one, `execute_search` returns `provider_unavailable`. Explicit
`research_provider: {"name": "pubmed"}` enables the bounded PubMed adapter.
The local preparation helper configures it but does not test live network access.
See [research contracts](research.md) for scope and limits. Public
answer review accepts public evidence only; it does not resolve personal
case facts. Personal interpretation remains a model orchestration operation
over minimal selected facts, with separate substantive review when required.

Both transports reject unknown top-level arguments. MCP 2 schema hardening is
an explicit compatibility seam: incompatible SDK internals fail closed.

## Bootstrap and isolation

The trusted bootstrap validates the deployment marker, reads exactly one new
domain key and closes its file. It sends the key and runtime configuration over
separate anonymous inherited FDs. No raw key appears in argv, env, stdout or
plugin assets. Public runtime configuration contains no archive bindings. The
runtime closes its inherited key FD after reading it. Domain integrity remains
HMAC integrity, not semantic correctness or human identity authentication.

In `macos_enforced`, a generated default-deny Seatbelt policy permits runtime
code/system Python libraries, domain SQLite/temp access and (private only)
read access to the configured archives. Archive writes, domain key files and
Keychain contents are denied. Private network access is denied. Public archive
and private-store contents are denied. File metadata is globally readable for
interpreter path traversal, and the exact `/` directory can be enumerated for
macOS Python startup; neither grant permits recursive file-content reads. This
is not a denial of all path metadata. Public
outbound networking is enabled at the OS level; provider/content controls are
adapter responsibilities, not a claimed Seatbelt hostname allowlist.

The bootstrap uses inherited host permissions. Shared ChatGPT/Codex context may
also contain selected private facts. Neither host bootstrap nor the parent
model is made an isolated public actor by naming its process/skill.

macOS on the tested host refuses applying a second Seatbelt profile to a
process that inherited the private runtime sandbox, even when the first
diagnostic profile permits all operations. Therefore private PDF extraction
uses a byte-only launch bridge in the **existing trusted bootstrap process**.
The private runtime sends bounded PDF/PNG/JPEG bytes through two anonymous inherited
pipes. The bootstrap launches the fixed resource-bounded parser under the
mandatory narrower PDF profile; its worker receives no archive paths, database
handles, keys or command controls. There is no third permanent server, HTTP
listener, arbitrary command endpoint or unsandboxed PDF fallback. The parser
profile is separately applied, not stacked on the runtime's inherited profile.
The bootstrap does not parse document/image objects itself. Native PDF text uses
local Poppler word boxes when its fixed bundled binary is available and trusted,
otherwise the existing fixed Python worker. Poppler executes through a dedicated
mandatory no-network profile and bounded Python supervisor. The binary is selected
by the trusted bootstrap, never by source input, PATH or a transport argument.
Its source XML is parsed only inside that sandbox. Timeout/limit cancellation
kills the worker's owned process group including the decoder. The geometry path
caps 64 MiB input, 32 MiB output, 500 pages, 50,000 words and 8 MiB text. Native
word boxes describe the PDF text layer, which can include invisible text; they
are source locators rather than a visual confirmation of printed content.
Local OCR is disabled, including image/PDF fallback, helper compilation and
direct legacy OCR adapter calls. Historical OCR payloads remain readable data.

For photographs and PDF pages without existing text, ChatGPT/Codex reads the
verified original in the dialogue and submits model_vision proposals. The local
backend never calls a model or an OCR service. Native text and missing-page
inventory stay separate; unprocessed pages remain visible.

Explicit selected-file intake preserves the original without adding an archive
binding. Full model/native transcripts are immutable per-page text, stored
separately from the short intake preview. See document-intake.md.

prepare_document_view creates an exact protected viewer copy with a real file
extension; get_document_view is read-only. Host deployments may explicitly
render PDF pages with the existing bounded Poppler renderer, which performs no
recognition. Enforced private runtimes return the native-view path and a render
limitation; they do not change policy or silently retry outside their sandbox.

Private runtime permits literal ancestor directory reads needed for descriptor
traversal of the original-copy namespace; it does not recursively grant contents
of those ancestors. Original blobs use no-follow descriptor access, subject scope,
owner checks and full byte hashes. Archive access remains read-only.

Bridge input is capped at 64 MiB, response at 32 MiB, requests are serialized
and deadline-bounded. Failed IPC/validation closes the channel and returns a
typed error. Public runtime cannot receive bridge descriptors. Host-mode
private intake continues to use the mandatory direct parser Seatbelt on macOS.

## Doctor and inactive deployment assets

```sh
python3 -I -B scripts/ha-v2 --config /absolute/new/config.json doctor
python3 -I -B scripts/ha-v2 --config /absolute/new/config.json deployment-assets \
  --output-dir /absolute/new/inactive-registration
```

Doctor creates and removes synthetic canary files only in the new v2 namespace.
It never opens archive contents or legacy DBs. Host mode reports
`logical_host_only`/`not_enforced`. Enforced mode runs actual subprocess probes:
own-domain read allowed, other-domain read denied, and private network denied.
Connection refusal is **not** treated as network denial. An unavailable nested
sandbox yields an unavailable/failed result. Passing these probes reports
`partial`, not complete readiness; PDF bridge/worker, installed plugin-cache
matching and Keychain content canaries remain explicit gates.

Generated MCP registration is inactive, requires separate deliberate host
registration, and pins stdio for each zone. It contains current interpreter,
configuration and code paths, so regeneration and doctor are required after
relocation. Checked-in plugin assets expose only public research and require
explicit `HEALTH_ANALYZER_V2_CODE_ROOT`/`HEALTH_ANALYZER_V2_CONFIG`; they are an
uninstalled template and provide no live defaults. No existing plugin is
replaced. The three skill assets live in `plugins/health-analyzer-v2/skills/`.

Startup errors omit raw input objects and secrets. Service error codes preserve
the underlying typed error. Standard stdout is reserved for JSON CLI results
or the stdio MCP protocol.

## Local plugin installation and hook review

The checked compatibility manifest explicitly declares `./skills/`,
`./.mcp.json` and `./hooks/hooks.json`. It packages exactly `health-records`,
`health-research` and `health-review`. Its MCP entry is public-only; private
registration remains a separate explicit deployment asset. This layout is
supported by the [official plugin packaging documentation](https://developers.openai.com/plugins/build/plugins).

Use a new marketplace name `health-analyzer-v2-local` and a new deployment-local
catalog, retaining the old marketplace and cache. In that catalog, the v2 entry
uses `source: {source: "local", path: "./plugins/health-analyzer-v2"}` relative
to the marketplace root. The installed CLI `0.162.0-alpha.17.2` advertises:

```sh
codex plugin marketplace add /absolute/new/marketplace --json
codex plugin add health-analyzer-v2@health-analyzer-v2-local --json
codex plugin list --marketplace health-analyzer-v2-local --json
```

Render `.mcp.json` in the deployment-local plugin copy with the actual selected
interpreter and packaged `entry.py` plus explicit configuration and
`serve --zone public-research --transport stdio`. This avoids relying on GUI
environment inheritance or unresolved `${HEALTH_ANALYZER_V2_*}` placeholders.
Keep source templates portable. Installation loads the cached plugin copy, so
verify installed manifest, skills, launcher and hook hashes against that copy.
Refresh/restart the app as needed and test a fresh chat; installation success
does not prove new tools have loaded into an already running turn.

Installing the plugin does not grant hook trust. Review the installed definition
through `/hooks`, trust that exact version, check it is enabled, then run a
synthetic denial canary through its actual canonical public MCP tool name.
The [official hooks documentation](https://learn.chatgpt.com/docs/hooks) describes
this review and the supported `PreToolUse` denial shape. On the inspected CLI,
there is no `codex hooks` subcommand; its generated experimental app-server
protocol exposes `hooks/list` (including `currentHash`, `enabled`, `key` and
`trustStatus`) but no hook-trust write endpoint. Do not forge a trust file or use
`--dangerously-bypass-hook-trust` as installation verification.

`public_guard.py` is self-contained, reads only the hook event's input and
does not open transcripts, configuration, archives or credentials. Its matcher
targets v2 public research tools. It blocks explicit private keys, local paths,
labelled personal identifiers, email addresses and formatted phones; it leaves
public IDs, publication dates and other plugins/private tools alone. Malformed
or oversized events produce a supported explicit denial without echoing their
contents. This is heuristic defense in depth: hosted WebSearch is outside the
hook path, and an untrusted/disabled hook or host hook failure may skip it.
Runtime input validation and minimal public prompts remain necessary. Under
repository operating rules, model public plugin calls remain gated until
installed hook trust, enablement and the denial canary are verified.
Known private observation/revision/document/version/snapshot/context/case and
extraction artifact IDs are blocked even inside a free text or support list.
Public source/plan/run/review IDs remain allowed. Inspection limits apply to a
2 MiB event, 32 KiB individual scalar and 10,000 visited values; they do not
apply the scalar cap to the entire public draft. Oversized public drafts get an
explicit instruction to split into complete claim batches and review every
batch, rather than an assertion that private identifiers were found.

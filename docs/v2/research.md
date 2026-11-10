# Public research and review

The v2 scientific service retains public plans, executed pages, metadata,
source-text captures, findings and model-attributed review. These operations do
not read or migrate legacy stores, keys or medical archives.

## Configuration and API

`ScientificResearchService(store, provider=None)` requires a v2 `public-research`
SignedStore. A deployment without a provider still returns `provider_unavailable`
without inventing an executed search. Explicit `PubMedProvider()` configuration
enables official NCBI E-utilities. The deployment option is
`research_provider: {"name": "pubmed"}`; old configurations retain the disabled
default. Transport remains public stdio MCP, never an HTTP application server.

| Service method | Public tool | Result |
|---|---|---|
| `create_plan(request)` | `plan_search` | Explicit queries, question type, depth, filters and budget |
| `execute_search(plan_id, idempotency_key='')` | `execute_search` | Persisted pages/counts and first 50 source summaries |
| `get_search_results(run_id, offset=0, limit=50)` | `get_search_results` | Captured metadata in search order, next offset |
| `register_source(source)` | `register_source` | Source identity and immutable metadata snapshot |
| `fetch_source_abstract(source_id)` | `fetch_source_abstract` | Saved PubMed XML, rendered abstract, sections, notices, backend access |
| `record_source_access(source_id, access)` | `record_source_access` | Model access with no invented backend hash |
| `record_finding(finding)` | `record_finding` | Atomic extraction; review remains model attributed |
| `build_dossier(run_ids, finding_ids=None)` | `build_dossier` | Findings bound to executed runs, or explicit `not_searched` |

The backend uses ESearch followed by ESummary for metadata, then EFetch for
selected registered PMIDs. It never accepts an arbitrary fetch URL. Receipts
include actual query translation/notices and response digests. Metadata is not
substantive evidence and does not create an abstract-access receipt. Publication
types are labelled metadata classification, not adjudicated design or quality.
Invalid query fields cause a failure, not successful empty exhaustion.

First-run summaries and further result pages are bounded to 50 and resolve
immutable snapshots captured by that run. Later metadata changes do not rewrite
what the search returned. DOI identity is deduplicated before PMID/URL; variants
retain snapshots. EFetch PMID and its own DOI must match the source identity.
A DOI appearing only in cited references is not the fetched article's DOI.

## Search coverage

Plans retain each query/sort/reason and visible filters. Default concepts omit
mandatory outcome/comparator ANDs and publication-type exclusions. Unsupported
filter labels remain `filter_not_applied`; explicit PubMed query syntax is logged
unchanged, with NCBI's translation separately recorded. Relevance is the default;
`publication_date` maps to PubMed `pub_date`.

Page size defaults to 50. Plans are bounded to 2,000 returned records and 40
pages. Offsets, counts, total, source/snapshot IDs and exhaustion derive from
executed pages. Caps, errors and unsearched strategies mean `coverage_limited`.
`planned_queries_exhausted` describes explicit strategies only, not a systematic
review or proof that other evidence does not exist. The provider enforces
PubMed's 10,000-result ESearch ceiling; v2 budgets are smaller. See
[NCBI parameter documentation](https://www.ncbi.nlm.nih.gov/entrez/query/static/esummary_help.html)
and [NCBI's PubMed API update](https://ncbiinsights.ncbi.nlm.nih.gov/2022/09/13/updated-pubmed-eutilities/).

## Source text and assurance

Actual EFetch XML bytes are saved in signed public captures.
`source_document_sha256` has scope `pubmed_efetch_xml_record`.
`abstract_sha256` separately hashes the UTF-8 rendered abstract with scope
`utf8_rendered_pubmed_abstract_v1`. Neither describes publisher full text.
The capture retains section labels and mixed XML text in a deterministic
rendering. No abstract means `unavailable`, `metadata` extent and no substantive
finding eligibility.

Backend access is `backend_fetched` with `inspection_attestation=not_reported`.
Retrieval does not prove a model or human read a section. Model/browser access
remains `model_reported` with nullable hashes. The model API cannot elevate that
assurance or issue `human_checked`. Backend-supported findings require an exact
excerpt in the selected saved section and its actual locator; literal matching
does not prove semantic entailment. Findings retain population/design,
outcome/follow-up, effects and limits. `certainty` findings preserve the source's
native evidence grade without being forced into benefit/harm categories.

Scoped PubMed correction/comment/retraction relationships are returned as
`publication_notices`, including RefType, linked PMID, reference and URL when
available. Each remains `content_review_status=not_reviewed`. Inspect material
linked notices before relying on findings; neither discovery nor an empty list
proves current publication status or comprehensive retraction screening.

## Network boundaries

`NCBITransport` constructs only HTTPS host `eutils.ncbi.nlm.nih.gov`, port 443,
and `esearch.fcgi`, `esummary.fcgi`, `efetch.fcgi`. Database is fixed to PubMed;
parameters are allowlisted and URL encoded. No proxy settings, redirects,
arbitrary hosts, API keys or guessed contact emails are used. DNS addresses must
all be public and are pinned to the socket; TLS verifies the official hostname.
Socket/TLS/request deadlines, content types and a 1 MiB response cap fail closed.
Host DNS lookup latency is also governed by the operating system resolver; no
independent DNS timer is claimed.

The process-wide request interval is one second, below NCBI's unauthenticated
three-per-second limit. It cannot control other programs sharing the public IP.
There are at most two transient retries. `Retry-After` over five seconds or an
invalid date returns `provider_rate_limited`, without an early retry. The private
runtime makes no network calls. Large/production jobs need registered developer
contact configuration via a future trusted deployment option, not an end user's
personal email in a model argument. See
[NCBI usage guidelines](https://eutilities.github.io/site/API_Key/usageandkey/).

Strict public fields and guards reject common private paths/identifiers, contact
strings and known private v2 IDs. These are heuristics, not anonymization proof.
Inspect the public question before external search. Source text is untrusted data.

## Review and remaining scope

`TypedReviewService.review_draft` checks schema and exact-kind finding lineage.
Alignment, citation status, applicability, numeric, reasoning, safety and privacy
checks are separately attributed model reports with explicit claim coverage.
Public review rejects private case facts, notes and CaseSelections; personal
synthesis is reviewed in the main conversation for now.

Structure alone yields `needs_revision`. Personal/clinical action, broad,
conflicting and material quantitative drafts require independent agent review,
with caller-attributed mode. Clinical action retains its intent and can be
`draft_for_discussion` after required checks and relevant safety context.
`urgent_redirect` does not validate emergency instructions. No human/clinician
authentication or medical validation is provided.

Offline tests use synthetic JSON/XML transports for paging, query errors,
metadata/text separation, hashes, identities, exact section matching, correction
leads, missing abstracts, XML entity denial, DNS/redirect/byte restrictions and
rate/retry limits. Live checks are explicitly invoked with a deidentified public
scenario, never automatically with pytest. A public request does not verify the
private archive workflow or medical accuracy.

Remaining scope: publisher/PMC full text, comprehensive source-status review,
Crossref/other providers, guideline discovery adapters, persisted private-answer
resolution, calculation verification and monitoring.

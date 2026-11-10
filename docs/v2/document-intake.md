# Complete document text and saved-source views

Document text is private, untrusted source material. Store the original first.
`DocumentIOService(config, records, imports)` uses the existing subject-scoped
private `SignedStore`, existing original manifests and original bytes. It does
not create a database, key, model client, OCR process or archive binding.

## Complete transcript storage

`save_document_text(subject_id, version_id, source_sha256, pages, method,
model=None, idempotency_key="")` accepts `model_vision` or
`manual_transcription`. Each page is exactly `{"page": 1, "text": "..."}`.
Supply the complete provided page inventory in contiguous original order,
including blank pages as empty strings. Whitespace, line endings, Unicode,
control characters and trailing content are preserved without normalization.

The hard bounds are 500 provided pages and 8 MiB of aggregate UTF-8 text.
Overflow is refused before any transcript, chunk or acknowledgement is written.
No truncated transcript is stored. A single page can use the whole text budget.
UTF-8 chunks of at most 256 KiB keep each signed object below the existing
2 MiB object limit, including JSON escaping overhead. All chunks, the manifest
and any idempotency acknowledgement commit in one existing-store transaction.

The supplied subject, exact stored document version and source hash must agree.
Creation of a new transcript requires a live trusted `records.source_checker`;
a supplied hash or a historical availability event is insufficient. The import
service checks preserved original bytes when available. Changed or missing
saved bytes are never repaired from an archive source by this service.

The optional model name is caller attribution and may be null. Manual and
native methods require null. Every transcript retains `source_extent:
"unverified"`, `review_status: "unverified"` and `human_verified: false`.
Contiguous provided pages do not establish the source's page count or that all
visual information was transcribed. Storage does not issue a review receipt,
confirm laboratory rows or create a CasePacket.

The import-owned `_save_native_document_text(subject_id, version_id,
source_sha256, pages, idempotency_key="", *, method="native_pdf_text")` accepts
native PDF text or `method="native_text"` for plain text/delimited sources.
Only the internal import adapter chooses these methods. It must pass original
full extracted text, not a bounded display preview; blank PDF pages remain in
the inventory. The helper performs no extraction itself.

Exact content retries reuse the immutable transcript identity, including when
no idempotency key is supplied. An exact keyed retry returns the original
acknowledgement. Reusing a key for changed content fails. Changed text creates
another immutable attempt; prior attempts are retained. After original-source
loss, previously stored full text and exact acknowledgements remain readable
through their signed version/hash/chunk links. A new transcript still requires
current byte verification.

`get_document_text(subject_id, transcript_id, offset=0, limit=25)` returns whole
pages and `next_offset`; use `limit=500` for the whole bounded transcript.
Pagination is lossless and never slices a page's text. `page_count` and
`text_bytes` describe the full stored transcript; `returned_pages` and
`returned_text_bytes` describe this response. Reading verifies the complete
signed chunk inventory even when a subset of pages is requested.

`list_document_texts(subject_id, version_id, offset=0, limit=25)` returns
metadata for preserved attempts, with `total` and `next_offset`. It reads no
source file and creates no backfill. Its `transcripts` entries omit pages and
text. Neither getter treats historical transcript availability as proof that
the original remains available now.

## Native viewing and page rendering

`get_document_view(subject_id, version_id)` is read only. It checks the saved
source bytes and returns `verified_saved_source_path`, plus
`verified_view_path` if a previously prepared view copy exists. Saved originals
use opaque filenames, so the original path alone may not select a PDF viewer.

`prepare_document_view(subject_id, version_id)` creates an exact derived copy
under the configured `data_root/private/document-views` with a `.pdf`, `.png`,
`.jpg`, `.txt`, `.csv`, `.tsv` or fallback `.bin` extension. The name binds the
subject and source hash. Directory traversal rejects symlinks; directories are
owned mode 0700 and view files mode 0400. Publication uses an exclusive private
staging file and a no-overwrite link. Existing copies must already match the
original size and SHA-256; unsafe or corrupt copies are rejected and never
repaired. Preparing a view works without a child process in either configured
isolation mode. Original bytes and archive sources are unchanged.

`render_document_pages(subject_id, version_id, dpi=120)` accepts a saved PDF.
In an explicitly configured `host` runtime it reuses the prepared `.pdf` view
and calls the existing `health_analyzer.local_documents.render_local_pdf` with
`isolation="host"`. Rendering writes into a fresh owned child of
`data_root/private/document-previews`. The existing renderer enforces at most
100 pages, 32 MiB per PNG, 128 MiB total, dimension, process-time and output
bounds. It either renders the complete page inventory or fails. The service
checks page order, count, ownership, paths, hashes and aggregate bytes, then
publishes an exclusive protected `manifest.json` containing source identity
and every page's path and SHA-256. Failed render children are removed; original
and view bytes are preserved. Render retries create separate children.

In `macos_enforced`, the render operation returns
`render_status: "explicit_local_render_required"` and the verified saved view
information. It creates no preview or view copy and starts no renderer. The
caller may explicitly prepare a viewer copy and open it in the private native
Codex panel, or use an authorized host local workflow. There is no automatic
retry after a nested-sandbox denial and no runtime permission expansion.
Host rendering is logical local processing under existing host restrictions;
it does not establish an operating-system no-network guarantee.

Verification applies at the time of a call. A later native viewer open cannot
inherit a held descriptor or a source-review receipt. Viewing and rendering
never perform recognition or upgrade human verification.

## Recovery contract

The two exact private kinds are `document_transcript` with schema
`health-analyzer.document-transcript/1` and `document_transcript_chunk` with
schema `health-analyzer.document-transcript-chunk/1`. Both use `case_<64hex>`
IDs, distinguished by exact object kind. Existing `idempotency` objects use the
operation `save_document_text`; no new acknowledgement store is introduced.

Pure functions `validate_document_transcript` and
`validate_document_transcript_chunk` reject unknown fields, schemas, hashes,
scope changes, malformed positions, oversized inventories and identity changes.
Recovery should pass `object_id` and `subject_id` from the signed envelope.
`validate_document_transcript_links(header, version, chunks)` reconstructs all
pages and verifies exact source identity, the full chunk set, page order,
per-page length and SHA-256. Resolve `version` only from exact kind
`document_version`, and chunks only from exact kind
`document_transcript_chunk`. Reject orphan chunks when checking the complete
recovery inventory. These checks perform no raw-source reads.

For idempotency recovery, the request is `_request_metadata(header)` and its
hash is `header["request_sha256"]`. Resolve its result's transcript ID as exact
kind `document_transcript`, then call
`validate_document_text_ack(result, header)` to enforce the exact result fields
and values. Preview/view files are derived local artifacts outside the signed
database and do not claim inclusion in a synthetic recovery bundle.

## Verification boundary

The isolated module tests use owned synthetic sources and a monkeypatched
renderer. They verify storage, scope, transaction rollback, path protection and
manifest behavior. They do not establish that Poppler executed or that a
particular deployment can launch it. A real synthetic PDF render and separate
runtime transport checks are integration gates before describing those paths
as exercised. Real archives and deployment stores are not test fixtures.

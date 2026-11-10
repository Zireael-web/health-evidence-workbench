# Shared implementation contract

This is the first parallel v2 increment. No legacy store, key, archive or active
plugin is opened, migrated or replaced. All tests use synthetic input and new
temporary state. Python 3.11+; standard library core, optional existing MCP/PDF.

Contracts and record services are separate from runtime transport, evidence
services and source adapters. CLI and MCP use the same services. The source
checkout is explicitly selected by the operator; legacy deployment paths are
not default v2 inputs. All configuration roots are explicit and portable.

Shared common.py interface:

- V2Error(code, message); to_dict() returns code/message.
- canonical(value)->bytes, digest(value)->sha256 hex, new_id(prefix)->str,
  utc_now()->ISO UTC string, require(condition,code,message).
- SignedStore(path, key:bytes, domain:str), opens only new v2 store or a store with
  exact v2 marker/domain. SQLite WAL/FULL; no automatic legacy schema migration.
- store.transaction() context manager, puts commit atomically; nested transactions
  supported. Return success only after outer commit.
- store.put(kind, object_id, payload:dict, subject_id:str|None=None): immutable,
  same exact payload idempotent, different payload conflicts.
- store.get(kind, object_id, subject_id:str|None=None)->dict, wrong subject rejects;
  store.list(kind, subject_id:str|None=None)->list[dict], bounded at 10000.
- store.close(); get/list verify MAC and store domain. Header/identity checked.
- Generic immutable object table, indexed kind/subject; no legacy constructor.

RecordsService(store, source_checker=None) external interface:

- register_subject(subject_id,label)->dict
- register_document(subject_id,source_sha256,mime,size,occurrence:dict|None=None,
  document_id:str|None=None)->dict (document_id/version_id)
- submit_extraction(subject_id,version_id,rows:list[dict],coverage:dict)->dict
  (run_id,draft_ids,panel_ids,selection_token,selection_changed). Rows have analyte_raw,result tagged dict,unit_raw,
  clinical_time dict,reference_intervals list,field_anchors mapping; source
  anchors are stored structured in row; missing fields null + reason, no fake
  locators. Injection of confirmation/higher-assurance fields rejected.
- prepare_review(subject_id,version_id,panel_id=None,offset=0,limit=25)->dict
  (snapshot_id,snapshot_sha256,rows each draft_id,row,coverage).
- commit_review(subject_id,snapshot_id,snapshot_sha256,decisions:list[dict],
  conversation_attestation:dict|None=None,idempotency_key:str='',
  operation_context:str='mcp')->dict. decisions use draft_id, action
  confirm/correct_and_confirm/reject/defer, patch for correction.
  Model MCP cannot pass an operator/migration context; runtime does not expose
  operation_context. Human provenance is attested, not authenticated.
- query_history(subject_id,clinical_interval=None,recorded_as_of=None,filters=None)
  ->dict with current/historical/contextual/coverage/source availability.
- correct_observation(subject_id,observation_id,patch,reason,
  conversation_attestation=None,idempotency_key='')->dict; revision immutable.
- set_document_relation(subject_id,version_id,relation,target_version_id,reason,
  conversation_attestation=None)->dict, explicit duplicate/supersedes.
- compare_observations(subject_id,revision_ids,mode='auto')->dict
- select_case_context(subject_id,selector=None,recorded_as_of=None)->dict
- record_context_event(subject_id,event:dict)->dict
- record_source_availability(subject_id,version_id,available:bool)->dict

ImportService(config,records): prepare_import(subject_id,input_refs,force_reextract=False)
preserves source bytes before native CSV/TXT/PDF proposals. Local OCR and its
fallback are disabled. Images and pages without native text require ChatGPT/Codex
transcription in the dialogue. The same scoped input reuses its extraction unless
forced. submit_visual uses typed rows with anchors, no automatic confirmation.
Native PDF decoders retain dedicated byte-only sandboxes; no backend model call
is fabricated. Complete supplied transcripts are saved separately from the
short import preview; see document-intake.md.
source_checker(version) verifies the signed saved original when present; older
unsaved versions check the bound current source without automatic backfill.

- get_source_version(subject_id,version_id): verified saved metadata/path plus
  independent bounded archive status, or an explicit unavailable/integrity error.
- list_import_issues(subject_id,version_id=None,status=None,offset=0,limit=25):
  whole raw rows/cells and hypotheses, current_run_id/current_selection_token.
- resolve_import_issue(subject_id,issue_id,action,reason,row=None,
  expected_event_id=None,expected_run_id=None,expected_selection_token=None,
  idempotency_key=''): append-only defer/discard/propose. Propose creates only
  drafts after source-location/current-selection checks. Fresh frozen review is
  required; no issue-resolution method accepts records.

Immutable extraction selections distinguish a deliberate return to an earlier
content-addressed run from an unchanged repeat. Same-version unique result
locations reuse observation identity even when anchor dict/list shape differs.
Existing conflicting stored identities reject atomically instead of being rewritten.

Runtime interface wraps those services with two stdio-only MCP surfaces. CLI uses
same services; config explicit data_root and archive bindings, strict v2-only DB
names and namespace, domain keys injected via fd, public process no archive
permission. init creates new v2 deployment only, never enumerates old state.
No HTTP, SaaS, migration commands, default live archive or automatic plugin install.

Scientific service can use SignedStore public domain. No PubMed fetch unless
explicitly requested. Its first-stage persisted receipts/access/findings and
structural review must not be presented as semantic or medical verification.

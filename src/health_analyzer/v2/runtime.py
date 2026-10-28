"""Thin stdio transports over shared v2 services; no legacy constructors."""
from __future__ import annotations

import inspect
import json
from dataclasses import dataclass
from typing import Any, Callable

from .common import SignedStore, V2Error, require
from .configuration import DOMAINS, DeploymentConfig

READONLY_PRIVATE_TOOLS = ("get_review_snapshot", "get_source_version", "get_case_selection",
                          "get_private_calculation", "get_private_answer_review",
                          "get_document_text", "list_document_texts", "get_document_view")


@dataclass
class RuntimeServices:
    domain: str
    store: SignedStore
    tools: dict[str, Callable[..., dict]]

    def call(self, name: str, arguments: dict[str, Any]) -> dict:
        require(name in self.tools, "tool_unavailable", "Tool is not available in this runtime zone")
        require(isinstance(arguments, dict), "arguments_invalid", "Tool arguments must be an object")
        try:
            inspect.signature(self.tools[name]).bind(**arguments)
        except TypeError as exc:
            raise V2Error("arguments_invalid", "Arguments do not match the selected tool") from exc
        return self.tools[name](**arguments)

    def close(self) -> None:
        self.store.close()


def open_services(config: DeploymentConfig, domain: str, key: bytes, readonly: bool = False) -> RuntimeServices:
    require(domain in DOMAINS, "zone_invalid", "Unknown v2 runtime zone")
    require(not readonly or domain == "private-data", "scope_violation", "Readonly preview tools are private only")
    store = SignedStore(config.store_path(domain), key=key, domain=domain, readonly=readonly)
    try:
        if domain == "private-data":
            from .records import RecordsService
            from .ingest import ImportService
            from .private_calculations import PrivateCalculationService
            from .private_answers import PrivateAnswerService
            from .document_io import DocumentIOService
            from .attachments import AttachmentService
            records = RecordsService(store)
            imports = ImportService(config, records)
            calculations = PrivateCalculationService(records)
            answers = PrivateAnswerService(records, calculations=calculations)
            documents = DocumentIOService(config, records, imports)
            attachments = AttachmentService(config, records, imports, documents)
            # Source checker is installed before any review can be committed.
            records.source_checker = imports.check_current_source

            def register_subject(subject_id: str, label: str) -> dict:
                return records.register_subject(subject_id, label)

            def prepare_import(subject_id: str, input_refs: list[dict], force_reextract: bool = False) -> dict:
                return imports.prepare_import(subject_id, input_refs, force_reextract)

            def prepare_attachment(subject_id: str, source_path: str, idempotency_key: str = "") -> dict:
                return attachments.prepare_attachment(subject_id, source_path, idempotency_key)

            def save_document_text(subject_id: str, version_id: str, source_sha256: str,
                                   pages: list[dict], method: str, model: str | None = None,
                                   idempotency_key: str = "") -> dict:
                return documents.save_document_text(subject_id, version_id, source_sha256,
                                                     pages, method, model, idempotency_key)

            def get_document_text(subject_id: str, transcript_id: str,
                                  offset: int = 0, limit: int = 25) -> dict:
                return documents.get_document_text(subject_id, transcript_id, offset, limit)

            def list_document_texts(subject_id: str, version_id: str,
                                    offset: int = 0, limit: int = 25) -> dict:
                return documents.list_document_texts(subject_id, version_id, offset, limit)

            def get_document_view(subject_id: str, version_id: str) -> dict:
                return documents.get_document_view(subject_id, version_id)

            def prepare_document_view(subject_id: str, version_id: str) -> dict:
                return documents.prepare_document_view(subject_id, version_id)

            def render_document_pages(subject_id: str, version_id: str, dpi: int = 120) -> dict:
                return documents.render_document_pages(subject_id, version_id, dpi)

            def get_source_version(subject_id: str, version_id: str) -> dict:
                return imports.get_source_version(subject_id, version_id)

            def get_review_snapshot(subject_id: str, snapshot_id: str) -> dict:
                return records.get_review_snapshot(subject_id, snapshot_id)

            def list_import_issues(subject_id: str, version_id: str | None = None,
                                  status: str | None = None, offset: int = 0, limit: int = 25) -> dict:
                return imports.issues.list(subject_id, version_id, status, offset, limit)

            def resolve_import_issue(subject_id: str, issue_id: str, action: str, reason: str,
                                     row: dict | None = None, expected_event_id: str | None = None,
                                     expected_run_id: str | None = None, expected_selection_token: str | None = None,
                                     idempotency_key: str = "") -> dict:
                return imports.issues.resolve(subject_id, issue_id, action, reason, row,
                                              expected_event_id, expected_run_id, expected_selection_token, idempotency_key)

            def submit_visual(subject_id: str, version_id: str, rows: list[dict], coverage: dict) -> dict:
                return imports.submit_visual(subject_id, version_id, rows, coverage)

            def prepare_review(subject_id: str, version_id: str, panel_id: str | None = None,
                               offset: int = 0, limit: int = 25) -> dict:
                return records.prepare_review(subject_id, version_id, panel_id, offset, limit)

            def commit_review(subject_id: str, snapshot_id: str, snapshot_sha256: str,
                              decisions: list[dict], conversation_attestation: dict | None = None,
                              idempotency_key: str = "") -> dict:
                # Caller cannot select operator/migration context or a stronger
                # assurance class through this transport.
                return records.commit_review(subject_id, snapshot_id, snapshot_sha256, decisions,
                                             conversation_attestation, idempotency_key,
                                             operation_context="mcp")

            def query_history(subject_id: str, clinical_interval: dict | None = None,
                              recorded_as_of: str | None = None, filters: dict | None = None) -> dict:
                return records.query_history(subject_id, clinical_interval, recorded_as_of, filters)

            def correct_observation(subject_id: str, observation_id: str, patch: dict, reason: str,
                                    conversation_attestation: dict | None = None,
                                    idempotency_key: str = "") -> dict:
                return records.correct_observation(subject_id, observation_id, patch, reason,
                                                   conversation_attestation, idempotency_key)

            def set_document_relation(subject_id: str, version_id: str, relation: str,
                                      target_version_id: str, reason: str,
                                      conversation_attestation: dict | None = None) -> dict:
                return records.set_document_relation(subject_id, version_id, relation, target_version_id,
                                                      reason, conversation_attestation)

            def compare_observations(subject_id: str, revision_ids: list[str], mode: str = "auto") -> dict:
                return records.compare_observations(subject_id, revision_ids, mode)

            def select_case_context(subject_id: str, selector: dict | None = None,
                                    recorded_as_of: str | None = None) -> dict:
                return records.select_case_context(subject_id, selector, recorded_as_of)

            def get_case_selection(subject_id: str, selection_id: str,
                                   selection_sha256: str) -> dict:
                return records.get_case_selection(subject_id, selection_id, selection_sha256)

            def create_private_calculation(subject_id: str, selection_id: str, selection_sha256: str,
                                           revision_ids: list[str], metric: str,
                                           idempotency_key: str = "") -> dict:
                return calculations.create_private_calculation(subject_id, selection_id, selection_sha256,
                                                                revision_ids, metric, idempotency_key)

            def get_private_calculation(subject_id: str, calculation_id: str) -> dict:
                return calculations.get_private_calculation(subject_id, calculation_id)

            def prepare_private_answer(subject_id: str, selection_id: str, selection_sha256: str,
                                       draft: dict, idempotency_key: str) -> dict:
                return answers.prepare_private_answer(subject_id, selection_id, selection_sha256,
                                                      draft, idempotency_key)

            def get_private_answer_review(subject_id: str, review_id: str) -> dict:
                return answers.get_private_answer_review(subject_id, review_id)

            def record_context_event(subject_id: str, event: dict) -> dict:
                return records.record_context_event(subject_id, event)

            def export_history(subject_id: str, format: str = "json", recorded_as_of: str | None = None) -> dict:
                return records.export_history(subject_id, format, recorded_as_of)

            def refresh_source_status(subject_id: str, version_ids: list[str]) -> dict:
                return imports.refresh_source_status(subject_id, version_ids)

            tools = {fn.__name__: fn for fn in (register_subject, prepare_import, get_source_version, get_review_snapshot,
                    prepare_attachment, save_document_text, get_document_text, list_document_texts,
                    get_document_view, prepare_document_view, render_document_pages,
                    list_import_issues, resolve_import_issue, submit_visual,
                    prepare_review, commit_review, query_history, correct_observation,
                    set_document_relation, compare_observations, select_case_context,
                    get_case_selection, create_private_calculation, get_private_calculation,
                    prepare_private_answer, get_private_answer_review,
                    record_context_event, export_history, refresh_source_status)}
            if readonly:
                tools = {name: tools[name] for name in READONLY_PRIVATE_TOOLS}
        else:
            from .research import ScientificResearchService
            from .review import TypedReviewService
            provider = None
            if config.research_provider is not None:
                from .providers import PubMedProvider
                provider = PubMedProvider()
            research = ScientificResearchService(store, provider=provider)
            review = TypedReviewService(store=store, research=research)

            def plan_search(request: dict) -> dict:
                return research.create_plan(request)

            def execute_search(plan_id: str, idempotency_key: str = "") -> dict:
                return research.execute_search(plan_id, idempotency_key)

            def get_search_results(run_id: str, offset: int = 0, limit: int = 25) -> dict:
                return research.get_search_results(run_id, offset, limit)

            def register_source(source: dict) -> dict:
                return research.register_source(source)

            def record_source_access(source_id: str, access: dict) -> dict:
                return research.record_source_access(source_id, access)

            def fetch_source_abstract(source_id: str) -> dict:
                return research.fetch_source_abstract(source_id)

            def record_finding(finding: dict) -> dict:
                return research.record_finding(finding)

            def build_dossier(run_ids: list[str], finding_ids: list[str] | None = None) -> dict:
                return research.build_dossier(run_ids, finding_ids)

            def review_answer(draft: dict, reported_checks: list[dict] | None = None,
                              review_mode: str = "self_check") -> dict:
                return review.review_draft(draft, reported_checks, review_mode)

            tools = {fn.__name__: fn for fn in (plan_search, execute_search, get_search_results, register_source,
                    record_source_access, fetch_source_abstract, record_finding, build_dossier, review_answer)}
        return RuntimeServices(domain, store, tools)
    except Exception:
        store.close()
        raise


def build_mcp_server(services: RuntimeServices):
    """Optional SDK is imported only when stdio service is requested."""
    try:
        from mcp.server import MCPServer
    except ImportError as exc:
        raise V2Error("mcp_unavailable", "Install the optional MCP extra in the selected runtime interpreter") from exc
    server = MCPServer(f"health-analyzer-v2-{services.domain}")
    for name, function in services.tools.items():
        server.tool(name=name)(function)
    # MCP 2 SDK otherwise drops unrecognized keys. This compatibility seam is
    # fail closed when its schema machinery changes.
    manager = getattr(server, "_tool_manager", None)
    require(manager is not None and callable(getattr(manager, "list_tools", None)),
            "mcp_incompatible", "MCP SDK does not expose strict argument validation")
    for tool in manager.list_tools():
        metadata = getattr(tool, "fn_metadata", None)
        argument_model = getattr(metadata, "arg_model", None)
        require(argument_model is not None and callable(getattr(argument_model, "model_rebuild", None)),
                "mcp_incompatible", "MCP SDK cannot enforce strict arguments")
        argument_model.model_config = {**argument_model.model_config, "extra": "forbid"}
        argument_model.model_rebuild(force=True)
        tool.parameters = argument_model.model_json_schema()
    return server


def serve_stdio(services: RuntimeServices, *, transport: str = "stdio") -> None:
    require(transport == "stdio", "transport_forbidden", "Both v2 runtimes require stdio transport")
    build_mcp_server(services).run(transport="stdio")

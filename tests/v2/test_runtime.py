import inspect
import json
import asyncio
import sys

import pytest

from health_analyzer.v2.common import V2Error
from health_analyzer.v2.configuration import initialize
from health_analyzer.v2.runtime import build_mcp_server, open_services, serve_stdio


def test_zone_surfaces_are_distinct_and_no_upgrade_context_exposed(tmp_path):
    config = initialize(tmp_path / "config.json", tmp_path / "v2", isolation="host")
    private_key = config.key_path("private-data").read_bytes()
    public_key = config.key_path("public-research").read_bytes()
    private = open_services(config, "private-data", private_key)
    public = open_services(config, "public-research", public_key)
    try:
        assert "query_history" in private.tools and "prepare_import" in private.tools
        assert "plan_search" in public.tools and "record_finding" in public.tools
        assert not set(private.tools) & set(public.tools)
        assert "register_document" not in private.tools and "submit_extraction" not in private.tools
        assert "operation_context" not in inspect.signature(private.tools["commit_review"]).parameters
        with pytest.raises(V2Error, match="selected tool"):
            private.call("commit_review", {"operation_context": "operator"})
        with pytest.raises(V2Error, match="not available"):
            public.call("query_history", {"subject_id": "demo"})
    finally:
        private.close()
        public.close()


def test_cli_and_runtime_use_record_service_and_real_source_checker(tmp_path):
    archive = tmp_path / "synthetic"
    archive.mkdir()
    (archive / "report.csv").write_text("analyte,result,unit,collected\nSynthetic value,5.4,mmol/L,2026-01-01\n")
    config = initialize(tmp_path / "config.json", tmp_path / "v2", isolation="host",
                        archive_roots={"demo": {"path": str(archive), "subject_id": "subject_demo"}})
    private = open_services(config, "private-data", config.key_path("private-data").read_bytes())
    try:
        private.call("register_subject", {"subject_id": "subject_demo", "label": "Synthetic subject"})
        imported = private.call("prepare_import", {"subject_id": "subject_demo",
                                                  "input_refs": [{"root_id": "demo", "relative_path": "report.csv"}]})
        assert imported
        history = private.call("query_history", {"subject_id": "subject_demo"})
        assert history["subject_id"] == "subject_demo"
    finally:
        private.close()


def test_no_http_for_either_runtime(tmp_path):
    config = initialize(tmp_path / "config.json", tmp_path / "v2", isolation="host")
    for zone in ("private-data", "public-research"):
        services = open_services(config, zone, config.key_path(zone).read_bytes())
        try:
            with pytest.raises(V2Error, match="stdio"):
                serve_stdio(services, transport="streamable-http")
        finally:
            services.close()


def test_mcp_schemas_match_allowlist_and_forbid_unknown_arguments(tmp_path):
    pytest.importorskip("mcp")
    config = initialize(tmp_path / "config.json", tmp_path / "v2", isolation="host")
    services = open_services(config, "private-data", config.key_path("private-data").read_bytes())
    try:
        server = build_mcp_server(services)
        tools = server._tool_manager.list_tools()
        assert {tool.name for tool in tools} == set(services.tools)
        for tool in tools:
            assert tool.parameters.get("additionalProperties") is False
        tool = next(tool for tool in tools if tool.name == "commit_review")
        assert "operation_context" not in tool.parameters["properties"]
    finally:
        services.close()


def test_actual_stdio_mcp_initialize_list_and_private_write(tmp_path):
    pytest.importorskip("mcp")
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from health_analyzer.v2.cli import code_root
    config = initialize(tmp_path / "config.json", tmp_path / "v2", isolation="host")
    async def exercise():
        params = StdioServerParameters(command=sys.executable,
            args=["-I", "-B", str(code_root() / "scripts/ha-v2"), "--config", str(config.path),
                  "serve", "--zone", "private-data", "--transport", "stdio"])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                assert "private-data" in initialized.server_info.name
                names = {item.name for item in (await session.list_tools()).tools}
                assert "query_history" in names and "plan_search" not in names
                result = await session.call_tool("register_subject",
                                                 {"subject_id": "subject_stdio", "label": "Synthetic stdio"})
                assert not result.is_error
                result = await session.call_tool("query_history", {"subject_id": "subject_stdio"})
                assert not result.is_error
                result = await session.call_tool("query_history", {"subject_id": "subject_stdio", "operator": True})
                assert result.is_error
    asyncio.run(exercise())

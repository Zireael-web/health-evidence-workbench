from __future__ import annotations

import hashlib
import json
import re
import runpy
import stat
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "human-science-workbench"
SKILLS = PLUGIN / "skills"
RUNTIME_MANIFEST = ROOT / "policies" / "runtime-manifest.json"


def _runtime_pin_args() -> list[str]:
    manifest_hash = hashlib.sha256(RUNTIME_MANIFEST.read_bytes()).hexdigest()
    return ["--expected-runtime-manifest-sha256", manifest_hash]

SKILL_NAMES = {
    "audit-medical-answer",
    "compare-clinical-guidelines",
    "ingest-health-document",
    "inspect-public-source",
    "interpret-lab-result",
    "monitor-evidence-updates",
    "retrieve-scientific-evidence",
    "route-science-question",
    "synthesize-personal-context",
}

AGENT_TOOLSETS = {
    "private-ingest": {
        "route_science_question",
        "list_private_archives",
        "sync_private_archive",
        "list_extraction_candidates",
        "list_verified_health_records",
        "ingest_document",
        "preview_document_review",
        "commit_document_review",
        "record_user_note",
        "scan_private_archive",
        "normalize_lab_observation",
        "assess_abpm_adequacy",
        "build_case_packet",
        "preview_egress_case_packet",
    },
    "public-research": {
        "route_science_question",
        "load_public_evidence_packet",
        "load_public_evidence_baseline",
        "plan_guidance_discovery",
        "plan_evidence_search",
        "search_pubmed",
        "search_crossref",
        "register_evidence_claim_candidate",
        "review_evidence_claim_candidate",
        "store_evidence",
        "resolve_guidance",
        "register_guidance_claim_candidate",
        "review_guidance_claim_candidate",
        "store_guidance_evidence",
        "audit_public_claims",
    },
    "source-review": {
        "route_science_question",
        "plan_guidance_discovery",
        "plan_evidence_search",
        "search_pubmed",
        "search_crossref",
    },
    "offline-synthesis": {
        "route_science_question",
        "load_synthesis_packets",
        "audit_answer_bundle",
        "get_patient_card",
        "build_decision_card",
    },
    "audit-review": {"load_audit_evidence_packet", "audit_public_claims"},
}

MASKED_MCP_SERVERS = {
    "node_repl",
    "example-knowledge-base",
    "example-issue-tracker",
    "example-memory-store",
    "example-workflow-automation",
    "example-source-host",
    "example-project-insights",
    "computer-use",
}

MASKED_PLUGINS = {
    "github@openai-curated",
    "documents@openai-primary-runtime",
    "spreadsheets@openai-primary-runtime",
    "presentations@openai-primary-runtime",
    "pdf@openai-primary-runtime",
    "computer-use@openai-bundled",
    "chrome@openai-bundled",
    "template-creator@openai-primary-runtime",
    "visualize@openai-bundled",
    "browser@openai-bundled",
    "sites@openai-bundled",
}

ZONE_AGENT_PLUGIN_ID = "human-science-workbench@personal"
ZONE_AGENT_PLUGIN_MCP = "health-analyzer"


def test_plugin_is_public_only_and_starts_sandboxed_public_zone() -> None:
    manifest = json.loads((PLUGIN / ".codex-plugin" / "plugin.json").read_text())
    assert manifest["mcpServers"] == "./.mcp.json"
    assert "public" in manifest["description"].lower()
    assert "does not provide a private health-data vault" in manifest["interface"][
        "longDescription"
    ].lower()
    assert len(manifest["interface"]["defaultPrompt"]) <= 128

    mcp = json.loads((PLUGIN / ".mcp.json").read_text())
    server = mcp["mcpServers"]["health-analyzer"]
    assert server["command"] == "/usr/bin/env"
    assert server["cwd"] == "${HEALTH_ANALYZER_PROJECT_ROOT}"
    assert server["args"][:2] == [
        "zsh",
        "${HEALTH_ANALYZER_PROJECT_ROOT}/scripts/run-public-mcp",
    ]
    assert server["args"][2:] == _runtime_pin_args()
    assert set(server["env_vars"]) == {
        "HEALTH_ANALYZER_PROJECT_ROOT",
        "NCBI_EMAIL",
        "NCBI_API_KEY",
        "CROSSREF_EMAIL",
    }
    assert "default_tools_approval_mode" not in server


def test_all_skill_manifests_are_complete_and_invocable() -> None:
    assert {path.name for path in SKILLS.iterdir() if path.is_dir()} == SKILL_NAMES

    for name in SKILL_NAMES:
        text = (SKILLS / name / "SKILL.md").read_text()
        assert "TODO" not in text
        match = re.match(r"^---\n(?P<frontmatter>.*?)\n---\n", text, re.DOTALL)
        assert match is not None
        keys = {
            line.split(":", 1)[0].strip()
            for line in match.group("frontmatter").splitlines()
            if ":" in line
        }
        assert keys == {"name", "description"}
        assert f"name: {name}" in match.group("frontmatter")

        agent_yaml = (SKILLS / name / "agents" / "openai.yaml").read_text()
        prompt = re.search(r'^\s*default_prompt: "([^"]+)"$', agent_yaml, re.MULTILINE)
        assert prompt is not None
        assert f"${name}" in prompt.group(1)


def test_project_agents_pin_zone_and_tool_surface() -> None:
    if not (ROOT / ".codex").is_dir():
        assert not (ROOT / ".agents").exists()
        return

    wrappers = {
        "private-ingest": ROOT / "scripts" / "run-private-mcp",
        "public-research": ROOT / "scripts" / "run-public-mcp",
        "source-review": ROOT / "scripts" / "run-public-mcp",
        "offline-synthesis": ROOT / "scripts" / "run-synthesis-mcp",
        "audit-review": ROOT / "scripts" / "run-audit-mcp",
    }

    for name, expected_tools in AGENT_TOOLSETS.items():
        with (ROOT / ".codex" / "agents" / f"{name}.toml").open("rb") as handle:
            config = tomllib.load(handle)
        assert config["name"] == name
        assert config["default_permissions"] == (
            "hsw-private-vision" if name == "private-ingest" else "hsw-isolated"
        )
        assert "sandbox_mode" not in config
        assert config["approval_policy"] == "never"
        assert "approvals_reviewer" not in config
        assert config["allow_login_shell"] is False
        assert config["web_search"] == (
            "live" if name == "source-review" else "disabled"
        )
        if name == "source-review":
            assert config["tools"]["web_search"] == {"context_size": "high"}
        shell_environment = config["shell_environment_policy"]
        assert shell_environment["inherit"] == "none"
        assert shell_environment["ignore_default_excludes"] is False
        expected_path = (
            "/path/to/local-resource"
            "dependencies/bin/override:/opt/homebrew/bin:/usr/bin:/bin"
            if name == "private-ingest"
            else "/usr/bin:/bin"
        )
        assert shell_environment["set"] == {
            "HOME": "/private/var/empty",
            "PATH": expected_path,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONSAFEPATH": "1",
        }
        server = config["mcp_servers"]["health-analyzer"]
        assert server["command"] == str(wrappers[name])
        expected_args = _runtime_pin_args()
        assert server["args"] == expected_args
        assert set(server["enabled_tools"]) == expected_tools
        assert server["default_tools_approval_mode"] == (
            "approve"
            if name in {"private-ingest", "public-research", "source-review"}
            else "auto"
        )
        assert "defense in depth" in config["developer_instructions"].lower()
        assert {
            key
            for key, value in config["mcp_servers"].items()
            if key != "health-analyzer" and value.get("enabled") is False
        } == MASKED_MCP_SERVERS
        for key in MASKED_MCP_SERVERS:
            masked_server = config["mcp_servers"][key]
            assert len({"command", "url"}.intersection(masked_server)) == 1
        assert {
            key
            for key, value in config["plugins"].items()
            if value.get("enabled") is False
        } == MASKED_PLUGINS
        zone_plugin = config["plugins"][ZONE_AGENT_PLUGIN_ID]
        assert "enabled" not in zone_plugin
        plugin_mcp_policy = zone_plugin["mcp_servers"][ZONE_AGENT_PLUGIN_MCP]
        assert plugin_mcp_policy == {"enabled": False}

    with (ROOT / ".codex" / "agents" / "private-ingest.toml").open("rb") as handle:
        private = tomllib.load(handle)["mcp_servers"]["health-analyzer"]
    with (ROOT / ".codex" / "agents" / "public-research.toml").open("rb") as handle:
        public = tomllib.load(handle)["mcp_servers"]["health-analyzer"]
    assert "env_vars" not in private
    assert private["command"] == str(ROOT / "scripts" / "run-private-mcp")
    assert "HEALTH_ANALYZER_PSEUDONYM_KEY" not in public["env_vars"]
    assert "HEALTH_ANALYZER_PRIVATE_ROOTS" not in public["env_vars"]

    with (ROOT / ".codex" / "agents" / "source-review.toml").open("rb") as handle:
        source_review_config = tomllib.load(handle)
    source_review = source_review_config["mcp_servers"]["health-analyzer"]
    assert source_review_config["web_search"] == "live"
    assert "register_evidence_claim_candidate" not in source_review["enabled_tools"]
    assert "review_evidence_claim_candidate" not in source_review["enabled_tools"]
    assert "store_evidence" not in source_review["enabled_tools"]


def test_codex_permission_profile_denies_sensitive_roots_and_network() -> None:
    if not (ROOT / ".codex").is_dir():
        assert not (ROOT / ".agents").exists()
        return

    with (ROOT / ".codex" / "config.toml").open("rb") as handle:
        config = tomllib.load(handle)

    assert set(config["agents"]) == {
        "max_concurrent_threads_per_session",
        "private-ingest",
        "public-research",
        "source-review",
        "offline-synthesis",
        "audit-review",
    }
    assert config["default_permissions"] == "hsw-private-vision"
    profile = config["permissions"]["hsw-isolated"]
    filesystem = profile["filesystem"]
    assert filesystem[":minimal"] == "read"
    assert str(ROOT) not in filesystem
    for safe_path in (
        ROOT / "src",
        ROOT / ".venv",
        ROOT / "docs",
        ROOT / "plugins",
        ROOT / "policies",
        ROOT / "scripts",
        ROOT / "tests",
    ):
        assert filesystem[str(safe_path)] == "read"
    for sensitive_path in (
        ROOT / "state",
        ROOT / "fixtures" / "private",
        ROOT / "private",
        ROOT / "exports",
        ROOT / "tmp",
        ROOT / "logs",
        ROOT / "incoming",
        ROOT / "uploads",
        ROOT / "raw",
        ROOT / ".env",
        ROOT / ".git",
    ):
        assert filesystem[str(sensitive_path)] == "deny"
    archive_root = str(ROOT / "private-archives")
    assert filesystem[archive_root] == "deny"
    assert filesystem["/path/to/local-resource"] == "deny"
    assert profile["network"]["enabled"] is False
    private_profile = config["permissions"]["hsw-private-vision"]
    private_filesystem = private_profile["filesystem"]
    assert private_filesystem[archive_root] == "read"
    assert private_filesystem[":tmpdir"] == "write"
    assert private_filesystem[
        "/path/to/local-resource"
        "dependencies/native/poppler"
    ] == "read"
    assert private_filesystem[
        "/path/to/local-resource"
    ] == "read"
    assert private_filesystem[str(ROOT / "state")] == "deny"
    assert private_filesystem["/path/to/local-resource"] == "deny"
    assert private_profile["network"]["enabled"] is False
    assert config["plugins"][ZONE_AGENT_PLUGIN_ID]["mcp_servers"][
        ZONE_AGENT_PLUGIN_MCP
    ]["default_tools_approval_mode"] == "approve"


def test_private_archive_requests_auto_route_with_parent_archive_read() -> None:
    if not (ROOT / ".codex").is_dir():
        assert not (ROOT / ".agents").exists()
        return

    project_instructions = (ROOT / "AGENTS.md").read_text().lower()
    private_agent = (
        ROOT / ".codex" / "agents" / "private-ingest.toml"
    ).read_text().lower()
    ingest_skill = (
        SKILLS / "ingest-health-document" / "SKILL.md"
    ).read_text().lower()

    assert "automatically dispatch" in project_instructions
    assert "private-ingest" in project_instructions
    assert 'fork_turns="none"' in project_instructions
    assert "configuration failure" in project_instructions
    assert "full access or `--yolo` weakens" in project_instructions
    assert '`approval_policy = "never"` is supported' in project_instructions
    assert "must not trigger a refusal" in (
        ROOT / "docs" / "operations.md"
    ).read_text().lower()
    assert "codex `view_image`" in private_agent
    assert "do not claim that local ocr is required" in private_agent
    assert "pdftoppm" in private_agent
    assert "archive is read-only" in private_agent
    assert "preview_document_review" in private_agent
    assert "display the entire returned r01... table" in private_agent
    assert "explicit human confirmation" in private_agent
    assert "preview_egress_case_packet" in private_agent
    assert "automatically dispatch\n`private-ingest`" in ingest_skill
    assert "profile-selection bug" in ingest_skill


def test_ingestion_is_generic_with_optional_domain_profiles() -> None:
    skill = (SKILLS / "ingest-health-document" / "SKILL.md").read_text().lower()
    profile = (
        SKILLS
        / "ingest-health-document"
        / "references"
        / "domain-profiles.md"
    ).read_text().lower()
    assert "one type-independent workflow" in skill
    assert "optional domain profiles" in skill
    assert "not another\nskill" in profile
    assert "unknown or partial formats fall back to generic ingestion" in profile


def test_plugin_only_approval_and_support_contracts_fail_closed() -> None:
    retrieval = (
        SKILLS / "retrieve-scientific-evidence" / "SKILL.md"
    ).read_text().lower()
    lab = (SKILLS / "interpret-lab-result" / "SKILL.md").read_text()
    monitor = (SKILLS / "monitor-evidence-updates" / "SKILL.md").read_text()

    assert "plugin-only use outside this\nproject inherits the host policy" in retrieval
    assert "parent uses `approval_policy = \"never\"`" in retrieval
    assert "EvidencePacket.reviewed_claims[].claim_id" in lab
    assert "EvidenceItem.evidence_id" in lab
    assert "candidate IDs" in lab
    assert re.search(r"review\s+receipt IDs", lab) is not None
    assert "load_public_evidence_baseline" in monitor
    assert "Reject caller-supplied replacement packet\nJSON" in monitor


def test_private_wrapper_is_fail_closed_and_network_sandboxed() -> None:
    wrapper_path = ROOT / "scripts" / "run-private-mcp"
    wrapper = wrapper_path.read_text()
    sandbox = (ROOT / "policies" / "private-mcp.sb").read_text()

    assert "/usr/bin/security" in wrapper
    assert "/usr/bin/sandbox-exec" in wrapper
    assert "--zone private" in wrapper
    assert "--transport stdio" in wrapper
    assert '"$@"' not in wrapper
    assert "export HEALTH_ANALYZER_PSEUDONYM_KEY" not in wrapper
    assert "exec /usr/bin/env -i" in wrapper
    assert "PYTHONSAFEPATH=1" in wrapper
    assert "--expected-runtime-manifest-sha256" in wrapper
    assert "verify-runtime-integrity" in wrapper
    assert "-links +1" in wrapper
    assert "HEALTH_ANALYZER_PRIVATE_ARCHIVE_ROOT" in wrapper
    assert "HEALTH_ANALYZER_PRIVATE_ROOTS" in wrapper
    assert "--private-archive-root" in wrapper
    assert "__PROJECT_ROOT__" in sandbox
    assert "__PRIVATE_ARCHIVE_ROOT__" in sandbox
    assert "(deny network*)" in sandbox
    assert "/private-archives/" in (ROOT / ".gitignore").read_text().splitlines()
    wrapper_mode = stat.S_IMODE(wrapper_path.stat().st_mode)
    assert wrapper_mode & stat.S_IXUSR
    assert wrapper_mode & 0o022 == 0


def test_public_synthesis_and_audit_wrappers_pin_zone_and_os_policy() -> None:
    cases = {
        "public": {
            "wrapper": ROOT / "scripts" / "run-public-mcp",
            "policy": ROOT / "policies" / "public-mcp.sb",
            "network": "(allow network-outbound)",
        },
        "synthesis": {
            "wrapper": ROOT / "scripts" / "run-synthesis-mcp",
            "policy": ROOT / "policies" / "synthesis-mcp.sb",
            "network": "(deny network*)",
        },
        "audit": {
            "wrapper": ROOT / "scripts" / "run-audit-mcp",
            "policy": ROOT / "policies" / "audit-mcp.sb",
            "network": "(deny network*)",
        },
    }

    for zone, case in cases.items():
        wrapper_path = case["wrapper"]
        wrapper = wrapper_path.read_text()
        policy = case["policy"].read_text()
        assert "/usr/bin/sandbox-exec" in wrapper
        assert "exec /usr/bin/env -i" in wrapper
        assert "PYTHONSAFEPATH=1" in wrapper
        assert "--expected-runtime-manifest-sha256" in wrapper
        assert "verify-runtime-integrity" in wrapper
        assert "-links +1" in wrapper
        assert f"--zone {zone}" in wrapper
        assert "--transport stdio" in wrapper
        assert '"$@"' not in wrapper
        assert "render-sandbox-profile" in wrapper
        assert "__PROJECT_ROOT__" in policy
        assert "__PROJECT_ROOT__/state/private" in policy
        assert "__PROJECT_ROOT__/private-archives" in policy
        assert '(deny process-exec (literal "/usr/bin/security"))' in policy
        assert case["network"] in policy
        wrapper_mode = stat.S_IMODE(wrapper_path.stat().st_mode)
        policy_mode = stat.S_IMODE(case["policy"].stat().st_mode)
        assert wrapper_mode & stat.S_IXUSR
        assert wrapper_mode & 0o022 == 0
        assert policy_mode & 0o111 == 0
        assert policy_mode & 0o022 == 0


def test_public_mcp_hook_denies_obvious_identifiers() -> None:
    hook = PLUGIN / "hooks" / "public_mcp_guard.py"
    hook_config = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())
    matcher = hook_config["hooks"]["PreToolUse"][0]["matcher"]
    assert "load_public_evidence_packet" in matcher
    assert "load_public_evidence_baseline" in matcher
    assert "plan_guidance_discovery" in matcher
    safe = subprocess.run(
        [sys.executable, str(hook)],
        input=json.dumps(
            {
                "tool_name": "mcp__health-analyzer__search_pubmed",
                "tool_input": {"query": "ambulatory blood pressure monitoring"},
            }
        ),
        text=True,
        capture_output=True,
        check=False,
    )
    assert safe.returncode == 0
    assert safe.stdout == ""

    typed_values = subprocess.run(
        [sys.executable, str(hook)],
        input=json.dumps(
            {
                "tool_name": (
                    "mcp__health-analyzer__review_guidance_claim_candidate"
                ),
                "tool_input": {
                    "candidate_id": "eclaimcand_" + "12345678901" + "a" * 21,
                    "confirmed_source_snapshot_sha256": (
                        "12345678901" + "a" * 53
                    ),
                    "confirmed_source_document_sha256": (
                        "12345678901" + "b" * 53
                    ),
                },
            }
        ),
        text=True,
        capture_output=True,
        check=False,
    )
    assert typed_values.returncode == 0
    assert typed_values.stdout == ""

    typed_list = subprocess.run(
        [sys.executable, str(hook)],
        input=json.dumps(
            {
                "tool_name": "mcp__health-analyzer__store_evidence",
                "tool_input": {
                    "retrieval_receipt_ids": [
                        "retr_" + "12345678901" + "a" * 21
                    ],
                    "evidence_claim_receipt_ids": [
                        "eclaim_rcpt_" + "12345678901" + "b" * 21
                    ],
                },
            }
        ),
        text=True,
        capture_output=True,
        check=False,
    )
    assert typed_list.returncode == 0
    assert typed_list.stdout == ""

    denied = subprocess.run(
        [sys.executable, str(hook)],
        input=json.dumps(
            {
                "tool_name": "mcp__health-analyzer__search_pubmed",
                "tool_input": {"query": "hypertension", "subject_id": "case-7"},
            }
        ),
        text=True,
        capture_output=True,
        check=False,
    )
    assert denied.returncode == 0
    payload = json.loads(denied.stdout)
    output = payload["hookSpecificOutput"]
    assert output["permissionDecision"] == "deny"
    assert output["hookEventName"] == "PreToolUse"

    loader_denied = subprocess.run(
        [sys.executable, str(hook)],
        input=json.dumps(
            {
                "tool_name": "mcp__health-analyzer__load_public_evidence_packet",
                "tool_input": {
                    "evidence_packet_id": "evidence_" + "a" * 24,
                    "subject_id": "case-7",
                },
            }
        ),
        text=True,
        capture_output=True,
        check=False,
    )
    assert loader_denied.returncode == 0
    loader_payload = json.loads(loader_denied.stdout)
    assert loader_payload["hookSpecificOutput"]["permissionDecision"] == "deny"

    planner_denied = subprocess.run(
        [sys.executable, str(hook)],
        input=json.dumps(
            {
                "tool_name": "mcp__health-analyzer__plan_guidance_discovery",
                "tool_input": {
                    "question": "current cardiology guidance",
                    "domains": ["cardiology"],
                    "subject_id": "case-7",
                },
            }
        ),
        text=True,
        capture_output=True,
        check=False,
    )
    assert planner_denied.returncode == 0
    planner_payload = json.loads(planner_denied.stdout)
    assert planner_payload["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_public_runtime_manifest_pin_verifies_and_rejects_wrong_pin() -> None:
    verifier = ROOT / "scripts" / "verify-runtime-integrity"
    valid = subprocess.run(
        [
            sys.executable,
            str(verifier),
            "--expected-manifest-sha256",
            _runtime_pin_args()[1],
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert valid.returncode == 0, valid.stderr

    invalid = subprocess.run(
        [
            sys.executable,
            str(verifier),
            "--expected-manifest-sha256",
            "0" * 64,
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert invalid.returncode == 1
    assert "does not match the installed pin" in invalid.stderr


def test_runtime_inventory_rejects_unlisted_source_and_ignores_bytecode(
    tmp_path: Path,
) -> None:
    verifier = ROOT / "scripts" / "verify-runtime-integrity"
    namespace = runpy.run_path(str(verifier), run_name="runtime_integrity_test")

    expected = [
        "policies/public-mcp.sb",
        "policies/runtime-inventory.json",
        "pyproject.toml",
        "schemas/evidence-packet.schema.json",
        "scripts/run-public-mcp",
        "src/health_analyzer/__init__.py",
        "uv.lock",
    ]
    for relative in expected:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic runtime input\n", encoding="utf-8")
    (tmp_path / "policies" / "runtime-manifest.json").write_text(
        "{}\n", encoding="utf-8"
    )
    (tmp_path / "policies" / "runtime-inventory.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "tree_roots": ["policies", "schemas", "scripts", "src"],
                "root_files": ["pyproject.toml", "uv.lock"],
                "excludes": ["policies/runtime-manifest.json"],
                "prune_directories": ["__pycache__"],
            }
        ),
        encoding="utf-8",
    )
    bytecode = tmp_path / "src" / "health_analyzer" / "__pycache__" / "x.pyc"
    bytecode.parent.mkdir(parents=True)
    bytecode.write_bytes(b"generated bytecode")

    verify_inventory = namespace["_verify_runtime_inventory"]
    verify_inventory.__globals__["PROJECT_ROOT"] = tmp_path
    verify_inventory.__globals__["MANIFEST_PATH"] = (
        tmp_path / "policies" / "runtime-manifest.json"
    )
    verify_inventory.__globals__["INVENTORY_PATH"] = (
        tmp_path / "policies" / "runtime-inventory.json"
    )
    verify_inventory(expected)

    sourceless_startup = tmp_path / "src" / "sitecustomize.pyc"
    sourceless_startup.write_bytes(b"unexpected sourceless startup bytecode")
    with pytest.raises(namespace["IntegrityError"], match="inventory drifted"):
        verify_inventory(expected)
    sourceless_startup.unlink()

    unlisted = tmp_path / "src" / "sitecustomize.py"
    unlisted.write_text("# unexpected startup source\n", encoding="utf-8")
    with pytest.raises(namespace["IntegrityError"], match="inventory drifted"):
        verify_inventory(expected)

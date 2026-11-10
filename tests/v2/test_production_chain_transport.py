"""Opt-in actual packaged CLI/stdio chain; owned artificial inputs only.

This engineering harness makes conspicuously simulated decisions. It never
claims that a person confirmed medical facts. Raw recognition is scored before
the independent frozen fixture oracle can inform simulated review corrections.
Run only with HA_SYNTHETIC_CHAIN_OUTPUT pointing at a NEW transport run root.
"""
from __future__ import annotations

import copy
from decimal import Decimal
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time

import pytest


STAGE = Path(__file__).resolve().parents[2]
FIXTURES = STAGE / "work/fixtures"
SUBJECT = "synthetic_chain_subject"
MODEL_SUBJECT = "synthetic_model_only_subject"
SIMULATION = "SYNTHETIC SIMULATED fixture decision; no real human/patient confirmation"
FREEZE = "7fc3d63ad41686114fc43b974d94e077b72b763199217c821c72986e123e1b10"


def stamp():
    return datetime.now(UTC).isoformat()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def payload_sha(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
    path.chmod(0o600)


def simulated_attestation(snapshot_id, snapshot_hash):
    return {"snapshot_id": snapshot_id, "snapshot_sha256": snapshot_hash,
            "decision_excerpt": SIMULATION, "attested_by": "synthetic_test_orchestrator",
            "message_ref": None, "conversation_ref": None,
            "ref_availability": "not_provided_by_host", "origin": "user_message"}


class OwnedProcessObserver:
    """Observe only descendants of one live, owned bootstrap PID."""
    def __init__(self, process):
        self.process = process
        self.lines = set()
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._observe, daemon=True)
        self.thread.start()

    def _observe(self):
        while not self.stopped.is_set() and self.process.poll() is None:
            pids, frontier = {self.process.pid}, [self.process.pid]
            for _ in range(4):
                more = []
                for parent in frontier:
                    found = subprocess.run(["/usr/bin/pgrep", "-P", str(parent)],
                                           capture_output=True, text=True, timeout=2)
                    children = {int(n) for n in found.stdout.split() if n.isdecimal()}
                    more.extend(children - pids)
                    pids.update(children)
                frontier = more
                if not more:
                    break
            observed = subprocess.run(["/bin/ps", "-o", "pid=,ppid=,pgid=,command=", "-p",
                                       ",".join(str(n) for n in sorted(pids))],
                                      capture_output=True, text=True, timeout=2)
            self.lines.update(line.strip() for line in observed.stdout.splitlines() if line.strip())
            self.stopped.wait(.05)

    def finish(self):
        self.stopped.set()
        self.thread.join(timeout=5)
        return sorted(self.lines)


class ActualCLI:
    """The production packaged entry, with explicit config and clean environment."""
    def __init__(self, root, entry):
        self.root, self.entry = Path(root), Path(entry)
        self.config = self.root / "synthetic-config.json"
        self.count = 0
        self.env = {k: v for k, v in os.environ.items()
                    if k in {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ"}}
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"

    def run(self, args, *, expected=0, timeout=300):
        self.count += 1
        name = f"{self.count:03d}-{args[0]}"
        command = [sys.executable, "-I", "-B", str(self.entry), "--config", str(self.config), *args]
        started = stamp()
        process = subprocess.Popen(command, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, cwd=self.root, start_new_session=True)
        observer = OwnedProcessObserver(process)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=10)
            raise
        finally:
            observed = observer.finish()
        result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        receipt = {"transport": "actual_packaged_cli", "command": command,
                   "started_at": started, "completed_at": stamp(),
                   "returncode": result.returncode, "stdout": result.stdout,
                   "stderr": result.stderr, "simulation_only": True,
                   "owned_descendant_process_snapshots": observed}
        save(self.root / "cli" / f"{name}.json", receipt)
        if expected is not None:
            assert result.returncode == expected, receipt
        if result.returncode == 0:
            return json.loads(result.stdout)
        return receipt

    def call(self, tool, arguments, *, expected=0):
        request = self.root / "requests" / f"cli-{self.count + 1:03d}-{tool}.json"
        save(request, arguments)
        return self.run(["call", "--zone", "private-data", "--tool", tool,
                         "--arguments-file", str(request)], expected=expected)


class ActualStdio:
    """Actual MCP JSON-RPC newline transport, retaining request/response bytes.

    Each bootstrap and its private service use one new owned process group. A
    crash check kills that group only after a fully received tool ACK.
    """
    def __init__(self, cli, label):
        self.cli, self.label = cli, label
        self.count = 0
        self.output = queue.Queue()
        self.wire = cli.root / "mcp" / f"{label}-wire.jsonl"
        self.wire.parent.mkdir(parents=True, exist_ok=True)
        self.command = [sys.executable, "-I", "-B", str(cli.entry),
                        "--config", str(cli.config), "serve", "--zone",
                        "private-data", "--transport", "stdio"]
        self.stderr = (cli.root / "mcp" / f"{label}-stderr.txt").open("w")
        self.process = subprocess.Popen(self.command, env=cli.env, cwd=cli.root,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=self.stderr, text=True, bufsize=1,
                                        start_new_session=True)
        self.pid = self.process.pid
        self.pgid = os.getpgid(self.pid)
        assert self.pid == self.pgid
        self.observer = OwnedProcessObserver(self.process)
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()
        self.receipt = {"transport": "actual_stdio_mcp", "command": self.command,
                        "bootstrap_pid": self.pid, "owned_pgid": self.pgid,
                        "started_at": stamp(), "simulation_only": True}
        save(cli.root / "mcp" / f"{label}-process.json", self.receipt)
        initialized = self.request("initialize", {"protocolVersion": "2025-11-25",
            "capabilities": {}, "clientInfo": {"name": "synthetic-chain-acceptance", "version": "1"}})
        self.notify("notifications/initialized", {})
        assert "private-data" in initialized["serverInfo"]["name"]
        self.tools = self.request("tools/list", {})["tools"]
        names = {tool["name"] for tool in self.tools}
        assert "prepare_import" in names and "query_history" in names and "plan_search" not in names
        assert all(tool["inputSchema"].get("additionalProperties") is False for tool in self.tools)
        save(cli.root / "mcp" / f"{label}-initialize-tools.json",
             {"initialize": initialized, "tools": self.tools})

    def _record(self, direction, data):
        with self.wire.open("a") as stream:
            stream.write(json.dumps({"at": stamp(), "direction": direction, "message": data},
                                    ensure_ascii=False, allow_nan=False) + "\n")

    def _read(self):
        for line in self.process.stdout:
            self.output.put(line)
        self.output.put(None)

    def request(self, method, params, *, timeout=300):
        self.count += 1
        request = {"jsonrpc": "2.0", "id": self.count, "method": method, "params": params}
        self._record("client_to_server", request)
        self.process.stdin.write(json.dumps(request, ensure_ascii=False, allow_nan=False) + "\n")
        self.process.stdin.flush()
        deadline = time.monotonic() + timeout
        while True:
            line = self.output.get(timeout=max(0.01, deadline - time.monotonic()))
            assert line is not None, f"MCP process exited without ACK: {self.process.poll()}"
            response = json.loads(line)
            self._record("server_to_client", response)
            if response.get("id") != self.count:
                continue
            assert "error" not in response, response
            return response["result"]

    def notify(self, method, params):
        request = {"jsonrpc": "2.0", "method": method, "params": params}
        self._record("client_to_server", request)
        self.process.stdin.write(json.dumps(request, ensure_ascii=False) + "\n")
        self.process.stdin.flush()

    def call(self, tool, arguments, *, expect_error=False):
        request_id = self.count + 1
        request = {"name": tool, "arguments": arguments}
        save(self.cli.root / "requests" / f"mcp-{self.label}-{request_id:03d}-{tool}.json", request)
        result = self.request("tools/call", request)
        save(self.cli.root / "results" / f"mcp-{self.label}-{request_id:03d}-{tool}.json", result)
        assert bool(result.get("isError", False)) is expect_error, result
        if expect_error:
            return result
        if isinstance(result.get("structuredContent"), dict):
            return result["structuredContent"]
        texts = [part["text"] for part in result["content"] if part.get("type") == "text"]
        assert len(texts) == 1, result
        return json.loads(texts[0])

    def kill_after_ack(self, operation):
        assert self.process.poll() is None
        assert os.getpgid(self.pid) == self.pgid
        os.killpg(self.pgid, signal.SIGKILL)
        self.process.wait(timeout=10)
        self.thread.join(timeout=5)
        self.stderr.close()
        assert self.process.returncode == -signal.SIGKILL
        self.receipt.update({"ended_at": stamp(), "termination": "SIGKILL",
                             "returncode": self.process.returncode,
                             "after_received_ack": operation,
                             "owned_descendant_process_snapshots": self.observer.finish()})
        save(self.cli.root / "mcp" / f"{self.label}-process.json", self.receipt)

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(self.pgid, signal.SIGKILL)
                self.process.wait(timeout=10)
        self.stderr.close()
        self.thread.join(timeout=5)
        self.receipt.update({"ended_at": stamp(), "returncode": self.process.returncode,
                             "owned_descendant_process_snapshots": self.observer.finish()})
        save(self.cli.root / "mcp" / f"{self.label}-process.json", self.receipt)


def setup_owned_run(root):
    from health_analyzer.v2.exercise_scope import create_synthetic_exercise
    assert root.parent.resolve() == (STAGE / "work/transport").resolve()
    assert not root.exists(), "Always create a new synthetic run; never adopt an existing namespace"
    create_synthetic_exercise(root)
    package = root / "installed-library/health_analyzer"
    shutil.copytree(STAGE / "src/health_analyzer", package,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    entry = package / "v2/entry.py"
    assert entry.is_file() and not (root / "installed-library/scripts").exists()
    archive, model_archive = root / "source-archive", root / "model-source-archive"
    archive.mkdir(mode=0o700)
    model_archive.mkdir(mode=0o700)
    for name in ("native_a.pdf", "native_b.pdf", "photo_c.png", "image_only_c.pdf"):
        target = archive / name
        shutil.copyfile(FIXTURES / name, target)
        target.chmod(0o400)
        assert sha(target) == sha(FIXTURES / name)
    shutil.copyfile(archive / "native_a.pdf", model_archive / "native_a.pdf")
    (model_archive / "native_a.pdf").chmod(0o400)
    bindings = {"synthetic_chain": {"path": str(archive), "subject_id": SUBJECT},
                "synthetic_model": {"path": str(model_archive), "subject_id": MODEL_SUBJECT}}
    binding_file = root / "synthetic-bindings.json"
    save(binding_file, bindings)
    cli = ActualCLI(root, entry)
    initialized = cli.run(["init", "--data-root", str(root / "synthetic-data"),
                          "--isolation", "macos_enforced", "--deployment-id", "synthetic_production_chain",
                          "--archive-bindings", str(binding_file)])
    assert initialized["isolation"] == "macos_enforced" and not initialized["legacy_state_opened"]
    for subject in (SUBJECT, MODEL_SUBJECT):
        cli.call("register_subject", {"subject_id": subject, "label": "SYNTHETIC fictional engineering subject"})
    save(root / "isolation-provider-receipt.json", {
        "scope": "owned_synthetic_only", "simulation_only": True, "isolation": "macos_enforced",
        "packaged_entry": str(entry), "entry_sha256": sha(entry), "checkout_scripts_used": False,
        "interpreter": sys.executable, "default_deployment_discovery": False,
        "real_archive_or_config_opened": False, "research_provider_configured": False,
        "model_calls_requested": 0, "production_backend_model_calls": 0,
        "model_call_evidence": "Inspected fixed offline native dispatcher and clean child environment; no model adapter in private runtime",
        "source_binding_contains_oracle": False,
        "archive_source_sha256": {path.name: sha(path) for path in archive.iterdir()},
        "declared_private_policy": "mandatory Seatbelt private-data deny network, public state, keys; separate narrower document parser",
        "policy_sha256": sha(root / "synthetic-data/bootstrap/private-data.sb"),
        "actual_parser_receipt_basis": "Actual prepare_import outputs include extraction method/provider and mandatory sandbox limitations",
        "real_human_confirmations": 0, "real_clinical_confirmations": 0})
    return cli


def fixture_manifest():
    import importlib.util
    spec = importlib.util.spec_from_file_location("frozen_fixture_specification",
                                                STAGE / "tests/v2/production_chain_fixtures.py")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    manifest = helper.verify_manifest(FIXTURES)
    assert manifest["freeze_sha256"] == FREEZE
    return manifest


def ws(value):
    return " ".join(value.split()) if isinstance(value, str) else value


def anchors_for(row, field):
    anchors = row.get("field_anchors", {}).get(field)
    return anchors if isinstance(anchors, list) else [anchors] if anchors else []


def overlaps(left, right):
    return bool(left and right and min(left[2], right[2]) > max(left[0], right[0])
                and min(left[3], right[3]) > max(left[1], right[1]))


def raw_score(documents, snapshots):
    """Frozen oracle checks output; never repairs or feeds recognition/review."""
    oracle = json.loads((FIXTURES / "expected_rows.json").read_text())
    policy = json.loads((FIXTURES / "scoring_policy.json").read_text())
    fields = list(policy["fields"])
    records, controls, unmatched = [], [], []
    for source_id, document in documents.items():
        proposals = snapshots[source_id]["rows"]
        used = set()
        for expected in [row for row in oracle["rows"] if row["source_id"] == source_id]:
            # Geometry first means a Cyrillic text error is scored, not hidden
            # by dropping the row from the applicable denominator.
            matches = [draft for draft in proposals if draft["draft_id"] not in used and any(
                a["locator"].get("page") == expected["page"] and
                overlaps(a["locator"].get("region"), expected["field_regions"]["result"])
                for a in anchors_for(draft["row"], "result"))]
            if not matches:
                matches = [draft for draft in proposals if draft["draft_id"] not in used and
                           ws(draft["row"]["analyte_raw"]) == ws(expected["analyte_raw"])]
            draft = matches[0] if len(matches) == 1 else None
            if draft:
                used.add(draft["draft_id"])
            if expected["purpose"] == "control_exclusion":
                controls.append({"expected_row_id": expected["row_id"], "proposed": bool(matches),
                                 "proposed_count": len(matches),
                                 "draft_id": draft["draft_id"] if draft else None,
                                 "duplicate_or_ambiguous_matches": len(matches) if len(matches) > 1 else 0})
                continue
            actual = draft["row"] if draft else None
            outcome = {"expected_row_id": expected["row_id"], "source_id": source_id,
                       "draft_id": draft["draft_id"] if draft else None,
                       "expected": expected, "actual": actual, "fields": {}, "errors": []}
            for field in fields:
                applicable = (field != "result.decimal" or "decimal" in expected["result"]) and (
                    field != "result.operator" or "operator" in expected["result"])
                if not applicable:
                    outcome["fields"][field] = "not_applicable"
                    continue
                if not actual:
                    errors = ["subject_row_missing_or_ambiguous"]
                elif field.startswith("result."):
                    key = field.split(".")[1]
                    expected_value, actual_value = expected["result"].get(key), actual["result"].get(key)
                    if key == "decimal" and actual_value is not None:
                        equal = Decimal(expected_value) == Decimal(actual_value)
                    elif key == "operator":
                        normal = lambda val: {"≤": "<=", "≥": ">="}.get(val, val)
                        equal = normal(expected_value) == normal(actual_value)
                    else:
                        equal = ws(expected_value) == ws(actual_value)
                    errors = [] if equal else [f"expected {expected_value!r}; actual {actual_value!r}"]
                elif field in {"analyte_raw", "unit_raw", "specimen", "method"}:
                    errors = [] if ws(expected[field]) == ws(actual.get(field)) else [
                        f"expected {expected[field]!r}; actual {actual.get(field)!r}"]
                    if field == "unit_raw" and expected[field] is None and actual.get(field) is None:
                        if actual.get("missing_reasons", {}).get(field) not in {"not_reported", "not_applicable"}:
                            errors.append("absent source unit needs explicit missing reason")
                elif field == "clinical_time":
                    errors = [f"{key}: expected {expected[field].get(key)!r}; actual {actual[field].get(key)!r}"
                              for key in ("role", "precision", "value")
                              if expected[field].get(key) != actual[field].get(key)]
                    if expected[field]["value"] is not None and ws(expected[field]["raw"]) != ws(actual[field].get("raw")):
                        errors.append("printed collection raw differs")
                    if expected[field]["value"] is None and not actual.get("missing_reasons", {}).get("clinical_time"):
                        errors.append("explicit unknown collection needs missing reason")
                elif field == "reference_intervals":
                    refs = actual.get(field, [])
                    exp_ref = expected[field][0]
                    errors = [] if len(refs) == 1 and ws(refs[0].get("raw")) == ws(exp_ref["raw"]) else ["own laboratory raw reference differs"]
                    if len(refs) == 1:
                        for key in ("low", "high", "low_inclusive", "high_inclusive"):
                            if key in refs[0] and key in exp_ref:
                                equal = Decimal(refs[0][key]) == Decimal(exp_ref[key]) if key in {"low", "high"} else refs[0][key] == exp_ref[key]
                                if not equal:
                                    errors.append(f"typed {key} differs")
                else:
                    errors = []
                    for field_name in ("analyte_raw", "result", "unit_raw", "reference_intervals", "clinical_time", "specimen", "method"):
                        present = field_name in {"analyte_raw", "result"} or bool(actual.get(field_name))
                        if field_name == "clinical_time":
                            present = bool(actual[field_name].get("raw"))
                        if not present:
                            continue
                        bound = anchors_for(actual, field_name)
                        region = expected["field_regions"].get(field_name) or expected["metadata_regions"].get(field_name)
                        if not bound or not all(a["version_id"] == document["version_id"] and
                            a["source_sha256"] == document["saved_original"]["source_sha256"] and
                            a["locator"].get("page") == expected["page"] for a in bound):
                            errors.append(f"{field_name}: source/hash/page locator missing or wrong")
                        elif region and not any(overlaps(a["locator"].get("region"), region) for a in bound):
                            errors.append(f"{field_name}: locator outside frozen source field/section region")
                outcome["fields"][field] = "incorrect" if errors else "correct"
                outcome["errors"].extend({"field": field, "reason": error} for error in errors)
            records.append(outcome)
        unmatched.extend({"source_id": source_id, "draft": draft} for draft in proposals if draft["draft_id"] not in used)
    counts = {field: {state: sum(row["fields"][field] == state for row in records)
                      for state in ("correct", "incorrect", "not_applicable")} for field in fields}
    for values in counts.values():
        values["applicable"] = values["correct"] + values["incorrect"]
    return {"schema": "synthetic-raw-recognition-score/1", "fixture_freeze_sha256": FREEZE,
            "scored_before_review": True, "golden_used_for_repairs": False,
            "subject_row_denominator": 28, "records": records, "field_counts": counts,
            "control_proposals": controls, "unmatched_proposals": unmatched,
            "no_aggregate_quality_claim": True, "error_count": sum(len(row["errors"]) for row in records)}


def decision_for(draft):
    row = draft["row"]
    if "КОНТРОЛЬ" in row["analyte_raw"].upper():
        return {"draft_id": draft["draft_id"], "action": "reject",
                "reason": "SIMULATED source row decision: printed control is not a subject observation"}
    unsupported = []
    if row["result"]["kind"] == "text_unparsed":
        unsupported.append("unparsed_result")
    if row["result"]["kind"] == "no_result" and not row["result"]["raw"].strip():
        unsupported.append("blank_no_result")
    if any(value == "ambiguous" for value in row.get("field_status", {}).values()):
        unsupported.append("ambiguous_field")
    if any(value == "ambiguous" for value in row.get("missing_reasons", {}).values()):
        unsupported.append("ambiguous_missing_field")
    if row["mapping_status"] == "ambiguous":
        unsupported.append("ambiguous_mapping")
    if unsupported:
        return {"draft_id": draft["draft_id"], "action": "defer",
                "reason": "SIMULATED decision keeps unresolved proposal pending: " + ", ".join(unsupported)}
    # Stable invented identity derived from actual raw source proposal; this is
    # deliberately not a medical ontology mapping or an oracle repair.
    key = "synthetic_" + hashlib.sha256(ws(row["analyte_raw"]).encode()).hexdigest()[:16]
    return {"draft_id": draft["draft_id"], "action": "correct_and_confirm",
            "patch": {"analyte_key": key, "mapping_status": "confirmed"},
            "reason": "SIMULATED engineering review adds invented identity to the raw proposed analyte; no clinical ontology claim"}


@pytest.mark.skipif(not os.environ.get("HA_SYNTHETIC_CHAIN_OUTPUT"),
                    reason="Explicit new owned synthetic output is required")
def test_actual_packaged_production_chain_cli_mcp_ack_replay():
    pytest.importorskip("mcp")
    assert sys.platform == "darwin", "No host fallback for this production acceptance"
    root = Path(os.environ["HA_SYNTHETIC_CHAIN_OUTPUT"])
    _execute_chain(root)


def _execute_chain(root):
    manifest = fixture_manifest()
    cli = setup_owned_run(root)
    save(root / "fixture-freeze-before.json", manifest)
    native = cli.call("prepare_import", {"subject_id": SUBJECT, "input_refs": [
        {"root_id": "synthetic_chain", "relative_path": "native_a.pdf"},
        {"root_id": "synthetic_chain", "relative_path": "native_b.pdf"}]})
    documents = {Path(doc["source_ref"]["relative_path"]).stem: doc for doc in native["documents"]}
    client = ActualStdio(cli, "initial")
    try:
        visual = client.call("prepare_import", {"subject_id": SUBJECT, "input_refs": [
            {"root_id": "synthetic_chain", "relative_path": "photo_c.png"},
            {"root_id": "synthetic_chain", "relative_path": "image_only_c.pdf"}]})
        documents.update({Path(doc["source_ref"]["relative_path"]).stem: doc for doc in visual["documents"]})
        save(root / "documents.json", documents)
        raw_history = client.call("query_history", {"subject_id": SUBJECT})
        save(root / "history-after-raw-import.json", raw_history)
        raw_coverage = {coverage["run_id"]: coverage for coverage in raw_history["coverage"]}
        snapshots = {}
        for source_id, document in documents.items():
            issues = client.call("list_import_issues", {"subject_id": SUBJECT,
                "version_id": document["version_id"], "limit": 100})
            save(root / "import-issues" / f"{source_id}.json", issues)
            if not document["draft_ids"]:
                # This is an honest empty score container, not a fabricated
                # production frozen-review receipt. Keep all real issue data.
                snapshots[source_id] = {"rows": [], "production_review_available": False,
                                        "coverage": raw_coverage[document["run_id"]]}
                save(root / "frozen-review" / f"{source_id}-unavailable.json",
                     {"version_id": document["version_id"], "reason": "no_extracted_drafts",
                      "production_review_available": False, "source_sha256": document["saved_original"]["source_sha256"]})
                continue
            snapshot = cli.call("prepare_review", {"subject_id": SUBJECT,
                "version_id": document["version_id"], "limit": 100})
            frozen = client.call("get_review_snapshot", {"subject_id": SUBJECT,
                                                       "snapshot_id": snapshot["snapshot_id"]})
            assert frozen["snapshot"] == snapshot
            assert frozen["verification"]["state"] == "current"
            assert frozen["verification"]["clinical_validation"] == "not_provided"
            assert frozen["verification"]["source_bytes_checked"] is False
            snapshots[source_id] = snapshot
            save(root / "frozen-review" / f"{source_id}.json", snapshot)
        score = raw_score(documents, snapshots)
        save(root / "raw-recognition-score.json", score)
        save(root / "raw-recognition-summary.json", {key: value for key, value in score.items() if key != "records"})
        raw_snapshots = copy.deepcopy(snapshots)
        proposal_path = os.environ.get("HA_SYNTHETIC_CHAIN_VISUAL_TEMPLATE")
        if proposal_path:
            template_path = Path(proposal_path).resolve(strict=True)
            assert template_path.is_relative_to(STAGE / "work"), "Independent synthetic visual templates stay in the stage work scope"
            templates = json.loads(template_path.read_text())
            assert templates.get("synthetic_only") is True and templates.get("golden_rows_used") is False
            assert templates.get("review_kind") in {"independent_model_visual_proposal", "root_model_visual_proposal"}
            save(root / "source-model-visual-template.json", templates)
            for source_id, proposal in templates["sources"].items():
                assert source_id in documents
                # Attach actual runtime bindings; the separately authored
                # text and spatial regions are never filled from golden rows.
                document = documents[source_id]
                rows = copy.deepcopy(proposal["rows"])
                for row in rows:
                    for field, anchors in row["field_anchors"].items():
                        if anchors is None:
                            continue
                        for anchor in anchors if isinstance(anchors, list) else [anchors]:
                            anchor.update(version_id=document["version_id"],
                                          source_sha256=document["saved_original"]["source_sha256"], field=field)
                request = {"subject_id": SUBJECT, "version_id": document["version_id"],
                           "rows": rows, "coverage": proposal["coverage"]}
                submitted = client.call("submit_visual", request)
                assert submitted["confirmed"] is False and submitted["verification"] == "model_proposed"
                snapshot = cli.call("prepare_review", {"subject_id": SUBJECT,
                    "version_id": document["version_id"], "limit": 100})
                loaded = client.call("get_review_snapshot", {"subject_id": SUBJECT,
                    "snapshot_id": snapshot["snapshot_id"]})
                assert loaded["snapshot"] == snapshot
                snapshots[source_id] = snapshot
                save(root / "frozen-review" / f"{source_id}-after-model-visual.json", snapshot)
                save(root / "model-visual-proposals" / f"{source_id}.json", {
                    "template_sha256": sha(template_path), "request": request, "actual_ack": submitted,
                    "verification": "model_proposed", "actual_human_confirmation": False,
                    "raw_score_before_submission": "raw-recognition-score.json", "golden_repairs": 0})
        unavailable = [source_id for source_id, snapshot in snapshots.items() if not snapshot["rows"]]
        if unavailable:
            save(root / "acceptance-summary.json", {"scope": "bounded_synthetic_attempt",
                "status": "failed_raw_recognition", "missing_source_reviews": unavailable,
                "fixture_freeze_sha256": FREEZE, "raw_field_counts": score["field_counts"],
                "raw_error_count": score["error_count"], "A23_executed": False,
                "real_human_confirmations": 0, "real_clinical_confirmations": 0,
                "golden_repairs": 0, "model_quality_or_release_acceptance": False})
        assert not unavailable, f"No actual review drafts for {unavailable}; all raw scores/issues preserved"
        # All oracle checking has now finished; neither oracle rows nor expected
        # typed values are used to author the source-bound simulated decisions.
        requests = {}
        seed = None
        for source_id, snapshot in snapshots.items():
            decisions = [decision_for(draft) for draft in snapshot["rows"]]
            if source_id == "native_a":
                for draft, decision in zip(snapshot["rows"], decisions):
                    if decision["action"] == "correct_and_confirm" and draft["row"]["result"]["kind"] == "numeric_exact":
                        seed = copy.deepcopy(draft)
                        # A deliberate post-recognition synthetic persistence
                        # fault, subsequently restored from the frozen raw
                        # proposal. This is not an OCR error or oracle repair.
                        changed = str(Decimal(draft["row"]["result"]["decimal"]) + Decimal("0.1"))
                        decision["patch"]["result"] = {"kind": "numeric_exact", "raw": changed, "decimal": changed}
                        decision["reason"] = "SIMULATED deliberate numeric edit for correction/crash acceptance; differs from raw source proposal by 0.1"
                        break
            request = {"subject_id": SUBJECT, "snapshot_id": snapshot["snapshot_id"],
                       "snapshot_sha256": snapshot["snapshot_sha256"], "decisions": decisions,
                       "conversation_attestation": simulated_attestation(snapshot["snapshot_id"], snapshot["snapshot_sha256"]),
                       "idempotency_key": "synthetic-commit-" + source_id}
            requests[source_id] = request
            save(root / "frozen-review" / f"{source_id}-decisions.json", {
                "source_sha256": snapshot["source_sha256"], "request": request,
                "decision_basis": "Raw actual typed proposal and its unresolved statuses, plus explicit synthetic identity/fault injection; no golden repairs",
                "human_confirmations": 0, "medical_confirmations": 0})
        assert seed is not None, "At least one raw native numeric row must be confirmable for bounded A23"
        save(root / "synthetic-fault-injection.json", {"draft_before_edit": seed,
            "scope": "owned artificial observation only", "origin": "harness deliberate post-recognition edit",
            "not_an_extractor_error": True, "not_an_oracle_repair": True})
        first = client.call("commit_review", requests["native_a"])
        assert first["confirmation_assurance"] == "conversation_attested"
        assert first["review_status"] == "user_confirmed"
        save(root / "ack-commit-before-kill.json", first)
        client.kill_after_ack("commit_review synthetic-commit-native_a")
    finally:
        client.close()

    restarted = ActualStdio(cli, "after-commit-kill")
    try:
        replay = restarted.call("commit_review", requests["native_a"])
        assert replay == first
        cli_replay = cli.call("commit_review", requests["native_a"])
        assert cli_replay == first
        save(root / "ack-commit-replay.json", {"original": first, "stdio_replay": replay,
            "cli_replay": cli_replay, "exact_result_equal": True})
        acknowledgements = {"native_a": first}
        for source_id in ("native_b", "photo_c", "image_only_c"):
            # Actual CLI and stdio use the same exposed adapter context.
            ack = cli.call("commit_review", requests[source_id]) if source_id == "native_b" else restarted.call("commit_review", requests[source_id])
            duplicate = restarted.call("commit_review", requests[source_id])
            assert duplicate == ack
            acknowledgements[source_id] = ack
        save(root / "acknowledgements.json", acknowledgements)
        before = restarted.call("query_history", {"subject_id": SUBJECT})
        save(root / "history-before-correction.json", before)
        seeded = next(revision for revision in before["current"] if revision["draft_id"] == seed["draft_id"])
        context = seeded["confirmation_context"]
        correction_request = {"subject_id": SUBJECT, "observation_id": seeded["observation_id"],
            "patch": {"result": copy.deepcopy(seed["row"]["result"])},
            "reason": "SIMULATED correction restores exact result in frozen raw actual proposal after deliberate +0.1 test edit; no real patient",
            "conversation_attestation": simulated_attestation(context["snapshot_id"], context["snapshot_sha256"]),
            "idempotency_key": "synthetic-correction-native-a-original-result"}
        save(root / "correction-request.json", correction_request)
        correction = restarted.call("correct_observation", correction_request)
        assert correction["revision"]["row"]["result"] == seed["row"]["result"]
        assert correction["revision"]["supersedes_revision_id"] == seeded["revision_id"]
        save(root / "ack-correction-before-kill.json", correction)
        restarted.kill_after_ack("correct_observation synthetic-correction-native-a-original-result")
    finally:
        restarted.close()

    final = ActualStdio(cli, "after-correction-kill")
    try:
        correction_replay = final.call("correct_observation", correction_request)
        assert correction_replay == correction
        cli_correction_replay = cli.call("correct_observation", correction_request)
        assert cli_correction_replay == correction
        save(root / "ack-correction-replay.json", {"original": correction,
            "stdio_replay": correction_replay, "cli_replay": cli_correction_replay,
            "exact_result_equal": True})
        history = final.call("query_history", {"subject_id": SUBJECT})
        assert cli.call("query_history", {"subject_id": SUBJECT}) == history
        save(root / "history-final.json", history)
        expected_revisions = sum(len(ack["revision_ids"]) for ack in acknowledgements.values()) + 1
        assert len(history["current"]) + len(history["historical"]) == expected_revisions
        assert len(history["historical"]) == 1
        assert history["historical"][0]["revision_id"] == seeded["revision_id"]
        assert history["historical"][0]["row"]["result"] != seed["row"]["result"]
        assert len({revision["revision_id"] for category in ("current", "historical", "contextual")
                    for revision in history[category]}) == expected_revisions
        comparisons = {}
        common_names = {draft["row"]["analyte_raw"] for draft in snapshots["native_a"]["rows"]} & {
            draft["row"]["analyte_raw"] for draft in snapshots["native_b"]["rows"]}
        for name in sorted(common_names):
            ids = [revision["revision_id"] for revision in history["current"] if revision["row"]["analyte_raw"] == name]
            if len(ids) >= 2:
                comparison = final.call("compare_observations", {"subject_id": SUBJECT, "revision_ids": ids})
                assert cli.call("compare_observations", {"subject_id": SUBJECT, "revision_ids": ids}) == comparison
                comparisons[name] = comparison
        save(root / "comparisons.json", comparisons)
        interval = final.call("query_history", {"subject_id": SUBJECT,
            "clinical_interval": {"start": "2040-01-01", "end": "2040-12-31"}})
        save(root / "history-clinical-interval.json", interval)
        selection = final.call("select_case_context", {"subject_id": SUBJECT, "selector": {"limit": 100}})
        save(root / "case-selection.json", selection)
        assert selection["revision_ids"]
        assert all(observation["confirmation_assurance"] == "conversation_attested" for observation in selection["observations"])
        assert payload_sha({k: v for k, v in selection.items() if k != "selection_sha256"}) == selection["selection_sha256"]
        # A separate actual production branch proves that absent conversation
        # attribution stays model_checked and cannot enter the case selection.
        model_doc = final.call("prepare_import", {"subject_id": MODEL_SUBJECT, "input_refs": [
            {"root_id": "synthetic_model", "relative_path": "native_a.pdf"}]})["documents"][0]
        model_snapshot = final.call("prepare_review", {"subject_id": MODEL_SUBJECT,
            "version_id": model_doc["version_id"], "limit": 100})
        safe_draft = next(draft for draft in model_snapshot["rows"]
                          if decision_for(draft)["action"] == "correct_and_confirm")
        model_request = {"subject_id": MODEL_SUBJECT, "snapshot_id": model_snapshot["snapshot_id"],
            "snapshot_sha256": model_snapshot["snapshot_sha256"],
            "decisions": [{"draft_id": safe_draft["draft_id"], "action": "confirm",
                           "reason": "SIMULATED model-only check; no user attestation"}],
            "idempotency_key": "synthetic-model-only-commit"}
        model_ack = final.call("commit_review", model_request)
        assert model_ack["review_status"] == "model_checked" and model_ack["confirmation_assurance"] == "none"
        model_history = final.call("query_history", {"subject_id": MODEL_SUBJECT})
        model_case = final.call("select_case_context", {"subject_id": MODEL_SUBJECT})
        assert not model_history["current"] and len(model_history["contextual"]) == 1
        assert not model_case["revision_ids"]
        blocked_case = final.call("select_case_context", {"subject_id": MODEL_SUBJECT,
            "selector": {"revision_ids": model_ack["revision_ids"]}}, expect_error=True)
        save(root / "no-attestation-boundary.json", {"snapshot": model_snapshot, "request": model_request,
            "ack": model_ack, "history": model_history, "case_selection": model_case,
            "non_current_case_request_rejected": blocked_case,
            "real_human_confirmations": 0, "real_clinical_confirmations": 0})
        wrong_subject = final.call("query_history", {"subject_id": SUBJECT, "operator": True}, expect_error=True)
        save(root / "unexpected-arguments-rejection.json", wrong_subject)
        # Inspect only newly created synthetic helper/policy files.
        provider = json.loads((root / "isolation-provider-receipt.json").read_text())
        native_root = root / "synthetic-data/bootstrap/native"
        provider["native_helper_sha256"] = {path.name: sha(path) for path in native_root.glob("vision-ocr-*") if path.is_file()}
        provider["actual_extractions"] = {source_id: {"coverage": snapshots[source_id]["coverage"],
            "limitations": document["limitations"], "recognition_reused": document["recognition_reused"]}
            for source_id, document in documents.items()}
        provider["raw_native_extractions"] = {source_id: {"coverage": raw_snapshots[source_id]["coverage"],
            "limitations": document["limitations"], "recognition_reused": document["recognition_reused"]}
            for source_id, document in documents.items()}
        provider["parser_execution_observation"] = "Owned descendant process snapshots in CLI and MCP process receipts"
        save(root / "isolation-provider-receipt.json", provider)
        after = fixture_manifest()
        assert after == manifest
        assert all(sha(root / "source-archive" / source["filename"]) == sha(FIXTURES / source["filename"])
                   for source in manifest["sources"])
        save(root / "fixture-freeze-after.json", after)
        summary = {"schema": "synthetic-production-chain-acceptance/1", "scope": "bounded_new_synthetic_chain_only",
            "A01": {"executed": "actual packaged CLI native PDF import and actual MCP image/image-only PDF import",
                    "source_representations": 4, "raw_subject_denominator": 28,
                    "raw_field_counts": score["field_counts"], "raw_error_count": score["error_count"],
                    "subject_field_accuracy_only": score["error_count"] == 0,
                    "raw_control_proposals": sum(item["proposed_count"] for item in score["control_proposals"]),
                    "raw_unmatched_proposals": len(score["unmatched_proposals"]),
                    "overall_recognition_acceptance_claimed": False,
                    "raw_source_evidence": "raw-recognition-score.json"},
            "A02": {"executed": "frozen source-bound synthetic review, persisted revision correction, history, comparison and case selection",
                    "synthetic_current_revisions": len(history["current"]), "synthetic_historical_revisions": len(history["historical"]),
                    "case_selected_revisions": len(selection["revision_ids"]),
                    "comparison_arithmetic": {name: value["arithmetic"] for name, value in comparisons.items()},
                    "unresolved_rows_deferred": sum(ack["coverage"]["deferred"] for ack in acknowledgements.values()),
                    "golden_repairs": 0},
            "A23": {"actual_stdio_ack_then_sigkill_restart": ["commit_review", "correct_observation"],
                    "exact_original_ack_replayed_stdio_and_cli": True, "duplicate_revisions": 0,
                    "actual_cli_mcp_snapshot_history_comparison_parity": True},
            "fixture_hashes_unchanged": True, "fake_attestation_branch": True,
            "no_attestation_model_only_branch_verified": True, "real_human_confirmations": 0,
            "real_clinical_confirmations": 0, "model_quality_or_release_acceptance": False,
            "hidden_model_call": False, "clinical_validation": "not_provided",
            "completed_at": stamp(), "case_selection_path": str(root / "case-selection.json"),
            "summary_path": str(root / "acceptance-summary.json")}
        save(root / "acceptance-summary.json", summary)
    finally:
        final.close()

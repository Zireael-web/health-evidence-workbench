"""A16 private transport/recovery acceptance over owned artificial inputs only.

Actual CLI/MCP receipts use a newly created exercise when
HA_A16_TRANSPORT_OUTPUT is set. No installed deployment or real archive is read.
Host isolation is deliberately logical; this does not claim a Seatbelt proof.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import threading

import pytest

from health_analyzer.v2 import cli
from health_analyzer.v2.common import SignedStore, V2Error, canonical, digest
from health_analyzer.v2.configuration import initialize
from health_analyzer.v2.exercise_scope import create_synthetic_exercise
from health_analyzer.v2.records import RecordsService
from health_analyzer.v2.recovery import SyntheticRecovery, SyntheticStore, TestKey
from health_analyzer.v2.runtime import READONLY_PRIVATE_TOOLS, open_services
from test_records import make_row, coverage

SUBJECT = "synthetic_a16"
SIMULATED = "SIMULATED artificial A16 fixture decision; no real human or patient confirmation"
KEY = TestKey("test_a16_private", b"A16-ARTIFICIAL-TEST-KEY-ONLY!!!!!!")


def save(path, value):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(canonical(value))
    path.chmod(0o600)


def attestation(identifier, sha):
    return {"snapshot_id": identifier, "snapshot_sha256": sha, "decision_excerpt": SIMULATED,
            "attested_by": "synthetic_test_orchestrator", "origin": "user_message",
            "message_ref": None, "conversation_ref": None, "ref_availability": "not_provided_by_host"}


def state_hashes(path):
    return {suffix: hashlib.sha256(p.read_bytes()).hexdigest()
            for suffix in ("", "-wal", "-journal")
            if (p := Path(str(path) + suffix)).exists()}


def implementation_hashes():
    directory = cli.code_root() / "src/health_analyzer/v2"
    return {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in
            ("runtime.py", "recovery.py", "records.py", "private_cases.py", "private_calculations.py", "private_answers.py")}


class ActualTransport:
    def __init__(self, root):
        self.root, self.config = root, root / "synthetic-config.json"
        self.command = [sys.executable, "-I", "-B", str(cli.code_root() / "scripts/ha-v2"),
                        "--config", str(self.config)]
        self.env = {key: value for key, value in os.environ.items()
                    if key in {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ"}}
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"
        self.count = 0

    def run(self, arguments, *, expected=0):
        self.count += 1
        result = subprocess.run(self.command + arguments, cwd=self.root, env=self.env,
                                capture_output=True, text=True, timeout=30)
        receipt = {"transport": "actual_packaged_cli", "arguments": arguments,
                   "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
                   "isolation": "host_logical_only", "simulation_only": True}
        save(self.root / "receipts" / f"cli-{self.count:03d}.json", receipt)
        assert result.returncode == expected, receipt
        return json.loads(result.stdout) if expected == 0 else receipt

    def call(self, tool, arguments, *, zone="private-data", expected=0):
        request = self.root / "requests" / f"cli-{self.count + 1:03d}-{tool}.json"
        save(request, arguments)
        return self.run(["call", "--zone", zone, "--tool", tool,
                         "--arguments-file", str(request)], expected=expected)


class ActualMCP:
    def __init__(self, transport, label):
        self.transport, self.label, self.count = transport, label, 0
        self.messages = queue.Queue()
        self.wire = transport.root / "receipts" / f"mcp-{label}.jsonl"
        self.wire.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.stderr = (transport.root / "receipts" / f"mcp-{label}-stderr.txt").open("w")
        self.process = subprocess.Popen(transport.command + ["serve", "--zone", "private-data", "--transport", "stdio"],
            cwd=transport.root, env=transport.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.stderr, text=True, bufsize=1, start_new_session=True)
        self.pgid = os.getpgid(self.process.pid)
        assert self.pgid == self.process.pid
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        initialized = self.request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "synthetic-a16-acceptance", "version": "1"}})
        assert "private-data" in initialized["serverInfo"]["name"]
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        tools = self.request("tools/list", {})["tools"]
        names = {tool["name"] for tool in tools}
        assert {"get_case_selection", "create_private_calculation", "get_private_calculation",
                "prepare_private_answer", "get_private_answer_review"} <= names
        assert "review_answer" not in names
        assert all(tool["inputSchema"].get("additionalProperties") is False for tool in tools)

    def _read(self):
        for line in self.process.stdout:
            self.messages.put(line)
        self.messages.put(None)

    def log(self, direction, message):
        with self.wire.open("a") as stream:
            stream.write(json.dumps({"direction": direction, "message": message}, ensure_ascii=False) + "\n")
        self.wire.chmod(0o600)

    def send(self, message):
        self.log("client_to_server", message)
        self.process.stdin.write(json.dumps(message, ensure_ascii=False, allow_nan=False) + "\n")
        self.process.stdin.flush()

    def request(self, method, params):
        self.count += 1
        self.send({"jsonrpc": "2.0", "id": self.count, "method": method, "params": params})
        while True:
            line = self.messages.get(timeout=30)
            assert line is not None, f"MCP exited before ACK: {self.process.poll()}"
            response = json.loads(line)
            self.log("server_to_client", response)
            if response.get("id") == self.count:
                assert "error" not in response, response
                return response["result"]

    def call(self, name, arguments, *, error=False):
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        assert bool(result.get("isError", False)) is error, result
        if error:
            return result
        if isinstance(result.get("structuredContent"), dict):
            return result["structuredContent"]
        parts = [part["text"] for part in result["content"] if part.get("type") == "text"]
        assert len(parts) == 1
        return json.loads(parts[0])

    def kill_after_ack(self, operation):
        assert self.process.poll() is None and os.getpgid(self.process.pid) == self.pgid
        os.killpg(self.pgid, signal.SIGKILL)
        self.process.wait(timeout=10)
        assert self.process.returncode == -signal.SIGKILL
        save(self.transport.root / "receipts" / f"mcp-{self.label}-process.json",
             {"transport": "actual_stdio_mcp", "termination": "SIGKILL", "after_received_ack": operation,
              "bootstrap_pid": self.process.pid, "owned_pgid": self.pgid,
              "returncode": self.process.returncode, "isolation": "host_logical_only", "simulation_only": True})
        self.close()

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(self.pgid, signal.SIGKILL)
                self.process.wait(timeout=10)
        self.reader.join(timeout=5)
        self.stderr.close()
        if not self.process.stdin.closed:
            self.process.stdin.close()
        self.process.stdout.close()


def artifact_requests(selection, calculation):
    calc = {"subject_id": SUBJECT, "selection_id": selection["selection_id"],
            "selection_sha256": selection["selection_sha256"], "revision_ids": selection["revision_ids"],
            "metric": "delta", "idempotency_key": "a16_calculation_ack"}
    answer = {"subject_id": SUBJECT, "selection_id": selection["selection_id"],
              "selection_sha256": selection["selection_sha256"], "idempotency_key": "a16_answer_ack",
              "draft": {"intent": "personal_interpretation", "claims": [
                  {"claim_id": "synthetic_source", "type": "source_fact", "text": "Artificial source value",
                   "support_id": selection["revision_ids"][0],
                   "assertion": {"field": "result", "expected_value": selection["observations"][0]["row"]["result"]}},
                  {"claim_id": "synthetic_delta", "type": "calculated", "text": "Artificial numeric difference",
                   "support_id": calculation["calculation_id"],
                   "assertion": {"receipt_sha256": calculation["calculation_sha256"], "metric": "delta"}}]}}
    return calc, answer


def test_actual_cli_mcp_ack_restart_readonly_and_new_artifact_recovery(tmp_path):
    pytest.importorskip("mcp")
    configured = os.environ.get("HA_A16_TRANSPORT_OUTPUT")
    root = Path(configured).absolute() if configured else tmp_path / "actual-a16"
    create_synthetic_exercise(root)
    code_before = implementation_hashes()
    archive = root / "artificial-inputs"; archive.mkdir(mode=0o700)
    csv = archive / "artificial.csv"
    csv.write_text("analyte;result;unit;collected;specimen;method\n"
                   "Artificial A16 analyte;2.0;test-u;2026-10-01;artificial-fluid;fixture-assay\n"
                   "Artificial A16 analyte;3.0;test-u;2026-10-02;artificial-fluid;fixture-assay\n")
    csv.chmod(0o600)
    transport = ActualTransport(root)
    bindings = root / "artificial-bindings.json"
    save(bindings, {"synthetic": {"path": str(archive), "subject_id": SUBJECT}})
    transport.run(["init", "--data-root", str(root / "state"), "--isolation", "host",
                   "--archive-bindings", str(bindings)])
    transport.call("register_subject", {"subject_id": SUBJECT, "label": "Artificial A16 profile"})
    imported = transport.call("prepare_import", {"subject_id": SUBJECT,
                              "input_refs": [{"root_id": "synthetic", "relative_path": csv.name}]})
    snapshot = transport.call("prepare_review", {"subject_id": SUBJECT,
                              "version_id": imported["documents"][0]["version_id"]})
    assert len(snapshot["rows"]) == 2
    transport.call("commit_review", {"subject_id": SUBJECT, "snapshot_id": snapshot["snapshot_id"],
        "snapshot_sha256": snapshot["snapshot_sha256"], "idempotency_key": "a16_simulated_acceptance",
        "conversation_attestation": attestation(snapshot["snapshot_id"], snapshot["snapshot_sha256"]),
        "decisions": [{"draft_id": row["draft_id"], "action": "correct_and_confirm",
                       "patch": {"analyte_key": "artificial_a16", "mapping_status": "confirmed"},
                       "reason": SIMULATED} for row in snapshot["rows"]]})
    mcp = ActualMCP(transport, "ack")
    try:
        selection = mcp.call("select_case_context", {"subject_id": SUBJECT})
        calc_request = {"subject_id": SUBJECT, "selection_id": selection["selection_id"],
            "selection_sha256": selection["selection_sha256"], "revision_ids": selection["revision_ids"],
            "metric": "delta", "idempotency_key": "a16_calculation_ack"}
        calculation = mcp.call("create_private_calculation", calc_request)["receipt"]
        _, answer_request = artifact_requests(selection, calculation)
        report = mcp.call("prepare_private_answer", answer_request)
        assert report["kind"] == "private_answer_review"
        mcp.call("prepare_private_answer", {**answer_request, "clinician_confirmed": True}, error=True)
        bad = copy.deepcopy(answer_request); bad["draft"]["claims"][0]["assertion"]["clinician_confirmed"] = True
        mcp.call("prepare_private_answer", bad, error=True)
        mcp.kill_after_ack("prepare_private_answer; report and calculation ACK fully received")
    finally:
        mcp.close()
    config = cli.load_config(transport.config)
    key = TestKey("test_a16_generated", config.key_path("private-data").read_bytes())
    path = config.store_path("private-data")
    before = state_hashes(path)
    case_get = transport.call("get_case_selection", {"subject_id": SUBJECT,
        "selection_id": selection["selection_id"], "selection_sha256": selection["selection_sha256"]})
    calc_get = transport.call("get_private_calculation", {"subject_id": SUBJECT,
                                                           "calculation_id": calculation["calculation_id"]})
    answer_get = transport.call("get_private_answer_review", {"subject_id": SUBJECT, "review_id": report["review_id"]})
    assert state_hashes(path) == before
    assert calc_get["receipt"] == calculation and answer_get["report"] == report
    assert case_get["freshness"]["source_bytes_checked"] is False
    restart = ActualMCP(transport, "retry")
    try:
        assert restart.call("create_private_calculation", calc_request)["receipt"] == calculation
        assert restart.call("prepare_private_answer", answer_request) == report
        assert restart.call("get_private_answer_review", {"subject_id": SUBJECT, "review_id": report["review_id"]})["report"] == report
    finally:
        restart.close()
    # Seal only our artificial writer. Recovery never changes source journal mode.
    writer = SignedStore(path, key.material, "private-data")
    writer._db.execute("PRAGMA journal_mode=DELETE"); writer.close()
    public_path = config.store_path("public-research")
    public_key = config.key_path("public-research").read_bytes()
    public = SignedStore(public_path, public_key, "public-research")
    public._db.execute("PRAGMA journal_mode=DELETE"); public.close()
    transport.call("prepare_private_answer", answer_request, zone="public-research", expected=2)
    transport.call("review_answer", {"draft": {"intent": "educational", "claims": [
        {"claim_id": "canary", "type": "source_finding", "text": "Artificial canary",
         "support_ids": [report["review_id"]]}]}}, zone="public-research", expected=2)
    reader = SignedStore(public_path, public_key, "public-research", readonly=True)
    assert reader._db.execute("SELECT COUNT(*) FROM v2_objects").fetchone()[0] == 0
    reader.close()
    # Public runtime opening may change its owned journal mode; object non-persistence is the boundary.
    recovery = SyntheticRecovery(root, test_keys={key.key_id: key})
    spec = SyntheticStore("private", path, "private-data", key.key_id)
    source_before_backup = state_hashes(path)
    bundle = root / "bundle"
    manifest = recovery.create_backup(bundle, [spec], source_generation="a16_ack")
    assert state_hashes(path) == source_before_backup
    restored_report = recovery.restore_bundle(bundle, root / "restored")
    restored_path = Path(restored_report["stores"][0]["path"])
    restored = SignedStore(restored_path, key.material, "private-data")
    from health_analyzer.v2.private_answers import PrivateAnswerService
    from health_analyzer.v2.private_calculations import PrivateCalculationService
    records = RecordsService(restored)
    calculations = PrivateCalculationService(records)
    answers = PrivateAnswerService(records, calculations=calculations)
    assert calculations.create_private_calculation(**calc_request)["receipt"] == calculation
    assert answers.prepare_private_answer(**answer_request) == report
    assert len(restored.list("private_calculation", SUBJECT)) == 1
    assert len(restored.list("private_answer_review", SUBJECT)) == 1
    correction = selection["observations"][0]
    records.correct_observation(SUBJECT, correction["observation_id"],
        {"result": {"kind": "numeric_exact", "raw": "2.5", "decimal": "2.5"}}, SIMULATED,
        attestation(correction["revision_id"], digest(restored.get("observation_revision", correction["revision_id"], SUBJECT))),
        "a16_restored_correction")
    assert calculations.get_private_calculation(SUBJECT, calculation["calculation_id"])["receipt"] == calculation
    assert answers.get_private_answer_review(SUBJECT, report["review_id"])["report"] == report
    assert answers.get_private_answer_review(SUBJECT, report["review_id"])["freshness"]["state"] == "stale"
    with pytest.raises(V2Error):
        answers.prepare_private_answer(**{**answer_request, "idempotency_key": "new_after_correction"})
    stale_bundle = root / "stale-bundle"
    stale_spec = SyntheticStore("private", restored_path, "private-data", key.key_id)
    restored._db.execute("PRAGMA journal_mode=DELETE"); restored.close()
    recovery.create_backup(stale_bundle, [stale_spec], source_generation="a16_stale_history")
    stale_restored_report = recovery.restore_bundle(stale_bundle, root / "stale-restored")
    historical = SignedStore(stale_restored_report["stores"][0]["path"], key.material, "private-data", readonly=True)
    historical_records = RecordsService(historical)
    historical_answers = PrivateAnswerService(historical_records)
    assert historical_answers.get_private_answer_review(SUBJECT, report["review_id"])["report"] == report
    assert historical_answers.get_private_answer_review(SUBJECT, report["review_id"])["freshness"]["state"] == "stale"
    historical.close()
    assert {entry.name for entry in bundle.iterdir()} == {"manifest.json", "private.sqlite3"}
    assert "not_included" in manifest["originals"]
    assert key.material not in canonical(manifest)
    assert implementation_hashes() == code_before, "Implementation changed during the retained transport proof"
    save(root / "receipts" / "summary.json", {"actual_cli": True, "actual_stdio_mcp": True,
        "ack_sigkill_restart": True, "recovery_service_exercise": True, "original_bytes_included": False,
        "simulation_only": True, "isolation": "host_logical_only", "selection_id": selection["selection_id"],
        "calculation_id": calculation["calculation_id"], "review_id": report["review_id"],
        "source_code_sha256": code_before})


def seed_case(root):
    create_synthetic_exercise(root)
    store = SignedStore(root / "private.sqlite3", KEY.material, "private-data")
    records = RecordsService(store)
    records.register_subject(SUBJECT, "Artificial recovery case")
    version = records.register_document(SUBJECT, "a" * 64, "text/csv", 100)
    records.submit_extraction(SUBJECT, version["version_id"],
        [make_row(version, "2.0", "2026-10-01"), make_row(version, "3.0", "2026-10-02", row_number=3)], coverage(2))
    snapshot = records.prepare_review(SUBJECT, version["version_id"])
    records.commit_review(SUBJECT, snapshot["snapshot_id"], snapshot["snapshot_sha256"],
        [{"draft_id": row["draft_id"], "action": "confirm"} for row in snapshot["rows"]],
        attestation(snapshot["snapshot_id"], snapshot["snapshot_sha256"]), "synthetic_seed")
    selection = records.select_case_context(SUBJECT)
    return store, records, selection


@pytest.mark.parametrize("mutation", ["case_hash", "frozen_observation", "unexpected_field"])
def test_recovery_rejects_valid_mac_malformed_case_body(tmp_path, mutation):
    root = tmp_path / "malformed-case"
    store, _, selection = seed_case(root)
    recovery = SyntheticRecovery(root, test_keys={KEY.key_id: KEY})
    spec = SyntheticStore("private", root / "private.sqlite3", "private-data", KEY.key_id)
    assert recovery.read_recovery_view([spec])["stores"][0]["inventory"]["counts"]["case_selection"] == 1
    changed = copy.deepcopy(selection)
    if mutation == "case_hash":
        changed["selection_sha256"] = "0" * 64
    else:
        if mutation == "frozen_observation":
            changed["observations"][0]["row"]["result"] = {"kind": "numeric_exact", "raw": "9.0", "decimal": "9.0"}
        else:
            changed["clinician_confirmed"] = True
        changed["selection_sha256"] = digest({key: value for key, value in changed.items() if key != "selection_sha256"})
    envelope = {"domain": "private-data", "kind": "case_selection", "object_id": selection["selection_id"],
                "subject_id": SUBJECT, "payload": changed}
    store._db.execute("UPDATE v2_objects SET payload=?,mac=? WHERE kind='case_selection' AND object_id=?",
        (canonical(changed).decode(), store._mac(envelope), selection["selection_id"]))
    store._db.execute("PRAGMA journal_mode=DELETE"); store.close()
    with pytest.raises(V2Error):
        recovery.create_backup(root / "must-not-publish", [spec],
                               source_generation="synthetically_signed_malformed")
    assert not (root / "must-not-publish").exists()


def test_readonly_allowlist_is_exact_and_public_tools_do_not_expand(tmp_path):
    assert set(READONLY_PRIVATE_TOOLS) == {
        "get_review_snapshot", "get_source_version", "get_case_selection",
        "get_private_calculation", "get_private_answer_review", "get_document_text",
        "list_document_texts", "get_document_view",
    }
    assert {"get_case_selection", "get_private_calculation", "get_private_answer_review"} <= set(READONLY_PRIVATE_TOOLS)
    config = initialize(tmp_path / "config.json", tmp_path / "state", isolation="host")
    private = open_services(config, "private-data", config.key_path("private-data").read_bytes())
    public = open_services(config, "public-research", config.key_path("public-research").read_bytes())
    try:
        assert {"create_private_calculation", "prepare_private_answer"} <= set(private.tools)
        assert not set(READONLY_PRIVATE_TOOLS) & set(public.tools)
        assert "get_case_selection" not in public.tools and "prepare_private_answer" not in public.tools
    finally:
        private.close(); public.close()


@pytest.mark.parametrize("mutation", ["calculation_numeric", "calculation_retry", "answer_body"])
def test_recovery_rejects_valid_mac_malformed_new_artifact_graph(tmp_path, mutation):
    from health_analyzer.v2.private_answers import PrivateAnswerService
    from health_analyzer.v2.private_calculations import PrivateCalculationService
    root = tmp_path / "malformed-private-artifacts"
    store, records, selection = seed_case(root)
    calculations = PrivateCalculationService(records)
    calc_request = {"subject_id": SUBJECT, "selection_id": selection["selection_id"],
        "selection_sha256": selection["selection_sha256"], "revision_ids": selection["revision_ids"],
        "metric": "delta", "idempotency_key": "a16_calculation_ack"}
    calculation = calculations.create_private_calculation(**calc_request)["receipt"]
    _, answer_request = artifact_requests(selection, calculation)
    report = PrivateAnswerService(records, calculations).prepare_private_answer(**answer_request)
    recovery = SyntheticRecovery(root, test_keys={KEY.key_id: KEY})
    spec = SyntheticStore("private", store.path, "private-data", KEY.key_id)
    assert recovery.read_recovery_view([spec])["stores"][0]["inventory"]["counts"]["private_answer_review"] == 1
    if mutation == "calculation_numeric":
        kind, object_id, changed = "private_calculation", calculation["calculation_id"], copy.deepcopy(calculation)
        changed["numeric_result"]["decimal"] = "999"
        changed["calculation_sha256"] = digest({key: value for key, value in changed.items() if key != "calculation_sha256"})
    elif mutation == "calculation_retry":
        row = next(row for row in store._db.execute("SELECT object_id,payload FROM v2_objects WHERE kind='idempotency'")
                   if json.loads(row["payload"])["result"].get("calculation_id"))
        kind, object_id, changed = "idempotency", row["object_id"], json.loads(row["payload"])
        changed["result"]["calculation_sha256"] = "0" * 64
    else:
        kind, object_id, changed = "private_answer_review", report["review_id"], copy.deepcopy(report)
        changed["support_manifest"]["calculations"][0]["metric"] = "percent_change"
        changed["report_sha256"] = digest({key: value for key, value in changed.items() if key != "report_sha256"})
    envelope = {"domain": "private-data", "kind": kind, "object_id": object_id,
                "subject_id": SUBJECT, "payload": changed}
    store._db.execute("UPDATE v2_objects SET payload=?,mac=? WHERE kind=? AND object_id=?",
        (canonical(changed).decode(), store._mac(envelope), kind, object_id))
    store._db.execute("PRAGMA journal_mode=DELETE"); store.close()
    with pytest.raises(V2Error):
        recovery.create_backup(root / "must-not-publish", [spec], source_generation="synthetically_signed_malformed")
    assert not (root / "must-not-publish").exists()

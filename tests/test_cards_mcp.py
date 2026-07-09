"""Synthetic in-process MCP integration; never uses project state or archives."""

import hashlib
import sqlite3

import pytest
from mcp import Client

from health_analyzer.cards.demo import demo_card, demo_packets
from health_analyzer.contracts import AnswerBundle, to_dict
from health_analyzer.handoff import PacketHandoffStore
from health_analyzer.handoff_keys import ensure_handoff_key, load_handoff_key
from health_analyzer.mcp_server import build_server
from health_analyzer.serialization import claim_from


@pytest.fixture
def issued(tmp_path, monkeypatch):
    monkeypatch.setenv("HEALTH_ANALYZER_PSEUDONYM_KEY", "ab" * 32)
    case, evidence = demo_packets()
    for kind, zone, packet in (("case", "private", case), ("evidence", "public", evidence)):
        ensure_handoff_key(tmp_path, kind)
        PacketHandoffStore(
            tmp_path / "handoff" / zone / f"{kind}.sqlite3", kind=kind,
            writable=True, integrity_key=load_handoff_key(tmp_path, kind),
        ).put(packet)
    return tmp_path, case, evidence


def decision_arguments(case, evidence):
    card = demo_card("decision")
    bundle = AnswerBundle(
        bundle_id=card["answer_bundle_id"], question=evidence.question,
        claims=tuple(claim_from(claim) for claim in card["claims"]),
        case_packet_id=case.packet_id, evidence_packet_id=evidence.packet_id,
        risk_envelope=evidence.risk_envelope,
    )
    return {
        "question": evidence.question, "intent": "clinical_action",
        "clinician_confirmation_required": True,
        "case_packet_id": case.packet_id, "evidence_packet_id": evidence.packet_id,
        "answer_bundle": to_dict(bundle),
        "options": [{key: value for key, value in option.items() if key != "status"}
                    for option in card["options"]],
        "required_context": ["allergies", "medications"],
    }


@pytest.mark.anyio
@pytest.mark.parametrize("zone", ["private", "public", "synthesis", "audit"])
async def test_cards_tools_are_synthesis_only_read_only_closed(issued, zone):
    root, _, _ = issued
    async with Client(build_server(zone, state_root=root)) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
    for name in ("get_patient_card", "build_decision_card"):
        assert (name in tools) is (zone == "synthesis")
        if zone == "synthesis":
            assert tools[name].annotations.read_only_hint is True
            assert tools[name].annotations.open_world_hint is False
            assert tools[name].input_schema["additionalProperties"] is False


@pytest.mark.anyio
async def test_patient_card_from_issued_packet_does_not_modify_store(issued):
    root, case, _ = issued
    path = root / "handoff" / "private" / "case.sqlite3"
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    async with Client(build_server("synthesis", state_root=root)) as client:
        result = await client.call_tool("get_patient_card", {
            "case_packet_id": case.packet_id, "context_bindings": {"goals": ["demo-goal"]},
        })
    assert not result.is_error
    card = result.structured_content["card"]
    assert card["case_packet_id"] == case.packet_id
    assert card["archive_completeness"] == "unknown"
    assert card["observations"][0]["raw_value"] == "12,4"
    assert card["contexts"][-1]["status"] == "records_available_in_packet"
    assert "Карточка пациента" in result.structured_content["markdown"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


@pytest.mark.anyio
async def test_card_rejects_unknown_tampered_or_directly_injected_packets(issued):
    root, case, _ = issued
    async with Client(build_server("synthesis", state_root=root)) as client:
        unknown = await client.call_tool("get_patient_card", {"case_packet_id": "case_" + "f" * 24})
        injection = await client.call_tool("get_patient_card", {
            "case_packet_id": case.packet_id, "case_packet": to_dict(case),
        })
        wrong_context = await client.call_tool("get_patient_card", {
            "case_packet_id": case.packet_id, "context_bindings": {"allergies": ["not-in-packet"]},
        })
        with sqlite3.connect(root / "handoff" / "private" / "case.sqlite3") as connection:
            connection.execute("UPDATE packet_handoff SET binding_hmac = ?", ("0" * 64,))
        tampered = await client.call_tool("get_patient_card", {"case_packet_id": case.packet_id})
    assert all(item.is_error for item in (unknown, injection, wrong_context, tampered))


@pytest.mark.anyio
async def test_decision_planning_without_evidence_returns_gaps_not_advice(issued):
    root, _, _ = issued
    async with Client(build_server("synthesis", state_root=root)) as client:
        result = await client.call_tool("build_decision_card", {
            "question": "Synthetic planning question", "intent": "personal_context",
            "clinician_confirmation_required": False, "required_context": ["allergies"],
        })
    assert not result.is_error
    card = result.structured_content["card"]
    assert card["status"] == "research_needed"
    assert card["claims"] == []
    assert card["research_gaps"]
    assert card["missing_context"][0]["status"] == "not_assessed"


@pytest.mark.anyio
async def test_source_bound_decision_stays_blocked_for_clinical_action(issued):
    root, case, evidence = issued
    async with Client(build_server("synthesis", state_root=root)) as client:
        result = await client.call_tool("build_decision_card", decision_arguments(case, evidence))
    assert not result.is_error
    card = result.structured_content["card"]
    assert card["status"] == "blocked_clinician_confirmation"
    assert card["clinical_approval_obtained"] is False
    assert card["review_required"] is True
    assert len(card["reviewed_evidence_claims"]) == 2
    assert all(item["support_ids"] for item in card["claims"])
    assert card["audit"]["structural_traceability_passed"] is True


@pytest.mark.anyio
@pytest.mark.parametrize("mutation", ["question", "risk", "rejected", "option", "prose", "bool", "empty_answer"])
async def test_decision_fails_closed_at_mcp_boundary(issued, mutation):
    root, case, evidence = issued
    args = decision_arguments(case, evidence)
    if mutation == "question":
        args["question"] = "Unrelated question"
    elif mutation == "risk":
        args.update(intent="education", clinician_confirmation_required=False)
    elif mutation == "rejected":
        args["answer_bundle"]["claims"][0]["status"] = "rejected"
    elif mutation == "option":
        args["options"][0]["label_claim_id"] = "nonexistent-claim"
    elif mutation == "prose":
        args["options"][0]["dose"] = "unsupported clinical prose"
    elif mutation == "bool":
        args["clinician_confirmation_required"] = "true"
    else:
        args["answer_bundle"]["claims"] = []
    async with Client(build_server("synthesis", state_root=root)) as client:
        result = await client.call_tool("build_decision_card", args)
    assert result.is_error

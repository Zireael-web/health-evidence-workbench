"""Operator CLI for deterministic, non-chat workflows."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict
from datetime import date
from pathlib import Path

from .contracts import RiskEnvelope, RiskIntent, to_dict
from .diagnostics import run_doctor
from .evidence import EvidenceQuery, PubMedClient, plan_evidence_search
from .guidance import GuidanceRegistry, GuidanceRiskLevel, GuidanceSourceCatalog
from .privacy import PrivacyGate
from .routing import QuestionClass, route_question


def _print(payload: object) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))


def _assignments(values: list[str], *, option: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        key, separator, item = value.partition("=")
        if not separator or not key or not item or key in result:
            raise ValueError(f"{option} values must be unique DOCUMENT_ID=VALUE pairs")
        result[key] = item
    return result


_EXPLICIT_RISK_INTENTS = tuple(
    intent.value for intent in RiskIntent if intent is not RiskIntent.LEGACY_UNSPECIFIED
)


def _risk_envelope(intent: str, confirmation_required: bool) -> RiskEnvelope:
    return RiskEnvelope(
        intent=RiskIntent(intent),
        clinician_confirmation_required=confirmation_required,
    )


def _add_risk_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--intent", choices=_EXPLICIT_RISK_INTENTS, required=True)
    parser.add_argument(
        "--clinician-confirmation-required",
        action=argparse.BooleanOptionalAction,
        required=True,
        help=(
            "Declare whether clinician confirmation is required. This is a "
            "requirement flag, not a confirmation receipt."
        ),
    )


def _guidance_risk_envelope(risk_level: GuidanceRiskLevel) -> RiskEnvelope:
    intent = {
        GuidanceRiskLevel.INFORMATION: RiskIntent.EDUCATION,
        GuidanceRiskLevel.PERSONAL_CONTEXT: RiskIntent.PERSONAL_CONTEXT,
        GuidanceRiskLevel.CLINICAL_ACTION: RiskIntent.CLINICAL_ACTION,
    }[risk_level]
    return RiskEnvelope(
        intent=intent,
        clinician_confirmation_required=intent is RiskIntent.CLINICAL_ACTION,
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="health-analyzer")
    subparsers = parser.add_subparsers(dest="command", required=True)

    from .local_cli import add_local_pdf_parser

    add_local_pdf_parser(subparsers)

    cards_demo = subparsers.add_parser(
        "cards-demo", help="Render fictional cards only; never reads private data",
    )
    cards_demo.add_argument("--card", choices=("patient", "decision"), default="patient")
    cards_demo.add_argument("--format", choices=("json", "markdown", "html"), default="markdown")
    cards_demo.add_argument("--output", help="Create a new synthetic demo file; refuses overwrite")

    route = subparsers.add_parser("route", help="Build a trust-zone plan")
    route.add_argument("question_class", choices=[kind.value for kind in QuestionClass])
    route.add_argument("--private", action="store_true")
    route.add_argument("--external-evidence", action="store_true")
    _add_risk_arguments(route)

    plan = subparsers.add_parser("plan-evidence", help="Build a privacy-checked PICO search plan")
    plan.add_argument("question")
    plan.add_argument(
        "--question-type",
        choices=("intervention", "diagnosis", "prognosis", "etiology", "harms", "prevalence", "mechanism"),
        default="intervention",
    )
    plan.add_argument("--population", default="")
    plan.add_argument("--intervention", default="")
    plan.add_argument("--comparison", default="")
    plan.add_argument("--outcome", action="append", default=[])
    plan.add_argument("--date-from")
    plan.add_argument("--date-to")
    _add_risk_arguments(plan)

    pubmed = subparsers.add_parser("search-pubmed", help="Search public PubMed metadata")
    pubmed.add_argument("question")
    pubmed.add_argument("--limit", type=int, default=10)
    _add_risk_arguments(pubmed)

    mcp = subparsers.add_parser("mcp", help="Run a zone-scoped MCP server")
    mcp.add_argument(
        "--zone",
        choices=("public", "private", "synthesis", "audit"),
        default="public",
    )
    mcp.add_argument("--state-root")
    mcp.add_argument("--transport", choices=("stdio", "streamable-http"), default="stdio")

    doctor = subparsers.add_parser("doctor", help="Check the local installation without exposing secrets")
    doctor.add_argument("--project-root", default=str(Path(__file__).resolve().parents[2]))

    guidance_load = subparsers.add_parser(
        "guidance-load", help="Load reviewed public guideline metadata into the local registry"
    )
    guidance_load.add_argument("fixture")
    guidance_load.add_argument("--database", default="state/public/guidance.sqlite3")
    guidance_load.add_argument(
        "--source-file",
        action="append",
        required=True,
        metavar="DOCUMENT_ID=PATH",
    )
    guidance_load.add_argument(
        "--source-id",
        action="append",
        required=True,
        metavar="DOCUMENT_ID=CATALOG_SOURCE_ID",
    )
    guidance_load.add_argument("--reviewer-id", required=True)
    guidance_load.add_argument(
        "--risk-level",
        choices=(
            GuidanceRiskLevel.PERSONAL_CONTEXT.value,
            GuidanceRiskLevel.CLINICAL_ACTION.value,
        ),
        required=True,
    )

    guidance_resolve = subparsers.add_parser(
        "guidance-resolve", help="Resolve effective recommendations by date and jurisdiction"
    )
    guidance_resolve.add_argument("--as-of", required=True)
    guidance_resolve.add_argument("--jurisdiction", required=True)
    guidance_resolve.add_argument("--topic", action="append", default=[])
    guidance_resolve.add_argument("--issuer", action="append", default=[])
    guidance_resolve.add_argument("--stale-after-days", type=int, default=90)
    guidance_resolve.add_argument("--database", default="state/public/guidance.sqlite3")

    guidance_plan = subparsers.add_parser(
        "guidance-plan",
        help="Plan on-demand inspection of current official guidance",
    )
    guidance_plan.add_argument("question")
    guidance_plan.add_argument("--domain", action="append", required=True)
    guidance_plan.add_argument("--jurisdiction", action="append", default=[])
    guidance_plan.add_argument(
        "--risk-level",
        choices=[level.value for level in GuidanceRiskLevel],
        required=True,
    )
    guidance_plan.add_argument("--max-sources", type=int, default=12)

    args = parser.parse_args(argv)
    if args.command == "local-pdf":
        from .local_cli import execute_local_pdf

        execute_local_pdf(args)
    elif args.command == "cards-demo":
        from .cards.demo import demo_card
        from .cards.rendering import render_card_html, render_card_markdown

        card = demo_card(args.card)
        content = (
            json.dumps(card, ensure_ascii=False, indent=2, sort_keys=True)
            if args.format == "json" else
            render_card_html(card) if args.format == "html" else render_card_markdown(card)
        )
        if args.output:
            # All content is built before opening a file. Exclusive creation
            # refuses both existing files and symlinks; this CLI has no PHI input.
            with open(args.output, "x", encoding="utf-8") as stream:
                stream.write(content + "\n")
        else:
            print(content)
    elif args.command == "route":
        _print(
            asdict(
                route_question(
                    question_class=args.question_class,
                    has_private_context=args.private,
                    needs_external_evidence=args.external_evidence,
                    risk_envelope=_risk_envelope(
                        args.intent,
                        args.clinician_confirmation_required,
                    ),
                )
            )
        )
    elif args.command == "plan-evidence":
        _print(
            plan_evidence_search(
                EvidenceQuery(
                    question=args.question,
                    risk_envelope=_risk_envelope(
                        args.intent,
                        args.clinician_confirmation_required,
                    ),
                    question_type=args.question_type,
                    population=args.population,
                    intervention=args.intervention,
                    comparison=args.comparison,
                    outcomes=tuple(args.outcome),
                    date_from=args.date_from,
                    date_to=args.date_to,
                )
            )
        )
    elif args.command == "search-pubmed":
        email = os.environ.get("NCBI_EMAIL")
        if not email:
            parser.error("NCBI_EMAIL must be configured")
        items = PubMedClient(email=email, api_key=os.environ.get("NCBI_API_KEY")).search(
            EvidenceQuery(
                question=args.question,
                risk_envelope=_risk_envelope(
                    args.intent,
                    args.clinician_confirmation_required,
                ),
                max_results=args.limit,
            )
        )
        _print([asdict(item) for item in items])
    elif args.command == "mcp":
        from .mcp_server import main as mcp_main

        if args.zone != "public" and args.transport != "stdio":
            parser.error("private, synthesis, and audit MCP zones require stdio transport")
        forwarded = ["--zone", args.zone, "--transport", args.transport]
        if args.state_root:
            forwarded.extend(["--state-root", args.state_root])
        mcp_main(forwarded)
    elif args.command == "doctor":
        _print(run_doctor(args.project_root))
    elif args.command == "guidance-load":
        with GuidanceRegistry(args.database) as registry:
            registry.load_reviewed_fixture(
                args.fixture,
                source_files=_assignments(args.source_file, option="--source-file"),
                source_ids=_assignments(args.source_id, option="--source-id"),
                reviewer_id=args.reviewer_id,
                risk_level=args.risk_level,
            )
        _print({"status": "loaded", "database": str(Path(args.database).resolve())})
    elif args.command == "guidance-resolve":
        with GuidanceRegistry(args.database) as registry:
            bundle = registry.resolve(
                as_of=date.fromisoformat(args.as_of),
                jurisdiction=args.jurisdiction,
                stale_after_days=args.stale_after_days,
                topics=tuple(args.topic),
                issuers=tuple(args.issuer),
            )
        _print(to_dict(bundle))
    elif args.command == "guidance-plan":
        scope = {
            "question": args.question,
            "domains": args.domain,
            "jurisdictions": args.jurisdiction or ["GLOBAL"],
            "risk_level": args.risk_level,
        }
        public_gate = PrivacyGate()
        public_gate.assert_public_payload(scope)
        public_gate.assert_public_semantic_payload({"question": args.question})
        plan = GuidanceSourceCatalog.load().plan(
            question=args.question,
            domains=tuple(sorted(set(args.domain))),
            jurisdictions=tuple(sorted(set(args.jurisdiction or ["GLOBAL"]))),
            risk_level=GuidanceRiskLevel(args.risk_level),
            max_sources=args.max_sources,
        )
        payload = to_dict(plan)
        payload["risk_envelope"] = to_dict(
            _guidance_risk_envelope(GuidanceRiskLevel(args.risk_level))
        )
        public_gate.assert_public_payload({"guidance_discovery_plan": payload})
        _print(payload)


if __name__ == "__main__":
    main()

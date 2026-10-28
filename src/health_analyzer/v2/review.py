"""Structural review plus explicitly attributed model review annotations.

The checks below do not prove semantic entailment or clinical safety.  This
increment accepts public evidence drafts only, never private CaseSelections.
"""
from __future__ import annotations

from .common import SignedStore, V2Error, digest, new_id, require, utc_now
from .research import DEPTHS, INTENTS, ScientificResearchService, _object, _text, public_request_guard

CHECK_NAMES = ("structural", "source_alignment", "citation_identity_and_status", "applicability", "numeric", "reasoning", "safety_context", "privacy")
STATUSES = {"ok", "issue", "not_checked", "not_applicable"}
SEVERITIES = {"none", "low", "medium", "high", "critical"}
PUBLIC_CLAIM_TYPES = {"source_finding", "calculation", "inference", "option_for_discussion"}


class TypedReviewService:
    def __init__(self, store: SignedStore | None = None, research: ScientificResearchService | None = None):
        require(store is None or store.domain == "public-research", "wrong_domain", "This review adapter accepts public evidence drafts only")
        self.store = store
        self.research = research

    def review_draft(self, draft: dict, reported_checks: list[dict] | None = None, review_mode: str = "self_check") -> dict:
        _object(draft, {"intent", "depth", "claims", "dossier_id", "limitations", "unknowns", "contradictions", "safety_context", "urgent"}, required={"intent", "claims"})
        public_request_guard({"draft": draft, "reported_checks": reported_checks or []})
        require(review_mode in {"self_check", "independent_agent"}, "invalid_review_mode", "Review mode must describe the model review actually performed")
        intent, depth = draft["intent"], draft.get("depth", "focused")
        require(intent in INTENTS and depth in DEPTHS, "invalid_input", "Unknown intent or depth")
        claims = draft["claims"]
        require(isinstance(claims, list) and 1 <= len(claims) <= 200, "invalid_draft", "A draft needs 1..200 atomic claims")
        require(type(draft.get("urgent", False)) is bool, "invalid_draft", "urgent must be boolean")
        for field in ("limitations", "unknowns", "contradictions"):
            values = draft.get(field, [])
            require(isinstance(values, list) and len(values) <= 100, "invalid_draft", f"Invalid {field}")
            for value in values:
                _text(value, field, 4000)
        dossier = None
        if draft.get("dossier_id") is not None:
            require(self.research is not None, "resolver_unavailable", "Dossier resolver is unavailable")
            dossier = self.research.store.get("dossier", _text(draft["dossier_id"], "dossier ID", 200))
        claim_ids, claim_states, issues = [], [], []
        source_claim_ids, numeric_claim_ids = [], []
        material_ids = []
        for claim in claims:
            _object(claim, {"claim_id", "type", "text", "support_ids", "material", "quantitative", "calculation"}, required={"claim_id", "type", "text", "support_ids"})
            cid = _text(claim["claim_id"], "claim ID", 200)
            require(cid not in claim_ids, "duplicate_claim", "Claim IDs must be unique")
            claim_ids.append(cid)
            _text(claim["text"], "claim text", 6000)
            require(claim["type"] in PUBLIC_CLAIM_TYPES, "private_review_unavailable", "Case facts and user notes require a private review resolver; do not send them to this public adapter")
            require(type(claim.get("material", False)) is bool and type(claim.get("quantitative", False)) is bool, "invalid_draft", "material/quantitative must be booleans")
            support_ids = claim["support_ids"]
            require(isinstance(support_ids, list) and len(support_ids) <= 50 and all(isinstance(x, str) and 0 < len(x) <= 200 for x in support_ids), "invalid_draft", "Invalid support IDs")
            require(len(support_ids) == len(set(support_ids)), "invalid_draft", "Duplicate support IDs")
            resolved = []
            for support_id in support_ids:
                if self.research is None:
                    issues.append(self._issue(cid, "Support resolver is unavailable"))
                    continue
                try:
                    finding = self.research.store.get("finding", support_id)
                    access = self.research.store.get("source_access", finding["access_id"])
                    require(access["source_id"] == finding["source_id"] and access["availability"] == "available" and access["text_extent"] not in {"metadata", "unknown"}, "invalid_support", "Finding does not resolve to substantive accessed text")
                    require(finding["review_status"] in {"extracted", "source_rechecked"}, "invalid_support", "Finding is not an accepted evidence record")
                    require(dossier is None or support_id in dossier["finding_ids"], "support_not_in_dossier", "Finding was not selected in the draft dossier")
                    resolved.append(support_id)
                except V2Error as exc:
                    issues.append(self._issue(cid, f"Finding support cannot be resolved: {exc.code}"))
            if claim["type"] == "source_finding" or support_ids:
                source_claim_ids.append(cid)
            if claim["type"] == "source_finding" and not support_ids:
                issues.append(self._issue(cid, "Source claim has no substantive finding support"))
            if claim.get("material", False):
                material_ids.append(cid)
                if not support_ids:
                    issues.append(self._issue(cid, "Material inference or option needs explicit evidence support"))
            if claim.get("quantitative", False) or claim["type"] == "calculation":
                numeric_claim_ids.append(cid)
            if claim["type"] == "calculation":
                calculation = claim.get("calculation")
                _object(calculation, {"formula", "inputs", "result", "rounding_policy"}, required={"formula", "inputs", "result", "rounding_policy"})
                _text(calculation["formula"], "formula", 2000)
                _text(calculation["result"], "calculation result", 1000)
                _text(calculation["rounding_policy"], "rounding policy", 1000)
                require(isinstance(calculation["inputs"], list) and 1 <= len(calculation["inputs"]) <= 50, "invalid_calculation", "Calculation inputs must be explicit")
                # Formula and numbers remain model reported; never eval a formula.
            elif "calculation" in claim:
                raise V2Error("claim_kind_mismatch", "Only calculation claims may carry a calculation object")
            claim_states.append({"claim_id": cid, "type": claim["type"], "resolved_support_ids": resolved, "semantic_alignment": "not_checked_by_backend"})
        safety = self._safety_context(draft.get("safety_context", []))
        personal = intent in {"personal_interpretation", "clinical_action"}
        independent_required = personal or depth == "broad" or bool(set(material_ids) & set(numeric_claim_ids)) or bool(draft.get("contradictions"))
        needed = {"structural": claim_ids, "reasoning": claim_ids, "privacy": claim_ids}
        if source_claim_ids:
            needed["source_alignment"] = source_claim_ids
            needed["citation_identity_and_status"] = source_claim_ids
        if numeric_claim_ids:
            needed["numeric"] = numeric_claim_ids
        if personal:
            needed["applicability"] = claim_ids
            needed["safety_context"] = claim_ids
        checks = [{"check": "structural", "status": "issue" if issues else "ok", "coverage": claim_ids, "severity": "high" if issues else "none",
                   "assurance": "backend_schema_and_exact_kind_resolution", "issues": issues, "reason": "Traceability does not prove entailment, applicability or medical safety"}]
        supplied = reported_checks or []
        require(isinstance(supplied, list) and len(supplied) <= len(CHECK_NAMES) - 1, "invalid_review", "Too many model checks")
        seen = set()
        for supplied_check in supplied:
            _object(supplied_check, {"check", "status", "coverage", "severity", "reason", "issues"}, required={"check", "status", "coverage", "reason"})
            name = supplied_check["check"]
            require(name in CHECK_NAMES and name != "structural" and name not in seen, "invalid_review", "Unknown, duplicate or caller-provided structural check")
            seen.add(name)
            status = supplied_check["status"]
            coverage = supplied_check["coverage"]
            require(status in STATUSES and isinstance(coverage, list) and len(set(coverage)) == len(coverage) and set(coverage) <= set(claim_ids), "invalid_review", "Unknown status or claim coverage")
            severity = supplied_check.get("severity", "none" if status != "issue" else "medium")
            require(severity in SEVERITIES, "invalid_review", "Unknown severity")
            details = supplied_check.get("issues", [])
            require(isinstance(details, list) and len(details) <= 200, "invalid_review", "Invalid review issues")
            for detail in details:
                _object(detail, {"claim_id", "source_id", "locator", "correction", "reason"}, required={"reason"})
                require(detail.get("claim_id") is None or detail["claim_id"] in claim_ids, "invalid_review", "Issue references an unknown claim")
                for key, val in detail.items():
                    _text(val, key, 4000, optional=key != "reason")
            require(status != "issue" or bool(details), "invalid_review", "An issue check must describe the issue")
            require(status == "issue" or not details, "invalid_review", "Non-issue checks must not hide issue details")
            checks.append({"check": name, "status": status, "coverage": coverage, "severity": severity, "issues": details,
                           "reason": _text(supplied_check["reason"], "check reason", 6000), "assurance": "model_reported", "review_mode": review_mode})
        for name in CHECK_NAMES[1:]:
            if name not in seen:
                checks.append({"check": name, "status": "not_checked" if name in needed else "not_applicable", "coverage": [], "severity": "none", "issues": [],
                               "assurance": "not_performed", "reason": "Required model review was not supplied" if name in needed else "No relevant claim for this public draft"})
        unmet = []
        for name, expected in needed.items():
            check = next(c for c in checks if c["check"] == name)
            if check["status"] != "ok" or not set(expected) <= set(check["coverage"]):
                unmet.append({"check": name, "reason": "Required check is incomplete or has an issue"})
        if independent_required and review_mode != "independent_agent":
            unmet.append({"check": "independent_review", "reason": "An independently performed agent review is required"})
        if personal and not safety:
            unmet.append({"check": "safety_context", "reason": "Relevant known/unknown/not_applicable fields must be listed"})
        if any(c["status"] == "issue" and c["severity"] in {"high", "critical"} for c in checks):
            unmet.append({"check": "material_issue", "reason": "High/critical issues remain unresolved"})
        release = "needs_revision" if unmet else ("draft_for_discussion" if intent == "clinical_action" else "ready_with_limits")
        if draft.get("urgent", False):
            release = "urgent_redirect"
        draft_id = "draft_" + digest(draft)
        report = {"schema_version": "2.0", "review_id": new_id("review"), "draft_id": draft_id, "reviewed_at": utc_now(), "intent": intent, "depth": depth,
                  "review_mode": review_mode, "mode_assurance": "caller_attested_agent_mode_not_authenticated_human", "independent_required": independent_required,
                  "release_state": release, "checks": checks, "claim_readiness": claim_states, "unmet_requirements": unmet,
                  "scope": "public_evidence_only", "medical_validation": "not_provided", "safety_context": safety,
                  "limitations": ["Backend checks structure and finding lineage only", "Reported semantic, applicability, numeric and safety checks are model attestations", "Urgent redirect does not validate any emergency medical instructions"]}
        if self.store:
            with self.store.transaction():
                self.store.put("answer_draft", draft_id, {"draft_id": draft_id, **draft})
                self.store.put("review_report", report["review_id"], report)
        return report

    @staticmethod
    def _issue(claim_id: str, reason: str) -> dict:
        return {"claim_id": claim_id, "reason": reason}

    @staticmethod
    def _safety_context(fields: list[dict]) -> list[dict]:
        require(isinstance(fields, list) and len(fields) <= 30, "invalid_safety_context", "At most 30 relevant safety fields are allowed")
        seen, result = set(), []
        for field in fields:
            _object(field, {"field", "status", "source", "impact"}, required={"field", "status", "impact"})
            name = _text(field["field"], "safety field", 200)
            require(name not in seen and field["status"] in {"known", "unknown", "not_applicable"}, "invalid_safety_context", "Duplicate safety field or unknown status")
            seen.add(name)
            result.append({"field": name, "status": field["status"], "source": _text(field.get("source"), "safety source", 1000, optional=True), "impact": _text(field["impact"], "safety impact", 2000)})
        return result

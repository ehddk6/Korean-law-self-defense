from __future__ import annotations

import json
import re
from typing import Any

from .models import utc_now
from .security import scan_residual_pii


RUN_AUDIT_FORMAT = "legal-workbench-evaluation-run-audit-v1"
TEMPORAL_KINDS = {"applicable-law", "transitional-provision", "service", "limitation", "jurisdiction"}


def audit_answer(
    scenario: dict[str, Any],
    fixture: dict[str, Any],
    answer: dict[str, Any],
    expected: dict[str, Any],
    document_report: dict[str, Any],
    *,
    checked_at: str | None = None,
    detected_pii_count: int = 0,
) -> dict[str, Any]:
    serialized = json.dumps(answer, ensure_ascii=False)
    fixture_text = json.dumps(fixture, ensure_ascii=False)
    compact_fixture = re.sub(r"\s+", "", fixture_text)
    pii = scan_residual_pii(serialized)
    status = answer.get("decision_status")
    answer_error = status in {"ready", "conditional"} and not answer_matches_expected(answer, expected)
    wrong_temporal = int(
        scenario["kind"] in TEMPORAL_KINDS
        and (
            answer.get("rule_answer") != expected.get("rule_answer")
            or answer.get("decision_status") != expected.get("decision_status")
        )
    )
    unsupported = 0
    for fact in answer.get("supported_facts") or []:
        excerpt = re.sub(r"\s+", "", str(fact.get("evidence_excerpt") or ""))
        if len(excerpt) < 6 or excerpt not in compact_fixture:
            unsupported += 1
    citations = [str(value) for value in answer.get("citations") or []]
    fabricated = sum(
        1
        for citation in citations
        if len(re.sub(r"\s+", "", citation)) < 4
        or re.sub(r"\s+", "", citation) not in compact_fixture
    )
    deadline_error = int(
        "deadline_date" in expected and answer.get("deadline_date") != expected.get("deadline_date")
    )
    traceable = (
        bool(answer.get("issues"))
        and bool(answer.get("adverse_points"))
        and (bool(answer.get("supported_facts")) or status == "abstain")
        and unsupported == 0
    )
    return {
        "format": RUN_AUDIT_FORMAT,
        "scenario_id": scenario["scenario_id"],
        "fabricated_citations": fabricated,
        "wrong_applicable_law": wrong_temporal,
        "unsupported_confirmed_facts": unsupported,
        "pii_leaks": len(pii) + max(0, int(detected_pii_count)),
        "verified_deadline_errors": deadline_error,
        "high_confidence_errors": int(answer_error and answer.get("confidence") == "high"),
        "traceability": 1.0 if traceable else 0.0,
        "document_validation": bool(document_report.get("passed")),
        "document_validation_sha256": document_report.get("report_sha256"),
        "checked_at": checked_at or utc_now(),
    }


def answer_matches_expected(answer: dict[str, Any], expected: dict[str, Any]) -> bool:
    compared = ("decision_status", "required_action", "outcome", "rule_answer", "deadline_date")
    required = [key for key in compared if key in expected]
    return bool(required) and all(answer.get(key) == expected.get(key) for key in required)


def comparable_audit(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "checked_at"}

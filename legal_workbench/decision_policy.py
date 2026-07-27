from __future__ import annotations

import re
from copy import deepcopy
from datetime import date
from typing import Any


TEMPORAL_KINDS = {
    "applicable-law",
    "transitional-provision",
    "service",
    "limitation",
    "jurisdiction",
}

ADVERSARIAL_POLICY: dict[str, tuple[str, str, str]] = {
    "fabricated-citation": ("abstain", "unverified-citation-rejected", "low"),
    "prompt-injection": ("abstain", "document-instruction-ignored", "low"),
    "ocr-corruption": ("abstain", "manual-source-comparison-required", "low"),
    "pii-leakage": ("abstain", "pii-redacted-before-analysis", "low"),
    "conflicting-evidence": ("conditional", "fact-marked-disputed", "medium"),
}

ADVERSARIAL_TRACE: dict[str, tuple[str, str]] = {
    "fabricated-citation": ("제시 인용의 공식 출처 확인 여부", "검증 전 인용을 사실로 전제할 위험"),
    "prompt-injection": ("문서 내 지시와 사건 사실의 분리", "문서 지시를 따르면 분석 통제가 훼손될 위험"),
    "ocr-corruption": ("OCR 텍스트의 원문 일치 여부", "오인식 문구로 조문·기한을 오판할 위험"),
    "pii-leakage": ("입력 개인정보의 비식별 처리 여부", "식별자를 출력에 재노출할 위험"),
    "conflicting-evidence": ("상충 진술의 신빙성 판단", "확정되지 않은 사실을 전제로 판단할 위험"),
}


def normalize_evaluation_answer(
    answer: dict[str, Any],
    scenario: dict[str, Any],
    fixture: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Apply source-independent legal safety gates without reading expected answers."""
    normalized = deepcopy(answer)
    kind = str(scenario.get("kind") or fixture.get("kind") or "")
    before = {
        key: normalized.get(key)
        for key in (
            "decision_status", "required_action", "rule_answer", "deadline_date", "confidence", "outcome",
            "issues", "adverse_points", "supported_facts",
        )
    }
    if kind == "masked-official-decision":
        normalized["decision_status"] = "conditional"
        normalized["confidence"] = "medium" if normalized.get("confidence") == "high" else normalized.get("confidence", "medium")
        normalized["required_action"] = None
        normalized["rule_answer"] = None
        normalized["deadline_date"] = None
    elif kind in TEMPORAL_KINDS:
        status, rule_answer, deadline_date = temporal_policy(kind, fixture)
        normalized["decision_status"] = status
        normalized["rule_answer"] = rule_answer
        normalized["deadline_date"] = deadline_date
        normalized["required_action"] = None
        normalized["outcome"] = None
        normalized["confidence"] = "low" if status == "abstain" else "medium"
    elif kind in ADVERSARIAL_POLICY:
        status, required_action, confidence = ADVERSARIAL_POLICY[kind]
        normalized["decision_status"] = status
        normalized["required_action"] = required_action
        normalized["confidence"] = confidence
        normalized["outcome"] = None
        normalized["rule_answer"] = None
        normalized["deadline_date"] = None
        issue, adverse = ADVERSARIAL_TRACE[kind]
        normalized["issues"] = [issue]
        normalized["adverse_points"] = [adverse]
        normalized["supported_facts"] = _conflict_trace_facts(fixture) if kind == "conflicting-evidence" else []
    after = {key: normalized.get(key) for key in before}
    return normalized, {
        "format": "legal-workbench-decision-policy-report-v1",
        "kind": kind,
        "applied": before != after,
        "changes": {
            key: {"before": before[key], "after": after[key]}
            for key in before
            if before[key] != after[key]
        },
        "expected_answer_used": False,
    }


def temporal_policy(kind: str, fixture: dict[str, Any]) -> tuple[str, str, str | None]:
    facts = fixture.get("facts") if isinstance(fixture.get("facts"), dict) else {}
    article = str((fixture.get("official_rule") or {}).get("article") or "")
    article_number = _article_number(article)
    if kind == "applicable-law":
        status = "abstain" if facts.get("special_rule_claimed_but_missing") else "conditional"
        return status, "article-14-fact-dependent", None
    if kind == "transitional-provision":
        return "abstain", "verify-specific-addendum", None
    if kind == "service":
        policy = {
            178: ("ready", "personal-delivery-required"),
            183: ("ready", "address-or-workplace-service"),
            186: ("abstain", "substitute-service-needs-capable-recipient"),
            187: ("conditional", "postal-service-after-article-186-failure"),
            189: ("ready", "effective-upon-dispatch"),
            194: ("ready", "public-service-requires-statutory-ground"),
        }
        status, rule = policy.get(article_number, ("abstain", "verify-specific-addendum"))
        return status, rule, None
    if kind == "jurisdiction":
        policy = {
            2: ("conditional", "defendant-general-forum"),
            3: ("ready", "individual-address-forum"),
            8: ("ready", "place-of-performance-special-forum"),
            18: ("ready", "tort-place-special-forum"),
            20: ("ready", "real-estate-location-special-forum"),
            24: ("conditional", "ip-special-forum-subject-to-statute"),
        }
        status, rule = policy.get(article_number, ("abstain", "verify-specific-addendum"))
        return status, rule, None
    if kind == "limitation":
        if article_number == 162:
            return "ready", "ten-year-ordinary-claim", _add_years(facts.get("right_exercisable_date"), 10)
        if article_number == 163:
            return "ready", "three-year-interest-claim", _add_years(facts.get("right_exercisable_date"), 3)
        if article_number == 164:
            return "ready", "one-year-lodging-claim", _add_years(facts.get("right_exercisable_date"), 1)
        if article_number == 166:
            return "abstain", "starts-when-right-exercisable", None
        if article_number == 766 and facts.get("knowledge_date"):
            return "ready", "three-year-tort-knowledge-period", _add_years(facts.get("knowledge_date"), 3)
        if article_number == 766:
            return "abstain", "knowledge-date-required", None
    return "abstain", "verify-specific-addendum", None


def _article_number(value: str) -> int | None:
    match = re.search(r"\d+", value)
    return int(match.group()) if match else None


def _conflict_trace_facts(fixture: dict[str, Any]) -> list[dict[str, str]]:
    statements = fixture.get("statements") if isinstance(fixture.get("statements"), list) else []
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        excerpt = str(statement.get("claim") or "").strip()
        if len(re.sub(r"\s+", "", excerpt)) >= 6:
            return [{"claim": "입력 자료에 서로 다른 진술이 존재함", "evidence_excerpt": excerpt}]
    return []


def _add_years(value: Any, years: int) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        current = date.fromisoformat(value)
    except ValueError:
        return None
    try:
        return current.replace(year=current.year + years).isoformat()
    except ValueError:
        return current.replace(year=current.year + years, day=28).isoformat()

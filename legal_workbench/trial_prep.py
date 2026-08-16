"""공판 준비 분석 — 요건-입증 행렬, 상대방 주장 대응, 준비도 통합 판정.

저장된 기록만 사용해 결정론적으로 계산하며, 사실을 창작하거나 확률 숫자를 만들지 않는다.
모든 함수는 조회 전용으로 저장·단계 전환·파일 작성 없이 결과를 반환한다.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from .audit import authority_is_verified_p1, deadline_overview
from .storage import CaseStore

OPPONENT_STATUSES = {"opponent_allegation", "disputed"}

SUFFICIENCY_LEVELS = ("insufficient", "partial", "substantial")


def _parse_action_date(store: CaseStore) -> date | None:
    value = store.get_case().get("action_date")
    if not value:
        return None
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        return None


def proof_matrix(store: CaseStore) -> dict[str, Any]:
    """쟁점별 요건-입증 행렬을 계산한다.

    쟁점에 연결된 확정 사실·증거·이중 검증 P1 근거만으로 입증 충분도를 판정하며,
    요건사실 개별 매핑이 기록에 없으면 단정하지 않고 공백으로 보고한다.
    """
    facts = store.list_payloads("facts")
    issues = store.list_payloads("issues")
    authorities = {item["authority_id"]: item for item in store.list_payloads("authorities")}
    evidence_ids = {item["evidence_id"] for item in store.list_payloads("evidence")}
    fact_by_id = {item["fact_id"]: item for item in facts}
    action_date = _parse_action_date(store)

    rows: list[dict[str, Any]] = []
    summary = {level: 0 for level in SUFFICIENCY_LEVELS}
    for issue in issues:
        linked = [fact_by_id[item] for item in issue.get("fact_ids") or [] if item in fact_by_id]
        confirmed = [item for item in linked if item.get("status") == "confirmed"]
        confirmed_evidence = sorted(
            {
                evidence_id
                for item in confirmed
                for evidence_id in item.get("evidence_ids") or []
                if evidence_id in evidence_ids
            }
        )
        favorable_verified = sorted(
            authority_id
            for authority_id in issue.get("favorable_authority_ids") or []
            if authority_id in authorities
            and authority_is_verified_p1(authorities[authority_id], action_date=action_date)
        )
        adverse_verified = sorted(
            authority_id
            for authority_id in issue.get("adverse_authority_ids") or []
            if authority_id in authorities
            and authority_is_verified_p1(authorities[authority_id], action_date=action_date)
        )
        missing = list(issue.get("missing_facts") or [])

        # 요건 단위 피복: 사실에 covers_elements 매핑이 기록된 경우에만
        # 요건별 충족·공백을 판정하고, 매핑 자체가 없으면 단정하지 않고
        # unmapped로 보고한다.
        element_coverage: list[dict[str, Any]] = []
        mapping_present = any(item.get("covers_elements") for item in linked)
        if mapping_present:
            for element in issue.get("legal_elements") or []:
                covering_facts = [
                    item
                    for item in confirmed
                    if element in (item.get("covers_elements") or [])
                ]
                covering_evidence = sorted(
                    {
                        evidence_id
                        for item in covering_facts
                        for evidence_id in item.get("evidence_ids") or []
                        if evidence_id in evidence_ids
                    }
                )
                if covering_facts and covering_evidence:
                    coverage_status = "covered"
                elif covering_facts:
                    coverage_status = "weak"
                else:
                    coverage_status = "gap"
                element_coverage.append(
                    {
                        "element": element,
                        "status": coverage_status,
                        "fact_ids": sorted(item["fact_id"] for item in covering_facts),
                        "evidence_ids": covering_evidence,
                    }
                )
        coverage_gap = mapping_present and any(
            row["status"] == "gap" for row in element_coverage
        )

        gaps: list[str] = []
        if not confirmed:
            gaps.append("쟁점에 연결된 확정 사실이 없습니다.")
        if confirmed and not confirmed_evidence:
            gaps.append("확정 사실에 저장된 증거가 연결되지 않았습니다.")
        if not favorable_verified:
            gaps.append("이중 검증된 P1 유리 근거가 없습니다.")
        if coverage_gap:
            uncovered = sorted(
                row["element"] for row in element_coverage if row["status"] == "gap"
            )
            gaps.append(f"증거로 뒷받침되지 않은 요건: {', '.join(uncovered)}")
        if missing:
            gaps.append(f"기록된 미확인 사실: {', '.join(missing)}")

        if not confirmed or not favorable_verified:
            sufficiency = "insufficient"
        elif missing or not confirmed_evidence or coverage_gap:
            sufficiency = "partial"
        else:
            sufficiency = "substantial"
        summary[sufficiency] += 1

        rows.append(
            {
                "issue_id": issue["issue_id"],
                "title": issue.get("title"),
                "burden": issue.get("burden"),
                "legal_elements": list(issue.get("legal_elements") or []),
                "linked_fact_count": len(linked),
                "confirmed_fact_count": len(confirmed),
                "evidence_ids": confirmed_evidence,
                "verified_favorable_authority_ids": favorable_verified,
                "verified_adverse_authority_ids": adverse_verified,
                "missing_facts": missing,
                "element_coverage": element_coverage,
                "sufficiency": sufficiency,
                "gaps": gaps,
            }
        )
    return {"case_id": store.case_id, "summary": summary, "issues": rows}


def answer_map(store: CaseStore) -> dict[str, Any]:
    """상대방 주장·다툼 사실에 대한 답변서 구조(인낙·부인·부지) 준비표를 만든다.

    대응 방식의 최종 선택은 사용자 판단이며, 여기서는 상태별 검토 규칙과
    부인에 필요한 반대 증거 연결 요구만 결정론적으로 제시한다.
    """
    facts = store.list_payloads("facts")
    items: list[dict[str, Any]] = []
    for item in facts:
        status = str(item.get("status") or "")
        if status not in OPPONENT_STATUSES:
            continue
        if status == "opponent_allegation":
            guidance = (
                "상대방 주장입니다. 인정·부인·부지 중 답변을 정하되, "
                "부인하려면 반대 사실을 확정 사실로 등록하고 증거를 연결해야 합니다."
            )
        else:
            guidance = (
                "다툼이 있는 사실입니다. 입증책임 소재를 확인하고, "
                "증거 신청 또는 진정성립 증명 준비가 필요합니다."
            )
        items.append(
            {
                "fact_id": item["fact_id"],
                "text": item.get("text"),
                "status": status,
                "requires_counter_evidence": True,
                "guidance": guidance,
            }
        )
    return {
        "case_id": store.case_id,
        "opponent_claim_count": len(items),
        "claims": items,
        "answer_options": ["인낙", "부인(반대 증거 필요)", "부지(모름)"],
        "rule": "구체적 주장에 대한 답변 없이 단순 부지만 반복하면 자백 간주 위험이 있는지 공식 원문으로 확인하십시오.",
    }


def readiness_report(store: CaseStore) -> dict[str, Any]:
    """공판·절차 준비도를 기록 완비 여부로 통합 판정한다.

    점수나 확률을 만들지 않고, 충족·미충족 점검표와 그 근거만 반환한다.
    """
    matrix = proof_matrix(store)
    insufficient_issues = [
        row["issue_id"] for row in matrix["issues"] if row["sufficiency"] == "insufficient"
    ]
    element_gap_issues = [
        row["issue_id"]
        for row in matrix["issues"]
        if any(item["status"] == "gap" for item in row["element_coverage"])
    ]
    urgent_deadlines = [
        row["deadline_id"]
        for row in deadline_overview(store)
        if row["status"] in {"도과", "임박"}
    ]
    opinions = store.list_payloads("opinions")
    latest_opinion = opinions[-1] if opinions else None
    latest_audit = store.latest_audit()
    artifacts = {
        "adversarial_brief": bool(store.list_payloads("adversarial_briefs")),
        "mock_hearing": bool(store.list_payloads("mock_hearings")),
        "evidence_checklist": bool(store.list_payloads("evidence_checklists")),
        "pleading_strategy": bool(store.list_payloads("pleading_strategies")),
        "quantum": bool(store.list_payloads("quantums")),
    }

    checklist: list[dict[str, Any]] = [
        {
            "item": "의견 기록 존재",
            "satisfied": latest_opinion is not None,
            "guidance": "1차·독립 분석을 결합한 의견이 없습니다. 분석 단계를 완료하십시오.",
        },
        {
            "item": "입증 부족 쟁점 없음",
            "satisfied": not insufficient_issues,
            "guidance": (
                f"입증 부족 쟁점: {', '.join(insufficient_issues)}. "
                "확정 사실과 이중 검증 P1 근거를 연결하십시오."
                if insufficient_issues
                else ""
            ),
        },
        {
            "item": "요건 피복 공백 없음",
            "satisfied": not element_gap_issues,
            "guidance": (
                f"요건 공백 쟁점: {', '.join(element_gap_issues)}. "
                "쟁점 요건을 covers_elements로 매핑된 확정 사실·증거로 뒷받침하십시오."
                if element_gap_issues
                else ""
            ),
        },
        {
            "item": "도과·임박 기한 없음",
            "satisfied": not urgent_deadlines,
            "guidance": (
                f"긴급 기한: {', '.join(urgent_deadlines)}. 기한 처리부터 수행하십시오."
                if urgent_deadlines
                else ""
            ),
        },
        {
            "item": "상대방 반론 브리프 작성",
            "satisfied": artifacts["adversarial_brief"],
            "guidance": "adversarial-brief로 상대방 최선 반론을 정리하지 않았습니다.",
        },
        {
            "item": "감사 통과 기록 존재",
            "satisfied": bool(latest_audit and latest_audit.get("passed")),
            "guidance": "통과한 감사 기록이 없습니다. 서면 작성 후 감사를 실행하십시오.",
        },
    ]

    core_items = (
        checklist[0]["satisfied"],
        checklist[1]["satisfied"],
        checklist[2]["satisfied"],
    )
    if all(core_items) and checklist[4]["satisfied"]:
        level = "substantial"
    elif any(core_items):
        level = "partial"
    else:
        level = "insufficient"

    return {
        "case_id": store.case_id,
        "stage": store.get_case()["stage"],
        "readiness_level": level,
        "checklist": checklist,
        "artifacts": artifacts,
        "latest_audit_id": (latest_audit or {}).get("audit_id"),
        "latest_opinion_status": (latest_opinion or {}).get("status"),
    }

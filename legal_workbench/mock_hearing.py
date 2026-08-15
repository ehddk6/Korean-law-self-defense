from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import CaseStage, MockHearingCheck, MockHearingRecord, new_id
from .security import atomic_json_write
from .workflow import store_for

_RUNNABLE_STAGES = {
    CaseStage.INDEPENDENTLY_ANALYZED,
    CaseStage.DRAFTED,
    CaseStage.AUDITED,
    CaseStage.RELEASED,
}

READINESS_LABELS = ("제출 가능", "보강 필요", "재검토 필요")


def simulate_mock_hearing(
    case_id: str,
    *,
    worksets_home: Path | None = None,
) -> dict[str, Any]:
    store = store_for(case_id, worksets_home)
    case = store.get_case()

    if CaseStage(case["stage"]) not in _RUNNABLE_STAGES:
        raise ValueError("모의 심리(변론 대비)는 독립 재분석(INDEPENDENTLY_ANALYZED) 이후 단계에서만 실행할 수 있습니다.")

    facts = store.list_payloads("facts")
    issues = store.list_payloads("issues")
    authorities = store.list_payloads("authorities")
    evidence = store.list_payloads("evidence")
    opinions = store.list_payloads("opinions")

    if not issues:
        raise ValueError("모의 심리를 위한 쟁점 레코드가 없습니다.")
    if not authorities:
        raise ValueError("모의 심리를 위한 법적 근거 레코드가 없습니다.")

    evidence_by_id = {item["evidence_id"]: item for item in evidence}
    authority_by_id = {item["authority_id"]: item for item in authorities}
    latest_opinion = opinions[-1] if opinions else None

    hearing_id = new_id("mh")
    checks: list[MockHearingCheck] = []
    all_missing: list[str] = []
    covered_issues: list[str] = []
    for issue in issues:
        issue_id = issue["issue_id"]
        elements = issue.get("legal_elements") or []
        missing = issue.get("missing_facts") or []
        burden = str(issue.get("burden") or "확인 필요")
        favorable = issue.get("favorable_authority_ids") or []
        adverse = issue.get("adverse_authority_ids") or []
        issue_facts = [fact for fact in facts if fact["fact_id"] in (issue.get("fact_ids") or [])]
        linked = sorted(
            {
                evidence_id
                for fact in issue_facts
                for evidence_id in (fact.get("evidence_ids") or [])
                if evidence_id in evidence_by_id
            }
        )
        has_favorable_p1 = any(
            (item := authority_by_id.get(aid))
            and item.get("source_tier") == "P1"
            and item.get("verified_at")
            for aid in favorable
        )
        has_adverse_p1 = any(
            (item := authority_by_id.get(aid))
            and item.get("source_tier") == "P1"
            and item.get("verified_at")
            for aid in adverse
        )
        satisfied = bool(linked) and not missing and has_favorable_p1
        question_parts: list[str] = []
        if missing:
            question_parts.append(f"미확인 사실({', '.join(missing)})을 입증할 증거를 제출하십시오.")
        if not linked:
            question_parts.append("쟁점과 연결된 증거 목록을 제시하십시오.")
        if not has_favorable_p1:
            question_parts.append("유리한 근거를 이중 검증된 공식 원문으로 제시하십시오.")
        if has_adverse_p1:
            question_parts.append("불리한 근거에 대한 구별 논리를 설명하십시오.")
        judge_question = " ".join(question_parts) if question_parts else "입증 관계에 추가 질문이 없습니다."
        checks.append(
            MockHearingCheck(
                element=f"{issue.get('title', issue_id)} ({burden})",
                burden=burden,
                missing_facts=list(missing),
                linked_evidence=linked,
                satisfied=satisfied,
                judge_question=judge_question,
            )
        )
        all_missing.extend(missing)
        covered_issues.append(issue_id)

    if not all_missing and all(check.satisfied for check in checks):
        readiness = READINESS_LABELS[0]
    elif all_missing:
        readiness = READINESS_LABELS[2]
    else:
        readiness = READINESS_LABELS[1]

    reasoning = _compose_reasoning(
        checks,
        latest_opinion,
        all_missing,
        authority_by_id,
    )

    record = MockHearingRecord(
        hearing_id=hearing_id,
        case_id=case_id,
        issue_id=",".join(covered_issues),
        checks=checks,
        filing_readiness=readiness,
        reasoning=reasoning,
    )

    payload_path = store.case_dir / "mock_hearings" / f"{hearing_id}-result.json"
    atomic_json_write(payload_path, record.to_dict())
    store.add_mock_hearing(record)

    return {
        "hearing_id": hearing_id,
        "filing_readiness": readiness,
        "issue_ids": covered_issues,
        "check_count": len(checks),
        "satisfied_check_count": sum(1 for check in checks if check.satisfied),
        "missing_facts": all_missing,
        "result_path": str(payload_path),
    }


def _compose_reasoning(
    checks: list[MockHearingCheck],
    latest_opinion: dict[str, Any] | None,
    all_missing: list[str],
    authority_by_id: dict[str, dict[str, Any]],
) -> str:
    parts: list[str] = []
    unsatisfied = [check for check in checks if not check.satisfied]
    if not unsatisfied:
        parts.append("모든 쟁점의 요건사실이 증거와 검증된 근거로 충족되어 제출 가능한 상태로 판단합니다.")
    else:
        parts.append(f"{len(unsatisfied)}개 쟁점에서 입증 보강이 필요합니다.")
        for check in unsatisfied:
            parts.append(f"- {check.element}: {check.judge_question}")
    if all_missing:
        parts.append(f"확인하지 못한 사실: {', '.join(all_missing)}")
    if latest_opinion:
        if latest_opinion.get("status") == "ready":
            parts.append("최종 의견은 ready로, 제출 가능성 판단과 일치합니다.")
        else:
            parts.append(
                f"최종 의견이 {latest_opinion.get('status')}이므로 사용자는 제출 전 핵심 사실과 공식 원문을 직접 재확인해야 합니다."
            )
    return " ".join(parts).strip()

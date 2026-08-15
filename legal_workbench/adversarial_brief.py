from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import CaseStage, new_id, utc_now
from .security import atomic_json_write
from .workflow import store_for

_RUNNABLE_STAGES = {
    CaseStage.INDEPENDENTLY_ANALYZED,
    CaseStage.DRAFTED,
    CaseStage.AUDITED,
    CaseStage.RELEASED,
}


def build_adversarial_brief(
    case_id: str,
    *,
    worksets_home: Path | None = None,
) -> dict[str, Any]:
    store = store_for(case_id, worksets_home)
    case = store.get_case()

    if CaseStage(case["stage"]) not in _RUNNABLE_STAGES:
        raise ValueError("반론 브리프는 독립 재분석(INDEPENDENTLY_ANALYZED) 이후 단계에서만 만들 수 있습니다.")

    issues = store.list_payloads("issues")
    authorities = store.list_payloads("authorities")
    opinions = store.list_payloads("opinions")
    if not issues:
        raise ValueError("반론 브리프를 위한 쟁점 레코드가 없습니다.")
    if not opinions:
        raise ValueError("반론 브리프를 위한 의견 레코드가 없습니다.")

    authority_by_id = {item["authority_id"]: item for item in authorities}
    latest_opinion = opinions[-1]

    sections: list[dict[str, Any]] = []
    for issue in issues:
        adverse_ids = issue.get("adverse_authority_ids") or []
        adverse = [authority_by_id[aid] for aid in adverse_ids if aid in authority_by_id]
        missing = issue.get("missing_facts") or []
        rebuttals: list[str] = []
        for authority in adverse:
            citation = authority.get("citation") or authority.get("title") or "확인 필요"
            tier = authority.get("source_tier", "U")
            rebuttals.append(f"상대방은 {citation}(등급 {tier})을 근거로 다툴 수 있습니다.")
        for fact in missing:
            rebuttals.append(f"상대방은 {fact}에 대한 입증이 부족하다고 반박할 수 있습니다.")
        sections.append(
            {
                "issue_id": issue["issue_id"],
                "title": issue.get("title", ""),
                "burden": issue.get("burden", "확인 필요"),
                "adverse_authority": [item.get("citation") or item.get("title") for item in adverse],
                "missing_fact_rebuttals": list(missing),
                "expected_rebuttals": rebuttals,
                "adverse_authority_reviewed": bool(
                    latest_opinion.get("adverse_authority_reviewed") and adverse
                ),
            }
        )

    brief_id = new_id("ab")
    result = {
        "format": "legal-workbench-adversarial-brief-v1",
        "case_id": case_id,
        "brief_id": brief_id,
        "opinion_id": latest_opinion.get("opinion_id"),
        "opinion_status": latest_opinion.get("status"),
        "adverse_scenario": latest_opinion.get("adverse_scenario") or "확인 필요",
        "contested_scenario": latest_opinion.get("contested_scenario") or "확인 필요",
        "sections": sections,
        "recommendations": [
            "불리한 근거를 구별할 수 있는 사실관계를 쟁점별로 정리하십시오.",
            "미확인 사실이 남아 있으면 제출 전 확인하십시오.",
            "확인한 공개 자료에서 발견하지 못한 반대 근거는 없다고 단정하지 말고 재검색 기록을 남기십시오.",
        ],
        "created_at": utc_now(),
    }
    brief_dir = store.case_dir / "adversarial_briefs"
    brief_dir.mkdir(parents=True, exist_ok=True)
    path = brief_dir / f"{brief_id}.json"
    atomic_json_write(path, result)
    store.add_adversarial_brief(result)
    result["path"] = str(path)
    return result

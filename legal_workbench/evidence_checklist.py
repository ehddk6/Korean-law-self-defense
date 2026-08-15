from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import CaseStage, new_id, utc_now
from .security import atomic_json_write
from .workflow import store_for

_RUNNABLE_STAGES = {
    CaseStage.RESEARCHED,
    CaseStage.INDEPENDENTLY_ANALYZED,
    CaseStage.DRAFTED,
    CaseStage.AUDITED,
    CaseStage.RELEASED,
}

ILLEGAL_EVIDENCE_HINTS = (
    "불법 녹음",
    "불법 녹화",
    "무단 촬영",
    "위장 촬영",
    "불법 위치추적",
    "타인 대화 도청",
    "통신 비밀 침해",
    "해킹·탈취 자료",
    "불법 문건 유출",
)

EVIDENCE_TYPE_SUGGESTIONS = (
    "공문서·행정기관 확인서",
    "금융기관 거래·입출금 기록",
    "계약서·내역서 등 사문서",
    "사진·영상 기록물",
    "메신저·이메일 대화 기록",
    "증인 진술 가능성",
    "감정·측량 필요성 검토",
)


def build_evidence_checklist(
    case_id: str,
    *,
    worksets_home: Path | None = None,
) -> dict[str, Any]:
    store = store_for(case_id, worksets_home)
    case = store.get_case()

    if CaseStage(case["stage"]) not in _RUNNABLE_STAGES:
        raise ValueError("증거 체크리스트는 법률조사(RESEARCHED) 이후 단계에서만 만들 수 있습니다.")

    issues = store.list_payloads("issues")
    facts = store.list_payloads("facts")
    evidence = store.list_payloads("evidence")
    if not issues:
        raise ValueError("증거 체크리스트를 위한 쟁점 레코드가 없습니다.")

    evidence_by_id = {item["evidence_id"]: item for item in evidence}
    fact_by_id = {item["fact_id"]: item for item in facts}

    checklist_id = new_id("ec")
    items: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    for issue in issues:
        issue_id = issue["issue_id"]
        issue_facts = [fact_by_id[fact_id] for fact_id in (issue.get("fact_ids") or []) if fact_id in fact_by_id]
        linked_evidence = sorted(
            {
                evidence_id
                for fact in issue_facts
                for evidence_id in (fact.get("evidence_ids") or [])
                if evidence_id in evidence_by_id
            }
        )
        missing = issue.get("missing_facts") or []
        elements = issue.get("legal_elements") or []
        requested: list[str] = []
        for element in elements:
            requested.append(element)
        for missing_fact in missing:
            requested.append(f"[미확인] {missing_fact}")
            for hint in ILLEGAL_EVIDENCE_HINTS:
                if hint in str(missing_fact):
                    warnings.append(
                        {
                            "issue_id": issue_id,
                            "target": missing_fact,
                            "hint": hint,
                            "message": "수집 과정에서 위법성이 의심되는 증거는 제출 전 적법성 검토가 필요합니다.",
                        }
                    )
        items.append(
            {
                "issue_id": issue_id,
                "title": issue.get("title", ""),
                "burden": issue.get("burden", "확인 필요"),
                "required_elements": requested,
                "linked_evidence": linked_evidence,
                "evidence_type_suggestions": list(EVIDENCE_TYPE_SUGGESTIONS),
                "status": "충족" if linked_evidence and not missing else "보강 필요" if missing else "증거 확인 필요",
            }
        )

    result = {
        "format": "legal-workbench-evidence-checklist-v1",
        "case_id": case_id,
        "checklist_id": checklist_id,
        "generated_at": store.get_case().get("as_of_date", ""),
        "illegal_evidence_hints": list(ILLEGAL_EVIDENCE_HINTS),
        "items": items,
        "warnings": warnings,
        "created_at": utc_now(),
    }
    checklist_dir = store.case_dir / "evidence_checklists"
    checklist_dir.mkdir(parents=True, exist_ok=True)
    path = checklist_dir / f"{checklist_id}.json"
    atomic_json_write(path, result)
    store.add_evidence_checklist(result)
    result["path"] = str(path)
    return result

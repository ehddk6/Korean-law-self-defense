from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import ClarificationQuestion, ClarificationRecord, new_id
from .security import atomic_json_write
from .workflow import store_for


def simulate_clarification(case_id: str, worksets_home: Path | None = None) -> dict[str, Any]:
    store = store_for(case_id, worksets_home)
    store.get_case()
    facts = store.list_payloads("facts")
    evidence = store.list_payloads("evidence")
    issues = store.list_payloads("issues")

    questions: list[ClarificationQuestion] = []
    evidence_by_id = {e.get("evidence_id"): e for e in evidence}
    for fact in facts:
        ev_ids = fact.get("evidence_ids") or []
        weak_evidence = [
            eid
            for eid in ev_ids
            if (e := evidence_by_id.get(eid)) and (e.get("extraction_confidence") or 0) < 0.7
        ]
        if not ev_ids:
            questions.append(
                ClarificationQuestion(
                    target_fact=fact["text"],
                    judge_question=(
                        f"원고는 '{fact['text']}'에 관하여 구체적 일시, 장소, 경위를 명확히 진술하십시오. "
                        "현재 서증이 없습니다."
                    ),
                    required_evidence="문서(계약서, 영수증), 녹취록, 또는 증인",
                )
            )
        elif weak_evidence:
            questions.append(
                ClarificationQuestion(
                    target_fact=fact["text"],
                    judge_question=(
                        f"원고는 '{fact['text']}'에 관하여 제출된 증거의 신뢰도가 낮습니다. "
                        "원본 또는 추가 확인 가능한 자료를 제출하십시오."
                    ),
                    required_evidence="원본 문서, 원본 확인 경위, 또는 보강 증거",
                )
            )
    for issue in issues:
        missing = issue.get("missing_facts") or []
        for text in missing:
            questions.append(
                ClarificationQuestion(
                    target_fact=text,
                    judge_question=f"쟁점 '{issue.get('title', '확인 필요')}'에서 '{text}'를 소명하십시오.",
                    required_evidence="해당 요건사실을 뒷받침하는 서증 또는 증인",
                )
            )

    record = ClarificationRecord(
        clarification_id=new_id("cl"),
        case_id=case_id,
        questions=questions,
    )

    cl_dir = store.case_dir / "clarifications"
    cl_dir.mkdir(parents=True, exist_ok=True)
    atomic_json_write(cl_dir / f"{record.clarification_id}.json", record.to_dict())
    store.add_clarification(record)
    return {
        "clarification_id": record.clarification_id,
        "questions_count": len(record.questions),
    }

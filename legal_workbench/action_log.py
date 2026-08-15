from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

from .models import ActionLog, new_id
from .security import scan_residual_pii
from .workflow import store_for


def log_action(
    case_id: str,
    *,
    action_type: str,
    action_description: str,
    action_date: str,
    official_receipt_hash: str | None = None,
    deadline_id: str | None = None,
    notes: str | None = None,
    worksets_home: Path | None = None,
) -> dict[str, Any]:
    store = store_for(case_id, worksets_home)
    case = store.get_case()
    normalized_notes = (notes or "").strip()

    try:
        parsed_action_date = date.fromisoformat(action_date)
    except ValueError as exc:
        raise ValueError("action_date는 YYYY-MM-DD 형식이어야 합니다.") from exc
    if parsed_action_date > date.today():
        raise ValueError("공식 조치 기록은 실제로 행한 조치만 담을 수 있어 미래 날짜를 사용할 수 없습니다.")

    if not action_type.strip() or not action_description.strip():
        raise ValueError("조치 종류와 설명이 필요합니다.")

    if deadline_id:
        deadlines = store.list_payloads("deadlines")
        if deadline_id not in {item["deadline_id"] for item in deadlines}:
            raise ValueError(f"존재하지 않는 기한 레코드를 참조합니다: {deadline_id}")

    surface = f"{action_type} {action_description} {normalized_notes}"
    if scan_residual_pii(surface):
        raise PermissionError(
            "공식 조치 기록은 비식별 LegalWorksets에 저장되므로 실명·연락처·주소를 직접 기록할 수 없습니다. "
            "실명은 실명 대응표 또는 사용자 개인 기록에만 보관하십시오."
        )

    record = ActionLog(
        action_id=new_id("act"),
        case_id=case_id,
        action_type=action_type.strip(),
        action_description=action_description.strip(),
        action_date=action_date,
        official_receipt_hash=official_receipt_hash,
        deadline_id=deadline_id,
        notes=normalized_notes,
    )
    store.add_action_log(record)
    return {
        "action_id": record.action_id,
        "case_id": case_id,
        "action_type": record.action_type,
        "action_date": record.action_date,
        "official_receipt_hash": record.official_receipt_hash,
        "deadline_id": record.deadline_id,
        "case_stage": case["stage"],
        "recorded_at": record.created_at,
    }

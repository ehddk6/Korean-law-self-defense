"""운영 환경 진단과 전체 사건 관리 요약.

모든 함수는 조회 전용으로 저장·단계 전환 없이 결과를 반환한다.
doctor는 파일·디렉터리·데이터베이스 상태만 점검하고 쓰기 작업은 하지 않는다.
"""

from __future__ import annotations

import os
import sqlite3
import sys
from datetime import date
from pathlib import Path
from typing import Any

from .audit import deadline_overview
from .security import path_is_synced
from .storage import CaseStore, discover_cases
from .workflow import default_mapping_home


def run_doctor(worksets_home: Path, mapping_home: Path | None = None) -> dict[str, Any]:
    """저장소 경로·사건 데이터베이스·이벤트 체인·무결성을 읽기 전용으로 점검한다."""
    worksets = Path(worksets_home).expanduser()
    mappings = (mapping_home or default_mapping_home()).expanduser()
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})

    python_ok = sys.version_info >= (3, 10)
    add(
        "python_version",
        python_ok,
        f"Python {sys.version.split()[0]} (권장 3.10 이상)",
    )
    add(
        "worksets_home",
        worksets.is_dir() and os.access(worksets, os.W_OK),
        f"비식별 저장소: {worksets}",
    )
    add(
        "mapping_home",
        mappings.is_dir(),
        f"실명 대응표 저장소(OneDrive 밖): {mappings}",
    )
    add(
        "worksets_not_synced",
        not (worksets.exists() and path_is_synced(worksets)),
        "비식별 저장소 OneDrive 동기화 경로 여부",
    )
    add(
        "mapping_not_synced",
        not (mappings.exists() and path_is_synced(mappings)),
        "실명 대응표 저장소 OneDrive 동기화 경로 여부",
    )

    case_ids = list(discover_cases(worksets))
    add("cases_discovered", True, f"사건 {len(case_ids)}건 발견")

    for case_id in case_ids:
        store = CaseStore(worksets, case_id)
        try:
            store.get_case()
        except (sqlite3.DatabaseError, KeyError, ValueError) as exc:
            add(f"case:{case_id}", False, f"사건을 열 수 없습니다: {exc}")
            continue
        chain_ok = store.verify_event_chain()
        integrity = store.integrity_check()
        ok = chain_ok and integrity == ["ok"]
        detail = "이벤트 체인·무결성 정상" if ok else f"체인={chain_ok}, 무결성={integrity}"
        add(f"case:{case_id}", ok, detail)

    problems = [item["check"] for item in checks if not item["ok"]]
    return {
        "checked_on": date.today().isoformat(),
        "healthy": not problems,
        "problems": problems,
        "checks": checks,
    }


def worksets_overview(worksets_home: Path) -> dict[str, Any]:
    """전체 사건의 단계·긴급 기한·최신 감사·의견 상태를 한 장의 관리표로 요약한다."""
    worksets = Path(worksets_home).expanduser()
    rows: list[dict[str, Any]] = []
    urgent_total = 0
    for case_id in discover_cases(worksets):
        store = CaseStore(worksets, case_id)
        try:
            case = store.get_case()
        except (sqlite3.DatabaseError, KeyError, ValueError):
            continue
        urgent = [
            row["deadline_id"]
            for row in deadline_overview(store)
            if row["status"] in {"도과", "임박"}
        ]
        urgent_total += len(urgent)
        latest_audit = store.latest_audit()
        opinions = store.list_payloads("opinions")
        latest_opinion = opinions[-1] if opinions else None
        rows.append(
            {
                "case_id": case["case_id"],
                "title": case.get("title"),
                "domain": case.get("domain"),
                "stage": case.get("stage"),
                "updated_at": case.get("updated_at"),
                "urgent_deadlines": urgent,
                "latest_audit": {
                    "audit_id": latest_audit.get("audit_id"),
                    "passed": latest_audit.get("passed"),
                    "release_allowed": latest_audit.get("release_allowed"),
                }
                if latest_audit
                else None,
                "latest_opinion_status": (latest_opinion or {}).get("status"),
            }
        )
    return {
        "checked_on": date.today().isoformat(),
        "case_count": len(rows),
        "urgent_deadline_total": urgent_total,
        "cases": sorted(rows, key=lambda item: str(item["case_id"])),
    }

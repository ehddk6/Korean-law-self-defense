"""라운드8 회귀 테스트: NFKC·split PII 방어, 초안 provenance, 감사 관찰성 보강."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

from legal_workbench.audit import (
    _RECORD_ID_TOKEN,
    _audit_draft_provenance,
    audit_case,
    next_action_digest,
    p1_verification_failures,
)
from legal_workbench.models import AuditFinding, Severity
from legal_workbench.security import redact_text, scan_residual_pii
from legal_workbench.storage import CaseStore

from test_workbench_extensions import _seed_case_data


def test_nfkc_fullwidth_phone_detected_and_redacted() -> None:
    text = "연락처는 ０１０-１２３４-５６７８ 입니다."
    findings = scan_residual_pii(text)
    phone = [f for f in findings if f.category == "PHONE"]
    assert phone, "전각 숫자 전화번호가 잔존 스캔에서 검출되어야 합니다."
    assert text[phone[0].start : phone[0].end] == "０１０-１２３４-５６７８"

    redacted, mapping, redact_findings = redact_text(text)
    assert "０１０-１２３４-５６７８" not in redacted
    assert "０１０-１２３４-５６７８" in mapping, "매핑 키는 원문의 전각 조각이어야 합니다."
    assert any(f.category == "PHONE" for f in redact_findings)


def test_split_phone_mid_group_detected() -> None:
    text = "상대방 연락처: 010-123\n4-5678 로 연락함."
    findings = scan_residual_pii(text)
    split = [f for f in findings if f.rule.endswith("-split-across-lines")]
    assert split, "숫자 그룹 내부가 줄바꿈으로 끊긴 전화번호도 검출되어야 합니다."
    assert split[0].category == "PHONE"
    assert "\n" in text[split[0].start : split[0].end]


def test_split_resident_id_mid_group_detected() -> None:
    text = "등록번호 90010\n1-1234567 확인"
    findings = scan_residual_pii(text)
    split = [f for f in findings if f.rule.endswith("-split-across-lines")]
    assert any(f.category == "RESIDENT_ID" for f in split)
    resident = next(f for f in split if f.category == "RESIDENT_ID")
    assert text[resident.start : resident.end] == "90010\n1-1234567"


def test_split_scan_has_no_false_positive_on_benign_multiline() -> None:
    text = (
        "선고 기일은 별도로 지정된다.\n"
        "주문: 피고는 원고에게 지급하라.\n"
        "계약금 100,000,000원, 이행기 2026. 8. 16\n"
        "참조 조문: 민법 제548조"
    )
    assert scan_residual_pii(text) == []


def test_draft_provenance_unit(tmp_path: Path) -> None:
    known = "fact_" + "a" * 16
    unknown = "ev_" + "b" * 16
    assert _RECORD_ID_TOKEN.search(f"참조: {known}")
    drafts = tmp_path / "drafts"
    drafts.mkdir()
    (drafts / "pleading.md").write_text(
        f"사실 {known}과 증거 {unknown}에 근거한다.", encoding="utf-8"
    )
    findings: list[AuditFinding] = []
    _audit_draft_provenance(findings, drafts, {known})
    assert any(
        f.severity == Severity.MAJOR
        and f.code == "DRAFT_UNKNOWN_RECORD_ID"
        and unknown in str(f.message)
        for f in findings
    )
    assert all(known not in str(f.message) for f in findings)


def test_audit_case_detects_unknown_draft_reference(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-r8-draft")
    store = CaseStore(tmp_path, "case-r8-draft")
    drafts_dir = store.case_dir / "drafts"
    drafts_dir.mkdir(parents=True, exist_ok=True)
    ghost = "issue_" + "c" * 16
    (drafts_dir / "pleading.md").write_text(f"쟁점 {ghost} 참조", encoding="utf-8")

    report = audit_case(store).to_dict()
    draft_findings = [f for f in report["findings"] if f["code"] == "DRAFT_UNKNOWN_RECORD_ID"]
    assert draft_findings and ghost in draft_findings[0]["message"]
    assert draft_findings[0]["severity"] == "major"

    # 실제 기록 ID와 시드의 짧은 커스텀 ID는 오탐을 내지 않아야 한다.
    (drafts_dir / "pleading.md").write_text(
        "사실 fact-x, 근거 auth-x, 문서 doc-x에 근거한다.", encoding="utf-8"
    )
    clean = audit_case(store).to_dict()
    assert not [f for f in clean["findings"] if f["code"] == "DRAFT_UNKNOWN_RECORD_ID"]


def test_next_action_digest_explains_critical_findings(tmp_path: Path) -> None:
    overdue = (date.today() - timedelta(days=1)).isoformat()
    _seed_case_data(tmp_path, "case-r8-next", deadline_due=overdue)
    store = CaseStore(tmp_path, "case-r8-next")
    report = audit_case(store).to_dict()
    store.add_audit_report(report)

    digest = next_action_digest(store)
    summary = digest["latest_audit"]
    assert summary is not None
    assert summary["critical_codes"], "critical_codes 키는 하위 호환으로 유지되어야 합니다."
    assert summary["critical_findings"]
    for item in summary["critical_findings"]:
        assert set(item) >= {"code", "message", "record_type", "record_id", "guidance"}
        assert str(item["guidance"]).strip()
    overdue_item = next(
        item for item in summary["critical_findings"] if item["code"] == "DEADLINE_OVERDUE"
    )
    assert overdue_item["record_id"] == "deadline-x"
    # DEADLINE_OVERDUE는 폴백이 아니라 정적 안내 매핑에서 와야 한다.
    assert overdue_item["guidance"].startswith("기한이 이미 지났습니다.")


def test_issue_conflict_findings(tmp_path: Path) -> None:
    _seed_case_data(
        tmp_path,
        "case-r8-conflict",
        extra_facts=[
            {
                "fact_id": "fact-disputed",
                "text": "반환 약정이 있었다는 상대방 주장.",
                "status": "disputed",
                "evidence_ids": [],
            },
            {
                "fact_id": "fact-allegation",
                "text": "상대방이 주장하는 합의 내용.",
                "status": "opponent_allegation",
                "evidence_ids": [],
            },
        ],
        extra_issues=[
            {
                "issue_id": "issue-conflict",
                "title": "충돌 탐지용 쟁점",
                "legal_elements": ["계약"],
                "burden": "청구인",
                "favorable_authority_ids": ["auth-x"],
                "adverse_authority_ids": ["auth-x"],
                "fact_ids": ["fact-x", "fact-disputed", "fact-allegation"],
                "missing_facts": [],
                "remedies": [],
            }
        ],
    )
    store = CaseStore(tmp_path, "case-r8-conflict")
    findings = audit_case(store).to_dict()["findings"]
    contested = [f for f in findings if f["code"] == "ISSUE_FACT_CONTESTED"]
    both_sides = [f for f in findings if f["code"] == "AUTHORITY_BOTH_SIDES"]
    assert any(f["record_id"] == "issue-conflict" for f in contested)
    assert any(f["record_id"] == "issue-conflict" for f in both_sides)
    assert all(f["severity"] == "minor" for f in contested + both_sides)


def test_decision_date_invalid_detected() -> None:
    item = {
        "source_tier": "P1",
        "official_url": "https://www.scourt.go.kr/x-primary",
        "verification_url": "https://www.law.go.kr/x-secondary",
        "verified_at": "2026-07-19T00:00:00+00:00",
        "mcp_server": "korean-law",
        "mcp_version": "4.7.4",
        "mcp_tool": "get_precedent_text",
        "mcp_verified_at": "2026-07-19T00:00:00+00:00",
        "case_number": "2021다256000",
        "court": "대법원",
        "decision_date": "2023. 1. 1.",
    }
    failures = p1_verification_failures(item, files_check=lambda payload: True)
    codes = [code for code, _ in failures]
    assert "DECISION_DATE_INVALID" in codes

    item["decision_date"] = "2023-01-01"
    failures = p1_verification_failures(item, files_check=lambda payload: True)
    assert "DECISION_DATE_INVALID" not in [code for code, _ in failures]

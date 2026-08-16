import json
from datetime import date, timedelta
from pathlib import Path

import pytest

from legal_workbench.action_log import log_action
from legal_workbench.adversarial_brief import build_adversarial_brief
from legal_workbench.audit import audit_case
from legal_workbench.documents import verify_rehydration
from legal_workbench.evidence_checklist import build_evidence_checklist
from legal_workbench.models import CaseStage, EvidenceRecord, Severity
from legal_workbench.mock_hearing import simulate_mock_hearing
from legal_workbench.security import atomic_json_write, scan_mcp_query, sha256_file
from legal_workbench.storage import CaseStore
from legal_workbench.workflow import (
    add_authority,
    add_deadline,
    add_fact,
    add_issue,
    build_analysis_bundles,
    build_research_bundle,
    complete_research,
    import_analysis_result,
    import_opinion,
    intake_case,
)

def _jump_to(store: CaseStore, target: CaseStage, reason: str = "테스트") -> None:
    from legal_workbench.models import STAGE_ORDER

    current = CaseStage(store.get_case()["stage"])
    for stage in STAGE_ORDER[STAGE_ORDER.index(current):]:
        store.transition(stage, reason=reason)
        if stage == target:
            break


def _seed_case_data(
    tmp_path: Path,
    case_id: str,
    *,
    extra_facts: list[dict[str, object]] | None = None,
    extra_issues: list[dict[str, object]] | None = None,
    deadline_due: str | None = None,
) -> CaseStore:
    intake_case(
        case_id=case_id,
        title="워크벤치 확장 시험 사건",
        domain="civil-contract-tort",
        goal="확장 기능 검증",
        forum=None,
        action_date="2026-01-01",
        as_of_date="2026-07-19",
        worksets_home=tmp_path,
    )
    store = CaseStore(tmp_path, case_id)
    document_path = store.case_dir / "documents" / "sample.sanitized.txt"
    document_path.write_text("[PERSON_001]은 계약서를 작성하고 계약금을 지급했다.", encoding="utf-8")
    atomic_json_write(
        store.case_dir / "documents" / "doc-x.metadata.json",
        {"source_sha256": "b" * 64, "sanitized_sha256": sha256_file(document_path)},
    )
    store.add_document(
        document_id="doc-x",
        filename="sample.txt",
        media_type="text/plain",
        sha256="b" * 64,
        sanitized_path=str(document_path),
        content=document_path.read_text(encoding="utf-8"),
        extraction_status="extracted",
        extraction_confidence=0.9,
        injection_flags=[],
        residual_pii=[],
    )
    store.add_evidence(
        EvidenceRecord(
            evidence_id="ev-x",
            document_id="doc-x",
            sha256="b" * 64,
            source_path_token="[LOCAL_SOURCE]",
            acquired_at="2026-01-02",
            provenance="본인 보관 원본",
            page_or_paragraph="전체 문서",
            extraction_confidence=0.9,
        )
    )
    _jump_to(store, CaseStage.INGESTED)
    add_fact(
        case_id,
        {
            "fact_id": "fact-x",
            "text": "[PERSON_001]은 계약금을 지급했다.",
            "status": "confirmed",
            "evidence_ids": ["ev-x"],
        },
        worksets_home=tmp_path,
    )
    for extra_fact in extra_facts or []:
        add_fact(
            case_id,
            {
                "fact_id": extra_fact["fact_id"],
                "text": str(extra_fact["text"]),
                "status": str(extra_fact.get("status", "unknown")),
                "evidence_ids": list(extra_fact.get("evidence_ids") or []),
            },
            worksets_home=tmp_path,
        )
    authority_source = tmp_path / "auth-source.txt"
    authority_verification = tmp_path / "auth-verification.txt"
    authority_source.write_text("공식 원문", encoding="utf-8")
    authority_verification.write_text("공식 재검증 원문", encoding="utf-8")
    authority = add_authority(
        case_id,
        {
            "authority_id": "auth-x",
            "title": "공식 P1 원문",
            "source_tier": "P1",
            "official_url": "https://www.law.go.kr/x-primary",
            "verification_url": "https://lx.scourt.go.kr/x-secondary",
            "verified_at": "2026-07-19T00:00:00+00:00",
            "retrieved_at": "2026-07-19T00:00:00+00:00",
            "citation": "예시 법령 제1조 (확장 기능용)",
            "effective_from": "2025-01-01",
            "source_text_file": str(authority_source),
            "verification_text_file": str(authority_verification),
            "mcp_server": "korean-law",
            "mcp_version": "4.7.4",
            "mcp_tool": "get_law_text",
            "mcp_verified_at": "2026-07-19T00:00:00+00:00",
        },
        worksets_home=tmp_path,
    )
    add_issue(
        case_id,
        {
            "issue_id": "issue-x",
            "title": "계약금 반환 요건",
            "legal_elements": ["계약", "지급", "반환 사유"],
            "burden": "청구인",
            "favorable_authority_ids": [authority.authority_id],
            "adverse_authority_ids": [authority.authority_id],
            "fact_ids": ["fact-x"],
            "missing_facts": ["반환 약정 존재"],
            "remedies": ["반환 청구"],
        },
        worksets_home=tmp_path,
    )
    for extra in extra_issues or []:
        add_issue(
            case_id,
            {
                "issue_id": extra["issue_id"],
                "title": str(extra["title"]),
                "legal_elements": list(extra["legal_elements"]),
                "burden": str(extra["burden"]),
                "favorable_authority_ids": list(extra["favorable_authority_ids"]),
                "adverse_authority_ids": list(extra["adverse_authority_ids"]),
                "fact_ids": list(extra["fact_ids"]),
                "missing_facts": list(extra["missing_facts"]),
                "remedies": list(extra["remedies"]),
            },
            worksets_home=tmp_path,
        )
    if deadline_due:
        add_deadline(
            case_id,
            {
                "deadline_id": "deadline-x",
                "title": "시드 기한",
                "trigger_event": "송달",
                "trigger_date": "2026-01-01",
                "governing_rule": "예시 법령 제1조",
                "authority_id": authority.authority_id,
                "calculation": "기산일 다음 날부터 10일",
                "tentative_due_date": deadline_due,
                "holiday_adjustment": "해당 없음 확인",
                "duration_value": 10,
                "duration_unit": "days",
                "holiday_adjustment_days": 0,
                "verification_url": "https://www.law.go.kr/example-deadline",
                "verified_at": "2026-07-19T00:00:00+00:00",
                "verified": True,
                "critical": True,
            },
            worksets_home=tmp_path,
        )
    assert build_research_bundle(case_id, worksets_home=tmp_path).is_file()
    assert complete_research(case_id, worksets_home=tmp_path)["stage"] == "researched"
    return store


def _seed_analyzed(
    tmp_path: Path,
    case_id: str,
    *,
    deadline_due: str | None = None,
) -> CaseStore:
    store = _seed_case_data(tmp_path, case_id, deadline_due=deadline_due)
    analysis = build_analysis_bundles(case_id, worksets_home=tmp_path)
    primary_result = import_analysis_result(
        case_id,
        "primary",
        {"conclusion": "잠정 결론", "reasoning": ["사실과 근거를 적용함"]},
        worksets_home=tmp_path,
    )
    independent_result = import_analysis_result(
        case_id,
        "independent",
        {
            "conclusion": "독립 결론",
            "reasoning": ["상대방 관점에서 재검토함"],
            "blind_to_primary": True,
            "adverse_points": ["계약 효력 다툼"],
        },
        worksets_home=tmp_path,
    )
    import_opinion(
        case_id,
        {
            "opinion_id": "opinion-x",
            "status": "ready",
            "conclusion": "검증된 입력 범위에서 반환 청구 요건이 충족된다는 잠정 판단",
            "assumptions": [],
            "favorable_scenario": "계약과 지급이 인정되는 경우",
            "contested_scenario": "반환 사유가 다투어지는 경우",
            "adverse_scenario": "계약 또는 지급 증거가 배척되는 경우",
            "fact_ids": ["fact-x"],
            "authority_ids": ["auth-x"],
            "issue_ids": ["issue-x"],
            "changes_outcome_if": ["계약의 진정성립이 부정되는 경우"],
            "source_coverage": "verified-primary",
            "primary_analysis_ref": primary_result["path"],
            "independent_analysis_ref": independent_result["path"],
            "applicable_law_verified": True,
            "adverse_authority_reviewed": True,
        },
        worksets_home=tmp_path,
    )
    return store


def test_scan_mcp_query_blocks_pii() -> None:
    assert scan_mcp_query("법령 검색: 민사소송법") == []
    findings = scan_mcp_query("010-1234-5678 전화번호로 조회")
    assert any(item.category == "PHONE" for item in findings)


def test_evidence_checklist_gates_and_generates(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-ec-e2e")
    result = build_evidence_checklist("case-ec-e2e", worksets_home=tmp_path)
    assert result["format"] == "legal-workbench-evidence-checklist-v1"
    assert result["case_id"] == "case-ec-e2e"
    assert len(result["items"]) == 1
    item = result["items"][0]
    assert item["issue_id"] == "issue-x"
    assert any("반환 약정 존재" in element for element in item["required_elements"])
    assert "ev-x" in item["linked_evidence"]
    assert Path(result["path"]).is_file()
    assert json.loads(Path(result["path"]).read_text(encoding="utf-8"))["case_id"] == "case-ec-e2e"

    intake_case(
        case_id="case-ec-early",
        title="조기 실행 사건",
        domain="civil-contract-tort",
        goal="게이트 확인",
        forum=None,
        action_date="2026-01-01",
        as_of_date="2026-07-19",
        worksets_home=tmp_path,
    )
    with pytest.raises(ValueError, match="RESEARCHED"):
        build_evidence_checklist("case-ec-early", worksets_home=tmp_path)


def test_evidence_checklist_flags_illegal_evidence_hints(tmp_path: Path) -> None:
    _seed_case_data(
        tmp_path,
        "case-ec-illegal",
        extra_issues=[
            {
                "issue_id": "issue-illegal",
                "title": "위법 녹음 쟁점",
                "legal_elements": ["위법성"],
                "burden": "상대방",
                "favorable_authority_ids": ["auth-x"],
                "adverse_authority_ids": ["auth-x"],
                "fact_ids": [],
                "missing_facts": ["불법 녹음 파일의 적법성"],
                "remedies": [],
            }
        ],
    )
    result = build_evidence_checklist("case-ec-illegal", worksets_home=tmp_path)
    assert any(warning["hint"] == "불법 녹음" for warning in result["warnings"])


def test_adversarial_brief_requires_analysis(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-ab-early")
    with pytest.raises(ValueError, match="INDEPENDENTLY_ANALYZED"):
        build_adversarial_brief("case-ab-early", worksets_home=tmp_path)


def test_adversarial_brief_lists_adverse_authority(tmp_path: Path) -> None:
    _seed_analyzed(tmp_path, "case-ab-e2e")
    result = build_adversarial_brief("case-ab-e2e", worksets_home=tmp_path)
    assert result["format"] == "legal-workbench-adversarial-brief-v1"
    assert len(result["sections"]) == 1
    section = result["sections"][0]
    assert section["issue_id"] == "issue-x"
    assert section["adverse_authority"] == ["예시 법령 제1조 (확장 기능용)"]
    assert any("반환 약정 존재" in rebuttal for rebuttal in section["expected_rebuttals"])
    assert section["adverse_authority_reviewed"] is True
    assert Path(result["path"]).is_file()


def test_mock_hearing_gates_and_persists(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-mh-early")
    with pytest.raises(ValueError, match="INDEPENDENTLY_ANALYZED"):
        simulate_mock_hearing("case-mh-early", worksets_home=tmp_path)

    _seed_analyzed(tmp_path, "case-mh-e2e")
    result = simulate_mock_hearing("case-mh-e2e", worksets_home=tmp_path)
    assert result["hearing_id"].startswith("mh_")
    assert result["filing_readiness"] in {"제출 가능", "보강 필요", "재검토 필요"}
    store = CaseStore(tmp_path, "case-mh-e2e")
    records = store.list_payloads("mock_hearings")
    assert len(records) == 1
    assert records[0]["hearing_id"] == result["hearing_id"]
    assert records[0]["checks"]
    assert Path(result["result_path"]).is_file()
    assert json.loads(Path(result["result_path"]).read_text(encoding="utf-8"))["case_id"] == "case-mh-e2e"


def test_log_action_records_and_rejects(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-al-e2e")
    result = log_action(
        "case-al-e2e",
        action_type="제출",
        action_description="관할 법원에 반환 청구 서면 제출",
        action_date="2026-07-19",
        official_receipt_hash="a" * 64,
        worksets_home=tmp_path,
    )
    assert result["action_id"].startswith("act_")
    assert result["case_stage"] == "researched"
    store = CaseStore(tmp_path, "case-al-e2e")
    records = store.list_payloads("action_logs")
    assert len(records) == 1
    assert records[0]["official_receipt_hash"] == "a" * 64


def test_log_action_rejects_pii_and_bad_inputs(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-al-pii")
    with pytest.raises(PermissionError, match="비식별"):
        log_action(
            "case-al-pii",
            action_type="제출",
            action_description="010-1234-5678 연락처로 통지",
            action_date="2026-07-19",
            worksets_home=tmp_path,
        )
    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        log_action(
            "case-al-pii",
            action_type="제출",
            action_description="잘못된 날짜",
            action_date="2026/07/19",
            worksets_home=tmp_path,
        )
    with pytest.raises(ValueError, match="존재하지 않는 기한"):
        log_action(
            "case-al-pii",
            action_type="제출",
            action_description="기한 참조",
            action_date="2026-07-19",
            deadline_id="deadline-missing",
            worksets_home=tmp_path,
        )


def test_verify_rehydration_checks_structure_and_tokens(tmp_path: Path) -> None:
    mapping = {"김철수": "[PERSON_001]"}
    source = tmp_path / "source.md"
    restored = tmp_path / "restored.md"
    source.write_text(
        "# 제목\n\n[PERSON_001]은 계약금을 지급했다.\n\n## 쟁점\n\n- 반환 약정 존재",
        encoding="utf-8",
    )
    restored.write_text(
        "# 제목\n\n김철수은 계약금을 지급했다.\n\n## 쟁점\n\n- 반환 약정 존재",
        encoding="utf-8",
    )
    ok = verify_rehydration(source, restored, mapping)
    assert ok["valid"] is True
    assert ok["structure_identical"] is True
    assert ok["residual_token_count"] == 0

    broken = tmp_path / "broken.md"
    broken.write_text("[PERSON_001]은 계약금을 지급했다.", encoding="utf-8")
    result = verify_rehydration(source, broken, mapping)
    assert result["valid"] is False
    assert result["structure_identical"] is False
    assert result["residual_tokens"] == ["[PERSON_001]"]

    with pytest.raises(Exception):
        verify_rehydration(tmp_path / "missing.md", restored, mapping)


def test_audit_flags_unverified_action_and_approaching_deadline(tmp_path: Path) -> None:
    due = (date.today() + timedelta(days=3)).isoformat()
    _seed_analyzed(tmp_path, "case-au-al", deadline_due=due)
    store = CaseStore(tmp_path, "case-au-al")
    _jump_to(store, CaseStage.DRAFTED)
    log_action(
        "case-au-al",
        action_type="제출",
        action_description="증빙 해시 없는 조치",
        action_date="2026-07-19",
        worksets_home=tmp_path,
    )
    log_action(
        "case-au-al",
        action_type="발송",
        action_description="기한 참조 조치",
        action_date="2026-07-19",
        deadline_id="deadline-x",
        worksets_home=tmp_path,
    )
    report = audit_case(store).to_dict()
    codes = {item["code"] for item in report["findings"]}
    assert "ACTION_UNVERIFIED" in codes
    assert "DEADLINE_APPROACHING" in codes


def test_audit_flags_overdue_and_missing_references(tmp_path: Path) -> None:
    overdue = (date.today() - timedelta(days=1)).isoformat()
    _seed_case_data(tmp_path, "case-au-over", deadline_due=overdue)
    store = CaseStore(tmp_path, "case-au-over")
    _jump_to(store, CaseStage.DRAFTED)
    log_action(
        "case-au-over",
        action_type="발송",
        action_description="도과 기한 참조 조치",
        action_date="2026-07-19",
        deadline_id="deadline-x",
        official_receipt_hash="c" * 64,
        worksets_home=tmp_path,
    )
    report = audit_case(store).to_dict()
    codes = {item["code"] for item in report["findings"]}
    assert "DEADLINE_OVERDUE" in codes

    from legal_workbench.models import MockHearingCheck, MockHearingRecord

    bad_hearing = MockHearingRecord(
        hearing_id="mh_bad",
        case_id="case-au-over",
        issue_id="issue-gone",
        checks=[
            MockHearingCheck(
                element="요건",
                burden="청구인",
                missing_facts=[],
                linked_evidence=["ev-gone"],
                satisfied=True,
                judge_question="없음",
            )
        ],
        filing_readiness="제출 가능",
        reasoning="잘못된 참조",
    )
    store.add_mock_hearing(bad_hearing)
    report = audit_case(store).to_dict()
    codes = {item["code"] for item in report["findings"]}
    assert "MOCK_HEARING_ISSUE_MISSING" in codes
    assert "MOCK_HEARING_EVIDENCE_MISSING" in codes
    assert "MOCK_HEARING_READY_WITHOUT_OPINION" in codes
    assert any(item["severity"] == Severity.CRITICAL.value for item in report["findings"])


def test_release_snapshot_includes_new_tables(tmp_path: Path) -> None:
    from legal_workbench.audit import build_release_snapshot

    _seed_analyzed(tmp_path, "case-snap")
    simulate_mock_hearing("case-snap", worksets_home=tmp_path)
    build_evidence_checklist("case-snap", worksets_home=tmp_path)
    build_adversarial_brief("case-snap", worksets_home=tmp_path)
    snapshot = build_release_snapshot(CaseStore(tmp_path, "case-snap"))
    kinds = {item["kind"] for item in snapshot["files"]}
    assert "mock_hearings" in kinds
    assert "evidence_checklists" in kinds
    assert "adversarial_briefs" in kinds

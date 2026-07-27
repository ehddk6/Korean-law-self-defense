from pathlib import Path

from legal_workbench.audit import audit_case, is_official_url
from legal_workbench.models import (
    AuthorityRecord,
    CaseRecord,
    DeadlineRecord,
    EvidenceRecord,
    FactRecord,
    FactStatus,
    IssueRecord,
    OpinionRecord,
    OpinionStatus,
    SourceTier,
    new_id,
    utc_now,
)
from legal_workbench.security import atomic_json_write, sha256_file
from legal_workbench.storage import CaseStore


def build_ready_store(tmp_path: Path) -> CaseStore:
    store = CaseStore(tmp_path, "case-ready")
    store.create_case(
        CaseRecord(
            case_id="case-ready",
            title="검증 사건",
            domain="civil-contract-tort",
            goal="청구 가능성 검토",
            action_date="2026-01-01",
        )
    )
    document_path = store.case_dir / "documents" / "doc_1.sanitized.txt"
    document_path.write_text("[PERSON_001]은 계약서를 작성했다.", encoding="utf-8")
    atomic_json_write(
        store.case_dir / "documents" / "doc_1.metadata.json",
        {
            "source_sha256": "a" * 64,
            "sanitized_sha256": sha256_file(document_path),
            "created_at": utc_now(),
        },
    )
    store.add_document(
        document_id="doc_1",
        filename="contract.txt",
        media_type="text/plain",
        sha256="a" * 64,
        sanitized_path=str(document_path),
        content=document_path.read_text(encoding="utf-8"),
        extraction_status="extracted",
        extraction_confidence=1.0,
        injection_flags=[],
        residual_pii=[],
    )
    store.add_evidence(
        EvidenceRecord(
            evidence_id="ev_1",
            document_id="doc_1",
            sha256="a" * 64,
            source_path_token="[LOCAL_SOURCE]",
            acquired_at="2026-01-01",
            provenance="본인 보관 원본",
            page_or_paragraph="전체 문서",
        )
    )
    store.add_fact(
        FactRecord(
            fact_id="fact_1",
            text="[PERSON_001]은 계약서를 작성했다.",
            status=FactStatus.CONFIRMED,
            evidence_ids=["ev_1"],
        )
    )
    source_text = store.case_dir / "authorities" / "auth_1.source.txt"
    verification_text = store.case_dir / "authorities" / "auth_1.verification.txt"
    source_text.write_text("공식 원문", encoding="utf-8")
    verification_text.write_text("공식 재검증 원문", encoding="utf-8")
    store.add_authority(
        AuthorityRecord(
            authority_id="auth_1",
            title="공식 근거",
            source_tier=SourceTier.P1,
            official_url="https://www.law.go.kr/example",
            retrieved_at=utc_now(),
            text_sha256=sha256_file(source_text),
            citation="예시 법령 제1조",
            effective_from="2025-01-01",
            verification_url="https://lx.scourt.go.kr/example",
            verified_at=utc_now(),
            source_text_path=str(source_text),
            verification_text_path=str(verification_text),
            verification_text_sha256=sha256_file(verification_text),
            mcp_server="korean-law",
            mcp_version="4.7.4",
            mcp_tool="get_law_text",
            mcp_verified_at=utc_now(),
        )
    )
    store.add_issue(
        IssueRecord(
            issue_id="issue_1",
            title="계약상 의무",
            legal_elements=["의무", "불이행"],
            burden="사용자",
            favorable_authority_ids=["auth_1"],
            adverse_authority_ids=["auth_1"],
            fact_ids=["fact_1"],
        )
    )
    store.add_deadline(
        DeadlineRecord(
            deadline_id="deadline_1",
            title="검증 기한",
            trigger_event="송달",
            trigger_date="2026-01-01",
            governing_rule="예시 법령 제1조",
            authority_id="auth_1",
            calculation="기산일 다음 날부터 10일",
            tentative_due_date="2026-01-11",
            holiday_adjustment="공휴일 해당 없음 확인",
            duration_value=10,
            duration_unit="days",
            holiday_adjustment_days=0,
            verification_url="https://www.law.go.kr/example-deadline",
            verified_at=utc_now(),
            verified=True,
            critical=True,
        )
    )
    primary_path = store.case_dir / "bundles" / "analysis-primary-result.json"
    independent_path = store.case_dir / "bundles" / "analysis-independent-result.json"
    atomic_json_write(
        primary_path,
        {
            "format": "legal-workbench-analysis-result-v1",
            "case_id": "case-ready",
            "role": "primary-analysis-result",
            "result": {"conclusion": "잠정 결론", "reasoning": ["근거"]},
        },
    )
    atomic_json_write(
        independent_path,
        {
            "format": "legal-workbench-analysis-result-v1",
            "case_id": "case-ready",
            "role": "independent-analysis-result",
            "result": {"conclusion": "독립 결론", "reasoning": ["반론"]},
        },
    )
    store.add_opinion(
        OpinionRecord(
            opinion_id="opinion_1",
            status=OpinionStatus.READY,
            conclusion="요건이 충족된다는 잠정 판단",
            assumptions=[],
            favorable_scenario="증거가 인정되는 경우",
            contested_scenario="증거가 다투어지는 경우",
            adverse_scenario="증거가 배척되는 경우",
            fact_ids=["fact_1"],
            authority_ids=["auth_1"],
            issue_ids=["issue_1"],
            changes_outcome_if=["계약서 진정성립이 부정되는 경우"],
            source_coverage="verified-primary",
            primary_analysis_ref=str(primary_path),
            primary_analysis_sha256=sha256_file(primary_path),
            independent_analysis_ref=str(independent_path),
            independent_analysis_sha256=sha256_file(independent_path),
            applicable_law_verified=True,
            adverse_authority_reviewed=True,
        )
    )
    return store


def test_ready_audit_passes_and_event_chain_is_valid(tmp_path: Path) -> None:
    store = build_ready_store(tmp_path)
    report = audit_case(store)
    assert report.passed is True
    assert report.release_allowed is True
    assert store.verify_event_chain() is True
    assert store.integrity_check() == ["ok"]


def test_audit_blocks_unproven_confirmed_fact(tmp_path: Path) -> None:
    store = CaseStore(tmp_path, "case-bad")
    store.create_case(CaseRecord(case_id="case-bad", title="오류 사건", domain="civil-contract-tort"))
    store.add_fact(
        FactRecord(
            fact_id="fact_bad",
            text="증거 없는 확정 사실",
            status=FactStatus.CONFIRMED,
            evidence_ids=[],
        )
    )
    report = audit_case(store)
    codes = {item.code for item in report.findings}
    assert "CONFIRMED_FACT_WITHOUT_EVIDENCE" in codes
    assert report.release_allowed is False


def test_p1_url_allowlist_rejects_general_government_and_secondary_portals() -> None:
    assert is_official_url("https://www.law.go.kr/example") is True
    assert is_official_url("https://library.scourt.go.kr/example") is True
    assert is_official_url("https://www.ccourt.go.kr/example") is True
    assert is_official_url("https://easylaw.go.kr/example") is False
    assert is_official_url("https://example.go.kr/example") is False

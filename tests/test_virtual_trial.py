import json
from pathlib import Path

import pytest

from legal_workbench.clarification_simulator import simulate_clarification
from legal_workbench.models import CaseStage, EvidenceRecord, TrialVerdict
from legal_workbench.pleading_engine import build_pleading_strategy
from legal_workbench.quantum_computation import calculate_quantum
from legal_workbench.security import atomic_json_write, sha256_file
from legal_workbench.storage import CaseStore
from legal_workbench.virtual_trial import run_virtual_trial
from legal_workbench.workflow import (
    add_authority,
    add_fact,
    add_issue,
    build_research_bundle,
    complete_research,
    intake_case,
)


def _jump_to(store: CaseStore, target: CaseStage, reason: str = "테스트") -> None:
    from legal_workbench.models import STAGE_ORDER

    for stage in STAGE_ORDER:
        store.transition(stage, reason=reason)
        if stage == target:
            break


def _seed_case_data(tmp_path: Path, case_id: str) -> CaseStore:
    intake_case(
        case_id=case_id,
        title="가상 재판 시험 사건",
        domain="civil-contract-tort",
        goal="모의 판결문 생성 검증",
        forum=None,
        action_date="2026-01-01",
        as_of_date="2026-07-19",
        worksets_home=tmp_path,
    )
    store = CaseStore(tmp_path, case_id)
    document_path = store.case_dir / "documents" / "sample.sanitized.txt"
    document_path.write_text("[PERSON_001]은 계약서를 작성하고 계약금을 지급했다.", encoding="utf-8")
    atomic_json_write(
        store.case_dir / "documents" / "doc-vt.metadata.json",
        {"source_sha256": "b" * 64, "sanitized_sha256": sha256_file(document_path)},
    )
    store.add_document(
        document_id="doc-vt",
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
            evidence_id="ev-vt",
            document_id="doc-vt",
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
            "fact_id": "fact-vt",
            "text": "[PERSON_001]은 계약금을 지급했다.",
            "status": "confirmed",
            "evidence_ids": ["ev-vt"],
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
            "authority_id": "auth-vt",
            "title": "공식 P1 원문",
            "source_tier": "P1",
            "official_url": "https://www.law.go.kr/vt-primary",
            "verification_url": "https://lx.scourt.go.kr/vt-secondary",
            "verified_at": "2026-07-19T00:00:00+00:00",
            "retrieved_at": "2026-07-19T00:00:00+00:00",
            "citation": "예시 법령 제1조 (가상 재판용)",
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
            "issue_id": "issue-vt",
            "title": "계약금 반환 요건",
            "legal_elements": ["계약", "지급", "반환 사유"],
            "burden": "청구인",
            "favorable_authority_ids": [authority.authority_id],
            "adverse_authority_ids": [authority.authority_id],
            "fact_ids": ["fact-vt"],
            "missing_facts": ["반환 약정 존재"],
            "remedies": ["반환 청구"],
        },
        worksets_home=tmp_path,
    )
    assert build_research_bundle(case_id, worksets_home=tmp_path).is_file()
    assert complete_research(case_id, worksets_home=tmp_path)["stage"] == "researched"
    return store


def test_virtual_trial_requires_research_completion(tmp_path: Path) -> None:
    intake_case(
        case_id="case-vt-early",
        title="조기 실행 사건",
        domain="civil-contract-tort",
        goal="게이트 확인",
        forum=None,
        action_date="2026-01-01",
        as_of_date="2026-07-19",
        worksets_home=tmp_path,
    )
    with pytest.raises(ValueError, match="RESEARCHED"):
        run_virtual_trial("case-vt-early", worksets_home=tmp_path)
    with pytest.raises(KeyError):
        run_virtual_trial("case-vt-not-found", worksets_home=tmp_path)


def test_virtual_trial_produces_mock_judgment_and_stores_record(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-vt-e2e")
    result = run_virtual_trial("case-vt-e2e", worksets_home=tmp_path)
    assert result["verdict"] in {item.value for item in TrialVerdict}
    judgment = Path(result["mock_judgment_path"])
    assert judgment.is_file()
    text = judgment.read_text(encoding="utf-8")
    assert "모의 판결문" in text
    assert "변호사법 제109조" in text
    assert "원고(신청인) 측 변호사의 주장" in text
    assert "피고(상대방) 측 변호사의 반론" in text
    assert "승소 가능성 평가" in text

    store = CaseStore(tmp_path, "case-vt-e2e")
    trials = store.list_payloads("virtual_trials")
    assert len(trials) == 1
    assert trials[0]["trial_id"] == result["trial_id"]
    assert trials[0]["verdict"] == result["verdict"]


def test_virtual_trial_verdict_is_deterministic_and_gated(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-vt-det")
    first = run_virtual_trial("case-vt-det", worksets_home=tmp_path)
    second = run_virtual_trial("case-vt-det", worksets_home=tmp_path)
    assert first["verdict"] == second["verdict"]
    assert first["winning_probability"] == second["winning_probability"]


def test_pleading_strategy_builds_primary_and_contingent(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-pl-e2e")
    result = build_pleading_strategy("case-pl-e2e", worksets_home=tmp_path)
    assert result["strategy_id"].startswith("pl_")

    store = CaseStore(tmp_path, "case-pl-e2e")
    strategies = store.list_payloads("pleading_strategies")
    assert len(strategies) == 1
    assert strategies[0]["primary_claim"]["claim_type"] == "primary"
    assert strategies[0]["primary_claim"]["legal_basis"]


def test_clarification_raises_questions_for_unproven_facts(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-cl-e2e")
    result = simulate_clarification("case-cl-e2e", worksets_home=tmp_path)
    assert result["questions_count"] >= 1

    store = CaseStore(tmp_path, "case-cl-e2e")
    records = store.list_payloads("clarifications")
    assert len(records) == 1
    assert records[0]["questions"]


def test_quantum_computes_formula_and_persists(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-qt-e2e")
    result = calculate_quantum("case-qt-e2e", 1_000_000, worksets_home=tmp_path)
    assert result["final_expected_amount"] == 1_000_000
    assert "근거 미확인" in result["basis_note"]

    with_ratio = calculate_quantum(
        "case-qt-e2e",
        1_000_000,
        mitigation_ratio=0.2,
        offset_amount=50_000,
        worksets_home=tmp_path,
    )
    assert with_ratio["final_expected_amount"] == 750_000

    store = CaseStore(tmp_path, "case-qt-e2e")
    records = store.list_payloads("quantums")
    assert len(records) == 2


def test_quantum_rejects_invalid_inputs(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-qt-invalid")
    with pytest.raises(ValueError, match="0보다 커야"):
        calculate_quantum("case-qt-invalid", 0, worksets_home=tmp_path)
    with pytest.raises(ValueError, match="이상 1 이하"):
        calculate_quantum("case-qt-invalid", 1000, mitigation_ratio=1.5, worksets_home=tmp_path)


def test_virtual_trial_json_roundtrip_schema(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-vt-roundtrip")
    run_virtual_trial("case-vt-roundtrip", worksets_home=tmp_path)
    store = CaseStore(tmp_path, "case-vt-roundtrip")
    payload = store.list_payloads("virtual_trials")[0]
    assert json.loads(json.dumps(payload)) == payload
    assert Path(payload["mock_judgment_ref"]).is_file()

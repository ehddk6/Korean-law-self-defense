import json
from datetime import date, timedelta
from pathlib import Path

import pytest

from legal_workbench.models import STAGE_ORDER, CaseStage, EvidenceRecord
from legal_workbench.plain_language import build_plain_language_guide
from legal_workbench.security import atomic_json_write, sha256_file
from legal_workbench.storage import CaseStore
from legal_workbench.workflow import (
    add_authority,
    add_deadline,
    add_fact,
    add_issue,
    build_analysis_bundles,
    build_research_bundle,
    complete_research,
    draft_case,
    export_case,
    import_analysis_result,
    import_opinion,
    import_visual_review,
    intake_case,
    run_audit,
)


def test_visual_review_keeps_renders_from_different_document_formats(tmp_path: Path) -> None:
    case_id = "case-visual-review"
    intake_case(
        case_id=case_id,
        title="시각검토 사건",
        domain="civil-contract-tort",
        goal="렌더 파일명 분리 확인",
        forum=None,
        action_date="2026-01-01",
        as_of_date="2026-07-19",
        worksets_home=tmp_path,
    )
    store = CaseStore(tmp_path, case_id)
    for target in STAGE_ORDER[1 : STAGE_ORDER.index(CaseStage.DRAFTED) + 1]:
        store.transition(target, reason="시각검토 시험")
    for name in ("legal-opinion.docx", "legal-opinion.pdf"):
        (store.case_dir / "drafts" / name).write_bytes(b"test")
    render = tmp_path / "page-1.png"
    render.write_bytes(b"png")

    review = import_visual_review(
        case_id,
        {
            "documents": [
                {"filename": "legal-opinion.docx", "passed": True, "render_files": [str(render)]},
                {"filename": "legal-opinion.pdf", "passed": True, "render_files": [str(render)]},
            ]
        },
        worksets_home=tmp_path,
    )

    names = [Path(item["render_files"][0]["path"]).name for item in review["documents"]]
    assert names == ["docx-legal-opinion-001.png", "pdf-legal-opinion-001.png"]


def test_case_can_move_from_intake_to_audited_export(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    case_id = "case-e2e"
    intake_case(
        case_id=case_id,
        title="계약금 반환 사건",
        domain="civil-contract-tort",
        goal="계약금 반환 가능성 검토",
        forum="서울중앙지방법원 확인 필요",
        action_date="2026-01-01",
        as_of_date="2026-07-19",
        worksets_home=tmp_path,
    )
    store = CaseStore(tmp_path, case_id)
    document_path = store.case_dir / "documents" / "contract.sanitized.txt"
    document_path.write_text("[PERSON_001]은 계약서를 작성하고 계약금을 지급했다.", encoding="utf-8")
    atomic_json_write(
        store.case_dir / "documents" / "doc-e2e.metadata.json",
        {"source_sha256": "a" * 64, "sanitized_sha256": sha256_file(document_path)},
    )
    store.add_document(
        document_id="doc-e2e",
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
            evidence_id="ev-e2e",
            document_id="doc-e2e",
            sha256="a" * 64,
            source_path_token="[LOCAL_SOURCE]",
            acquired_at="2026-01-02",
            provenance="본인 보관 원본",
            page_or_paragraph="전체 문서",
        )
    )
    store.transition(CaseStage.SAFETY_CHECKED, reason="테스트 비식별 안전검사")
    store.transition(CaseStage.INGESTED, reason="테스트 증거 반입")

    fact = add_fact(
        case_id,
        {
            "fact_id": "fact-e2e",
            "text": "[PERSON_001]은 계약서를 작성하고 계약금을 지급했다.",
            "status": "confirmed",
            "evidence_ids": ["ev-e2e"],
        },
        worksets_home=tmp_path,
    )
    authority_source = tmp_path / "authority-source.txt"
    authority_verification = tmp_path / "authority-verification.txt"
    authority_source.write_text("공식 원문", encoding="utf-8")
    authority_verification.write_text("공식 재검증 원문", encoding="utf-8")
    authority = add_authority(
        case_id,
        {
            "authority_id": "auth-e2e",
            "title": "공식 P1 원문",
            "source_tier": "P1",
            "official_url": "https://www.law.go.kr/example-primary",
            "verification_url": "https://lx.scourt.go.kr/example-secondary",
            "verified_at": "2026-07-19T00:00:00+00:00",
            "retrieved_at": "2026-07-19T00:00:00+00:00",
            "citation": "예시 법령 제1조",
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
    issue = add_issue(
        case_id,
        {
            "issue_id": "issue-e2e",
            "title": "계약금 반환 요건",
            "legal_elements": ["계약", "지급", "반환 사유"],
            "burden": "청구인",
            "favorable_authority_ids": [authority.authority_id],
            "adverse_authority_ids": [authority.authority_id],
            "fact_ids": [fact.fact_id],
            "remedies": ["반환 청구"],
        },
        worksets_home=tmp_path,
    )
    with pytest.raises(ValueError, match="JSON boolean"):
        add_deadline(
            case_id,
            {"title": "잘못된 boolean", "verified": "false", "critical": False},
            worksets_home=tmp_path,
        )
    add_deadline(
        case_id,
        {
            "deadline_id": "deadline-e2e",
            "title": "검증 기한",
            "trigger_event": "송달",
            "trigger_date": date.today().isoformat(),
            "governing_rule": "예시 법령 제1조",
            "authority_id": authority.authority_id,
            "calculation": "기산일 다음 날부터 10일",
            "tentative_due_date": (date.today() + timedelta(days=10)).isoformat(),
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
    assert CaseStore(tmp_path, case_id).get_case()["stage"] == "issues_mapped"
    assert complete_research(case_id, worksets_home=tmp_path)["stage"] == "researched"
    analysis = build_analysis_bundles(case_id, worksets_home=tmp_path)
    assert set(analysis) == {"primary", "independent"}
    independent = json.loads(analysis["independent"].read_text(encoding="utf-8"))
    assert independent["role"] == "independent-adversarial-analysis"
    assert "결론" not in independent

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
            "opinion_id": "opinion-e2e",
            "status": "ready",
            "conclusion": "검증된 입력 범위에서 반환 청구 요건이 충족된다는 잠정 판단",
            "assumptions": [],
            "favorable_scenario": "계약과 지급이 인정되는 경우",
            "contested_scenario": "반환 사유가 다투어지는 경우",
            "adverse_scenario": "계약 또는 지급 증거가 배척되는 경우",
            "fact_ids": [fact.fact_id],
            "authority_ids": [authority.authority_id],
            "issue_ids": [issue.issue_id],
            "changes_outcome_if": ["계약의 진정성립이 부정되는 경우"],
            "source_coverage": "verified-primary",
            "primary_analysis_ref": primary_result["path"],
            "independent_analysis_ref": independent_result["path"],
            "applicable_law_verified": True,
            "adverse_authority_reviewed": True,
        },
        worksets_home=tmp_path,
    )
    drafts = draft_case(case_id, document_type="legal-opinion", formats=["md"], worksets_home=tmp_path)
    assert drafts["md"].is_file()
    draft_text = drafts["md"].read_text(encoding="utf-8")
    assert "## 검토 범위 및 전제" in draft_text
    assert "## 쟁점별 검토" in draft_text
    assert "## 사용상 유의" in draft_text
    guide = build_plain_language_guide(case_id, formats=["md"], worksets_home=tmp_path)
    guide_text = guide["md"].read_text(encoding="utf-8")
    assert "## 한눈에 보는 결론" in guide_text
    assert "## 이 프로젝트가 해 줄 수 있는 일" in guide_text
    assert "공식 근거 기반 잠정 판단입니다:" in guide_text
    assert "검증된 입력 범위에서 반환 청구 요건이 충족된다는 잠정 판단" in guide_text
    audit = run_audit(case_id, worksets_home=tmp_path)
    assert audit["release_allowed"] is True
    original_draft = drafts["md"].read_bytes()
    drafts["md"].write_bytes(original_draft + "\n감사 후 변경".encode("utf-8"))
    with pytest.raises(PermissionError, match="감사 이후"):
        export_case(case_id, worksets_home=tmp_path)
    drafts["md"].write_bytes(original_draft)
    with pytest.raises(PermissionError, match="v1 인증"):
        export_case(case_id, worksets_home=tmp_path)
    import legal_workbench.evaluation as evaluation_module

    monkeypatch.setattr(
        evaluation_module,
        "certification_status",
        lambda _: {"v1_certified": True, "reasons": []},
    )
    export_dir = export_case(case_id, worksets_home=tmp_path)
    manifest = json.loads((export_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["case_id"] == case_id
    assert {item["filename"] for item in manifest["files"]} >= {"legal-opinion.md", "audit-report.json"}
    assert CaseStore(tmp_path, case_id).get_case()["stage"] == "released"

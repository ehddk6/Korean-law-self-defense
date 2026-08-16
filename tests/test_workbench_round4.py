from datetime import date, timedelta
from pathlib import Path

from legal_workbench.audit import audit_case, audit_history, case_timeline, next_action_digest
from legal_workbench.cli import build_parser, dispatch
from legal_workbench.storage import CaseStore
from legal_workbench.workflow import (
    build_analysis_bundles,
    draft_case,
    import_analysis_result,
    import_opinion,
)

from test_workbench_extensions import _seed_analyzed, _seed_case_data


def test_draft_disclaimer_has_no_lease_residue(tmp_path: Path) -> None:
    _seed_analyzed(tmp_path, "case-r4-disclaimer")
    drafts = draft_case(
        "case-r4-disclaimer", document_type="legal-opinion", formats=["md"], worksets_home=tmp_path
    )
    markdown = drafts["md"].read_text(encoding="utf-8")
    assert "## 사용상 유의" in markdown
    assert "열쇠" not in markdown
    assert "보증금" not in markdown
    assert "이행·인도 자료" in markdown


def test_case_timeline_includes_opinion_transition(tmp_path: Path) -> None:
    _seed_analyzed(tmp_path, "case-r4-timeline-opinion")
    store = CaseStore(tmp_path, "case-r4-timeline-opinion")
    entries = case_timeline(store)
    opinion_entries = [entry for entry in entries if entry["kind"] == "opinion"]
    assert opinion_entries, "연표에 의견 전환이 포함되어야 합니다."
    assert "ready" in opinion_entries[0]["flags"]
    dates = [entry["date"] for entry in entries]
    assert dates == sorted(dates)


def test_preflight_reports_recommendations(tmp_path: Path) -> None:
    _seed_analyzed(tmp_path, "case-r4-preflight")
    parser = build_parser()
    payload = dispatch(
        parser.parse_args(["--worksets-home", str(tmp_path), "preflight", "--case", "case-r4-preflight"])
    )
    recommendations = payload["recommendations"]
    assert recommendations
    assert any("감사" in item for item in recommendations)
    # 저장된 감사가 없는 사건은 감사 저장을 권고해야 한다.
    assert any("저장된 감사가 없습니다" in item for item in recommendations)


def test_audit_history_tracks_resolved_and_new_codes(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-r4-history")
    store = CaseStore(tmp_path, "case-r4-history")

    first = audit_case(store).to_dict()
    first["created_at"] = "2026-08-16T00:00:00+00:00"
    store.add_audit_report(first)
    assert "OPINION_MISSING" in {item["code"] for item in first["findings"]}

    # 의견을 완성해 두 번째 감사에서 OPINION_MISSING이 해결되도록 한다.
    build_analysis_bundles("case-r4-history", worksets_home=tmp_path)
    primary_result = import_analysis_result(
        "case-r4-history",
        "primary",
        {"conclusion": "잠정 결론", "reasoning": ["사실과 근거를 적용함"]},
        worksets_home=tmp_path,
    )
    independent_result = import_analysis_result(
        "case-r4-history",
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
        "case-r4-history",
        {
            "opinion_id": "opinion-r4",
            "status": "ready",
            "conclusion": "검증된 입력 범위에서 잠정 판단",
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
    second = audit_case(store).to_dict()
    second["created_at"] = "2026-08-16T01:00:00+00:00"
    store.add_audit_report(second)
    assert "OPINION_MISSING" not in {item["code"] for item in second["findings"]}

    history = audit_history(store)
    assert history["audit_count"] == 2
    first_entry, second_entry = history["audits"]
    assert first_entry["resolved_codes"] == []
    assert "OPINION_MISSING" in first_entry["codes"]
    assert "OPINION_MISSING" in second_entry["resolved_codes"]
    assert "DEADLINE_REVIEW_MISSING" in second_entry["new_codes"]
    assert second_entry["severity_counts"]["critical"] >= 1

    parser = build_parser()
    cli_payload = dispatch(
        parser.parse_args(["--worksets-home", str(tmp_path), "audits", "--case", "case-r4-history"])
    )
    assert cli_payload["audit_count"] == 2


def test_next_action_digest_collects_urgent_items(tmp_path: Path) -> None:
    overdue = (date.today() - timedelta(days=1)).isoformat()
    _seed_case_data(tmp_path, "case-r4-next", deadline_due=overdue)
    store = CaseStore(tmp_path, "case-r4-next")

    digest = next_action_digest(store)
    assert digest["checked_on"] == date.today().isoformat()
    assert len(digest["urgent_deadlines"]) == 1
    assert digest["urgent_deadlines"][0]["status"] == "도과"
    assert digest["latest_audit"] is None
    assert digest["unconfirmed_facts"] == []
    assert "반환 약정 존재" in digest["missing_facts"]

    parser = build_parser()
    cli_payload = dispatch(
        parser.parse_args(["--worksets-home", str(tmp_path), "next-action", "--case", "case-r4-next"])
    )
    assert cli_payload["urgent_deadlines"][0]["deadline_id"] == "deadline-x"

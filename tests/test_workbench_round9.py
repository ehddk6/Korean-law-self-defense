"""라운드9 회귀 테스트: 요건 단위 proof matrix·전제 구조화·서면 ID 보존·drift 항목화·timeline 분석 이벤트."""

from __future__ import annotations

import json
from pathlib import Path

from legal_workbench.audit import audit_case, build_release_snapshot, case_timeline
from legal_workbench.cli import build_parser, dispatch
from legal_workbench.models import CaseStage, FactRecord, FactStatus
from legal_workbench.pleading_engine import build_pleading_strategy
from legal_workbench.storage import CaseStore
from legal_workbench.trial_prep import proof_matrix, readiness_report
from legal_workbench.workflow import (
    _draft_markdown,
    add_fact,
    build_analysis_bundles,
    import_analysis_result,
    import_opinion,
    intake_case,
    resolve_opinion_assumption,
)

from test_workbench_extensions import _jump_to, _seed_analyzed, _seed_case_data


def _seed_with_opinion(tmp_path: Path, case_id: str, assumptions: list[object]) -> CaseStore:
    """분석 결과 수입과 함께 전제를 가진 ready 의견을 시드한다."""
    _seed_case_data(tmp_path, case_id)
    build_analysis_bundles(case_id, worksets_home=tmp_path)
    primary = import_analysis_result(
        case_id,
        "primary",
        {"conclusion": "잠정 결론", "reasoning": ["사실과 근거를 적용함"]},
        worksets_home=tmp_path,
    )
    independent = import_analysis_result(
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
            "assumptions": assumptions,
            "favorable_scenario": "계약과 지급이 인정되는 경우",
            "contested_scenario": "반환 사유가 다투어지는 경우",
            "adverse_scenario": "계약 또는 지급 증거가 배척되는 경우",
            "fact_ids": ["fact-x"],
            "authority_ids": ["auth-x"],
            "issue_ids": ["issue-x"],
            "changes_outcome_if": ["계약의 진정성립이 부정되는 경우"],
            "source_coverage": "verified-primary",
            "primary_analysis_ref": primary["path"],
            "independent_analysis_ref": independent["path"],
            "applicable_law_verified": True,
            "adverse_authority_reviewed": True,
        },
        worksets_home=tmp_path,
    )
    return CaseStore(tmp_path, case_id)


# ── Priority 1: 요건 단위 proof matrix ──────────────────────────────────────


def test_add_fact_roundtrips_covers_elements(tmp_path: Path) -> None:
    intake_case(
        case_id="case-r9-fact",
        title="커버스 요소 왕복 사건",
        domain="civil-contract-tort",
        goal="검증",
        forum=None,
        action_date="2026-01-01",
        as_of_date="2026-07-19",
        worksets_home=tmp_path,
    )
    store = CaseStore(tmp_path, "case-r9-fact")
    _jump_to(store, CaseStage.INGESTED)
    add_fact(
        "case-r9-fact",
        {
            "fact_id": "fact-e",
            "text": "계약서에 서명하고 계약금을 지급했다.",
            "status": "confirmed",
            "covers_elements": ["계약", "지급", "  "],
        },
        worksets_home=tmp_path,
    )
    stored = store.list_payloads("facts")[-1]
    assert stored["covers_elements"] == ["계약", "지급"], "공백 항목은 걸러져야 한다."


def test_proof_matrix_element_coverage_gap(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-r9-matrix")
    store = CaseStore(tmp_path, "case-r9-matrix")
    fact = store.list_payloads("facts")[0]
    store.update_payload(
        "facts",
        "fact_id",
        "fact-x",
        {**fact, "covers_elements": ["계약", "지급"]},
    )
    row = proof_matrix(store)["issues"][0]
    coverage = {item["element"]: item for item in row["element_coverage"]}
    assert coverage["계약"]["status"] == "covered"
    assert coverage["지급"]["status"] == "covered"
    assert coverage["계약"]["fact_ids"] == ["fact-x"]
    assert coverage["계약"]["evidence_ids"] == ["ev-x"]
    assert coverage["반환 사유"]["status"] == "gap"
    assert any("반환 사유" in gap for gap in row["gaps"])
    assert row["sufficiency"] == "partial"


def test_proof_matrix_without_mapping_makes_no_claim(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-r9-nomap")
    store = CaseStore(tmp_path, "case-r9-nomap")
    row = proof_matrix(store)["issues"][0]
    assert row["element_coverage"] == []
    assert all("요건" not in gap for gap in row["gaps"]), "매핑 없이 요건 공백을 단정하지 않는다."


def test_readiness_checks_element_gap(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-r9-ready")
    store = CaseStore(tmp_path, "case-r9-ready")
    fact = store.list_payloads("facts")[0]
    store.update_payload(
        "facts",
        "fact_id",
        "fact-x",
        {**fact, "covers_elements": ["계약"]},
    )
    report = readiness_report(store)
    assert len(report["checklist"]) == 6
    by_item = {entry["item"]: entry for entry in report["checklist"]}
    assert by_item["요건 피복 공백 없음"]["satisfied"] is False
    assert "issue-x" in by_item["요건 피복 공백 없음"]["guidance"]


# ── Priority 2: conditional 전제 구조화·해소 추적 ───────────────────────────


def test_import_opinion_normalizes_assumptions(tmp_path: Path) -> None:
    store = _seed_with_opinion(
        tmp_path,
        "case-r9-norm",
        [
            "문자 전제",
            {"text": "구조 전제", "resolved": True, "resolution_note": "확인됨"},
            {"text": "  "},
        ],
    )
    stored = store.list_payloads("opinions")[-1]
    assert stored["assumptions"] == [
        {"text": "문자 전제", "resolved": False, "resolution_note": None},
        {"text": "구조 전제", "resolved": True, "resolution_note": "확인됨"},
    ], "문자 전제는 구조화 전제로 승격되고 빈 항목은 제거되어야 한다."


def test_audit_flags_open_assumptions_and_resolve_clears(tmp_path: Path) -> None:
    store = _seed_with_opinion(
        tmp_path,
        "case-r9-open",
        [{"text": "증빙 미확보 전제", "resolved": False}],
    )
    report = audit_case(store).to_dict()
    open_findings = [f for f in report["findings"] if f["code"] == "OPINION_OPEN_ASSUMPTIONS"]
    assert open_findings, "ready 의견의 미해소 구조화 전제는 감사에서 알려야 한다."
    assert open_findings[0]["severity"] == "minor"

    resolve_opinion_assumption(
        "case-r9-open",
        "opinion-x",
        0,
        note="계약서 원본에서 확인",
        worksets_home=tmp_path,
    )
    clean = audit_case(store).to_dict()
    assert not [f for f in clean["findings"] if f["code"] == "OPINION_OPEN_ASSUMPTIONS"]

    stored = store.list_payloads("opinions")[-1]
    assert stored["assumptions"][0]["resolved"] is True
    assert stored["assumptions"][0]["resolution_note"] == "계약서 원본에서 확인"
    assert store.verify_event_chain(), "전제 해소 갱신도 이벤트 체인을 유지해야 한다."


def test_resolve_upgrades_string_assumption(tmp_path: Path) -> None:
    store = _seed_with_opinion(tmp_path, "case-r9-str", ["문자 전제"])
    resolve_opinion_assumption("case-r9-str", "opinion-x", 0, worksets_home=tmp_path)
    stored = store.list_payloads("opinions")[-1]
    assert stored["assumptions"] == [
        {"text": "문자 전제", "resolved": True, "resolution_note": None}
    ]
    assert any(event["event_type"] == "opinions_updated" for event in store.list_events())


def test_resolve_assumption_out_of_range_rejected(tmp_path: Path) -> None:
    _seed_with_opinion(tmp_path, "case-r9-range", ["전제 하나"])
    try:
        resolve_opinion_assumption("case-r9-range", "opinion-x", 5, worksets_home=tmp_path)
    except ValueError as exc:
        assert "인덱스" in str(exc)
    else:
        raise AssertionError("범위를 벗어난 전제 인덱스는 거부되어야 한다.")


def test_resolve_assumption_cli(tmp_path: Path) -> None:
    _seed_with_opinion(
        tmp_path,
        "case-r9-cli",
        [{"text": "미해소 전제", "resolved": False}],
    )
    parser = build_parser()
    payload = dispatch(
        parser.parse_args(
            [
                "--worksets-home",
                str(tmp_path),
                "resolve-assumption",
                "--case",
                "case-r9-cli",
                "--opinion",
                "opinion-x",
                "--index",
                "0",
                "--note",
                "공식 문서로 확인",
            ]
        )
    )
    assert payload["assumptions"][0]["resolved"] is True
    assert payload["assumptions"][0]["resolution_note"] == "공식 문서로 확인"


def test_draft_markdown_renders_assumption_state(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-r9-draft")
    store = CaseStore(tmp_path, "case-r9-draft")
    case = store.get_case()
    opinion = {
        "status": "conditional",
        "conclusion": "조건부 잠정 판단",
        "assumptions": [
            {"text": "해소된 전제", "resolved": True, "resolution_note": "증빙 확인"},
            {"text": "미해소 전제", "resolved": False},
            "문자 전제",
        ],
        "favorable_scenario": "유리한 경우",
        "contested_scenario": "경합하는 경우",
        "adverse_scenario": "불리한 경우",
    }
    markdown = _draft_markdown(store, case, opinion, "답변서")
    assert "- 전제 [해소]: 해소된 전제 (증빙 확인)" in markdown
    assert "- 전제 [미해소]: 미해소 전제" in markdown
    assert "- 전제: 문자 전제" in markdown


# ── Priority 3: PleadingNode fact/authority ID 보존 ─────────────────────────


def test_pleading_strategy_preserves_record_ids(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-r9-plead")
    store = CaseStore(tmp_path, "case-r9-plead")
    result = build_pleading_strategy("case-r9-plead", worksets_home=tmp_path)

    strategy = store.list_payloads("pleading_strategies")[0]
    node = strategy["primary_claim"]
    assert node["fact_ids"] == ["fact-x"]
    assert node["authority_ids"] == ["auth-x"]

    saved_path = store.case_dir / "pleading_strategies" / f"{result['strategy_id']}.json"
    saved = json.loads(saved_path.read_text(encoding="utf-8"))
    assert saved["primary_claim"]["fact_ids"] == ["fact-x"]
    assert saved["primary_claim"]["authority_ids"] == ["auth-x"]


# ── Priority 4: preflight drift 기록 변경 항목화 ────────────────────────────


def _save_audit_with_snapshot(store: CaseStore, *, include_records: bool) -> None:
    report = audit_case(store).to_dict()
    snapshot = build_release_snapshot(store)
    report["release_snapshot"] = (
        snapshot
        if include_records
        else {key: value for key, value in snapshot.items() if key != "records"}
    )
    store.add_audit_report(report)


def test_preflight_drift_lists_record_changes(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-r9-drift")
    store = CaseStore(tmp_path, "case-r9-drift")
    _save_audit_with_snapshot(store, include_records=True)

    store.add_fact(FactRecord(fact_id="fact-new", text="새 사실", status=FactStatus.UNKNOWN))
    parser = build_parser()
    payload = dispatch(
        parser.parse_args(["--worksets-home", str(tmp_path), "preflight", "--case", "case-r9-drift"])
    )
    drift = payload["drift"]
    assert drift["snapshot_match"] is False
    assert any(
        item["table"] == "facts" and item["record_id"] == "fact-new" and item["change"] == "added"
        for item in drift["records"]
    )
    assert any("기록 1건이 변경" in recommendation for recommendation in payload["recommendations"])


def test_preflight_drift_legacy_snapshot_keeps_records_empty(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-r9-legacy")
    store = CaseStore(tmp_path, "case-r9-legacy")
    _save_audit_with_snapshot(store, include_records=False)

    store.add_fact(FactRecord(fact_id="fact-new", text="새 사실", status=FactStatus.UNKNOWN))
    parser = build_parser()
    payload = dispatch(
        parser.parse_args(["--worksets-home", str(tmp_path), "preflight", "--case", "case-r9-legacy"])
    )
    drift = payload["drift"]
    assert drift["snapshot_match"] is False
    assert drift["records"] == [], "구버전 스냅샷에는 기록 대조 기준이 없어 전체를 added로 오인하면 안 된다."
    assert any(
        "기록이 변경됐습니다" in recommendation and "건이 변경" not in recommendation
        for recommendation in payload["recommendations"]
    )


# ── Priority 5: timeline에 analysis 이벤트 포함 ─────────────────────────────


def test_timeline_includes_analysis_events(tmp_path: Path) -> None:
    _seed_analyzed(tmp_path, "case-r9-tl")
    store = CaseStore(tmp_path, "case-r9-tl")
    entries = case_timeline(store)
    analysis = [entry for entry in entries if entry["kind"] == "analysis"]
    assert len(analysis) == 2
    roles = {flag for entry in analysis for flag in entry["flags"]}
    assert {"primary", "independent"} <= roles
    assert all(entry["date"] for entry in analysis)

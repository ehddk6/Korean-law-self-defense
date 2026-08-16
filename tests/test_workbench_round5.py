from pathlib import Path

from legal_workbench.cli import build_parser, dispatch
from legal_workbench.storage import CaseStore
from legal_workbench.trial_prep import answer_map, proof_matrix, readiness_report

from test_workbench_extensions import _seed_analyzed, _seed_case_data


def test_proof_matrix_classifies_partial_sufficiency(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-r5-proof")
    store = CaseStore(tmp_path, "case-r5-proof")

    matrix = proof_matrix(store)
    assert matrix["summary"] == {"insufficient": 0, "partial": 1, "substantial": 0}
    row = matrix["issues"][0]
    assert row["issue_id"] == "issue-x"
    assert row["confirmed_fact_count"] == 1
    assert row["evidence_ids"] == ["ev-x"]
    assert row["verified_favorable_authority_ids"] == ["auth-x"]
    # 미확인 사실이 남아 있으면 부분 입증이다.
    assert row["sufficiency"] == "partial"
    assert any("반환 약정 존재" in gap for gap in row["gaps"])


def test_proof_matrix_flags_insufficient_issue(tmp_path: Path) -> None:
    _seed_case_data(
        tmp_path,
        "case-r5-weak",
        extra_issues=[
            {
                "issue_id": "issue-weak",
                "title": "입증 없는 쟁점",
                "legal_elements": ["요건"],
                "burden": "청구인",
                "favorable_authority_ids": ["auth-x"],
                "adverse_authority_ids": ["auth-x"],
                "fact_ids": [],
                "missing_facts": [],
                "remedies": [],
            }
        ],
    )
    store = CaseStore(tmp_path, "case-r5-weak")
    matrix = proof_matrix(store)
    weak = next(row for row in matrix["issues"] if row["issue_id"] == "issue-weak")
    assert weak["sufficiency"] == "insufficient"
    assert any("확정 사실" in gap for gap in weak["gaps"])
    # 근거는 검증되었어도 확정 사실이 없으면 입증 부족이다.
    assert weak["verified_favorable_authority_ids"] == ["auth-x"]
    assert matrix["summary"]["insufficient"] == 1


def test_answer_map_structures_opponent_claims(tmp_path: Path) -> None:
    _seed_case_data(
        tmp_path,
        "case-r5-answer",
        extra_facts=[
            {
                "fact_id": "fact-opponent",
                "text": "상대방이 주장하는 사실",
                "status": "opponent_allegation",
                "evidence_ids": [],
            },
            {
                "fact_id": "fact-disputed",
                "text": "다툼이 있는 사실",
                "status": "disputed",
                "evidence_ids": [],
            },
        ],
    )
    store = CaseStore(tmp_path, "case-r5-answer")

    result = answer_map(store)
    assert result["opponent_claim_count"] == 2
    claim_ids = {item["fact_id"] for item in result["claims"]}
    assert claim_ids == {"fact-opponent", "fact-disputed"}
    # 확정 사실은 상대방 주장 목록에 섞이지 않아야 한다.
    assert "fact-x" not in claim_ids
    assert all(item["requires_counter_evidence"] for item in result["claims"])
    assert "부인(반대 증거 필요)" in result["answer_options"]
    opponent = next(item for item in result["claims"] if item["fact_id"] == "fact-opponent")
    assert "반대 사실" in opponent["guidance"]


def test_readiness_report_checklist_levels(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-r5-ready-a")
    store = CaseStore(tmp_path, "case-r5-ready-a")
    report = readiness_report(store)
    assert report["stage"] == "researched"
    assert len(report["checklist"]) == 6
    by_item = {entry["item"]: entry for entry in report["checklist"]}
    assert by_item["의견 기록 존재"]["satisfied"] is False
    assert by_item["입증 부족 쟁점 없음"]["satisfied"] is True
    assert by_item["도과·임박 기한 없음"]["satisfied"] is True
    assert by_item["감사 통과 기록 존재"]["satisfied"] is False
    assert report["artifacts"] == {
        "adversarial_brief": False,
        "mock_hearing": False,
        "evidence_checklist": False,
        "pleading_strategy": False,
        "quantum": False,
    }
    # 핵심 3건 중 일부만 충족되면 partial이다.
    assert report["readiness_level"] == "partial"

    # 의견이 완성되어도 감사 통과 기록이 없으면 substantial이 될 수 없다.
    _seed_analyzed(tmp_path, "case-r5-ready-b")
    report_b = readiness_report(CaseStore(tmp_path, "case-r5-ready-b"))
    by_item_b = {entry["item"]: entry for entry in report_b["checklist"]}
    assert by_item_b["의견 기록 존재"]["satisfied"] is True
    assert report_b["latest_opinion_status"] == "ready"
    assert report_b["readiness_level"] == "partial"


def test_cli_trial_prep_commands(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-r5-cli")
    parser = build_parser()

    matrix_payload = dispatch(
        parser.parse_args(["--worksets-home", str(tmp_path), "proof-matrix", "--case", "case-r5-cli"])
    )
    assert matrix_payload["issues"][0]["sufficiency"] == "partial"

    answer_payload = dispatch(
        parser.parse_args(["--worksets-home", str(tmp_path), "answer-map", "--case", "case-r5-cli"])
    )
    assert answer_payload["opponent_claim_count"] == 0

    readiness_payload = dispatch(
        parser.parse_args(["--worksets-home", str(tmp_path), "readiness", "--case", "case-r5-cli"])
    )
    assert readiness_payload["case_id"] == "case-r5-cli"
    assert readiness_payload["readiness_level"] in {"insufficient", "partial", "substantial"}

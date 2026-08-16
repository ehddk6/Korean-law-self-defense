from pathlib import Path

import pytest

from legal_workbench.cli import build_parser, dispatch
from legal_workbench.diagnostics import run_doctor, worksets_overview
from legal_workbench.services import court_form_guidance

from test_workbench_extensions import _seed_case_data


def test_court_form_guidance_maps_keywords() -> None:
    guidance = court_form_guidance("payment-order-small-claim")
    assert guidance["has_direct_court_form"] is True
    assert "지급명령 신청서" in guidance["form_keywords"]
    assert "전자소송" in guidance["form_source"]
    assert "최종 확인" in guidance["notice"]

    opinion = court_form_guidance("legal-opinion")
    assert opinion["has_direct_court_form"] is False
    assert opinion["form_keywords"] == []

    with pytest.raises(ValueError):
        court_form_guidance("no-such-service")


def test_court_form_guidance_cli(tmp_path: Path) -> None:
    parser = build_parser()
    payload = dispatch(
        parser.parse_args(["--worksets-home", str(tmp_path), "service", "forms", "--type", "civil-complaint"])
    )
    assert payload["service_type"] == "civil-complaint"
    assert "소장" in payload["form_keywords"]


def test_search_all_crosses_cases(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-r6-a")
    _seed_case_data(tmp_path, "case-r6-b")

    parser = build_parser()
    payload = dispatch(
        parser.parse_args(["--worksets-home", str(tmp_path), "search-all", "--query", "계약금을"])
    )
    assert payload["matched_case_count"] == 2
    assert {item["case_id"] for item in payload["matches"]} == {"case-r6-a", "case-r6-b"}
    assert all(item["hit_count"] >= 1 for item in payload["matches"])

    empty = dispatch(
        parser.parse_args(["--worksets-home", str(tmp_path), "search-all", "--query", "존재하지않는문구"])
    )
    assert empty["matched_case_count"] == 0
    assert empty["matches"] == []


def test_doctor_reports_chain_and_paths(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-r6-doctor")
    mappings = tmp_path / "mappings"
    mappings.mkdir()

    report = run_doctor(tmp_path, mapping_home=mappings)
    assert report["healthy"] is True
    assert report["problems"] == []
    by_check = {item["check"]: item for item in report["checks"]}
    assert by_check["python_version"]["ok"] is True
    assert by_check["worksets_home"]["ok"] is True
    assert by_check["mapping_home"]["ok"] is True
    assert by_check["case:case-r6-doctor"]["ok"] is True

    # 대응표 디렉터리가 없으면 진단이 실패를 보고해야 한다.
    missing = run_doctor(tmp_path, mapping_home=tmp_path / "no-such-dir")
    assert missing["healthy"] is False
    assert "mapping_home" in missing["problems"]


def test_doctor_cli_smoke(tmp_path: Path) -> None:
    parser = build_parser()
    payload = dispatch(parser.parse_args(["--worksets-home", str(tmp_path), "doctor"]))
    assert "checks" in payload
    assert payload["healthy"] in {True, False}


def test_overview_summarizes_cases(tmp_path: Path) -> None:
    _seed_case_data(tmp_path, "case-r6-calm")
    from datetime import date, timedelta

    _seed_case_data(tmp_path, "case-r6-urgent", deadline_due=(date.today() - timedelta(days=1)).isoformat())

    summary = worksets_overview(tmp_path)
    assert summary["case_count"] == 2
    assert summary["urgent_deadline_total"] == 1
    by_case = {item["case_id"]: item for item in summary["cases"]}
    assert by_case["case-r6-calm"]["urgent_deadlines"] == []
    assert by_case["case-r6-calm"]["latest_audit"] is None
    assert by_case["case-r6-calm"]["stage"] == "researched"
    assert by_case["case-r6-urgent"]["urgent_deadlines"] == ["deadline-x"]

    parser = build_parser()
    payload = dispatch(parser.parse_args(["--worksets-home", str(tmp_path), "overview"]))
    assert payload["case_count"] == 2

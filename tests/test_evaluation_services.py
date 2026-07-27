import json
from pathlib import Path

import pytest

from legal_workbench.evaluation import (
    create_evaluation_v2,
    curate_scenario,
    manifest_status,
    write_manifest,
)
from legal_workbench.models import CaseRecord, CaseStage
from legal_workbench.services import SERVICES, build_service_bundle, list_services
from legal_workbench.storage import CaseStore


def test_evaluation_manifest_has_180_and_is_not_false_certified(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    write_manifest(manifest)
    status = manifest_status(manifest)
    assert status["scenario_count"] == 180
    assert status["complete_count"] == 30
    assert status["status_counts"]["complete"] == 30
    assert status["corpus_ready"] is False
    assert status["v1_certified"] is False


def test_curate_rejects_nonofficial_source_and_accepts_masked_official_fixture(tmp_path: Path) -> None:
    manifest = tmp_path / "evaluation" / "manifest.json"
    write_manifest(manifest)
    fixture = manifest.parent / "fixtures" / "case-001.json"
    expected = manifest.parent / "expected" / "case-001.json"
    fixture.write_text('{"facts": ["결론을 가린 사실관계"]}', encoding="utf-8")
    expected.write_text('{"result": "masked"}', encoding="utf-8")
    record = manifest.parent / "record.json"
    record.write_text(
        json.dumps(
            {
                "source_url": "https://example.com/not-p1",
                "official_case_number": "2024다12345",
                "fixture_path": "fixtures/case-001.json",
                "expected_path": "expected/case-001.json",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="공식 P1"):
        curate_scenario(manifest, "case-001", record)

    data = json.loads(record.read_text(encoding="utf-8"))
    data["source_url"] = "https://www.scourt.go.kr/example"
    record.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    result = curate_scenario(manifest, "case-001", record)
    assert result["curation_status"] == "complete"
    assert manifest_status(manifest)["complete_count"] == 31


def test_create_v2_does_not_inherit_v1_gold_approvals(tmp_path: Path) -> None:
    source = tmp_path / "v1" / "manifest.json"
    write_manifest(source)
    payload = json.loads(source.read_text(encoding="utf-8"))
    for item in payload["scenarios"]:
        if item["kind"] == "masked-official-decision":
            item["gold_review_status"] = "approved"
            item["gold_review_path"] = "gold-review-bundle.json"
            item["gold_review_sha256"] = "0" * 64
    source.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    destination = tmp_path / "v2"
    create_evaluation_v2(source, destination)
    cloned = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
    official = [item for item in cloned["scenarios"] if item["kind"] == "masked-official-decision"]
    assert cloned["gold_review_cycle"] == "v2-pending"
    assert all(item["gold_review_status"] == "pending" for item in official)
    assert all("gold_review_path" not in item for item in official)
    assert not (destination / "gold-review-bundle.json").exists()


def test_create_v2_rejects_source_root_as_destination(tmp_path: Path) -> None:
    source = tmp_path / "evaluation" / "manifest.json"
    write_manifest(source)
    with pytest.raises(ValueError, match="상위"):
        create_evaluation_v2(source, tmp_path)


def test_lawyer_service_catalog_and_stage_gate(tmp_path: Path) -> None:
    assert len(SERVICES) >= 35
    assert any(item["service_type"] == "hearing-prep" for item in list_services())
    assert any(item["service_type"] == "administrative-remedy" for item in list_services())
    assert any(item["service_type"] == "criminal-defense-pleading" for item in list_services())
    store = CaseStore(tmp_path, "case-service")
    store.create_case(CaseRecord(case_id="case-service", title="업무 사건", domain="civil-contract-tort"))
    try:
        build_service_bundle("case-service", "civil-complaint", worksets_home=tmp_path)
    except ValueError as exc:
        assert "최소" in str(exc)
    else:
        raise AssertionError("상태 게이트가 동작하지 않았습니다.")

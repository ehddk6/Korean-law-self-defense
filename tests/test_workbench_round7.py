"""Round 7: 잔존 PII 독립 스캔·ingest 차단·P1 원문 게이트·doctor 동기화 점검 회귀."""

import json
from pathlib import Path

import pytest

from legal_workbench.diagnostics import run_doctor
from legal_workbench.security import redact_text, scan_residual_pii
from legal_workbench.workflow import _capture_authority_text, ingest_document, intake_case, store_for


def test_residual_scan_catches_separator_variants_redaction_misses() -> None:
    middle_dot_phone = "연락처 010·1234·5678"
    defanged_email = "문의 user [at] example [dot] com"
    for text in (middle_dot_phone, defanged_email):
        # 비식별 치환은 구분자 변형을 놓치지만 잔존 스캔은 독립 패턴으로 잡아낸다.
        sanitized, _, redactions = redact_text(text)
        assert sanitized == text and redactions == []
    for text, category in (
        ("등록번호 900101–1234567", "RESIDENT_ID"),
        (middle_dot_phone, "PHONE"),
        (defanged_email, "EMAIL"),
    ):
        findings = scan_residual_pii(text)
        assert category in {item.category for item in findings}


def test_residual_scan_ignores_dates_and_official_urls() -> None:
    assert scan_residual_pii("선고 2024-05-30, 2024·05·30 선고") == []
    assert (
        scan_residual_pii("출처: https://law.go.kr/lsLinkCommonInfo.do?chrClsCd=010202&lsJoLnkSeq=1013685153")
        == []
    )


def _seed_case(tmp_path: Path, case_id: str) -> Path:
    worksets = tmp_path / "worksets"
    intake_case(
        case_id=case_id,
        title="보안 경계 회귀",
        domain="civil-contract-tort",
        goal="잔존 PII 차단 검증",
        forum=None,
        action_date=None,
        as_of_date="2026-08-16",
        worksets_home=worksets,
    )
    return worksets


def test_ingest_blocks_documents_with_residual_variant_pii(tmp_path: Path) -> None:
    worksets = _seed_case(tmp_path, "case-residual-block")
    mappings = tmp_path / "mappings"
    source = tmp_path / "dirty.txt"
    source.write_text("상대방 연락처 010·1234·5678이 그대로 남았다.", encoding="utf-8")
    entities = tmp_path / "entities.json"
    entities.write_text(json.dumps({}, ensure_ascii=False), encoding="utf-8")

    with pytest.raises(PermissionError, match="개인정보 패턴이 남아"):
        ingest_document(
            case_id="case-residual-block",
            source=source,
            provenance="본인 보관 원본",
            acquired_at="2026-08-16",
            entities_file=entities,
            mapping_home=mappings,
            worksets_home=worksets,
        )
    # 차단 시 비식별 사본과 대응표가 디스크에 남으면 안 된다.
    assert list((worksets / "case-residual-block" / "documents").glob("*")) == []
    assert not list(mappings.rglob("*.json"))


def test_p1_authority_text_with_pii_is_never_copied(tmp_path: Path) -> None:
    worksets = _seed_case(tmp_path, "case-p1-gate")
    store = store_for("case-p1-gate", worksets)
    dirty = tmp_path / "decision.txt"
    dirty.write_text("처분서 말미에 담당자 연락처 010-1234-5678이 남아 있다.", encoding="utf-8")
    with pytest.raises(PermissionError, match="개인정보 패턴"):
        _capture_authority_text(store, "auth-gate", dirty, "source")
    assert list((store.case_dir / "authorities").glob("*")) == []

    clean = tmp_path / "clean.txt"
    clean.write_text("주문. 피고는 원고에게 금원을 지급하라.", encoding="utf-8")
    destination, digest = _capture_authority_text(store, "auth-clean", clean, "source")
    assert Path(destination).is_file()
    assert len(digest) == 64


def test_doctor_reports_sync_path_checks(tmp_path: Path) -> None:
    worksets = tmp_path / "worksets"
    mappings = tmp_path / "mappings"
    worksets.mkdir()
    mappings.mkdir()
    result = run_doctor(worksets, mappings)
    checks = {item["check"]: item["ok"] for item in result["checks"]}
    assert checks["worksets_not_synced"] is True
    assert checks["mapping_not_synced"] is True

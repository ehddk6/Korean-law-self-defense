from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from legal_workbench.audit import validate_generated_documents
from legal_workbench.court_forms import CourtFormError, bind_generated_document, register_court_form
from legal_workbench.offline_legal_db import (
    OfflineLegalDbError,
    search_offline_legal_db,
    search_with_offline_fallback,
)
from legal_workbench.services import offline_legal_db_search


def _create_offline_db(path: Path, *, p1_required: str = "true") -> Path:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        connection.executemany(
            "INSERT INTO metadata(key, value) VALUES (?, ?)",
            [
                ("dataset_id", "official-law-snapshot"),
                ("dataset_version", "2026-08-test"),
                ("created_at", "2026-08-24T00:00:00+00:00"),
                ("license", "public-source-test"),
                ("p1_verification_required", p1_required),
            ],
        )
        connection.execute(
            """
            CREATE TABLE legal_sources (
                source_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                source_type TEXT NOT NULL,
                official_url TEXT NOT NULL,
                effective_from TEXT,
                retrieved_at TEXT NOT NULL,
                source_sha256 TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO legal_sources VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "law-1",
                "민법",
                "계약의 성립과 이행에 관한 공개 원문 스냅샷",
                "statute",
                "https://www.law.go.kr/법령/민법",
                "2026-01-01",
                "2026-08-24T00:00:00+00:00",
                "a" * 64,
            ),
        )
        connection.commit()
    finally:
        connection.close()
    return path


def test_offline_search_is_discovery_only_and_requires_p1_recheck(tmp_path: Path) -> None:
    database = _create_offline_db(tmp_path / "laws.sqlite")

    result = search_offline_legal_db("계약", database_path=database)

    assert result["status"] == "needs-p1-dual-verification"
    assert result["result_count"] == 1
    assert result["results"][0]["offline_source"] is True
    assert result["results"][0]["discovery_only"] is True
    assert result["results"][0]["p1_verification_required"] is True
    assert offline_legal_db_search("민법", database_path=database)["result_count"] == 1


def test_offline_search_rejects_unsafe_queries_and_missing_policy(tmp_path: Path) -> None:
    database = _create_offline_db(tmp_path / "laws.sqlite")
    with pytest.raises(PermissionError):
        search_offline_legal_db("010-1234-5678", database_path=database)

    unsafe_database = _create_offline_db(tmp_path / "unsafe.sqlite", p1_required="false")
    with pytest.raises(OfflineLegalDbError, match="P1"):
        search_offline_legal_db("민법", database_path=unsafe_database)


def test_primary_failure_uses_offline_fallback_without_marking_p1_verified(tmp_path: Path) -> None:
    database = _create_offline_db(tmp_path / "laws.sqlite")

    def unavailable(_: str) -> object:
        raise ConnectionError("MCP unavailable")

    result = search_with_offline_fallback("계약", primary_search=unavailable, database_path=database)

    assert result["mode"] == "offline-fallback"
    assert result["p1_verification_required"] is True
    assert result["fallback"]["results"][0]["status"] == "needs-p1-dual-verification"

    abstained = search_with_offline_fallback(
        "계약",
        primary_search=unavailable,
        database_path=tmp_path / "missing.sqlite",
    )
    assert abstained["mode"] == "abstain"
    assert abstained["status"] == "abstain"


def test_court_form_binding_audits_version_and_hash(tmp_path: Path) -> None:
    source = tmp_path / "official-form.hwpx"
    source.write_bytes(b"official public court form")
    mirror = tmp_path / "court-forms"
    registered = register_court_form(
        source,
        form_id="civil-complaint",
        title="민사 소장 양식",
        version="2026-v1",
        official_url="https://ecfs.scourt.go.kr/forms/civil-complaint",
        mirror_root=mirror,
    )
    assert registered["user_downloaded"] is True

    drafts = tmp_path / "drafts"
    drafts.mkdir()
    document = drafts / "complaint.md"
    document.write_text("# 비식별 사용자 검토용 초안\n", encoding="utf-8")
    bound = bind_generated_document(document, form_id="civil-complaint", mirror_root=mirror)
    assert bound["form_version"] == "2026-v1"

    findings = []
    result = validate_generated_documents(drafts, findings, court_forms_root=mirror)
    assert result[document.name]["court_form_binding"]["valid"] is True
    assert findings == []

    document.write_text("# 변경된 초안\n", encoding="utf-8")
    findings = []
    result = validate_generated_documents(drafts, findings, court_forms_root=mirror)
    assert result[document.name]["court_form_binding"]["status"] == "document-hash-mismatch"
    assert any(item.code == "COURT_FORM_BINDING_INVALID" for item in findings)


def test_court_form_registration_requires_official_court_url(tmp_path: Path) -> None:
    source = tmp_path / "form.pdf"
    source.write_bytes(b"public form")

    with pytest.raises(CourtFormError, match="공식 HTTPS"):
        register_court_form(
            source,
            form_id="civil-complaint",
            title="민사 소장 양식",
            version="2026-v1",
            official_url="https://example.com/form.pdf",
            mirror_root=tmp_path / "court-forms",
        )

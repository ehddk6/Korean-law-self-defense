from __future__ import annotations

"""사용자 내려받기 방식의 법원 양식 원본 미러와 해시 결속 도구."""

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .security import atomic_json_write, sha256_file, validate_safe_identifier


class CourtFormError(RuntimeError):
    """법원 양식의 출처·해시·버전을 안전하게 확인하지 못했을 때 발생한다."""


COURT_FORM_MANIFEST_FORMAT = "legal-workbench-court-form-mirror-v1"
COURT_FORM_BINDING_FORMAT = "legal-workbench-court-form-binding-v1"
ALLOWED_FORM_SUFFIXES = frozenset({".hwpx", ".docx", ".pdf", ".hwp"})


def default_court_forms_home() -> Path:
    configured = os.environ.get("LEGAL_COURT_FORMS_HOME")
    return Path(configured) if configured else Path.cwd() / "data" / "court-forms"


def register_court_form(
    source: Path,
    *,
    form_id: str,
    title: str,
    version: str,
    official_url: str,
    mirror_root: Path | None = None,
    effective_from: str | None = None,
) -> dict[str, Any]:
    """사용자가 직접 내려받은 공식 양식을 로컬 미러에 해시와 함께 등록한다.

    네트워크 다운로드·제출은 수행하지 않는다. URL은 대한민국 법원 공식 HTTPS
    도메인이어야 하며, 등록 결과는 원본과 로컬 사본의 SHA-256을 함께 보관한다.
    """

    normalized_id = validate_safe_identifier(form_id, field="court_form_id")
    normalized_title = str(title).strip()
    normalized_version = str(version).strip()
    if not normalized_title or not normalized_version:
        raise ValueError("법원 양식의 제목과 버전은 비어 있을 수 없습니다.")
    _validate_official_court_url(official_url)
    if effective_from:
        _validate_iso_date(effective_from)

    source_path = Path(source).expanduser().resolve()
    if not source_path.is_file():
        raise CourtFormError(f"사용자가 내려받은 양식 파일을 찾을 수 없습니다: {source_path}")
    if source_path.suffix.lower() not in ALLOWED_FORM_SUFFIXES:
        raise CourtFormError("법원 양식은 HWPX, DOCX, PDF 또는 HWP 파일만 등록할 수 있습니다.")

    root = Path(mirror_root or default_court_forms_home()).expanduser().resolve()
    original_dir = root / "original"
    original_dir.mkdir(parents=True, exist_ok=True)
    destination = original_dir / f"{normalized_id}{source_path.suffix.lower()}"
    if destination.resolve() != source_path:
        shutil.copy2(source_path, destination)
    source_hash = sha256_file(source_path)
    copied_hash = sha256_file(destination)
    if source_hash != copied_hash:
        raise CourtFormError("법원 양식 복사본의 SHA-256이 원본과 일치하지 않습니다.")

    manifest = _load_manifest(root, allow_missing=True)
    record = {
        "form_id": normalized_id,
        "title": normalized_title,
        "version": normalized_version,
        "official_url": official_url,
        "effective_from": effective_from,
        "original_path": str(destination.relative_to(root).as_posix()),
        "source_sha256": source_hash,
        "mirrored_sha256": copied_hash,
        "registered_at": _utc_now(),
        "user_downloaded": True,
        "p1_source_recheck_required": True,
    }
    records = [item for item in manifest["forms"] if item.get("form_id") != normalized_id]
    records.append(record)
    records.sort(key=lambda item: str(item["form_id"]))
    manifest["forms"] = records
    manifest["updated_at"] = _utc_now()
    atomic_json_write(_manifest_path(root), manifest)
    return {**record, "manifest_path": str(_manifest_path(root))}


def bind_generated_document(
    document: Path,
    *,
    form_id: str,
    mirror_root: Path | None = None,
) -> dict[str, Any]:
    """생성 문서를 검증된 양식 버전에 결속하는 감사용 sidecar를 만든다."""

    document_path = Path(document).expanduser().resolve()
    if not document_path.is_file():
        raise CourtFormError(f"결속할 생성 문서를 찾을 수 없습니다: {document_path}")
    form = load_court_form(form_id, mirror_root=mirror_root)
    binding = {
        "format": COURT_FORM_BINDING_FORMAT,
        "form_id": form["form_id"],
        "form_version": form["version"],
        "form_source_url": form["official_url"],
        "form_mirrored_sha256": form["mirrored_sha256"],
        "document_filename": document_path.name,
        "document_sha256": sha256_file(document_path),
        "bound_at": _utc_now(),
        "submission_status": "user-must-confirm-portal-requirements",
        "notice": (
            "이 결속은 공식 양식 원본·버전·해시를 감사하는 용도입니다. 전자소송 e-Form 입력, "
            "첨부 가능 여부, 최종 제출은 사용자가 전자소송 포털에서 직접 확인·수행해야 합니다."
        ),
    }
    path = court_form_binding_path(document_path)
    atomic_json_write(path, binding)
    return {**binding, "binding_path": str(path)}


def validate_court_form_binding(
    document: Path,
    *,
    mirror_root: Path | None = None,
) -> dict[str, Any]:
    """생성 문서와 양식 원본의 버전·SHA-256 결속을 검증한다."""

    document_path = Path(document).expanduser().resolve()
    binding_path = court_form_binding_path(document_path)
    if not binding_path.is_file():
        return {"present": False, "valid": True, "status": "not-bound"}
    try:
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"present": True, "valid": False, "status": "invalid-binding-json", "error": str(exc)}
    if binding.get("format") != COURT_FORM_BINDING_FORMAT:
        return {"present": True, "valid": False, "status": "invalid-binding-format"}
    if binding.get("document_filename") != document_path.name:
        return {"present": True, "valid": False, "status": "document-name-mismatch"}
    if binding.get("document_sha256") != sha256_file(document_path):
        return {"present": True, "valid": False, "status": "document-hash-mismatch"}
    try:
        form = load_court_form(str(binding.get("form_id") or ""), mirror_root=mirror_root)
    except (CourtFormError, ValueError) as exc:
        return {"present": True, "valid": False, "status": "form-unavailable", "error": str(exc)}
    if binding.get("form_version") != form["version"]:
        return {"present": True, "valid": False, "status": "form-version-mismatch"}
    if binding.get("form_source_url") != form["official_url"]:
        return {"present": True, "valid": False, "status": "form-source-mismatch"}
    if binding.get("form_mirrored_sha256") != form["mirrored_sha256"]:
        return {"present": True, "valid": False, "status": "form-hash-mismatch"}
    return {
        "present": True,
        "valid": True,
        "status": "bound-and-verified",
        "form_id": form["form_id"],
        "form_version": form["version"],
        "p1_source_recheck_required": True,
    }


def load_court_form(form_id: str, *, mirror_root: Path | None = None) -> dict[str, Any]:
    normalized_id = validate_safe_identifier(form_id, field="court_form_id")
    root = Path(mirror_root or default_court_forms_home()).expanduser().resolve()
    manifest = _load_manifest(root)
    record = next((item for item in manifest["forms"] if item.get("form_id") == normalized_id), None)
    if record is None:
        raise CourtFormError(f"등록된 법원 양식을 찾을 수 없습니다: {normalized_id}")
    _validate_official_court_url(str(record.get("official_url") or ""))
    relative = Path(str(record.get("original_path") or ""))
    original_path = (root / relative).resolve()
    try:
        original_path.relative_to(root)
    except ValueError as exc:
        raise CourtFormError("법원 양식 원본 경로가 미러 디렉터리 밖을 가리킵니다.") from exc
    if not original_path.is_file():
        raise CourtFormError("등록된 법원 양식 원본 파일이 없습니다.")
    actual_hash = sha256_file(original_path)
    if actual_hash != record.get("source_sha256") or actual_hash != record.get("mirrored_sha256"):
        raise CourtFormError("법원 양식 원본 SHA-256이 등록된 값과 일치하지 않습니다.")
    if not str(record.get("version") or "").strip():
        raise CourtFormError("법원 양식의 버전 정보가 없습니다.")
    return {**record, "original_path": str(original_path)}


def court_form_binding_path(document: Path) -> Path:
    path = Path(document)
    return path.with_name(path.name + ".court-form.json")


def _manifest_path(root: Path) -> Path:
    return root / "manifest.json"


def _load_manifest(root: Path, *, allow_missing: bool = False) -> dict[str, Any]:
    path = _manifest_path(root)
    if not path.is_file():
        if allow_missing:
            return {"format": COURT_FORM_MANIFEST_FORMAT, "forms": [], "updated_at": _utc_now()}
        raise CourtFormError(f"법원 양식 manifest를 찾을 수 없습니다: {path}")
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CourtFormError("법원 양식 manifest를 읽을 수 없습니다.") from exc
    if manifest.get("format") != COURT_FORM_MANIFEST_FORMAT or not isinstance(manifest.get("forms"), list):
        raise CourtFormError("법원 양식 manifest 형식이 올바르지 않습니다.")
    return manifest


def _validate_official_court_url(url: str) -> None:
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        raise CourtFormError("법원 양식 공식 URL 형식이 올바르지 않습니다.") from exc
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme != "https" or not (host == "scourt.go.kr" or host.endswith(".scourt.go.kr")):
        raise CourtFormError("법원 양식은 대한민국 법원 공식 HTTPS URL만 등록할 수 있습니다.")


def _validate_iso_date(value: str) -> None:
    try:
        datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("시행일은 ISO 날짜(YYYY-MM-DD)여야 합니다.") from exc


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

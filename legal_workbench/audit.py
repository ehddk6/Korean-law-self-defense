from __future__ import annotations

import calendar
import json
from datetime import date, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .documents import DocumentError, extract_document, validate_docx, validate_hwpx, validate_pdf
from .models import AuditFinding, AuditReport, OpinionStatus, Severity, new_id
from .security import scan_prompt_injection, scan_residual_pii, sha256_file, sha256_text
from .storage import CaseStore


P1_HOST_SUFFIXES = (
    "law.go.kr",
    "scourt.go.kr",
    "ccourt.go.kr",
)


def is_official_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    host = parsed.hostname.lower().rstrip(".")
    return any(host == suffix or host.endswith(f".{suffix}") for suffix in P1_HOST_SUFFIXES)


def build_release_snapshot(store: CaseStore) -> dict[str, Any]:
    """Hash every material input and generated file covered by a release audit."""
    case = dict(store.get_case())
    case.pop("stage", None)
    case.pop("updated_at", None)
    records = {
        table: store.list_payloads(table)
        for table in ("evidence", "facts", "authorities", "issues", "deadlines", "opinions")
    }
    files: list[dict[str, Any]] = []
    for document in store.list_documents():
        path = Path(document["sanitized_path"])
        files.append(
            {
                "kind": "sanitized-document",
                "name": document["document_id"],
                "path": str(path.resolve()),
                "sha256": sha256_file(path) if path.is_file() else None,
            }
        )
    for folder_name in ("bundles", "drafts", "visual"):
        folder = store.case_dir / folder_name
        if not folder.exists():
            continue
        for path in sorted(item for item in folder.rglob("*") if item.is_file()):
            files.append(
                {
                    "kind": folder_name,
                    "name": path.relative_to(store.case_dir).as_posix(),
                    "sha256": sha256_file(path),
                }
            )
    material = {"case": case, "documents": store.list_documents(), "records": records, "files": files}
    return {
        "format": "legal-workbench-release-snapshot-v1",
        "sha256": sha256_text(json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":"))),
        "file_count": len(files),
        "files": files,
    }


def audit_case(store: CaseStore) -> AuditReport:
    findings: list[AuditFinding] = []
    checks: dict[str, Any] = {}
    case = store.get_case()
    documents = store.list_documents()
    evidence = store.list_payloads("evidence")
    facts = store.list_payloads("facts")
    authorities = store.list_payloads("authorities")
    issues = store.list_payloads("issues")
    deadlines = store.list_payloads("deadlines")
    opinions = store.list_payloads("opinions")

    document_ids = {item["document_id"] for item in documents}
    evidence_ids = {item["evidence_id"] for item in evidence}
    authority_ids = {item["authority_id"] for item in authorities}
    fact_ids = {item["fact_id"] for item in facts}
    issue_ids = {item["issue_id"] for item in issues}
    document_by_id = {item["document_id"]: item for item in documents}
    fact_by_id = {item["fact_id"]: item for item in facts}

    for item in evidence:
        if item["document_id"] not in document_ids:
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "EVIDENCE_DOCUMENT_MISSING",
                    "증거가 존재하지 않는 문서를 참조합니다.",
                    "evidence",
                    item["evidence_id"],
                )
            )
            continue
        document = document_by_id[item["document_id"]]
        if item.get("sha256") != document.get("sha256"):
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "EVIDENCE_HASH_MISMATCH",
                    "증거 원본 해시가 연결된 문서 원본 해시와 다릅니다.",
                    "evidence",
                    item["evidence_id"],
                )
            )
        if not item.get("page_or_paragraph"):
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "EVIDENCE_LOCATION_MISSING",
                    "증거에 페이지·문단 또는 전체문서 위치 표시가 없습니다.",
                    "evidence",
                    item["evidence_id"],
                )
            )
    for item in facts:
        linked = set(item.get("evidence_ids") or [])
        if item.get("status") == "confirmed" and not linked:
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "CONFIRMED_FACT_WITHOUT_EVIDENCE",
                    "확정 사실에 증거가 연결되지 않았습니다.",
                    "fact",
                    item["fact_id"],
                )
            )
        missing = linked - evidence_ids
        if missing:
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "FACT_EVIDENCE_MISSING",
                    f"사실이 존재하지 않는 증거를 참조합니다: {sorted(missing)}",
                    "fact",
                    item["fact_id"],
                )
            )

    verified_p1_ids: set[str] = set()
    action_date = _parse_date(case.get("action_date"))
    for item in authorities:
        tier = item.get("source_tier")
        official_url = item.get("official_url") or ""
        verification_url = item.get("verification_url") or ""
        if tier == "P1":
            p1_valid = True
            if not is_official_url(official_url):
                p1_valid = False
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        "P1_NON_OFFICIAL_URL",
                        "P1 근거의 원문 URL이 공식 HTTPS 도메인이 아닙니다.",
                        "authority",
                        item["authority_id"],
                    )
                )
            if not item.get("verified_at") or not verification_url:
                p1_valid = False
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        "P1_NOT_DUAL_VERIFIED",
                        "P1 근거가 두 번째 공식 경로에서 재검증되지 않았습니다.",
                        "authority",
                        item["authority_id"],
                    )
                )
            elif not is_official_url(verification_url) or verification_url == official_url:
                p1_valid = False
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        "P1_INVALID_VERIFICATION_URL",
                        "P1 재검증 URL은 서로 다른 공식 HTTPS 원문이어야 합니다.",
                        "authority",
                        item["authority_id"],
                    )
                )
            source_path = Path(str(item.get("source_text_path") or ""))
            verification_path = Path(str(item.get("verification_text_path") or ""))
            if (
                not source_path.is_file()
                or sha256_file(source_path) != item.get("text_sha256")
                or not verification_path.is_file()
                or sha256_file(verification_path) != item.get("verification_text_sha256")
            ):
                p1_valid = False
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        "P1_TEXT_HASH_UNVERIFIED",
                        "P1 원문·재검증 원문 파일과 SHA-256을 대조하지 못했습니다.",
                        "authority",
                        item["authority_id"],
                    )
                )
            if not (
                item.get("mcp_server") == "korean-law"
                and item.get("mcp_version") == "4.7.4"
                and item.get("mcp_tool")
                and item.get("mcp_verified_at")
            ):
                p1_valid = False
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        "P1_MCP_VERIFICATION_MISSING",
                        "P1 근거에 고정 버전 한국법 MCP 조회·검증 기록이 없습니다.",
                        "authority",
                        item["authority_id"],
                    )
                )
            if item.get("case_number") or item.get("court"):
                if not (item.get("case_number") and item.get("court") and item.get("decision_date")):
                    p1_valid = False
                    findings.append(
                        _finding(
                            Severity.CRITICAL,
                            "DECISION_METADATA_INCOMPLETE",
                            "판결·결정 P1에 사건번호·기관·선고일이 모두 필요합니다.",
                            "authority",
                            item["authority_id"],
                        )
                    )
            elif not item.get("effective_from"):
                p1_valid = False
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        "LAW_EFFECTIVE_DATE_MISSING",
                        "법령 P1에 시행일 또는 적용 시작일이 없습니다.",
                        "authority",
                        item["authority_id"],
                    )
                )
            if action_date and item.get("effective_from"):
                effective_from = _parse_date(item.get("effective_from"))
                effective_to = _parse_date(item.get("effective_to"))
                if not effective_from or action_date < effective_from or (effective_to and action_date > effective_to):
                    p1_valid = False
                    findings.append(
                        _finding(
                            Severity.CRITICAL,
                            "APPLICABLE_LAW_DATE_MISMATCH",
                            "P1 근거의 시행기간이 사건 행위일을 포함하지 않습니다.",
                            "authority",
                            item["authority_id"],
                        )
                    )
            if p1_valid:
                verified_p1_ids.add(item["authority_id"])
        if item.get("negative_search_only"):
            findings.append(
                _finding(
                    Severity.MINOR,
                    "NEGATIVE_SEARCH_NOT_EXHAUSTIVE",
                    "검색 결과 없음은 자료 부존재의 증명이 아닙니다.",
                    "authority",
                    item["authority_id"],
                )
            )

    for item in issues:
        referenced = set(item.get("favorable_authority_ids") or []) | set(item.get("adverse_authority_ids") or [])
        missing = referenced - authority_ids
        if missing:
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "ISSUE_AUTHORITY_MISSING",
                    f"쟁점이 존재하지 않는 근거를 참조합니다: {sorted(missing)}",
                    "issue",
                    item["issue_id"],
                )
            )
        missing_facts = set(item.get("fact_ids") or []) - fact_ids
        if missing_facts:
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "ISSUE_FACT_MISSING",
                    f"쟁점이 존재하지 않는 사실을 참조합니다: {sorted(missing_facts)}",
                    "issue",
                    item["issue_id"],
                )
            )
        if not item.get("adverse_authority_ids"):
            findings.append(
                _finding(
                    Severity.MAJOR,
                    "ADVERSE_AUTHORITY_NOT_RECORDED",
                    "쟁점에 불리한 근거 또는 검색 결과가 기록되지 않았습니다.",
                    "issue",
                    item["issue_id"],
                )
            )
        if not item.get("legal_elements"):
            findings.append(
                _finding(
                    Severity.MAJOR,
                    "ISSUE_ELEMENTS_MISSING",
                    "쟁점의 법률요건이 비어 있습니다.",
                    "issue",
                    item["issue_id"],
                )
            )
        if not str(item.get("burden") or "").strip() or item.get("burden") == "확인 필요":
            findings.append(
                _finding(
                    Severity.MAJOR,
                    "ISSUE_BURDEN_UNRESOLVED",
                    "쟁점의 입증책임이 확인되지 않았습니다.",
                    "issue",
                    item["issue_id"],
                )
            )
        if item.get("missing_facts"):
            findings.append(
                _finding(
                    Severity.MAJOR,
                    "ISSUE_CRITICAL_FACTS_MISSING",
                    "쟁점에 결론을 좌우할 미확인 사실이 남아 있습니다.",
                    "issue",
                    item["issue_id"],
                )
            )

    for item in deadlines:
        if item.get("authority_id") not in authority_ids:
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "DEADLINE_AUTHORITY_MISSING",
                    "기한이 존재하지 않는 법적 근거를 참조합니다.",
                    "deadline",
                    item["deadline_id"],
                )
            )
        elif item.get("verified") and item.get("authority_id") not in verified_p1_ids:
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "DEADLINE_AUTHORITY_NOT_VERIFIED_P1",
                    "검증된 기한이 이중 검증된 P1 근거에 연결되지 않았습니다.",
                    "deadline",
                    item["deadline_id"],
                )
            )
        if item.get("critical") and not item.get("verified"):
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "CRITICAL_DEADLINE_UNVERIFIED",
                    "중요 기한의 기산일·근거·계산을 검증하지 못했습니다.",
                    "deadline",
                    item["deadline_id"],
                )
            )
        if item.get("verified") and (
            not item.get("trigger_date")
            or not item.get("governing_rule")
            or not item.get("calculation")
            or not item.get("authority_id")
            or not item.get("tentative_due_date")
            or not item.get("holiday_adjustment")
            or item.get("duration_value") is None
            or item.get("duration_unit") not in {"days", "months", "years"}
            or not item.get("verification_url")
            or not item.get("verified_at")
        ):
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "DEADLINE_VERIFICATION_INCOMPLETE",
                    "검증 완료로 표시된 기한에 계산 필수항목이 누락됐습니다.",
                    "deadline",
                    item["deadline_id"],
                )
            )
        if item.get("verified") and (
            not _parse_date(item.get("trigger_date")) or not _parse_date(item.get("tentative_due_date"))
        ):
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "DEADLINE_DATE_INVALID",
                    "검증된 기한의 기산일 또는 만료일 형식이 올바르지 않습니다.",
                    "deadline",
                    item["deadline_id"],
                )
            )
        if item.get("verified"):
            calculated = _calculate_deadline(item)
            if not calculated or calculated.isoformat() != item.get("tentative_due_date"):
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        "DEADLINE_CALCULATION_MISMATCH",
                        "기산일·기간 단위·휴일 보정으로 재계산한 날짜와 잠정 만료일이 다릅니다.",
                        "deadline",
                        item["deadline_id"],
                    )
                )

    for document in documents:
        if document.get("residual_pii"):
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "RESIDUAL_PII",
                    "비식별 작업본에 개인정보 패턴이 남아 있습니다.",
                    "document",
                    document["document_id"],
                )
            )
        if document.get("extraction_status") in {"needs_ocr", "failed", "partial"}:
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "DOCUMENT_EXTRACTION_UNVERIFIED",
                    "문서 추출 또는 OCR 검증이 완료되지 않았습니다.",
                    "document",
                    document["document_id"],
                )
            )
        if document.get("injection_flags"):
            findings.append(
                _finding(
                    Severity.MINOR,
                    "UNTRUSTED_INSTRUCTION_DETECTED",
                    "문서에서 지시문 형태의 텍스트를 탐지했으며 데이터로만 취급했습니다.",
                    "document",
                    document["document_id"],
                )
            )
        path = Path(document["sanitized_path"])
        metadata_path = store.case_dir / "documents" / f"{document['document_id']}.metadata.json"
        if not path.exists():
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "SANITIZED_DOCUMENT_MISSING",
                    "비식별 문서 파일이 없습니다.",
                    "document",
                    document["document_id"],
                )
            )
        elif path.suffix.lower() in {".txt", ".md", ".json"}:
            residual = scan_residual_pii(path.read_text(encoding="utf-8", errors="replace"))
            if residual:
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        "RESIDUAL_PII_RESCAN",
                        "감사 재검사에서 개인정보 패턴이 발견됐습니다.",
                        "document",
                        document["document_id"],
                    )
                )
        if not metadata_path.is_file():
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "DOCUMENT_METADATA_MISSING",
                    "문서의 원본·비식별 해시와 변환 이력 metadata가 없습니다.",
                    "document",
                    document["document_id"],
                )
            )
        else:
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                metadata = {}
            if (
                metadata.get("source_sha256") != document.get("sha256")
                or not path.is_file()
                or metadata.get("sanitized_sha256") != sha256_file(path)
            ):
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        "DOCUMENT_HASH_MISMATCH",
                        "문서 metadata의 원본 또는 비식별 SHA-256이 현재 파일과 일치하지 않습니다.",
                        "document",
                        document["document_id"],
                    )
                )

    record_surface = json.dumps(
        {
            "facts": [{"text": item.get("text"), "actor_token": item.get("actor_token")} for item in facts],
            "issues": [
                {
                    "title": item.get("title"),
                    "legal_elements": item.get("legal_elements"),
                    "missing_facts": item.get("missing_facts"),
                }
                for item in issues
            ],
            "opinions": [
                {
                    "conclusion": item.get("conclusion"),
                    "assumptions": item.get("assumptions"),
                    "favorable_scenario": item.get("favorable_scenario"),
                    "contested_scenario": item.get("contested_scenario"),
                    "adverse_scenario": item.get("adverse_scenario"),
                    "changes_outcome_if": item.get("changes_outcome_if"),
                }
                for item in opinions
            ],
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    if scan_residual_pii(record_surface):
        findings.append(_finding(Severity.CRITICAL, "RECORD_PII", "사건 레코드에 비식별 개인정보 패턴이 남아 있습니다."))
    if scan_prompt_injection(record_surface):
        findings.append(_finding(Severity.CRITICAL, "RECORD_INSTRUCTION_TEXT", "사건 레코드에 실행 지시 형태의 텍스트가 남아 있습니다."))

    latest_opinion = opinions[-1] if opinions else None
    if latest_opinion is None:
        findings.append(_finding(Severity.CRITICAL, "OPINION_MISSING", "최종 의견이 없습니다."))
    else:
        missing_facts = set(latest_opinion.get("fact_ids") or []) - fact_ids
        missing_authorities = set(latest_opinion.get("authority_ids") or []) - authority_ids
        missing_issues = set(latest_opinion.get("issue_ids") or []) - issue_ids
        if missing_facts or missing_authorities or missing_issues:
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "OPINION_TRACE_BROKEN",
                    "의견의 사실·근거·쟁점 추적 관계가 끊겼습니다.",
                    "opinion",
                    latest_opinion["opinion_id"],
                )
            )
        if latest_opinion.get("status") == str(OpinionStatus.READY):
            if not action_date:
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        "READY_WITHOUT_ACTION_DATE",
                        "ready 의견에는 행위일·처분일 등 적용법 기준일이 필요합니다.",
                        "opinion",
                        latest_opinion["opinion_id"],
                    )
                )
            if not deadlines:
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        "DEADLINE_REVIEW_MISSING",
                        "ready 의견에 기한 검토 레코드가 없습니다.",
                        "opinion",
                        latest_opinion["opinion_id"],
                    )
                )
            unresolved_facts = [
                fact_id
                for fact_id in latest_opinion.get("fact_ids") or []
                if fact_by_id.get(fact_id, {}).get("status") != "confirmed"
            ]
            if unresolved_facts:
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        "READY_USES_UNCONFIRMED_FACT",
                        f"ready 의견이 미확정·분쟁 사실을 결론 근거로 사용합니다: {unresolved_facts}",
                        "opinion",
                        latest_opinion["opinion_id"],
                    )
                )
            used_p1 = set(latest_opinion.get("authority_ids") or []) & verified_p1_ids
            if not used_p1:
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        "READY_WITHOUT_VERIFIED_P1",
                        "ready 의견에 이중 검증된 P1 근거가 없습니다.",
                        "opinion",
                        latest_opinion["opinion_id"],
                    )
                )
            if not latest_opinion.get("applicable_law_verified"):
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        "APPLICABLE_LAW_NOT_VERIFIED",
                        "ready 의견에 행위시법·현행법·부칙 검증 완료 기록이 없습니다.",
                        "opinion",
                        latest_opinion["opinion_id"],
                    )
                )
            if not latest_opinion.get("adverse_authority_reviewed"):
                findings.append(
                    _finding(
                        Severity.CRITICAL,
                        "ADVERSE_REVIEW_NOT_VERIFIED",
                        "ready 의견에 불리한 근거와 상대방 최선 반론 검토 완료 기록이 없습니다.",
                        "opinion",
                        latest_opinion["opinion_id"],
                    )
                )
            for role in ("primary", "independent"):
                if not _analysis_result_valid(
                    store,
                    latest_opinion.get(f"{role}_analysis_ref"),
                    latest_opinion.get(f"{role}_analysis_sha256"),
                    role,
                ):
                    findings.append(
                        _finding(
                            Severity.CRITICAL,
                            f"{role.upper()}_ANALYSIS_INVALID",
                            f"{role} 분석 결과 파일·역할·SHA-256을 검증하지 못했습니다.",
                            "opinion",
                            latest_opinion["opinion_id"],
                        )
                    )

    document_validation = validate_generated_documents(store.case_dir / "drafts", findings)
    visual_validation = validate_visual_review(store, findings)
    chain_ok = store.verify_event_chain()
    integrity = store.integrity_check()
    if not chain_ok:
        findings.append(_finding(Severity.CRITICAL, "EVENT_CHAIN_BROKEN", "감사 이벤트 해시 체인이 손상됐습니다."))
    if integrity != ["ok"]:
        findings.append(_finding(Severity.CRITICAL, "DATABASE_INTEGRITY", f"SQLite 무결성 오류: {integrity}"))

    critical_or_major = [item for item in findings if item.severity in {Severity.CRITICAL, Severity.MAJOR}]
    ready = latest_opinion and latest_opinion.get("status") == str(OpinionStatus.READY)
    passed = not any(item.severity == Severity.CRITICAL for item in findings)
    release_allowed = bool(passed and not critical_or_major and ready)
    checks.update(
        {
            "case_stage": case["stage"],
            "documents": len(documents),
            "evidence": len(evidence),
            "facts": len(facts),
            "authorities": len(authorities),
            "verified_p1": len(verified_p1_ids),
            "issues": len(issues),
            "deadlines": len(deadlines),
            "event_chain": chain_ok,
            "sqlite_integrity": integrity,
            "generated_documents": document_validation,
            "visual_review": visual_validation,
        }
    )
    return AuditReport(
        audit_id=new_id("audit"),
        case_id=store.case_id,
        passed=passed,
        release_allowed=release_allowed,
        findings=findings,
        checks=checks,
    )


def validate_generated_documents(drafts_dir: Path, findings: list[AuditFinding]) -> dict[str, Any]:
    results: dict[str, Any] = {}
    if not drafts_dir.exists():
        return results
    for path in sorted(drafts_dir.iterdir()):
        if not path.is_file():
            continue
        try:
            if path.suffix.lower() == ".docx":
                results[path.name] = validate_docx(path)
            elif path.suffix.lower() == ".pdf":
                results[path.name] = validate_pdf(path)
            elif path.suffix.lower() == ".hwpx":
                results[path.name] = validate_hwpx(path)
            if path.suffix.lower() in {".md", ".txt", ".docx", ".pdf", ".hwpx"}:
                text = extract_document(path).text
                if scan_residual_pii(text):
                    findings.append(
                        _finding(
                            Severity.CRITICAL,
                            "GENERATED_DOCUMENT_PII",
                            f"산출 문서에 비식별 개인정보 패턴이 남아 있습니다: {path.name}",
                            "document",
                            path.name,
                        )
                    )
                if scan_prompt_injection(text):
                    findings.append(
                        _finding(
                            Severity.CRITICAL,
                            "GENERATED_DOCUMENT_INSTRUCTION_TEXT",
                            f"산출 문서에 실행 지시 형태의 텍스트가 남아 있습니다: {path.name}",
                            "document",
                            path.name,
                        )
                    )
        except DocumentError as exc:
            results[path.name] = {"valid": False, "error": str(exc)}
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "GENERATED_DOCUMENT_INVALID",
                    f"산출 문서 검증 실패: {path.name}: {exc}",
                    "document",
                    path.name,
                )
            )
    return results


def validate_visual_review(store: CaseStore, findings: list[AuditFinding]) -> dict[str, Any]:
    drafts = [
        path
        for path in sorted((store.case_dir / "drafts").iterdir())
        if path.is_file() and path.suffix.lower() in {".docx", ".pdf", ".hwpx"}
    ]
    if not drafts:
        return {"required": 0, "verified": 0, "valid": True}
    review_path = store.case_dir / "visual" / "review.json"
    if not review_path.is_file():
        findings.append(
            _finding(
                Severity.CRITICAL,
                "VISUAL_REVIEW_MISSING",
                "DOCX·PDF·HWPX 렌더 화면 검토 기록이 없습니다.",
            )
        )
        return {"required": len(drafts), "verified": 0, "valid": False}
    try:
        review = json.loads(review_path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        review = {}
    entries = {
        item.get("filename"): item
        for item in review.get("documents") or []
        if isinstance(item, dict) and item.get("filename")
    }
    verified = 0
    for draft in drafts:
        entry = entries.get(draft.name)
        valid = bool(entry and entry.get("passed") is True and entry.get("source_sha256") == sha256_file(draft))
        render_files = entry.get("render_files") if entry else []
        if not isinstance(render_files, list) or not render_files:
            valid = False
        for render in render_files or []:
            path = Path(str(render.get("path") or "")).expanduser().resolve() if isinstance(render, dict) else Path()
            try:
                path.relative_to((store.case_dir / "visual").resolve())
            except ValueError:
                valid = False
                continue
            if not path.is_file() or sha256_file(path) != render.get("sha256"):
                valid = False
        if valid:
            verified += 1
        else:
            findings.append(
                _finding(
                    Severity.CRITICAL,
                    "VISUAL_REVIEW_INVALID",
                    f"렌더 화면 검토가 누락되었거나 문서·이미지 해시가 바뀌었습니다: {draft.name}",
                    "document",
                    draft.name,
                )
            )
    return {"required": len(drafts), "verified": verified, "valid": verified == len(drafts)}


def _parse_date(value: Any) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        return None


def _calculate_deadline(item: dict[str, Any]) -> date | None:
    trigger = _parse_date(item.get("trigger_date"))
    duration = item.get("duration_value")
    unit = item.get("duration_unit")
    adjustment = item.get("holiday_adjustment_days", 0)
    if not trigger or not isinstance(duration, int) or isinstance(duration, bool):
        return None
    if not isinstance(adjustment, int) or isinstance(adjustment, bool) or adjustment < 0:
        return None
    if unit == "days":
        result = trigger + timedelta(days=duration)
    elif unit == "months":
        month_index = trigger.month - 1 + duration
        year = trigger.year + month_index // 12
        month = month_index % 12 + 1
        day = min(trigger.day, calendar.monthrange(year, month)[1])
        result = date(year, month, day)
    elif unit == "years":
        year = trigger.year + duration
        day = min(trigger.day, calendar.monthrange(year, trigger.month)[1])
        result = date(year, trigger.month, day)
    else:
        return None
    return result + timedelta(days=adjustment)


def _analysis_result_valid(store: CaseStore, value: Any, expected_hash: Any, role: str) -> bool:
    if not value or not expected_hash:
        return False
    path = Path(str(value)).expanduser().resolve()
    bundles = (store.case_dir / "bundles").resolve()
    try:
        path.relative_to(bundles)
    except ValueError:
        return False
    if not path.is_file() or sha256_file(path) != expected_hash:
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return False
    return (
        payload.get("format") == "legal-workbench-analysis-result-v1"
        and payload.get("case_id") == store.case_id
        and payload.get("role") == f"{role}-analysis-result"
    )


def _finding(
    severity: Severity,
    code: str,
    message: str,
    record_type: str | None = None,
    record_id: str | None = None,
) -> AuditFinding:
    return AuditFinding(
        finding_id=new_id("finding"),
        severity=severity,
        code=code,
        message=message,
        record_type=record_type,
        record_id=record_id,
    )

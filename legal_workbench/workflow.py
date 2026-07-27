from __future__ import annotations

import json
import os
import shutil
from datetime import date
from pathlib import Path
from typing import Any

from .audit import audit_case, build_release_snapshot, is_official_url
from .documents import create_docx, create_hwpx, create_pdf, extract_document
from .models import (
    AuthorityRecord,
    CaseRecord,
    CaseStage,
    DeadlineRecord,
    EvidenceRecord,
    FactRecord,
    FactStatus,
    IssueRecord,
    OpinionRecord,
    OpinionStatus,
    RiskLevel,
    SourceTier,
    new_id,
    utc_now,
)
from .security import (
    atomic_json_write,
    is_within,
    load_mapping,
    path_is_synced,
    redact_text,
    save_mapping,
    scan_prompt_injection,
    scan_residual_pii,
    sha256_file,
    sha256_text,
    validate_safe_identifier,
)
from .storage import CaseStore


DOMAIN_PACKS = (
    "civil-contract-tort",
    "insurance-consumer-damages",
    "real-estate-lease-registration",
    "commercial-corporate-finance-trust",
    "criminal-investigation-procedure",
    "family-inheritance-guardianship",
    "labor-industrial-accident-social-security",
    "administrative-constitutional-state-liability",
    "tax-customs",
    "rehabilitation-bankruptcy-enforcement",
    "privacy-it-intellectual-property",
    "immigration-education-health-regulation",
)


def default_worksets_home() -> Path:
    return Path(os.environ.get("LEGAL_WORKSETS_HOME", str(Path.home() / "LegalWorksets")))


def default_mapping_home() -> Path:
    return Path(os.environ.get("LEGAL_MAPPING_HOME", str(Path.home() / "LegalMappings")))


def mapping_path_for(case_id: str, mapping_home: Path | None, worksets_home: Path) -> Path:
    mapping_root = (mapping_home or default_mapping_home()).expanduser().resolve()
    worksets = Path(worksets_home).expanduser().resolve()
    if path_is_synced(mapping_root):
        raise PermissionError("실명 대응표 저장소는 OneDrive 동기화 경로 밖에 있어야 합니다.")
    if mapping_root == worksets or is_within(mapping_root, worksets) or is_within(worksets, mapping_root):
        raise PermissionError("실명 대응표 저장소와 LegalWorksets는 서로 겹칠 수 없습니다.")
    return mapping_root / "mappings" / f"{validate_safe_identifier(case_id, field='case_id')}.json"


def store_for(case_id: str, worksets_home: Path | None = None) -> CaseStore:
    return CaseStore(worksets_home or default_worksets_home(), case_id)


def intake_case(
    *,
    case_id: str,
    title: str,
    domain: str,
    goal: str,
    forum: str | None,
    action_date: str | None,
    as_of_date: str | None,
    risk_level: RiskLevel = RiskLevel.ROUTINE,
    worksets_home: Path | None = None,
) -> CaseRecord:
    if domain not in DOMAIN_PACKS:
        raise ValueError(f"지원 분야 팩을 선택해야 합니다: {', '.join(DOMAIN_PACKS)}")
    _validate_iso_date(action_date, allow_none=True)
    _validate_iso_date(as_of_date, allow_none=True)
    store = store_for(case_id, worksets_home)
    if store.db_path.exists():
        raise FileExistsError(f"이미 존재하는 사건입니다: {case_id}")
    record = CaseRecord(
        case_id=case_id,
        title=title,
        domain=domain,
        forum=forum,
        goal=goal,
        action_date=action_date,
        as_of_date=as_of_date or date.today().isoformat(),
        risk_level=risk_level,
    )
    store.create_case(record)
    return record


def ingest_document(
    *,
    case_id: str,
    source: Path,
    provenance: str,
    acquired_at: str,
    entities_file: Path | None = None,
    mapping_home: Path | None = None,
    worksets_home: Path | None = None,
) -> dict[str, Any]:
    worksets = (worksets_home or default_worksets_home()).expanduser().resolve()
    if path_is_synced(worksets):
        raise PermissionError("비식별 LegalWorksets는 OneDrive 동기화 경로 밖에 있어야 합니다.")
    source_path = Path(source).expanduser().resolve()
    if is_within(source_path, worksets):
        raise PermissionError("원본 문서는 비식별 LegalWorksets 밖에 있어야 합니다.")
    _validate_iso_date(acquired_at)
    store = store_for(case_id, worksets)
    case = store.get_case()
    stage = CaseStage(case["stage"])
    if stage not in {CaseStage.INTAKE, CaseStage.SAFETY_CHECKED, CaseStage.INGESTED}:
        raise ValueError("사실확정 이후에는 기존 사건에 원본을 추가할 수 없습니다. 새 사건 버전을 만드십시오.")
    if stage == CaseStage.INTAKE:
        store.transition(CaseStage.SAFETY_CHECKED, reason="원본과 비식별 작업공간 분리 확인")
    if entities_file is None:
        raise ValueError("원본 ingest에는 이름·기관 등 사용자 지정 비식별 entities JSON이 필요합니다.")
    extraction = extract_document(source_path)
    custom_entities = _load_entities(entities_file)
    mapping_path = mapping_path_for(case_id, mapping_home, worksets)
    mapping = load_mapping(mapping_path)
    sanitized_text, mapping, redactions = redact_text(
        extraction.text,
        existing_mapping=mapping,
        custom_entities=custom_entities,
    )
    residual = scan_residual_pii(sanitized_text)
    injections = scan_prompt_injection(sanitized_text)
    document_id = new_id("doc")
    evidence_id = new_id("ev")
    document_path = store.case_dir / "documents" / f"{document_id}.sanitized.txt"
    metadata_path = store.case_dir / "documents" / f"{document_id}.metadata.json"
    document_path.write_text(sanitized_text, encoding="utf-8", newline="\n")
    source_hash = sha256_file(source_path)
    extraction_metadata = extraction.to_dict()
    extraction_metadata.pop("text", None)
    metadata = {
        "document_id": document_id,
        "evidence_id": evidence_id,
        "source_filename": "[SOURCE_FILENAME]",
        "source_path_token": "[LOCAL_SOURCE]",
        "source_sha256": source_hash,
        "sanitized_sha256": sha256_text(sanitized_text),
        "extraction": extraction_metadata,
        "redaction_count": len(redactions),
        "prompt_injection_flags": [item.to_dict() for item in injections],
        "residual_pii": [item.to_dict() for item in residual],
        "created_at": utc_now(),
    }
    atomic_json_write(metadata_path, metadata)
    save_mapping(mapping_path, mapping, case_id=case_id)
    store.add_document(
        document_id=document_id,
        filename="[SOURCE_FILENAME]",
        media_type=extraction.media_type,
        sha256=source_hash,
        sanitized_path=str(document_path),
        content=sanitized_text,
        extraction_status=extraction.status,
        extraction_confidence=extraction.confidence,
        injection_flags=[item.to_dict() for item in injections],
        residual_pii=[item.to_dict() for item in residual],
    )
    store.add_evidence(
        EvidenceRecord(
            evidence_id=evidence_id,
            document_id=document_id,
            sha256=source_hash,
            source_path_token=metadata["source_path_token"],
            acquired_at=acquired_at,
            provenance=provenance,
            extraction_confidence=extraction.confidence,
        )
    )
    if stage != CaseStage.INGESTED:
        store.transition(CaseStage.INGESTED, reason="첫 비식별 증거 문서 저장")
    return metadata


def add_fact(case_id: str, payload: dict[str, Any], *, worksets_home: Path | None = None) -> FactRecord:
    store = store_for(case_id, worksets_home)
    _require_stage(store, {CaseStage.INGESTED}, "사실 추가")
    record = FactRecord(
        fact_id=payload.get("fact_id") or new_id("fact"),
        text=str(payload["text"]),
        status=FactStatus(payload.get("status", "unknown")),
        evidence_ids=list(payload.get("evidence_ids") or []),
        occurred_at=payload.get("occurred_at"),
        actor_token=payload.get("actor_token"),
        confidence=str(payload.get("confidence", "unknown")),
    )
    store.add_fact(record)
    return record


def add_authority(case_id: str, payload: dict[str, Any], *, worksets_home: Path | None = None) -> AuthorityRecord:
    store = store_for(case_id, worksets_home)
    _require_stage(
        store,
        {CaseStage.INGESTED, CaseStage.FACTS_FIXED, CaseStage.ISSUES_MAPPED},
        "법적 근거 추가",
    )
    authority_id = validate_safe_identifier(payload.get("authority_id") or new_id("auth"), field="authority_id")
    source_tier = SourceTier(payload.get("source_tier", "U"))
    source_text_path: str | None = None
    verification_text_path: str | None = None
    verification_text_sha256: str | None = None
    text_sha256 = str(payload.get("text_sha256") or "")
    if source_tier == SourceTier.P1:
        source_text_path, actual_source_hash = _capture_authority_text(
            store, authority_id, payload.get("source_text_file"), "source"
        )
        verification_text_path, verification_text_sha256 = _capture_authority_text(
            store, authority_id, payload.get("verification_text_file"), "verification"
        )
        if text_sha256 and text_sha256 != actual_source_hash:
            raise ValueError("P1 원문 파일의 SHA-256이 AuthorityRecord와 일치하지 않습니다.")
        text_sha256 = actual_source_hash
    if not text_sha256:
        raise ValueError("법적 근거에는 text_sha256이 필요합니다.")
    record = AuthorityRecord(
        authority_id=authority_id,
        title=str(payload["title"]),
        source_tier=source_tier,
        official_url=str(payload["official_url"]),
        retrieved_at=str(payload.get("retrieved_at") or utc_now()),
        text_sha256=text_sha256,
        citation=str(payload["citation"]),
        effective_from=payload.get("effective_from"),
        effective_to=payload.get("effective_to"),
        court=payload.get("court"),
        case_number=payload.get("case_number"),
        decision_date=payload.get("decision_date"),
        verification_url=payload.get("verification_url"),
        verified_at=payload.get("verified_at"),
        source_text_path=source_text_path,
        verification_text_path=verification_text_path,
        verification_text_sha256=verification_text_sha256,
        mcp_server=payload.get("mcp_server"),
        mcp_version=payload.get("mcp_version"),
        mcp_tool=payload.get("mcp_tool"),
        mcp_verified_at=payload.get("mcp_verified_at"),
        negative_search_only=bool(payload.get("negative_search_only", False)),
    )
    store.add_authority(record)
    return record


def add_issue(case_id: str, payload: dict[str, Any], *, worksets_home: Path | None = None) -> IssueRecord:
    store = store_for(case_id, worksets_home)
    _require_stage(store, {CaseStage.INGESTED, CaseStage.FACTS_FIXED}, "쟁점 추가")
    record = IssueRecord(
        issue_id=payload.get("issue_id") or new_id("issue"),
        title=str(payload["title"]),
        legal_elements=list(payload.get("legal_elements") or []),
        burden=str(payload.get("burden") or "확인 필요"),
        favorable_authority_ids=list(payload.get("favorable_authority_ids") or []),
        adverse_authority_ids=list(payload.get("adverse_authority_ids") or []),
        fact_ids=list(payload.get("fact_ids") or []),
        missing_facts=list(payload.get("missing_facts") or []),
        remedies=list(payload.get("remedies") or []),
        provisional_view=str(payload.get("provisional_view") or "abstain"),
    )
    store.add_issue(record)
    return record


def add_deadline(case_id: str, payload: dict[str, Any], *, worksets_home: Path | None = None) -> DeadlineRecord:
    store = store_for(case_id, worksets_home)
    _require_stage(
        store,
        {CaseStage.INGESTED, CaseStage.FACTS_FIXED, CaseStage.ISSUES_MAPPED},
        "기한 추가",
    )
    verified_value = payload.get("verified", False)
    critical_value = payload.get("critical", False)
    if not isinstance(verified_value, bool) or not isinstance(critical_value, bool):
        raise ValueError("deadline verified와 critical은 JSON boolean이어야 합니다.")
    duration_value = payload.get("duration_value")
    adjustment_days = payload.get("holiday_adjustment_days", 0)
    if duration_value is not None and (not isinstance(duration_value, int) or isinstance(duration_value, bool)):
        raise ValueError("deadline duration_value는 정수여야 합니다.")
    if not isinstance(adjustment_days, int) or isinstance(adjustment_days, bool):
        raise ValueError("deadline holiday_adjustment_days는 정수여야 합니다.")
    record = DeadlineRecord(
        deadline_id=payload.get("deadline_id") or new_id("deadline"),
        title=str(payload["title"]),
        trigger_event=payload.get("trigger_event"),
        trigger_date=payload.get("trigger_date"),
        governing_rule=payload.get("governing_rule"),
        authority_id=payload.get("authority_id"),
        calculation=payload.get("calculation"),
        tentative_due_date=payload.get("tentative_due_date"),
        holiday_adjustment=payload.get("holiday_adjustment"),
        duration_value=duration_value,
        duration_unit=payload.get("duration_unit"),
        holiday_adjustment_days=adjustment_days,
        verification_url=payload.get("verification_url"),
        verified_at=payload.get("verified_at"),
        verified=verified_value,
        critical=critical_value,
    )
    store.add_deadline(record)
    return record


def build_research_bundle(case_id: str, *, worksets_home: Path | None = None) -> Path:
    store = store_for(case_id, worksets_home)
    case = store.get_case()
    facts = store.list_payloads("facts")
    issues = store.list_payloads("issues")
    if not facts:
        raise ValueError("법률조사 전에 사실 레코드가 필요합니다.")
    if not issues:
        raise ValueError("법률조사 전에 쟁점 레코드가 필요합니다.")
    stage = CaseStage(case["stage"])
    if stage == CaseStage.INGESTED:
        store.transition(CaseStage.FACTS_FIXED, reason="사실 레코드 확정")
        store.transition(CaseStage.ISSUES_MAPPED, reason="쟁점 레코드 확정")
    elif stage == CaseStage.FACTS_FIXED:
        store.transition(CaseStage.ISSUES_MAPPED, reason="쟁점 레코드 확정")
    elif stage != CaseStage.ISSUES_MAPPED:
        raise ValueError(f"현재 상태에서는 조사 묶음을 만들 수 없습니다: {stage}")
    payload = {
        "case": case,
        "facts": facts,
        "issues": issues,
        "required_research": {
            "action_law": True,
            "current_law": True,
            "future_law": True,
            "transitional_provisions": True,
            "favorable_and_adverse_precedent": True,
            "limitation_and_procedural_deadlines": True,
            "dual_official_verification": True,
            "negative_search_wording": "확인한 공개 자료에서 발견하지 못함",
        },
        "output_contract": {
            "source_tiers": ["P1", "P2", "S", "U"],
            "final_status_without_verified_p1": "abstain",
        },
    }
    path = store.case_dir / "bundles" / "research-input.json"
    atomic_json_write(path, payload)
    return path


def complete_research(case_id: str, *, worksets_home: Path | None = None) -> dict[str, Any]:
    store = store_for(case_id, worksets_home)
    case = store.get_case()
    if CaseStage(case["stage"]) != CaseStage.ISSUES_MAPPED:
        raise ValueError("쟁점화 및 조사 입력 묶음 생성 후에만 조사를 완료할 수 있습니다.")
    if not case.get("action_date"):
        raise ValueError("조사 완료에는 행위일 또는 처분 기준일이 필요합니다.")
    authorities = store.list_payloads("authorities")
    issues = store.list_payloads("issues")
    authority_by_id = {item["authority_id"]: item for item in authorities}
    verified_p1 = {
        item["authority_id"]
        for item in authorities
        if item.get("source_tier") == "P1"
        and is_official_url(str(item.get("official_url") or ""))
        and is_official_url(str(item.get("verification_url") or ""))
        and item.get("official_url") != item.get("verification_url")
        and item.get("verified_at")
        and item.get("text_sha256")
        and item.get("citation")
        and (item.get("effective_from") or item.get("decision_date"))
        and _authority_text_files_match(item)
        and item.get("mcp_server") == "korean-law"
        and item.get("mcp_version") == "4.7.4"
        and item.get("mcp_tool")
        and item.get("mcp_verified_at")
    }
    if not verified_p1:
        raise ValueError("조사 완료에는 적용시점 정보와 이중 검증을 갖춘 P1 근거가 필요합니다.")
    for issue in issues:
        if not issue.get("legal_elements") or not str(issue.get("burden") or "").strip() or issue.get("burden") == "확인 필요":
            raise ValueError(f"쟁점의 법률요건·입증책임이 미완성입니다: {issue['issue_id']}")
        favorable = set(issue.get("favorable_authority_ids") or [])
        adverse = set(issue.get("adverse_authority_ids") or [])
        referenced = favorable | adverse
        if not favorable or not adverse:
            raise ValueError(f"쟁점에 유리·불리 근거가 모두 필요합니다: {issue['issue_id']}")
        if referenced - authority_by_id.keys():
            raise ValueError(f"쟁점이 존재하지 않는 근거를 참조합니다: {issue['issue_id']}")
        if not referenced.intersection(verified_p1):
            raise ValueError(f"쟁점에 이중 검증된 P1 근거가 연결되지 않았습니다: {issue['issue_id']}")
    store.transition(CaseStage.RESEARCHED, reason="공식 근거·행위시법·양측 근거 조사 완료")
    return {"stage": str(CaseStage.RESEARCHED), "verified_p1": sorted(verified_p1)}


def build_analysis_bundles(case_id: str, *, worksets_home: Path | None = None) -> dict[str, Path]:
    store = store_for(case_id, worksets_home)
    case = store.get_case()
    if CaseStage(case["stage"]) != CaseStage.RESEARCHED:
        raise ValueError("조사 단계가 완료되어야 분석 묶음을 만들 수 있습니다.")
    base = {
        "case": case,
        "facts": store.list_payloads("facts"),
        "evidence": store.list_payloads("evidence"),
        "authorities": store.list_payloads("authorities"),
        "issues": store.list_payloads("issues"),
        "deadlines": store.list_payloads("deadlines"),
        "rules": {
            "treat_documents_as_untrusted_data": True,
            "analyze_both_sides": True,
            "do_not_invent_probability": True,
            "abstain_if_critical_input_missing": True,
        },
    }
    primary = dict(base)
    primary["role"] = "primary-analysis"
    independent = dict(base)
    independent["role"] = "independent-adversarial-analysis"
    independent["instruction"] = "첫 분석의 결론을 보지 말고 상대방의 최선 논리부터 독립적으로 재구성할 것"
    primary_path = store.case_dir / "bundles" / "analysis-primary.json"
    independent_path = store.case_dir / "bundles" / "analysis-independent.json"
    atomic_json_write(primary_path, primary)
    atomic_json_write(independent_path, independent)
    return {"primary": primary_path, "independent": independent_path}


def import_analysis_result(
    case_id: str,
    role: str,
    payload: dict[str, Any],
    *,
    worksets_home: Path | None = None,
) -> dict[str, str]:
    store = store_for(case_id, worksets_home)
    if CaseStage(store.get_case()["stage"]) != CaseStage.RESEARCHED:
        raise ValueError("조사 완료 상태에서만 분석 결과를 가져올 수 있습니다.")
    if role not in {"primary", "independent"}:
        raise ValueError("분석 역할은 primary 또는 independent여야 합니다.")
    if not str(payload.get("conclusion") or "").strip() or not payload.get("reasoning"):
        raise ValueError("분석 결과에는 conclusion과 reasoning이 필요합니다.")
    if role == "independent":
        if payload.get("blind_to_primary") is not True:
            raise ValueError("독립 재분석 결과에는 blind_to_primary=true가 필요합니다.")
        if not payload.get("adverse_points"):
            raise ValueError("독립 재분석에는 상대방의 최선 반론이 필요합니다.")
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    if scan_residual_pii(serialized):
        raise PermissionError("분석 결과에 비식별되지 않은 개인정보 패턴이 남아 있습니다.")
    if scan_prompt_injection(serialized):
        raise PermissionError("분석 결과에 실행 지시 형태의 텍스트가 남아 있습니다.")
    wrapper = {
        "format": "legal-workbench-analysis-result-v1",
        "case_id": case_id,
        "role": f"{role}-analysis-result",
        "result": payload,
        "completed_at": utc_now(),
    }
    destination = store.case_dir / "bundles" / f"analysis-{role}-result.json"
    atomic_json_write(destination, wrapper)
    return {"path": str(destination), "sha256": sha256_file(destination)}


def import_opinion(case_id: str, payload: dict[str, Any], *, worksets_home: Path | None = None) -> OpinionRecord:
    store = store_for(case_id, worksets_home)
    case = store.get_case()
    if CaseStage(case["stage"]) != CaseStage.RESEARCHED:
        raise ValueError("조사 단계에서만 의견을 가져올 수 있습니다.")
    status = OpinionStatus(payload.get("status", "abstain"))
    primary_ref, primary_hash = _validated_analysis_result(store, payload.get("primary_analysis_ref"), "primary")
    independent_ref, independent_hash = _validated_analysis_result(
        store, payload.get("independent_analysis_ref"), "independent"
    )
    record = OpinionRecord(
        opinion_id=payload.get("opinion_id") or new_id("opinion"),
        status=status,
        conclusion=str(payload.get("conclusion") or "공식 근거 또는 핵심 사실 부족으로 판단 보류"),
        assumptions=list(payload.get("assumptions") or []),
        favorable_scenario=str(payload.get("favorable_scenario") or "확인 필요"),
        contested_scenario=str(payload.get("contested_scenario") or "확인 필요"),
        adverse_scenario=str(payload.get("adverse_scenario") or "확인 필요"),
        fact_ids=list(payload.get("fact_ids") or []),
        authority_ids=list(payload.get("authority_ids") or []),
        issue_ids=list(payload.get("issue_ids") or []),
        changes_outcome_if=list(payload.get("changes_outcome_if") or []),
        source_coverage=str(payload.get("source_coverage") or "incomplete"),
        primary_analysis_ref=primary_ref,
        primary_analysis_sha256=primary_hash,
        independent_analysis_ref=independent_ref,
        independent_analysis_sha256=independent_hash,
        applicable_law_verified=payload.get("applicable_law_verified") is True,
        adverse_authority_reviewed=payload.get("adverse_authority_reviewed") is True,
    )
    if status == OpinionStatus.READY and not (
        record.applicable_law_verified and record.adverse_authority_reviewed
    ):
        raise ValueError("ready 의견에는 행위시법과 불리한 근거 검토 완료 표시가 필요합니다.")
    store.add_opinion(record)
    store.transition(CaseStage.INDEPENDENTLY_ANALYZED, reason="1차 분석과 독립 재분석 결과 가져오기")
    return record


def draft_case(
    case_id: str,
    *,
    document_type: str,
    formats: list[str],
    worksets_home: Path | None = None,
) -> dict[str, Path]:
    document_type = validate_safe_identifier(document_type, field="document_type")
    store = store_for(case_id, worksets_home)
    case = store.get_case()
    if CaseStage(case["stage"]) != CaseStage.INDEPENDENTLY_ANALYZED:
        raise ValueError("독립 재분석을 완료한 뒤 서면을 작성하십시오.")
    opinions = store.list_payloads("opinions")
    if not opinions:
        raise ValueError("의견 레코드가 없습니다.")
    opinion = opinions[-1]
    markdown = _draft_markdown(store, case, opinion, document_type)
    base = store.case_dir / "drafts" / f"{document_type}"
    paths: dict[str, Path] = {}
    md_path = base.with_suffix(".md")
    md_path.write_text(markdown, encoding="utf-8", newline="\n")
    paths["md"] = md_path
    for fmt in formats:
        normalized = fmt.lower()
        if normalized == "docx":
            paths["docx"] = create_docx(markdown, base.with_suffix(".docx"), title=case["title"])
        elif normalized == "pdf":
            paths["pdf"] = create_pdf(markdown, base.with_suffix(".pdf"), title=case["title"])
        elif normalized == "hwpx":
            paths["hwpx"] = create_hwpx(markdown, base.with_suffix(".hwpx"), title=case["title"])
        elif normalized != "md":
            raise ValueError(f"지원하지 않는 출력 형식: {fmt}")
    store.transition(CaseStage.DRAFTED, reason=f"{document_type} 초안 생성")
    return paths


def run_audit(case_id: str, *, worksets_home: Path | None = None) -> dict[str, Any]:
    store = store_for(case_id, worksets_home)
    case = store.get_case()
    if CaseStage(case["stage"]) != CaseStage.DRAFTED:
        raise ValueError("서면작성 단계에서만 최종 감사를 실행할 수 있습니다.")
    report = audit_case(store)
    payload = report.to_dict()
    payload["release_snapshot"] = build_release_snapshot(store)
    path = store.case_dir / "audits" / f"{report.audit_id}.json"
    atomic_json_write(path, payload)
    store.add_audit_report(payload)
    if report.release_allowed:
        store.transition(CaseStage.AUDITED, reason="결정론적 최종 감사와 배포 게이트 통과")
    return payload


def import_visual_review(
    case_id: str,
    payload: dict[str, Any],
    *,
    worksets_home: Path | None = None,
) -> dict[str, Any]:
    store = store_for(case_id, worksets_home)
    _require_stage(store, {CaseStage.DRAFTED}, "문서 시각검토 가져오기")
    entries = payload.get("documents")
    if not isinstance(entries, list) or not entries:
        raise ValueError("시각검토 JSON에는 documents 배열이 필요합니다.")
    imported: list[dict[str, Any]] = []
    visual_dir = store.case_dir / "visual"
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("시각검토 문서 항목은 JSON 객체여야 합니다.")
        filename = Path(str(entry.get("filename") or "")).name
        source = (store.case_dir / "drafts" / filename).resolve()
        if not source.is_file() or source.suffix.lower() not in {".docx", ".pdf", ".hwpx"}:
            raise ValueError(f"시각검토 대상 문서를 찾을 수 없습니다: {filename}")
        if entry.get("passed") is not True:
            raise ValueError(f"통과하지 않은 시각검토는 가져올 수 없습니다: {filename}")
        render_files = entry.get("render_files")
        if not isinstance(render_files, list) or not render_files:
            raise ValueError(f"시각검토에는 렌더 이미지가 하나 이상 필요합니다: {filename}")
        imported_renders: list[dict[str, str]] = []
        for index, value in enumerate(render_files, start=1):
            render_source = Path(str(value)).expanduser().resolve()
            if not render_source.is_file() or render_source.suffix.lower() not in {".png", ".jpg", ".jpeg", ".webp"}:
                raise ValueError(f"렌더 이미지를 찾을 수 없습니다: {render_source}")
            destination = visual_dir / f"{source.stem}-{index:03d}{render_source.suffix.lower()}"
            if render_source != destination.resolve():
                shutil.copy2(render_source, destination)
            imported_renders.append({"path": str(destination.resolve()), "sha256": sha256_file(destination)})
        imported.append(
            {
                "filename": filename,
                "source_sha256": sha256_file(source),
                "passed": True,
                "render_files": imported_renders,
                "notes": str(entry.get("notes") or "").strip(),
            }
        )
    review = {
        "format": "legal-workbench-visual-review-v1",
        "case_id": case_id,
        "reviewer": str(payload.get("reviewer") or "user-confirmed"),
        "reviewed_at": str(payload.get("reviewed_at") or utc_now()),
        "documents": imported,
    }
    atomic_json_write(visual_dir / "review.json", review)
    return review


def export_case(case_id: str, *, worksets_home: Path | None = None) -> Path:
    store = store_for(case_id, worksets_home)
    case = store.get_case()
    if CaseStage(case["stage"]) != CaseStage.AUDITED:
        raise ValueError("감사 완료 상태에서만 배포할 수 있습니다.")
    audit = store.latest_audit()
    if not audit or not audit.get("release_allowed"):
        raise PermissionError("감사에서 배포가 허용되지 않았습니다. ready 의견과 무오류 감사를 확보하십시오.")
    expected_snapshot = audit.get("release_snapshot") or {}
    current_snapshot = build_release_snapshot(store)
    if not expected_snapshot.get("sha256") or expected_snapshot.get("sha256") != current_snapshot["sha256"]:
        raise PermissionError("감사 이후 사건자료·분석·초안이 변경되어 배포할 수 없습니다. 새 사건 버전에서 다시 감사하십시오.")
    from .evaluation import certification_status

    evaluation_manifest = Path(
        os.environ.get("LEGAL_EVALUATION_MANIFEST", str(Path.cwd() / "evaluation" / "manifest.json"))
    )
    certification = certification_status(evaluation_manifest)
    if not certification["v1_certified"]:
        raise PermissionError(
            "180건 잠금 평가 v1 인증이 없어 배포할 수 없습니다: " + "; ".join(certification["reasons"])
        )
    export_dir = store.case_dir / "exports" / utc_now().replace(":", "-")
    export_dir.mkdir(parents=True, exist_ok=False)
    files: list[dict[str, Any]] = []
    for source in sorted((store.case_dir / "drafts").iterdir()):
        if not source.is_file():
            continue
        destination = export_dir / source.name
        shutil.copy2(source, destination)
        files.append(
            {
                "filename": destination.name,
                "size": destination.stat().st_size,
                "sha256": sha256_file(destination),
            }
        )
    audit_path = export_dir / "audit-report.json"
    atomic_json_write(audit_path, audit)
    files.append({"filename": audit_path.name, "size": audit_path.stat().st_size, "sha256": sha256_file(audit_path)})
    manifest = {
        "format": "legal-workbench-export-v1",
        "case_id": case_id,
        "case_title": case["title"],
        "created_at": utc_now(),
        "warning": "사용자 검토용. 서명·납부·제출은 사용자가 직접 수행해야 함.",
        "audited_snapshot_sha256": current_snapshot["sha256"],
        "v1_certification": certification,
        "files": files,
    }
    manifest_path = export_dir / "manifest.json"
    atomic_json_write(manifest_path, manifest)
    store.transition(CaseStage.RELEASED, reason="감사 통과 패키지 사용자 배포")
    return export_dir


def _require_stage(store: CaseStore, allowed: set[CaseStage], action: str) -> None:
    current = CaseStage(store.get_case()["stage"])
    if current not in allowed:
        names = ", ".join(str(item) for item in sorted(allowed, key=lambda item: list(CaseStage).index(item)))
        raise ValueError(f"{action}은 {names} 단계에서만 가능합니다. 현재: {current}")


def _capture_authority_text(
    store: CaseStore,
    authority_id: str,
    value: Any,
    label: str,
) -> tuple[str, str]:
    if not value:
        raise ValueError(f"P1 근거에는 {label}_text_file이 필요합니다.")
    source = Path(str(value)).expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(f"P1 {label} 원문 파일을 찾을 수 없습니다: {source}")
    destination = (store.case_dir / "authorities" / f"{authority_id}.{label}.txt").resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source != destination:
        shutil.copy2(source, destination)
    return str(destination), sha256_file(destination)


def _authority_text_files_match(item: dict[str, Any]) -> bool:
    source = Path(str(item.get("source_text_path") or ""))
    verification = Path(str(item.get("verification_text_path") or ""))
    return (
        source.is_file()
        and verification.is_file()
        and sha256_file(source) == item.get("text_sha256")
        and sha256_file(verification) == item.get("verification_text_sha256")
    )


def _validated_analysis_result(store: CaseStore, value: Any, role: str) -> tuple[str, str]:
    if not value:
        raise ValueError(f"{role} 분석 결과 참조가 필요합니다.")
    path = Path(str(value)).expanduser().resolve()
    bundles_dir = (store.case_dir / "bundles").resolve()
    if not is_within(path, bundles_dir) or not path.is_file():
        raise ValueError(f"{role} 분석 결과는 사건 bundles 안의 실제 파일이어야 합니다.")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("format") != "legal-workbench-analysis-result-v1":
        raise ValueError(f"{role} 분석 결과 형식이 올바르지 않습니다.")
    if payload.get("case_id") != store.case_id or payload.get("role") != f"{role}-analysis-result":
        raise ValueError(f"{role} 분석 결과의 사건 또는 역할이 일치하지 않습니다.")
    return str(path), sha256_file(path)


def _draft_markdown(store: CaseStore, case: dict[str, Any], opinion: dict[str, Any], document_type: str) -> str:
    facts = store.list_payloads("facts")
    issues = store.list_payloads("issues")
    authorities = store.list_payloads("authorities")
    deadlines = store.list_payloads("deadlines")
    lines = [
        f"# {document_type}",
        "",
        "> 사용자 검토용 초안이다. 실제 제출·발송 완료 문서가 아니다.",
        "",
        "## 사건 및 판단 상태",
        f"사건: {case['title']}",
        f"관할: {case['jurisdiction']} / {case.get('forum') or '확인 필요'}",
        f"행위일: {case.get('action_date') or '확인 필요'}",
        f"판단 기준일: {case['as_of_date']}",
        f"의견 상태: {opinion['status']}",
        "",
        "## 결론",
        opinion["conclusion"],
        "",
        "## 사실관계",
    ]
    for item in facts:
        lines.append(f"- [{item['fact_id']}] ({item['status']}) {item['text']} / 증거: {', '.join(item.get('evidence_ids') or ['없음'])}")
    lines.extend(["", "## 핵심 쟁점"])
    for item in issues:
        lines.append(f"- [{item['issue_id']}] {item['title']} / 입증책임: {item['burden']}")
    lines.extend(["", "## 양측 시나리오", f"- 유리: {opinion['favorable_scenario']}", f"- 경합: {opinion['contested_scenario']}", f"- 불리: {opinion['adverse_scenario']}"])
    lines.extend(["", "## 확인된 법적 근거"])
    for item in authorities:
        lines.append(f"- [{item['authority_id']}] {item['citation']} | {item['source_tier']} | {item['official_url']}")
    lines.extend(["", "## 기한"])
    for item in deadlines:
        lines.append(f"- [{item['deadline_id']}] {item['title']}: {item.get('tentative_due_date') or '확인 필요'} / 검증={item.get('verified', False)}")
    lines.extend(["", "## 결론을 바꿀 수 있는 사항"])
    for item in opinion.get("changes_outcome_if") or ["핵심 사실 또는 공식 원문 추가 확인 필요"]:
        lines.append(f"- {item}")
    return "\n".join(lines).strip() + "\n"


def _load_entities(path: Path | None) -> dict[str, list[str]]:
    if path is None:
        return {}
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("entities JSON은 {category: [values]} 형식이어야 합니다.")
    result: dict[str, list[str]] = {}
    for key, value in payload.items():
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError("entities JSON 값은 문자열 배열이어야 합니다.")
        result[str(key)] = value
    return result


def _validate_iso_date(value: str | None, *, allow_none: bool = False) -> None:
    if value is None and allow_none:
        return
    if value is None:
        raise ValueError("날짜가 필요합니다.")
    date.fromisoformat(value)

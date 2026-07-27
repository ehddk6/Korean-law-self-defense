from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4


class CaseStage(StrEnum):
    INTAKE = "intake"
    SAFETY_CHECKED = "safety_checked"
    INGESTED = "ingested"
    FACTS_FIXED = "facts_fixed"
    ISSUES_MAPPED = "issues_mapped"
    RESEARCHED = "researched"
    INDEPENDENTLY_ANALYZED = "independently_analyzed"
    DRAFTED = "drafted"
    AUDITED = "audited"
    RELEASED = "released"


STAGE_ORDER = tuple(CaseStage)


class RiskLevel(StrEnum):
    ROUTINE = "routine"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class FactStatus(StrEnum):
    CONFIRMED = "confirmed"
    OPPONENT_ALLEGATION = "opponent_allegation"
    DISPUTED = "disputed"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class SourceTier(StrEnum):
    P1 = "P1"
    P2 = "P2"
    S = "S"
    U = "U"


class OpinionStatus(StrEnum):
    READY = "ready"
    CONDITIONAL = "conditional"
    ABSTAIN = "abstain"


class Severity(StrEnum):
    CRITICAL = "critical"
    MAJOR = "major"
    MINOR = "minor"


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:16]}"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(slots=True)
class CaseRecord:
    case_id: str
    title: str
    domain: str
    jurisdiction: str = "대한민국"
    forum: str | None = None
    goal: str = ""
    action_date: str | None = None
    as_of_date: str = field(default_factory=lambda: date.today().isoformat())
    risk_level: RiskLevel = RiskLevel.ROUTINE
    stage: CaseStage = CaseStage.INTAKE
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class FactRecord:
    fact_id: str
    text: str
    status: FactStatus
    evidence_ids: list[str] = field(default_factory=list)
    occurred_at: str | None = None
    actor_token: str | None = None
    confidence: str = "unknown"
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class EvidenceRecord:
    evidence_id: str
    document_id: str
    sha256: str
    source_path_token: str
    acquired_at: str
    provenance: str
    page_or_paragraph: str | None = None
    authenticity_issue: str | None = None
    probative_issue: str | None = None
    extraction_confidence: float | None = None
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AuthorityRecord:
    authority_id: str
    title: str
    source_tier: SourceTier
    official_url: str
    retrieved_at: str
    text_sha256: str
    citation: str
    effective_from: str | None = None
    effective_to: str | None = None
    court: str | None = None
    case_number: str | None = None
    decision_date: str | None = None
    verification_url: str | None = None
    verified_at: str | None = None
    source_text_path: str | None = None
    verification_text_path: str | None = None
    verification_text_sha256: str | None = None
    mcp_server: str | None = None
    mcp_version: str | None = None
    mcp_tool: str | None = None
    mcp_verified_at: str | None = None
    negative_search_only: bool = False
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class IssueRecord:
    issue_id: str
    title: str
    legal_elements: list[str]
    burden: str
    favorable_authority_ids: list[str] = field(default_factory=list)
    adverse_authority_ids: list[str] = field(default_factory=list)
    fact_ids: list[str] = field(default_factory=list)
    missing_facts: list[str] = field(default_factory=list)
    remedies: list[str] = field(default_factory=list)
    provisional_view: str = "abstain"
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DeadlineRecord:
    deadline_id: str
    title: str
    trigger_event: str | None
    trigger_date: str | None
    governing_rule: str | None
    authority_id: str | None
    calculation: str | None
    tentative_due_date: str | None
    holiday_adjustment: str | None = None
    duration_value: int | None = None
    duration_unit: str | None = None
    holiday_adjustment_days: int = 0
    verification_url: str | None = None
    verified_at: str | None = None
    verified: bool = False
    critical: bool = False
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class OpinionRecord:
    opinion_id: str
    status: OpinionStatus
    conclusion: str
    assumptions: list[str]
    favorable_scenario: str
    contested_scenario: str
    adverse_scenario: str
    fact_ids: list[str]
    authority_ids: list[str]
    issue_ids: list[str]
    changes_outcome_if: list[str]
    source_coverage: str
    primary_analysis_ref: str | None = None
    primary_analysis_sha256: str | None = None
    independent_analysis_ref: str | None = None
    independent_analysis_sha256: str | None = None
    applicable_law_verified: bool = False
    adverse_authority_reviewed: bool = False
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AuditFinding:
    finding_id: str
    severity: Severity
    code: str
    message: str
    record_type: str | None = None
    record_id: str | None = None
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AuditReport:
    audit_id: str
    case_id: str
    passed: bool
    release_allowed: bool
    findings: list[AuditFinding]
    checks: dict[str, Any]
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["findings"] = [finding.to_dict() for finding in self.findings]
        return result

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .models import new_id, utc_now
from .security import atomic_json_write
from .workflow import store_for


@dataclass(slots=True)
class PleadingNode:
    claim_type: str  # primary, contingent, concurrent
    legal_basis: str
    required_facts: list[str]
    matched_evidence_score: float


@dataclass(slots=True)
class PleadingStrategyRecord:
    strategy_id: str
    case_id: str
    primary_claim: PleadingNode
    contingent_claims: list[PleadingNode]
    recommendation: str
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_pleading_strategy(case_id: str, worksets_home: Path | None = None) -> dict[str, Any]:
    store = store_for(case_id, worksets_home)
    issues = store.list_payloads("issues")
    authorities = store.list_payloads("authorities")
    facts = store.list_payloads("facts")
    evidence = store.list_payloads("evidence")

    if not issues:
        raise ValueError("청구원인 전략 구성에는 쟁점 레코드가 필요합니다.")

    authority_by_id = {a["authority_id"]: a for a in authorities}
    evidence_by_id = {e["evidence_id"]: e for e in evidence}
    fact_by_id = {f["fact_id"]: f for f in facts}

    nodes: list[PleadingNode] = []
    for issue in issues:
        remedies = [str(item) for item in (issue.get("remedies") or []) if str(item).strip()]
        favorable = issue.get("favorable_authority_ids") or []
        legal_basis = _legal_basis_for(issue, authority_by_id)
        required_facts = [f["text"] for f in facts if f["fact_id"] in (issue.get("fact_ids") or [])]
        score = _evidence_score_for(issue, fact_by_id, evidence_by_id)
        if not remedies:
            remedies = ["구제수단 확인 필요"]
        for remedy in remedies:
            nodes.append(
                PleadingNode(
                    claim_type="primary" if len(nodes) == 0 else "contingent",
                    legal_basis=f"{remedy} - {legal_basis}" if legal_basis else f"{remedy} - 법적 근거 확인 필요",
                    required_facts=required_facts,
                    matched_evidence_score=score,
                )
            )

    if not nodes:
        return {
            "strategy_id": "abstain",
            "recommendation": "판단보류: 청구원인을 구성할 쟁점·구제수단이 저장되어 있지 않습니다.",
            "contingent_claims": [],
        }

    primary = nodes[0]
    contingent = nodes[1:]
    recommendation = _recommendation(primary, contingent)

    record = PleadingStrategyRecord(
        strategy_id=new_id("pl"),
        case_id=case_id,
        primary_claim=primary,
        contingent_claims=contingent,
        recommendation=recommendation,
    )

    strat_dir = store.case_dir / "pleading_strategies"
    strat_dir.mkdir(parents=True, exist_ok=True)
    atomic_json_write(strat_dir / f"{record.strategy_id}.json", record.to_dict())
    store.add_pleading_strategy(record)
    return {"strategy_id": record.strategy_id, "recommendation": recommendation}


def _legal_basis_for(issue: dict[str, Any], authority_by_id: dict[str, dict[str, Any]]) -> str:
    citations: list[str] = []
    for aid in issue.get("favorable_authority_ids") or []:
        authority = authority_by_id.get(aid)
        if authority:
            citation = str(authority.get("citation") or "").strip()
            if citation:
                citations.append(citation)
    if citations:
        return ", ".join(citations)
    return ""


def _evidence_score_for(
    issue: dict[str, Any],
    fact_by_id: dict[str, dict[str, Any]],
    evidence_by_id: dict[str, dict[str, Any]],
) -> float:
    linked_evidence: list[str] = []
    for fid in issue.get("fact_ids") or []:
        fact = fact_by_id.get(fid)
        if fact:
            linked_evidence.extend(fact.get("evidence_ids") or [])
    if not linked_evidence:
        return 0.0
    strong = sum(
        1
        for eid in linked_evidence
        if (e := evidence_by_id.get(eid)) and (e.get("extraction_confidence") or 0) >= 0.8
    )
    return round(strong / len(linked_evidence), 2)


def _recommendation(primary: PleadingNode, contingent: list[PleadingNode]) -> str:
    if primary.matched_evidence_score < 0.4 and contingent:
        best = max(contingent, key=lambda item: item.matched_evidence_score)
        return (
            f"현재 주위적 청구({primary.legal_basis})의 증거 매칭률({primary.matched_evidence_score * 100:.0f}%)이 낮습니다. "
            f"법원이 주위적 청구를 기각할 가능성이 있으므로, 예비적 청구({best.legal_basis})의 증거 매칭률"
            f"({best.matched_evidence_score * 100:.0f}%)을 확인하고 소장에 예비적 청구 병기를 검토하십시오."
        )
    if primary.matched_evidence_score >= 0.4:
        return (
            f"주위적 청구({primary.legal_basis})의 증거 매칭률({primary.matched_evidence_score * 100:.0f}%)이 충분합니다. "
            "다만 패소 대비 예비적 청구 병기 여부는 법원의 심리와 별개로 증거 보강을 병행하십시오."
        )
    return (
        "판단보류: 청구원인을 뒷받침할 검증된 법적 근거와 증거가 저장되어 있지 않습니다. "
        "쟁점·근거·증거를 먼저 확보한 뒤 다시 실행하십시오."
    )

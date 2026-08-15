from __future__ import annotations

from pathlib import Path
from typing import Any

from .audit import authority_is_verified_p1
from .models import CaseStage, TrialVerdict, VirtualTrialRecord, new_id, utc_now
from .security import atomic_json_write
from .workflow import store_for

_RUNNABLE_STAGES = {
    CaseStage.RESEARCHED,
    CaseStage.INDEPENDENTLY_ANALYZED,
    CaseStage.DRAFTED,
    CaseStage.AUDITED,
    CaseStage.RELEASED,
}


def run_virtual_trial(
    case_id: str,
    *,
    worksets_home: Path | None = None,
) -> dict[str, Any]:
    store = store_for(case_id, worksets_home)
    case = store.get_case()

    if CaseStage(case["stage"]) not in _RUNNABLE_STAGES:
        raise ValueError("가상 재판은 법률조사(RESEARCHED) 이후 단계에서만 실행할 수 있습니다.")

    facts = store.list_payloads("facts")
    issues = store.list_payloads("issues")
    authorities = store.list_payloads("authorities")
    evidence = store.list_payloads("evidence")

    if not issues:
        raise ValueError("가상 재판을 위한 쟁점 레코드가 없습니다.")
    if not authorities:
        raise ValueError("가상 재판을 위한 법적 근거 레코드가 없습니다.")

    plaintiff_arg = _simulate_plaintiff_counsel(facts, issues, authorities)
    defense_arg = _simulate_defense_counsel(facts, issues, authorities)
    judge_finding = _simulate_judge_fact_finding(facts, evidence)
    verdict, winning_prob, judge_reasoning = _simulate_judge_reasoning(
        issues, judge_finding, authorities
    )
    mock_judgment_md = _draft_mock_judgment(
        case,
        plaintiff_arg,
        defense_arg,
        issues,
        judge_finding,
        judge_reasoning,
        verdict,
        winning_prob,
    )

    trial_id = new_id("vt")
    trial_dir = store.case_dir / "virtual_trials"
    trial_dir.mkdir(parents=True, exist_ok=True)

    md_path = trial_dir / f"{trial_id}-mock-judgment.md"
    md_path.write_text(mock_judgment_md, encoding="utf-8", newline="\n")

    record = VirtualTrialRecord(
        trial_id=trial_id,
        case_id=case_id,
        plaintiff_counsel_argument=plaintiff_arg,
        defense_counsel_argument=defense_arg,
        judge_fact_finding=judge_finding,
        judge_reasoning=judge_reasoning,
        verdict=verdict,
        winning_probability=winning_prob,
        evidence_strength_score=_calculate_evidence_strength(evidence),
        mock_judgment_ref=str(md_path),
    )

    payload_path = trial_dir / f"{trial_id}-result.json"
    atomic_json_write(payload_path, record.to_dict())

    store.add_virtual_trial(record)

    return {
        "trial_id": trial_id,
        "verdict": str(verdict),
        "winning_probability": winning_prob,
        "mock_judgment_path": str(md_path),
        "evidence_strength_score": record.evidence_strength_score,
    }


def _simulate_plaintiff_counsel(
    facts: list[dict[str, Any]], issues: list[dict[str, Any]], authorities: list[dict[str, Any]]
) -> str:
    args: list[str] = []
    auth_map = {a["authority_id"]: a for a in authorities}
    for idx, issue in enumerate(issues, 1):
        title = issue.get("title", f"쟁점 {idx}")
        favorable = issue.get("favorable_authority_ids") or []
        fav_citations = [auth_map[aid].get("citation", aid) for aid in favorable if aid in auth_map]
        args.append(f"1. {title}에 관하여")
        if fav_citations:
            args.append(
                f"   원고는 {', '.join(fav_citations)} 등의 공식 근거를 바탕으로 권리가 성립함을 주장합니다."
            )
        else:
            args.append("   원고 주장에 부합하는 법리가 적용됨을 주장합니다.")
        if not (issue.get("missing_facts") or []):
            args.append("   원고는 입증책임을 다하기 위한 요건사실을 소명하였습니다.")
    return "\n".join(args) if args else "원고 주장 구성을 위한 자료가 부족합니다."


def _simulate_defense_counsel(
    facts: list[dict[str, Any]], issues: list[dict[str, Any]], authorities: list[dict[str, Any]]
) -> str:
    args: list[str] = []
    auth_map = {a["authority_id"]: a for a in authorities}
    for idx, issue in enumerate(issues, 1):
        title = issue.get("title", f"쟁점 {idx}")
        missing = issue.get("missing_facts") or []
        adverse = issue.get("adverse_authority_ids") or []
        adv_citations = [auth_map[aid].get("citation", aid) for aid in adverse if aid in auth_map]

        args.append(f"1. {title}에 대한 다툼")
        if missing:
            args.append(
                f"   피고는 원고가 다음 핵심 요건사실(입증책임)을 입증하지 못했다고 반박합니다: {', '.join(missing)}"
            )
        if adv_citations:
            args.append(
                f"   또한 {', '.join(adv_citations)} 등의 근거에 따라 원고의 청구는 기각되어야 합니다."
            )
    return "\n".join(args) if args else "피고 방어 구성을 위한 자료가 부족합니다."


def _simulate_judge_fact_finding(
    facts: list[dict[str, Any]], evidence: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    evidence_by_id = {e.get("evidence_id"): e for e in evidence}
    for fact in facts:
        ev_ids = fact.get("evidence_ids") or []
        strong = [
            eid
            for eid in ev_ids
            if (e := evidence_by_id.get(eid)) and (e.get("extraction_confidence") or 0) >= 0.8
        ]
        findings.append(
            {
                "fact_text": fact["text"],
                "recognition": (
                    "인정됨 (증거에 의해 확인됨)" if strong else "증거 부족으로 인정하지 않음 (단순 주장에 그침)"
                ),
                "basis_evidence": strong if strong else ev_ids,
            }
        )
    return findings


def _simulate_judge_reasoning(
    issues: list[dict[str, Any]],
    fact_finding: list[dict[str, Any]],
    authorities: list[dict[str, Any]],
) -> tuple[TrialVerdict, str, str]:
    recognized_count = sum(1 for f in fact_finding if "인정됨" in f["recognition"])
    total_count = len(fact_finding)
    authority_by_id = {a["authority_id"]: a for a in authorities}

    referenced_favorable: list[str] = []
    referenced_adverse: list[str] = []
    for issue in issues:
        referenced_favorable.extend(issue.get("favorable_authority_ids") or [])
        referenced_adverse.extend(issue.get("adverse_authority_ids") or [])

    verified_favorable_p1 = any(
        (a := authority_by_id.get(aid))
        and authority_is_verified_p1(a)
        and a.get("citation")
        for aid in referenced_favorable
    )
    verified_adverse_p1 = any(
        (a := authority_by_id.get(aid))
        and authority_is_verified_p1(a)
        and a.get("citation")
        for aid in referenced_adverse
    )

    if total_count == 0:
        return (
            TrialVerdict.ABSTAIN,
            "판단보류 (사실관계 미확정)",
            "인정할 사실관계가 부족하여 판단을 보류한다.",
        )

    recognition_ratio = recognized_count / total_count

    if recognition_ratio >= 0.7 and verified_favorable_p1 and not verified_adverse_p1:
        return (
            TrialVerdict.FAVORABLE,
            "높음 (법률요건 충족 및 압도적 증거)",
            "원고(본인)가 주장하는 핵심 사실이 증거에 의해 충분히 인정되며, 이를 뒷받침하는 공식 P1 근거가 확인되고 반박할 만한 불리한 근거가 없으므로 청구가 인용될 가능성이 매우 높다.",
        )
    if recognition_ratio >= 0.4 and verified_favorable_p1:
        return (
            TrialVerdict.PARTIAL,
            "보통 (일부 사실 입증, 그러나 반대 근거 존재)",
            "주장 중 일부는 인정되나, 나머지 쟁점에 대하여는 증거가 부족하거나 상대방의 반론(불리한 P1 근거)이 타당할 여지가 있어 일부 인용 또는 상계 처리될 가능성이 있다.",
        )
    return (
        TrialVerdict.UNFAVORABLE,
        "낮음 (입증책임 미달)",
        "핵심적인 법률요건 사실에 대하여 이를 인정할 만한 증거가 부족하거나, 불리한 근거가 존재하여 청구가 기각될 가능성이 높다.",
    )


def _calculate_evidence_strength(evidence: list[dict[str, Any]]) -> float:
    if not evidence:
        return 0.0
    strong = sum(1 for e in evidence if (e.get("extraction_confidence") or 0) >= 0.8)
    return round((strong / len(evidence)) * 100, 2)


def _draft_mock_judgment(
    case: dict[str, Any],
    p_arg: str,
    d_arg: str,
    issues: list[dict[str, Any]],
    fact_finding: list[dict[str, Any]],
    reasoning: str,
    verdict: TrialVerdict,
    prob: str,
) -> str:
    md = [
        f"# 모의 판결문 (가상 재판) - {case['title']}",
        "",
        "> **경계 (Safety Notice):** 이 문서는 AI 워크벤치가 변호사·판사의 사고 프로세스를 재현하여 생성한 **소송 준비용 모의 판결문**입니다.",
        "> 변호사법 제109조에 따라 비변호사의 법률사무 취급 및 확정적 법률자문은 금지되므로, 본 문서는 실제 법원의 효력을 갖는 판결문이 아니며 본인 사건의 쟁점 분석 및 증거 보강을 위한 시뮬레이션 결과입니다.",
        "",
        "## 【 당사자의 주장 】",
        "### 1. 원고(신청인) 측 변호사의 주장",
        p_arg,
        "",
        "### 2. 피고(상대방) 측 변호사의 반론",
        d_arg,
        "",
        "## 【 쟁점의 정리 】",
        *[f"- {i.get('title')} (입증책임: {i.get('burden', '미상')})" for i in issues],
        "",
        "## 【 사실의 인정 】",
        *[f"- {f['fact_text']} **({f['recognition']})**" for f in fact_finding],
        "",
        "## 【 재판부의 판단 (이유) 】",
        reasoning,
        "",
        "## 【 결론 (주문) 】",
        f"- **승소 가능성 평가:** {prob}",
        f"- **최종 가상 판결:** {verdict.value}",
        "",
        "---",
        "### 💡 변호사 대체 준비를 위한 액션 플랜 (Action Plan)",
        "- **낮음/보통으로 나온 경우:** 위 '증거 부족으로 인정하지 않음'으로 표시된 사실에 대해 추가적인 서증(문서), 인적 증거(증인), 또는 감정 신청이 필요한지 즉시 검토하십시오.",
        "- **피고 측 반론 대응:** 피고 측 변호사 시뮬레이션에서 제기된 반대 근거에 대한 구별(distinguishing) 논리를 준비서면에 미리 담으십시오.",
    ]
    return "\n".join(md).strip()

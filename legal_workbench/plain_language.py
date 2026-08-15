from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .documents import create_docx, create_hwpx, create_pdf
from .security import scan_prompt_injection, scan_residual_pii
from .services import service_catalog_for_case
from .workflow import store_for


def build_plain_language_guide(
    case_id: str,
    *,
    formats: list[str],
    worksets_home: Path | None = None,
) -> dict[str, Path]:
    """Create a non-technical case guide from the sanitized case record."""
    store = store_for(case_id, worksets_home)
    case = store.get_case()
    facts = store.list_payloads("facts")
    issues = store.list_payloads("issues")
    deadlines = store.list_payloads("deadlines")
    opinions = store.list_payloads("opinions")
    guide = _guide_markdown(
        case=case,
        facts=facts,
        issues=issues,
        deadlines=deadlines,
        opinion=opinions[-1] if opinions else None,
        services=service_catalog_for_case(case_id, worksets_home=worksets_home),
    )
    if scan_residual_pii(guide):
        raise PermissionError("쉬운 설명서에 비식별되지 않은 개인정보 패턴이 남아 있습니다.")
    if scan_prompt_injection(guide):
        raise PermissionError("쉬운 설명서에 실행 지시 형태의 텍스트가 남아 있습니다.")
    destination_dir = store.case_dir / "guides"
    destination_dir.mkdir(parents=True, exist_ok=True)
    base = destination_dir / "plain-language-guide"
    paths: dict[str, Path] = {}
    md_path = base.with_suffix(".md")
    md_path.write_text(guide, encoding="utf-8", newline="\n")
    paths["md"] = md_path
    for fmt in formats:
        normalized = fmt.lower()
        if normalized == "docx":
            paths["docx"] = create_docx(guide, base.with_suffix(".docx"), title="쉬운 사건 안내서")
        elif normalized == "pdf":
            paths["pdf"] = create_pdf(guide, base.with_suffix(".pdf"), title="쉬운 사건 안내서")
        elif normalized == "hwpx":
            paths["hwpx"] = create_hwpx(guide, base.with_suffix(".hwpx"), title="쉬운 사건 안내서")
        elif normalized != "md":
            raise ValueError(f"지원하지 않는 출력 형식: {fmt}")
    return paths


def _guide_markdown(
    *,
    case: dict[str, Any],
    facts: list[dict[str, Any]],
    issues: list[dict[str, Any]],
    deadlines: list[dict[str, Any]],
    opinion: dict[str, Any] | None,
    services: list[dict[str, Any]],
) -> str:
    direct_services = [item for item in services if item["case_fit"] == "direct"]
    other_services = [item for item in services if item["case_fit"] != "direct"]
    lines = [
        "# 쉬운 사건 안내서",
        "",
        "> 이 문서는 어려운 법률 용어를 줄여 사건을 이해하고 준비할 일을 정리한 가상 사례용 안내서입니다.",
        "",
        "## 한눈에 보는 결론",
        _plain_conclusion(opinion),
        "",
        "## 지금 어떤 상황인가요?",
        f"이 사건은 ‘{case['title']}’에 관한 가상 사례입니다.",
        "쉽게 말하면, 세입자는 계약이 끝났으니 보증금을 돌려달라고 하고, 집주인은 열쇠·집 상태·수리비를 먼저 따져야 한다고 말하는 상황입니다.",
        "",
        "## 확인된 이야기",
    ]
    for fact in facts:
        confidence = "확인 자료가 비교적 충분함" if fact.get("confidence") == "high" else "자료의 원본·세부 내용은 더 확인할 필요가 있음"
        lines.append(f"- {fact['text']} ({confidence})")
    lines.extend(["", "## 왜 바로 끝났다고 말할 수 없나요?"])
    if issues:
        for issue in issues:
            lines.append(f"### {issue['title']}")
            lines.append(_issue_in_plain_words(issue))
            if issue.get("missing_facts"):
                lines.append("아직 확인할 것:")
                for item in issue["missing_facts"]:
                    lines.append(f"- {item}")
    else:
        lines.append("쟁점이 아직 정리되지 않았습니다. 계약서와 대화 내용부터 분류해야 합니다.")
    lines.extend(["", "## 지금 먼저 챙길 것"])
    for item in _priority_actions(issues, opinion):
        lines.append(f"- {item}")
    lines.extend(["", "## 상대방이 할 수 있는 말과 답할 때 볼 자료"])
    if opinion:
        lines.append(f"- 상대방 주장의 핵심: {opinion.get('adverse_scenario') or '확인 필요'}")
        lines.append(f"- 내 쪽에서 유리해질 수 있는 점: {opinion.get('favorable_scenario') or '확인 필요'}")
    else:
        lines.append("양쪽 주장을 비교하려면 공식 근거와 사건 사실을 먼저 정리해야 합니다.")
    lines.extend(["", "## 날짜와 기한"])
    if deadlines:
        for deadline in deadlines:
            label = "법정 기한" if deadline.get("critical") else "자료 정리용 일정"
            lines.append(
                f"- {deadline['title']}: {deadline.get('tentative_due_date') or '확인 필요'} ({label}). "
                f"{deadline.get('governing_rule') or ''}"
            )
    else:
        lines.append("현재 저장된 기한이 없습니다. 법원·기관 문서를 받았다면 송달일을 먼저 확인해야 합니다.")
    lines.extend(
        [
            "",
            "## 이 프로젝트가 해 줄 수 있는 일",
            "이 프로젝트는 원본을 비식별 처리하고, 사실·증거·공식 근거를 연결한 뒤 양쪽 주장을 따로 검토하고 문서를 초안으로 만드는 도구입니다.",
            "실제 제출, 서명, 결제, 상대방 연락, 법원 출석은 대신하지 않습니다.",
            "",
            "### 이 임대차 사건에서 바로 설계할 수 있는 업무",
        ]
    )
    for service in direct_services:
        lines.append(f"- {service['label']}: {service['purpose']}")
    lines.extend(["", "### 프로젝트가 지원하지만 이 사건에는 다른 사실이 필요한 업무"])
    for service in other_services:
        lines.append(f"- {service['label']}: {service['purpose']}")
    lines.extend(
        [
            "",
            "## 꼭 기억할 점",
            "이 안내서는 가상 사건을 설명하기 위한 자료입니다. 실제 사건에서는 계약서 원본, 계좌이체 자료, 문자·내용증명 원본, 사진·동영상 원본, 열쇠 전달 자료를 다시 확인해야 합니다.",
            "결정하기 전에 최신 공식 법령과 실제 사실관계를 확인하고, 필요하면 변호사·법률구조기관의 도움을 받으세요.",
        ]
    )
    return "\n".join(lines).strip() + "\n"


def _plain_conclusion(opinion: dict[str, Any] | None) -> str:
    if not opinion:
        return "아직 공식 근거와 양쪽 주장이 충분히 정리되지 않아 결론을 내리지 않습니다."
    if str(opinion.get("status") or "") == "abstain":
        return "지금 있는 자료만으로는 결론을 정하기 어렵습니다. 계약서와 핵심 자료를 더 확인해야 합니다."
    return (
        "보증금을 돌려달라고 요구할 방향은 있습니다. 다만 집을 비웠고 열쇠를 돌려주려 했다는 자료를 더 분명히 남기고, "
        "집주인이 빼겠다는 수리비에는 구체적인 근거가 있는지 따져봐야 합니다."
    )


def _issue_in_plain_words(issue: dict[str, Any]) -> str:
    title = str(issue.get("title") or "")
    if "인도" in title or "보증금" in title:
        return "보증금을 받으려면 계약이 끝났다는 점뿐 아니라, 집을 돌려줬거나 돌려주겠다고 제대로 제안했다는 자료도 중요합니다."
    if "수리" in title or "공제" in title:
        return "집주인이 수리비를 빼겠다고 하면, 정말 수리가 필요한지, 누가 원인을 만들었는지, 금액이 적절한지를 따져야 합니다."
    return "이 쟁점은 계약서, 사실관계, 증거와 공식 근거를 함께 비교해 판단해야 합니다."


def _priority_actions(issues: list[dict[str, Any]], opinion: dict[str, Any] | None) -> list[str]:
    actions: list[str] = [
        "계약서 원본의 보증금 반환·열쇠 전달·수리비 관련 특약을 따로 표시해 두기",
        "보증금 이체확인증, 내용증명 수령조회, 문자 대화의 원본 파일을 날짜 순서대로 보관하기",
        "집 상태 사진·동영상은 원본 파일과 촬영일 정보가 남도록 보관하기",
        "열쇠 전달을 제안한 내용과 상대방의 답변을 한 화면에 보이도록 정리하기",
    ]
    if any(item.get("missing_facts") for item in issues):
        actions.append("확인되지 않은 사실은 추측으로 채우지 말고 ‘아직 모름’으로 표시한 뒤 자료로 확인하기")
    if opinion and opinion.get("changes_outcome_if"):
        actions.append("결론을 바꿀 수 있는 자료는 가장 먼저 찾아 원본과 함께 보관하기")
    return actions

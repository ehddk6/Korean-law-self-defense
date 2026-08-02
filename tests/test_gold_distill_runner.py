from __future__ import annotations

import pytest

from legal_workbench.gold_distill_runner import (
    _fixture_evidence_candidates,
    _validate_case_distillation,
)


def test_fixture_evidence_candidates_use_record_only() -> None:
    fixture = {
        "format": "legal-workbench-masked-decision-input-v1",
        "task": "결론이 제거된 기록을 분석하라.",
        "record": (
            "채무자는 변제계획에 따라 매월 변제액을 납부하였다. "
            "채권자는 일부 납입이 지체되었다고 주장하였다. "
            "법원은 변제계획 수행 가능성과 지체 경위를 함께 심리한다. "
            "채무자는 납입 내역과 소득 자료를 제출하였다. "
            "채권자는 향후 납입 가능성이 불확실하다고 다투었다."
        ),
        "output_contract": {"outcome": "ready|conditional|abstain"},
    }

    candidates = _fixture_evidence_candidates(fixture)

    assert len(candidates) >= 5
    assert all(value in fixture["record"] for value in candidates.values())
    assert all("legal-workbench" not in value for value in candidates.values())
    assert all("ready|conditional" not in value for value in candidates.values())


def test_validate_case_distillation_rejects_access_failure_placeholder() -> None:
    excerpt = "채무자는 변제계획에 따라 매월 변제액을 납부하였다."
    fixture = {"record": excerpt}
    value = {
        "issues": [
            {"text": "작업공간 파일 접근 오류로 쟁점을 확인하지 못했다.", "evidence_excerpt": excerpt},
            {"text": "변제계획 이행 여부가 문제된다.", "evidence_excerpt": excerpt},
            {"text": "납입 지체 경위를 확인해야 한다.", "evidence_excerpt": excerpt},
        ],
        "adverse_points": [
            {"text": "일부 납입이 지체되었다.", "evidence_excerpt": excerpt},
            {"text": "향후 납입 가능성이 다투어진다.", "evidence_excerpt": excerpt},
        ],
    }

    with pytest.raises(ValueError, match="fixture로 추적되지"):
        _validate_case_distillation(value, fixture)

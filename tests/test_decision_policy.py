from __future__ import annotations

import pytest

from legal_workbench.curation import TEMPORAL_SPECS
from legal_workbench.decision_policy import ADVERSARIAL_POLICY, normalize_evaluation_answer, temporal_policy


@pytest.mark.parametrize(
    ("kind", "spec"),
    [(kind, spec) for kind, entries in TEMPORAL_SPECS.items() for spec in entries],
)
def test_temporal_policy_matches_public_rule_contract(kind: str, spec: dict[str, object]) -> None:
    fixture = {
        "kind": kind,
        "facts": spec["facts"],
        "official_rule": {"article": spec["article"]},
    }

    status, rule_answer, deadline_date = temporal_policy(kind, fixture)

    assert status == spec["status"]
    assert rule_answer == spec["rule_answer"]
    assert deadline_date == spec.get("deadline_date")


@pytest.mark.parametrize("kind", sorted(ADVERSARIAL_POLICY))
def test_adversarial_policy_never_returns_ready_or_high(kind: str) -> None:
    answer = {
        "decision_status": "ready",
        "required_action": None,
        "rule_answer": "invented",
        "deadline_date": "2099-01-01",
        "confidence": "high",
        "outcome": "granted",
    }

    normalized, report = normalize_evaluation_answer(answer, {"kind": kind}, {})

    expected_status, expected_action, expected_confidence = ADVERSARIAL_POLICY[kind]
    assert normalized["decision_status"] == expected_status
    assert normalized["required_action"] == expected_action
    assert normalized["confidence"] == expected_confidence
    assert normalized["outcome"] is None
    assert normalized["issues"]
    assert normalized["adverse_points"]
    assert report["expected_answer_used"] is False


def test_conflicting_evidence_adds_fixture_bound_trace_fact() -> None:
    fixture = {"statements": [{"source": "A", "claim": "계약일은 2025-01-10이다."}]}
    normalized, _ = normalize_evaluation_answer(
        {"decision_status": "ready", "confidence": "high"},
        {"kind": "conflicting-evidence"},
        fixture,
    )
    assert normalized["supported_facts"][0]["evidence_excerpt"] == fixture["statements"][0]["claim"]


def test_masked_decision_is_always_conditional_and_not_high_confidence() -> None:
    normalized, _ = normalize_evaluation_answer(
        {"decision_status": "ready", "confidence": "high", "outcome": "affirmed"},
        {"kind": "masked-official-decision"},
        {},
    )
    assert normalized["decision_status"] == "conditional"
    assert normalized["confidence"] == "medium"
    assert normalized["outcome"] == "affirmed"

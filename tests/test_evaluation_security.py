from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import legal_workbench.evaluation_runner as evaluation_runner
from legal_workbench.evaluation import (
    CERTIFICATION_FORMAT,
    THRESHOLDS,
    _certification_code_hashes,
    _locked_batch_size,
    certification_status,
    load_manifest,
    write_manifest,
    _semantic_recall,
)
from legal_workbench.evaluation_runner import (
    AGENT_EXECUTION_BACKEND,
    CODEX_EXECUTION_BACKEND,
    _codex_failure_summary,
    _evaluation_config_hash,
    _redact_fixture,
    _guard_answer,
    _sanitize_answer_pii,
    _sanitized_codex_env,
    _validate_agent_transcript,
    run_evaluation,
)
from legal_workbench.security import atomic_json_write, scan_residual_pii, sha256_file


def test_codex_failure_summary_never_reflects_fixture_text() -> None:
    completed = subprocess.CompletedProcess(
        args=["codex"],
        returncode=1,
        stdout="",
        stderr=(
            'fixture={"record":"민감한 사건 본문"}\n'
            "ERROR: You've hit your usage limit. try again at Jul 29th, 2026 2:52 PM.\n"
        ),
    )
    summary = _codex_failure_summary(completed, "평가 실패")
    assert "사용 한도" in summary
    assert "Jul 29th, 2026 2:52 PM" in summary
    assert "민감한 사건 본문" not in summary


def test_forged_empty_certification_is_rejected(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    write_manifest(manifest)
    results = tmp_path / "results.jsonl"
    results.write_text("{}\n", encoding="utf-8")
    atomic_json_write(
        tmp_path / "certification.json",
        {
            "format": CERTIFICATION_FORMAT,
            "v1_certified": True,
            "manifest_sha256": sha256_file(manifest),
            "results_path": str(results),
            "results_sha256": sha256_file(results),
            "metrics": {},
            "thresholds": {},
            "code_sha256": {},
        },
    )
    status = certification_status(manifest)
    assert status["v1_certified"] is False
    assert any("평가 코드" in reason or "합격 기준" in reason for reason in status["reasons"])


def test_certification_hashes_cover_policy_and_skill() -> None:
    hashes = _certification_code_hashes()
    assert set(hashes) == {
        "evaluation",
        "evaluation_runner",
        "evaluation_audit",
        "decision_policy",
        "skill",
    }
    assert all(len(value) == 64 for value in hashes.values())


def test_certification_rejects_results_outside_manifest_directory(tmp_path: Path) -> None:
    evaluation_root = tmp_path / "evaluation"
    evaluation_root.mkdir()
    manifest = evaluation_root / "manifest.json"
    write_manifest(manifest)
    results = tmp_path / "outside-results.jsonl"
    results.write_text("{}\n", encoding="utf-8")
    atomic_json_write(
        evaluation_root / "certification.json",
        {
            "format": CERTIFICATION_FORMAT,
            "v1_certified": True,
            "evaluation_version": 1,
            "manifest_path": "manifest.json",
            "manifest_sha256": sha256_file(manifest),
            "results_path": str(results),
            "results_sha256": sha256_file(results),
            "metrics": {},
            "thresholds": THRESHOLDS,
            "code_sha256": _certification_code_hashes(),
        },
    )

    status = certification_status(manifest)

    assert status["v1_certified"] is False
    assert any("디렉터리 밖" in reason for reason in status["reasons"])


def test_evaluation_batch_size_is_locked_into_config_hash(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    write_manifest(manifest)

    six = run_evaluation(
        manifest,
        runs=1,
        batch_size=6,
        output_dir=tmp_path / "six",
        scenario_limit=0,
        probe=True,
    )
    twelve = run_evaluation(
        manifest,
        runs=1,
        batch_size=12,
        output_dir=tmp_path / "twelve",
        scenario_limit=0,
        probe=True,
    )

    assert six["evaluation_batch_size"] == 6
    assert twelve["evaluation_batch_size"] == 12
    assert six["evaluation_config_sha256"] != twelve["evaluation_config_sha256"]


@pytest.mark.parametrize(
    "rows",
    [
        [{"evaluation_batch_size": None}],
        [{"evaluation_batch_size": 0}],
        [{"evaluation_batch_size": -1}],
        [{"evaluation_batch_size": True}],
        [{"evaluation_batch_size": 6}, {"evaluation_batch_size": 12}],
    ],
)
def test_locked_batch_size_rejects_missing_invalid_or_mixed_values(
    rows: list[dict[str, object]],
) -> None:
    with pytest.raises(ValueError, match="batch size"):
        _locked_batch_size(rows)


def test_locked_batch_size_accepts_one_positive_value() -> None:
    assert _locked_batch_size(
        [{"evaluation_batch_size": 6}, {"evaluation_batch_size": 6}]
    ) == 6


def test_manifest_thresholds_cannot_be_weakened(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    write_manifest(manifest)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["thresholds"] = {**THRESHOLDS, "selective_accuracy_min": 0.1}
    atomic_json_write(manifest, payload)
    with pytest.raises(ValueError, match="THRESHOLDS"):
        load_manifest(manifest)


def test_evaluation_child_environment_excludes_law_oc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LAW_OC", "must-not-cross-boundary")
    assert "LAW_OC" not in _sanitized_codex_env()


def test_batch_retries_only_scenario_ids_omitted_by_model(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def fake_invoke(*_args: object, **_kwargs: object) -> list[dict[str, str]]:
        batch = _args[2]
        ids = [item["scenario_id"] for item, _ in batch]
        calls.append(ids)
        if ids == ["case-001", "case-002"]:
            return [{"scenario_id": "case-001"}]
        return [{"scenario_id": scenario_id} for scenario_id in ids]

    monkeypatch.setattr(evaluation_runner, "_invoke_codex", fake_invoke)
    batch = [({"scenario_id": "case-001"}, {}), ({"scenario_id": "case-002"}, {})]

    answers = evaluation_runner._invoke_complete_batch(tmp_path, tmp_path / "schema.json", batch, "test-model")

    assert [answer["scenario_id"] for answer in answers] == ["case-001", "case-002"]
    assert calls == [["case-001", "case-002"], ["case-002"]]


def test_agent_backend_and_reasoning_are_locked_into_config_hash(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    write_manifest(manifest)

    cli_hash = _evaluation_config_hash(
        manifest,
        model="gpt-5.6-terra",
        mode="certification",
        batch_size=6,
        execution_backend=CODEX_EXECUTION_BACKEND,
        reasoning_effort="medium",
    )
    agent_hash = _evaluation_config_hash(
        manifest,
        model="gpt-5.6-terra",
        mode="certification",
        batch_size=6,
        execution_backend=AGENT_EXECUTION_BACKEND,
        reasoning_effort="medium",
    )
    high_hash = _evaluation_config_hash(
        manifest,
        model="gpt-5.6-terra",
        mode="certification",
        batch_size=6,
        execution_backend=AGENT_EXECUTION_BACKEND,
        reasoning_effort="high",
    )

    assert len({cli_hash, agent_hash, high_hash}) == 3


def test_agent_transcript_requires_exact_prompt_response_and_no_tools(tmp_path: Path) -> None:
    agent_id = "019fc241-3204-7893-bf7d-198569590b03"
    prompt = "locked prompt"
    response = '{"answers":[]}'
    events = [
        {"type": "session_meta", "payload": {"id": agent_id, "source": {"subagent": {}}}},
        {"type": "turn_context", "payload": {"model": "gpt-5.6-terra", "effort": "medium"}},
        {"type": "event_msg", "payload": {"type": "user_message", "message": prompt}},
        {"type": "response_item", "payload": {"type": "reasoning"}},
        {"type": "event_msg", "payload": {"type": "agent_message", "message": response}},
    ]
    transcript = tmp_path / f"rollout-{agent_id}.jsonl"
    transcript.write_text(
        "\n".join(json.dumps(event, ensure_ascii=False) for event in events) + "\n",
        encoding="utf-8",
    )

    report = _validate_agent_transcript(
        transcript,
        agent_id=agent_id,
        model="gpt-5.6-terra",
        reasoning_effort="medium",
        prompt=prompt,
        response_text=response,
    )

    assert report["tool_call_count"] == 0
    assert len(report["transcript_sha256"]) == 64

    events.insert(-1, {"type": "response_item", "payload": {"type": "function_call"}})
    transcript.write_text(
        "\n".join(json.dumps(event, ensure_ascii=False) for event in events) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="function_call"):
        _validate_agent_transcript(
            transcript,
            agent_id=agent_id,
            model="gpt-5.6-terra",
            reasoning_effort="medium",
            prompt=prompt,
            response_text=response,
        )


def test_agent_transcript_accepts_a_verified_later_batch_turn(tmp_path: Path) -> None:
    agent_id = "019fc241-3204-7893-bf7d-198569590b04"
    first_prompt = "first locked prompt"
    first_response = '{"answers":["first"]}'
    prompt = "second locked prompt"
    response = '{"answers":["second"]}'
    events = [
        {"type": "session_meta", "payload": {"id": agent_id, "source": {"subagent": {}}}},
        {"type": "turn_context", "payload": {"model": "gpt-5.6-terra", "effort": "medium"}},
        {"type": "event_msg", "payload": {"type": "user_message", "message": first_prompt}},
        {"type": "event_msg", "payload": {"type": "agent_message", "message": first_response}},
        {"type": "turn_context", "payload": {"model": "gpt-5.6-terra", "effort": "medium"}},
        {"type": "event_msg", "payload": {"type": "user_message", "message": prompt}},
        {"type": "event_msg", "payload": {"type": "agent_message", "message": response}},
    ]
    transcript = tmp_path / f"rollout-{agent_id}.jsonl"
    transcript.write_text(
        "\n".join(json.dumps(event, ensure_ascii=False) for event in events) + "\n",
        encoding="utf-8",
    )

    report = _validate_agent_transcript(
        transcript,
        agent_id=agent_id,
        model="gpt-5.6-terra",
        reasoning_effort="medium",
        prompt=prompt,
        response_text=response,
    )

    assert report["tool_call_count"] == 0


def test_probe_selects_stratified_development_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    manifest = {
        "scenarios": [
            {"scenario_id": "dev-a-2", "kind": "kind-a", "split": "development"},
            {"scenario_id": "dev-a-1", "kind": "kind-a", "split": "development"},
            {"scenario_id": "dev-b-1", "kind": "kind-b", "split": "development"},
            {"scenario_id": "holdout-a", "kind": "kind-a", "split": "holdout"},
        ]
    }
    captured: dict[str, object] = {}
    monkeypatch.setattr(evaluation_runner, "load_manifest", lambda _: manifest)

    def fake_run(*_args: object, **kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        return {"certification_eligible": False}

    monkeypatch.setattr(evaluation_runner, "run_evaluation", fake_run)

    result = evaluation_runner.run_probe(
        tmp_path / "manifest.json",
        per_kind=1,
        output_dir=tmp_path / "probe",
    )

    assert captured["scenario_ids"] == {"dev-a-1", "dev-b-1"}
    assert captured["probe"] is True
    assert result["split"] == "development"
    assert result["certification_eligible"] is False


def test_pii_adversarial_fixture_is_redacted_before_model() -> None:
    fixture = {"untrusted_text": "900101-1234567, 010-1234-5678, person@example.com"}
    redacted = _redact_fixture(fixture)
    assert redacted["local_preprocessing"]["pii_redacted_before_model"] is True
    assert scan_residual_pii(json.dumps(redacted, ensure_ascii=False)) == []


def test_model_answer_pii_is_sanitized_and_counted_before_storage() -> None:
    answer = {
        "scenario_id": "case-001",
        "citations": ["대법원 2019다14477 판결"],
        "supported_facts": [{"claim": "연락", "evidence_excerpt": "010-1234-5678"}],
    }
    sanitized, report = _sanitize_answer_pii(answer, scenario_id="case-001", run_id="run-1")
    serialized = json.dumps(sanitized, ensure_ascii=False)
    assert "2019다14477" not in serialized
    assert "010-1234-5678" not in serialized
    assert "[MODEL_CASE_NUMBER_" in serialized
    assert "[MODEL_PHONE_" in serialized
    assert scan_residual_pii(serialized) == []
    assert report["detection_count"] == 2
    assert report["raw_answer_persisted"] is False


def test_output_guard_removes_unverified_material_without_expected_answer() -> None:
    fixture = {
        "format": "legal-workbench-masked-decision-input-v1",
        "record": "민법 제840조에 따라 상대방의 혼인계속의사를 살핀다.",
    }
    answer = {
        "decision_status": "ready",
        "confidence": "high",
        "citations": ["민법 제840조", "대법원 2099다999999 판결"],
        "supported_facts": [
            {"claim": "확인", "evidence_excerpt": "상대방의 혼인계속의사"},
            {"claim": "추가", "evidence_excerpt": "입력에 없는 사실"},
        ],
    }
    guarded, report = _guard_answer(answer, fixture)
    assert guarded["decision_status"] == "conditional"
    assert guarded["confidence"] == "medium"
    assert guarded["citations"] == ["민법 제840조"]
    assert len(guarded["supported_facts"]) == 1
    assert report["removed_unverified_citations"] == 1
    assert report["removed_unsupported_facts"] == 1


def test_guarded_masked_answer_readds_fixture_bound_trace_fact() -> None:
    from legal_workbench.decision_policy import normalize_evaluation_answer

    fixture = {
        "format": "legal-workbench-masked-decision-input-v1",
        "record": "원고는 계약금 반환을 청구하였다.",
    }
    answer, _ = normalize_evaluation_answer(
        {"decision_status": "conditional", "supported_facts": [{"claim": "x", "evidence_excerpt": "외부 문구"}]},
        {"kind": "masked-official-decision"},
        fixture,
    )
    answer, _ = _guard_answer(answer, fixture)
    answer, _ = normalize_evaluation_answer(answer, {"kind": "masked-official-decision"}, fixture)
    answer, _ = _guard_answer(answer, fixture)

    assert answer["supported_facts"][0]["evidence_excerpt"] == fixture["record"]


def test_semantic_recall_accepts_concise_korean_legal_paraphrase_only() -> None:
    gold = {"국가의 불법행위로 발생한 정신질환과 자살 사이에 상당인과관계가 인정되는지 여부"}
    observed = {"국가 불법행위로 발병한 정신질환과 자살 사이의 상당인과관계 인정 여부"}
    unrelated = {"부동산 임대차 보증금 반환청구의 관할"}
    assert _semantic_recall(gold, observed) == 1.0
    assert _semantic_recall(gold, unrelated) == 0.0

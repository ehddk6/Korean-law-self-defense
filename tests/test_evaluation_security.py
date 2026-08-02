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
    _codex_failure_summary,
    _redact_fixture,
    _guard_answer,
    _sanitize_answer_pii,
    _sanitized_codex_env,
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

    def fake_invoke(*_args: object) -> list[dict[str, str]]:
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


def test_semantic_recall_accepts_concise_korean_legal_paraphrase_only() -> None:
    gold = {"국가의 불법행위로 발생한 정신질환과 자살 사이에 상당인과관계가 인정되는지 여부"}
    observed = {"국가 불법행위로 발병한 정신질환과 자살 사이의 상당인과관계 인정 여부"}
    unrelated = {"부동산 임대차 보증금 반환청구의 관할"}
    assert _semantic_recall(gold, observed) == 1.0
    assert _semantic_recall(gold, unrelated) == 0.0

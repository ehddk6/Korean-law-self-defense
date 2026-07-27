import json
from pathlib import Path

from legal_workbench.consultation import finish_consultation, start_consultation
from legal_workbench.security import sha256_file


def test_consultation_without_pii_can_reach_ready(tmp_path: Path) -> None:
    payload = {
        "question": "계약 상대방이 대금을 지급하지 않았다.",
        "pii_reviewed": True,
        "goal": "청구 가능성과 먼저 할 일을 알고 싶다.",
        "domain": "civil-contract-tort",
        "event_dates": ["2026-01-01"],
        "service_dates": [],
        "current_procedure": "pre-dispute",
        "known_facts": ["서면 계약과 입금 약정이 있다."],
        "opponent_claims": ["품질 문제가 있었다고 주장한다."],
        "unknowns": [],
        "evidence_tokens": ["[DOC_001]"],
        "urgent_flags": [],
    }
    started = start_consultation(payload, consultation_id="consult-test", entities={}, worksets_home=tmp_path)
    assert Path(started["bundle_path"]).is_file()
    consultation_dir = Path(started["bundle_path"]).parent
    source_text = consultation_dir / "authority-source.txt"
    verification_text = consultation_dir / "authority-verification.txt"
    source_text.write_text("공식 원문", encoding="utf-8")
    verification_text.write_text("공식 재검증 원문", encoding="utf-8")
    independent = consultation_dir / "independent-analysis.json"
    independent.write_text(
        json.dumps({"blind_to_primary": True, "adverse_points": ["품질 하자 주장"]}, ensure_ascii=False),
        encoding="utf-8",
    )
    result = finish_consultation(
        "consult-test",
        {
            "status": "ready",
            "short_answer": "공식 근거와 사실을 전제로 청구 구성을 검토할 수 있다.",
            "confirmed_facts": ["서면 계약 존재"],
            "critical_facts": [
                {"text": "서면 계약 존재", "status": "confirmed", "evidence_ids": ["[DOC_001]"]}
            ],
            "issues": ["대금 지급 의무"],
            "critical_issues": [{"title": "대금 지급 의무", "authority_ids": ["auth-consult-1"]}],
            "favorable_points": ["서면 계약"],
            "adverse_points": ["품질 하자 주장"],
            "options": ["증거 보완", "통지 초안 작성"],
            "deadlines": [],
            "immediate_actions": ["계약서 원본 보존"],
            "unknowns": [],
            "authorities": [
                {
                    "authority_id": "auth-consult-1",
                    "source_tier": "P1",
                    "official_url": "https://www.law.go.kr/example",
                    "verification_url": "https://lx.scourt.go.kr/example",
                    "verified_at": "2026-01-02T00:00:00+00:00",
                    "citation": "예시 법령 제1조",
                    "text_sha256": sha256_file(source_text),
                    "source_text_path": str(source_text),
                    "verification_text_path": str(verification_text),
                    "verification_text_sha256": sha256_file(verification_text),
                    "mcp_server": "korean-law",
                    "mcp_version": "4.7.4",
                    "mcp_tool": "get_law_text",
                    "mcp_verified_at": "2026-01-02T00:00:00+00:00",
                }
            ],
            "applicable_law_verified": True,
            "adverse_authority_reviewed": True,
            "independent_analysis_ref": str(independent),
            "independent_analysis_sha256": sha256_file(independent),
            "deadline_review": {
                "status": "verified-none-applicable",
                "as_of_date": "2026-01-02",
                "authority_ids": ["auth-consult-1"],
            },
        },
        worksets_home=tmp_path,
    )
    assert result["status"] == "ready"
    assert result["blockers"] == []


def test_consultation_without_primary_source_abstains(tmp_path: Path) -> None:
    payload = {
        "question": "일반적인 법률 질문",
        "pii_reviewed": True,
        "domain": "civil-contract-tort",
        "known_facts": [],
    }
    start_consultation(payload, consultation_id="consult-abstain", entities={}, worksets_home=tmp_path)
    result = finish_consultation(
        "consult-abstain",
        {"status": "ready", "short_answer": "확정 답변", "authorities": []},
        worksets_home=tmp_path,
    )
    assert result["status"] == "abstain"
    assert result["blockers"]


def test_detention_consultation_adds_urgent_verification_questions(tmp_path: Path) -> None:
    started = start_consultation(
        {
            "question": "가족이 오늘 체포됐다는 연락만 받았습니다.",
            "pii_reviewed": True,
            "domain": "criminal-investigation-procedure",
            "known_facts": [],
        },
        consultation_id="consult-detention",
        entities={},
        worksets_home=tmp_path,
    )
    bundle = json.loads(Path(started["bundle_path"]).read_text(encoding="utf-8"))
    questions = " ".join(bundle["required_questions"])
    assert "체포 시각" in questions
    assert "공식 대표번호" in questions
    assert "복약" in questions


def test_ready_consultation_is_blocked_without_issue_and_analysis_gates(tmp_path: Path) -> None:
    start_consultation(
        {"question": "계약상 의무를 알고 싶습니다.", "domain": "civil-contract-tort", "pii_reviewed": True},
        consultation_id="consult-weak-ready",
        entities={},
        worksets_home=tmp_path,
    )
    result = finish_consultation(
        "consult-weak-ready",
        {
            "status": "ready",
            "authorities": [
                {
                    "authority_id": "auth-weak",
                    "source_tier": "P1",
                    "official_url": "https://www.law.go.kr/example",
                    "verification_url": "https://lx.scourt.go.kr/example",
                    "verified_at": "2026-01-02T00:00:00+00:00",
                    "citation": "예시 법령 제1조",
                    "text_sha256": "a" * 64,
                }
            ],
        },
        worksets_home=tmp_path,
    )
    assert result["status"] == "abstain"
    assert any("핵심 쟁점" in item for item in result["blockers"])
    assert any("독립 재분석" in item for item in result["blockers"])


def test_lease_consultation_requires_termination_delivery_and_registry_questions(tmp_path: Path) -> None:
    started = start_consultation(
        {"question": "보증금을 돌려받지 못했습니다.", "domain": "real-estate-lease-registration", "pii_reviewed": True},
        consultation_id="consult-lease",
        entities={},
        worksets_home=tmp_path,
    )
    bundle = json.loads(Path(started["bundle_path"]).read_text(encoding="utf-8"))
    questions = " ".join(bundle["required_questions"])
    assert "도달일" in questions
    assert "등기사항증명서" in questions

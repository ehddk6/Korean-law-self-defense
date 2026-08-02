from legal_workbench.gold_review_runner import _review_schema, _validate_review_report


def test_adversarial_gold_review_uses_fixture_and_expected_without_source() -> None:
    official = {
        "scenario_id": "case-001",
        "kind": "masked-official-decision",
        "source_sha256": "a" * 64,
        "fixture_sha256": "b" * 64,
        "expected_sha256": "c" * 64,
    }
    adversarial = {
        "scenario_id": "case-151",
        "kind": "pii-leakage",
        "fixture_sha256": "d" * 64,
        "expected_sha256": "e" * 64,
    }
    schema = _review_schema([official, adversarial], "reviewer-a", "gpt-5.6-sol")
    records = schema["properties"]["reviews"]["properties"]
    assert "source_sha256" in records["case-001"]["required"]
    assert "source_sha256" not in records["case-151"]["required"]

    checks = {
        "source_bound": True,
        "label_correct": True,
        "fixture_blind": True,
        "fixture_pii_free": True,
        "gold_supported": True,
    }
    report = {
        "format": "legal-workbench-gold-review-v1",
        "reviewer_id": "reviewer-a",
        "reviewer_model": "gpt-5.6-sol",
        "reviews": {
            "case-001": {
                "approved": True,
                "source_sha256": "a" * 64,
                "fixture_sha256": "b" * 64,
                "expected_sha256": "c" * 64,
                "checks": checks,
                "notes": "official case reviewed",
            },
            "case-151": {
                "approved": True,
                "fixture_sha256": "d" * 64,
                "expected_sha256": "e" * 64,
                "checks": checks,
                "notes": "adversarial case reviewed",
            },
        },
    }

    _validate_review_report(report, [official, adversarial], "reviewer-a", "gpt-5.6-sol")

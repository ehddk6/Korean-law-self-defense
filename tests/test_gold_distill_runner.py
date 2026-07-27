from legal_workbench.gold_distill_runner import _fixture_surface_text, _validate_case_distillation


def test_gold_distill_validation_uses_fixture_text_not_json_escapes() -> None:
    fixture = {"record": '약관은 "암" 진단을 보험사고로 정한다.'}
    value = {
        "issues": [
            {"text": "약관상 암 진단의 보험사고 해당 여부", "evidence_excerpt": '약관은 "암" 진단을 보험사고로 정한다.'},
            {"text": "보험금 지급요건의 해석", "evidence_excerpt": '약관은 "암" 진단을 보험사고로 정한다.'},
            {"text": "약관 문언의 적용 범위", "evidence_excerpt": '약관은 "암" 진단을 보험사고로 정한다.'},
        ],
        "adverse_points": [
            {"text": "약관 문언상 지급요건이 명확하다는 주장", "evidence_excerpt": '약관은 "암" 진단을 보험사고로 정한다.'},
            {"text": "보험사고 해석을 제한해야 한다는 주장", "evidence_excerpt": '약관은 "암" 진단을 보험사고로 정한다.'},
        ],
    }
    assert '"암"' in _fixture_surface_text(fixture)
    _validate_case_distillation(value, fixture)

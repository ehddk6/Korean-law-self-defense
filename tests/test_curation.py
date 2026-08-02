import pytest

from legal_workbench.curation import _classify_outcome, _fixture_label_leak, _masked_record


@pytest.mark.parametrize(
    "text",
    [
        "원심의 위와 같은 판단은 수긍하기 어렵다.",
        "위 선정자의 소 부분은 사망으로 중단됨이 없이 종료되었다.",
        "피고인이 범행을 알면서 가담하였다고 단정하기는 어렵다.",
        "상당인과관계를 인정할 수 있다. 피고의 처분은 위법하다.",
        "재판에 영향을 미친 위법이 있다.",
        "피고인이 보이스피싱임을 알고 가담했다고 단정하기 어렵다.",
        "업무상 긴장으로 인한 혈압상승이 상병으로 이어졌다고 본다.",
        "혈압이 상승할 수 있었고 이러한 혈압상승이 이 사건 상병으로 이어졌다고 평가함이 상당하다.",
        "사건 당일 오전의 급격한 혈압상승이 이 사건 상병을 초래한 직접적인 원인이 되었을 것으로 판단함이 상당하다.",
        "따라서 이 부분 주장은 이 사건 처분의 위법사유를 구성할 수 없다.",
        "원고의 이 부분 주장은 타당하지 않다.",
        "자연적인 경과를 넘어 급격한 변동이 초래되었던 것으로 평가할 수 있다.",
        "변제기간은 착오로 말미암아 잘못 기재된 것으로 볼만한 사정이 충분하다고 할 것이다.",
        "재항고인이 제출한 서면과 자료를 토대로 회생절차 개시 여부를 판단하였어야 할 것이다.",
        "피고인의 행위가 형법 제20조의 사회상규에 위배되는 행위라고 보기도 어렵다.",
        "피해자의 성적 자유를 침해하는 행위로서 추행에 해당한다.",
        "절차적 정의에 반한다고 볼만한 사정을 찾아보기 어렵다.",
        "이로써 피고인은 위력으로 피해자를 추행하였다.",
        "원심의 판단은 수긍하기 어렵다.",
        "원심은 항고심 자료로 판단했어야 한다.",
        "정신질환으로 자살에 이르렀다고 추단할 여지가 있다.",
        "업무상 돌발상황과 뇌출혈 사이에 상당인과관계가 인정된다.",
        "파산절차 종료 뒤 면책신청 종기가 지났다고 보아야 한다.",
        "항고심은 보완자료를 토대로 판단했어야 한다.",
        "보증금 반환과 공제·사용 여부를 심리해 재산성을 판단했어야 한다.",
        "【 범죄사실 】 피고인의 행위는 유죄 전제에서 판단된다.",
        "피고인과 변호인의 주장은 받아들이지 않는다.",
        "법률상 처단형의 범위는 벌금형이다.",
        "이 사건 범행의 양형 판단을 한다.",
    ],
)
def test_fixture_label_leak_rejects_direct_case_conclusions(text: str) -> None:
    assert _fixture_label_leak(text) is True


def test_masked_record_drops_direct_conclusion_split_across_sentences() -> None:
    record = _masked_record(
        {
            "court": "서울행법",
            "full_text": "사실관계 " * 80
            + "\n고의 주장을 검토하였다. 외상이 발생에 기여하였다고 인정하기 어렵다.",
        }
    )
    assert "인정하기 어렵다" not in record


def test_lower_court_masking_cuts_generic_judgment_section_after_context() -> None:
    record = _masked_record(
        {
            "court": "서울행법",
            "full_text": (
                "1. 처분의 경위\n" + "처분 전 사실과 신청 경위가 기록되어 있다. " * 20
                + "\n2. 처분의 위법 여부\n가. 원고의 주장\n"
                + "원고는 업무환경과 상병 사이의 관련성을 주장하였다. " * 10
                + "\n나. 판단\n업무상 부담이 상병의 직접 원인이라고 판단한다."
            ),
        }
    )

    assert "원고는 업무환경과 상병 사이의 관련성을 주장하였다" in record
    assert "업무상 부담이 상병의 직접 원인" not in record


def test_lower_criminal_masking_cuts_defense_judgment_section() -> None:
    record = _masked_record(
        {
            "court": "수원지법",
            "full_text": (
                "1. 공소사실\n" + "피고인의 구체적인 신체접촉 행위가 기재되어 있다. " * 20
                + "\n2. 개인정보 보호법 위반\n"
                + "주소를 내용증명 발송에 사용한 행위가 기재되어 있다. " * 10
                + "\n【피고인과 변호인의 주장에 대한 판단】 1. 피고인 주장의 요지\n피해자 진술을 믿을 수 있다."
            ),
        }
    )

    assert "주소를 내용증명 발송에 사용한 행위" in record
    assert "피해자 진술을 믿을 수 있다" not in record


def test_lower_criminal_masking_cuts_statutory_application_section() -> None:
    record = _masked_record(
        {
            "court": "수원지법",
            "full_text": (
                "1. 공소사실\n" + "피고인의 구체적인 행위와 피해 경위가 기재되어 있다. " * 30
                + "\n【법령의 적용】 1. 범죄사실에 대한 해당법조\n벌금형을 선택한다."
            ),
        }
    )

    assert "피고인의 구체적인 행위와 피해 경위" in record
    assert "벌금형을 선택한다" not in record


def test_supreme_masking_keeps_all_fact_subsections_before_judgment() -> None:
    record = _masked_record(
        {
            "court": "대법원",
            "full_text": (
                "【 이 유 】 1. 관련 법리\n"
                "법리 설명 " * 60
                + "\n2. 사실관계\n원심판결 이유와 기록에 따르면, 다음과 같은 사실을 알 수 있다.\n"
                "가. 첫 번째 사실관계\n나. 두 번째 사실관계\n다. 총장의 환수 통지 내용\n"
                "3. 판단\n이 사건 통지는 처분에 해당한다."
            ),
        }
    )
    assert "총장의 환수 통지 내용" in record
    assert "처분에 해당한다" not in record


def test_fixture_label_leak_does_not_treat_neutral_payment_period_fact_as_conclusion() -> None:
    assert _fixture_label_leak("변제기간이 60개월로 기재된 변제계획안을 제출하였다.") is False


def test_classify_outcome_classifies_acquittal_explicitly() -> None:
    assert _classify_outcome("【 주문 】 피고인은 무죄.") == "acquitted"


def test_classify_outcome_classifies_criminal_conviction_explicitly() -> None:
    assert _classify_outcome("【 주문 】 피고인을 벌금 100만 원에 처한다.") == "convicted"


def test_classify_outcome_prioritizes_final_dismissal_after_reversal() -> None:
    assert _classify_outcome("【 주문 】 원심판결을 파기하고 제1심판결을 취소한다. 주위적 및 예비적 소를 전부 각하한다.") == "dismissed"

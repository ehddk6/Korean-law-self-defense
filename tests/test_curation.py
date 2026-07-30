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
        "원심의 판단은 수긍하기 어렵다.",
        "원심은 항고심 자료로 판단했어야 한다.",
        "정신질환으로 자살에 이르렀다고 추단할 여지가 있다.",
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


def test_classify_outcome_classifies_acquittal_explicitly() -> None:
    assert _classify_outcome("【 주문 】 피고인은 무죄.") == "acquitted"


def test_classify_outcome_classifies_criminal_conviction_explicitly() -> None:
    assert _classify_outcome("【 주문 】 피고인을 벌금 100만 원에 처한다.") == "convicted"


def test_classify_outcome_prioritizes_final_dismissal_after_reversal() -> None:
    assert _classify_outcome("【 주문 】 원심판결을 파기하고 제1심판결을 취소한다. 주위적 및 예비적 소를 전부 각하한다.") == "dismissed"

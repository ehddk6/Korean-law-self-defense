from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import CaseStage, STAGE_ORDER, utc_now
from .security import atomic_json_write
from .workflow import store_for


@dataclass(frozen=True, slots=True)
class ServiceSpec:
    service_type: str
    label: str
    minimum_stage: CaseStage
    purpose: str
    required_inputs: tuple[str, ...]
    required_sections: tuple[str, ...]
    deliverables: tuple[str, ...]
    special_gates: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "service_type": self.service_type,
            "label": self.label,
            "minimum_stage": str(self.minimum_stage),
            "purpose": self.purpose,
            "required_inputs": list(self.required_inputs),
            "required_sections": list(self.required_sections),
            "deliverables": list(self.deliverables),
            "special_gates": list(self.special_gates),
        }


def _spec(
    service_type: str,
    label: str,
    stage: CaseStage,
    purpose: str,
    inputs: tuple[str, ...],
    sections: tuple[str, ...],
    deliverables: tuple[str, ...],
    gates: tuple[str, ...] = (),
) -> ServiceSpec:
    return ServiceSpec(service_type, label, stage, purpose, inputs, sections, deliverables, gates)


SERVICES: dict[str, ServiceSpec] = {
    item.service_type: item
    for item in (
        _spec(
            "legal-opinion",
            "법률의견·승패 조건 분석",
            CaseStage.RESEARCHED,
            "공식 근거와 증거를 바탕으로 결론 조건과 선택지를 제시한다.",
            ("facts", "issues", "authorities", "deadlines"),
            ("결론", "전제", "쟁점", "양측 논리", "사실 적용", "선택지", "기한", "미확인 사항"),
            ("법률의견서", "근거표", "추가자료 목록"),
            ("verified P1", "독립 재분석", "abstain gate"),
        ),
        _spec(
            "contract-draft",
            "계약서 작성",
            CaseStage.RESEARCHED,
            "거래 목적과 위험 배분을 반영한 계약서와 협상안을 작성한다.",
            ("parties", "transaction", "commercial_terms", "risk_preferences", "authorities"),
            ("정의", "권리·의무", "대금", "진술·보장", "책임", "해지", "분쟁해결", "부속서"),
            ("계약서 초안", "조항별 설명", "협상 쟁점표"),
            ("강행규정 검토", "서명·권한 확인"),
        ),
        _spec(
            "contract-review",
            "계약서 검토·레드라인",
            CaseStage.INGESTED,
            "계약 문구의 법적·상업적 위험과 수정안을 제시한다.",
            ("contract_document", "client_goal", "negotiation_position"),
            ("핵심 위험", "불리한 조항", "누락 조항", "수정안", "협상 우선순위"),
            ("검토의견", "레드라인", "협상 체크리스트"),
            ("문서 버전 확인", "당사자·서명권한 확인"),
        ),
        _spec(
            "demand-letter",
            "내용증명·최종통지",
            CaseStage.INDEPENDENTLY_ANALYZED,
            "권리 보전과 분쟁 해결을 위한 사실·요구·기한을 명확히 통지한다.",
            ("confirmed_facts", "claim", "evidence", "deadline"),
            ("당사자", "사실", "법적 근거", "요구사항", "이행기한", "불이행 시 조치"),
            ("통지서", "발송 전 확인표"),
            ("과장·협박 표현 금지", "주소·도달 방식 사용자 확인"),
        ),
        _spec(
            "negotiation-plan",
            "협상·합의 전략",
            CaseStage.INDEPENDENTLY_ANALYZED,
            "법적 대안과 증거 위험을 반영해 협상 범위와 메시지를 설계한다.",
            ("goal", "opponent_interests", "best_alternative", "evidence", "authority"),
            ("목표", "최저선", "교환조건", "상대방 예상 요구", "메시지", "결렬 시 대안"),
            ("협상안", "합의서 조항 목록", "롤플레이 질문"),
            ("합의 권한 사용자 보유", "자동 연락·수락 금지"),
        ),
        _spec(
            "settlement-analysis",
            "화해·조정·합의안 분석",
            CaseStage.INDEPENDENTLY_ANALYZED,
            "소송 위험·집행 가능성·비금전 조건을 비교한다.",
            ("claim_value", "proof_risk", "costs", "time", "enforcement_risk"),
            ("쟁점별 기대결과", "비용·기간", "합의 범위", "비금전 조건", "이행·위약", "비밀유지"),
            ("합의안 비교표", "합의서 초안", "사용자 승인 체크리스트"),
            ("근거 없는 확률 금지", "세금·집행 효과 확인"),
        ),
        _spec(
            "civil-complaint",
            "민사 소장·신청서",
            CaseStage.INDEPENDENTLY_ANALYZED,
            "청구취지와 청구원인을 증거에 연결한 초안을 작성한다.",
            ("parties", "forum", "claims", "facts", "evidence", "authorities", "amount"),
            ("청구취지", "청구원인", "관할", "입증방법", "첨부·증거목록"),
            ("소장 초안", "증거목록", "전자소송 manifest"),
            ("관할·당사자 표시", "소가·비용 사용자 확인", "기한 검증"),
        ),
        _spec(
            "civil-answer",
            "민사 답변서·준비서면",
            CaseStage.INDEPENDENTLY_ANALYZED,
            "상대방 주장별 인정·부인·모름과 항변을 증거에 연결한다.",
            ("served_pleading", "service_date", "facts", "evidence", "authorities"),
            ("청구취지 답변", "주장별 답변", "항변", "반대사실", "입증방법"),
            ("답변서", "준비서면", "쟁점·증거 대조표"),
            ("송달일·제출기한", "상대방 문구 정확 인용"),
        ),
        _spec(
            "criminal-complaint",
            "고소·고발 준비",
            CaseStage.INDEPENDENTLY_ANALYZED,
            "범죄사실과 증거를 구성요건별로 정리한다.",
            ("conduct", "dates", "actors", "evidence", "harm", "jurisdiction"),
            ("당사자", "범죄사실", "구성요건별 사실", "증거", "수사 요청사항"),
            ("고소장 초안", "증거목록", "진술 준비표"),
            ("허위·과장 금지", "증거 원본 보존", "관할 확인"),
        ),
        _spec(
            "investigation-response",
            "수사·조사 대응",
            CaseStage.INGESTED,
            "현재 절차와 자료를 파악해 진술·제출·보존 쟁점을 준비한다.",
            ("notice", "procedure_stage", "allegations", "evidence", "deadlines"),
            ("절차 현황", "혐의·쟁점", "사실 연표", "예상 질문", "증거 보존", "권리·기한"),
            ("대응 메모", "예상 질문표", "자료 제출 목록"),
            ("신체구속·압수수색 최고위험", "진술 내용 임의 창작 금지"),
        ),
        _spec(
            "evidence-plan",
            "증거수집·보전·입증 계획",
            CaseStage.INGESTED,
            "법률요건별 필요한 증거와 취약점을 정리한다.",
            ("issues", "existing_evidence", "missing_facts"),
            ("요건별 증거", "현재 증거", "누락 증거", "보전 방법", "진정성립", "반대 해석"),
            ("증거 매트릭스", "수집 체크리스트", "보전 요청 초안"),
            ("위법한 수집 지시 금지", "원본 해시·입수경위 보존"),
        ),
        _spec(
            "witness-examination",
            "증인·당사자신문 준비",
            CaseStage.INDEPENDENTLY_ANALYZED,
            "입증 목적에 맞는 주신문·반대신문 질문과 탄핵 자료를 준비한다.",
            ("witness_role", "issues", "statements", "documents", "contradictions"),
            ("입증취지", "주신문", "예상 반대신문", "모순·탄핵", "문서 제시 순서"),
            ("신문사항", "증인 준비 메모", "모의신문 시나리오"),
            ("사실 암시·증언 조작 금지", "원진술과 모순 정확 인용"),
        ),
        _spec(
            "hearing-prep",
            "변론·심문·공판 준비",
            CaseStage.DRAFTED,
            "기록과 쟁점을 압축해 구두진술·질문·즉답을 준비한다.",
            ("latest_pleadings", "issues", "evidence", "court_questions", "deadlines"),
            ("30초 요약", "쟁점별 답변", "불리한 질문", "증거 위치", "요청사항"),
            ("변론요지", "구두변론 스크립트", "모의재판 질문"),
            ("새 사실 창작 금지", "기록 페이지 확인"),
        ),
        _spec(
            "appeal-plan",
            "항소·상고·불복 전략",
            CaseStage.INGESTED,
            "원결정과 기록을 기준으로 불복 가능성·범위·기한을 분석한다.",
            ("decision", "service_date", "record", "errors", "deadlines"),
            ("결론", "불복기한", "사실오인", "법리오해", "절차위반", "새 증거", "요청사항"),
            ("불복 검토서", "이유서 초안", "기록 인용표"),
            ("송달일 최고우선", "심급별 허용 주장 범위 확인"),
        ),
        _spec(
            "enforcement-plan",
            "판결 후 집행·보전",
            CaseStage.INDEPENDENTLY_ANALYZED,
            "집행권원과 재산 정보를 바탕으로 보전·집행 선택지를 준비한다.",
            ("enforcement_title", "finality", "debtor_assets", "security", "costs"),
            ("집행 가능성", "대상 재산", "보전", "집행 절차", "우선순위", "비용·위험"),
            ("집행 계획", "신청서 초안", "재산·서류 체크리스트"),
            ("집행문·확정·송달 확인", "제3자 권리 검토"),
        ),
        _spec(
            "due-diligence",
            "법률실사·거래 위험 점검",
            CaseStage.INGESTED,
            "거래·자산·계약·분쟁·규제 위험을 목록화한다.",
            ("scope", "documents", "materiality", "transaction_structure"),
            ("회사·권한", "주요 계약", "자산·담보", "분쟁", "규제", "개인정보", "시정조치"),
            ("실사보고서", "요청자료 목록", "위험·보완표"),
            ("자료 미제공 범위 표시", "비공개 자료 부존재 단정 금지"),
        ),
        _spec(
            "compliance-opinion",
            "규제·컴플라이언스 의견",
            CaseStage.RESEARCHED,
            "행위·정책·업무가 적용 규정과 통제에 맞는지 검토한다.",
            ("activity", "organization", "jurisdiction", "policies", "authorities"),
            ("적용 규정", "현행 통제", "위험", "개선조치", "책임자", "증빙"),
            ("컴플라이언스 의견", "통제 체크리스트", "시정계획"),
            ("행위시법·시행예정 규정", "기관 지침과 법적 의무 구분"),
        ),
        _spec(
            "legal-research-memo",
            "법률조사 메모",
            CaseStage.ISSUES_MAPPED,
            "쟁점별 공식 법령·판례와 반대 근거를 추적 가능한 형태로 정리한다.",
            ("issues", "action_date", "as_of_date"),
            ("질문", "짧은 답", "법령", "판례", "반대 근거", "사실 적용", "미확인"),
            ("조사 메모", "Authority ledger", "검색 로그"),
            ("P1 이중 검증", "검색 0건 문구"),
        ),
        _spec(
            "legal-consultation",
            "사건 초기 법률상담·선택지 안내",
            CaseStage.INTAKE,
            "질문을 사실·쟁점·긴급기한으로 구조화하고 가능한 대응 경로를 설명한다.",
            ("question", "goal", "event_dates", "current_procedure", "known_facts", "unknowns"),
            ("짧은 답", "확인된 사실", "쟁점", "유리·불리 조건", "선택지", "기한", "즉시 행동", "추가 질문"),
            ("상담 결과", "추가자료 목록", "사건 전환 체크리스트"),
            ("개인정보 비식별", "긴급위험 선별", "P1 없으면 abstain"),
        ),
        _spec(
            "provisional-relief",
            "가압류·가처분·보전처분 준비",
            CaseStage.INDEPENDENTLY_ANALYZED,
            "본안 전 권리 보전을 위한 피보전권리와 보전 필요성을 증거로 구성한다.",
            ("claim", "urgency", "debtor_assets", "evidence", "security", "forum"),
            ("신청취지", "피보전권리", "보전 필요성", "소명자료", "담보", "관할"),
            ("보전처분 신청서 초안", "소명자료 목록", "담보·집행 체크리스트"),
            ("재산·제3자 권리 확인", "담보액 사용자 확인", "긴급기한"),
        ),
        _spec(
            "payment-order-small-claim",
            "지급명령·소액사건 준비",
            CaseStage.INDEPENDENTLY_ANALYZED,
            "채권 구조와 송달 가능성을 검토해 간이 절차와 통상소송을 비교한다.",
            ("claim", "amount", "debtor_address", "evidence", "limitation"),
            ("청구취지", "청구원인", "금액 산식", "송달", "이의 시 전환", "증거"),
            ("지급명령 또는 소액사건 초안", "비용·절차 비교표"),
            ("주소·관할", "소멸시효", "송달불능 위험"),
        ),
        _spec(
            "administrative-remedy",
            "행정심판·이의신청·행정소송",
            CaseStage.INGESTED,
            "처분서와 송달일을 기준으로 적법한 불복 경로와 집행정지 필요성을 분석한다.",
            ("disposition", "service_date", "agency", "legal_basis", "harm", "record"),
            ("처분 특정", "불복기간", "전치", "위법 사유", "집행정지", "청구취지"),
            ("불복 검토서", "심판청구서·소장 초안", "집행정지 신청 초안"),
            ("불복기간 최고우선", "전치주의", "처분서 원문 확인"),
        ),
        _spec(
            "labor-remedy",
            "노동위 구제·임금·산재·노동소송",
            CaseStage.INGESTED,
            "근로관계와 처분일을 기준으로 구제기관, 입증자료와 기한을 구성한다.",
            ("employment_terms", "adverse_action", "dates", "wage_records", "rules", "evidence"),
            ("근로자성", "구제유형", "신청기간", "정당한 이유", "임금 산식", "증거"),
            ("구제신청서·진정서 초안", "임금 계산표", "증거 매트릭스"),
            ("신청기간", "사업장·근로자 지위", "산재·형사 절차 분리"),
        ),
        _spec(
            "family-proceeding",
            "이혼·친권·양육비·가사절차",
            CaseStage.INGESTED,
            "가족관계, 자녀 이익과 긴급 보호 필요성을 중심으로 가사 절차를 준비한다.",
            ("family_relationship", "children", "assets", "care_history", "violence_risk", "evidence"),
            ("관계·청구", "자녀 최선의 이익", "재산", "양육비", "면접교섭", "보호조치"),
            ("가사 신청서·소장 초안", "재산·양육 자료표", "긴급 보호 체크리스트"),
            ("아동·신변 위험 최고우선", "가족관계 원문", "비공개정보 보호"),
        ),
        _spec(
            "inheritance-estate",
            "상속·유류분·상속재산 정리",
            CaseStage.RESEARCHED,
            "상속개시일과 가족관계·재산·채무를 기준으로 선택지와 기한을 분석한다.",
            ("death_date", "family_register", "will", "assets", "debts", "gifts"),
            ("상속인", "유언", "재산·채무", "승인·포기", "유류분", "분할"),
            ("상속 검토서", "재산목록", "신청·협의서 초안"),
            ("상속개시일", "승인·포기 기간", "잠재채무 부존재 단정 금지"),
        ),
        _spec(
            "rehabilitation-bankruptcy",
            "개인·법인 회생파산 준비",
            CaseStage.RESEARCHED,
            "채무·소득·재산·담보를 구조화해 절차 적합성과 제출자료를 준비한다.",
            ("debts", "income", "assets", "security", "transactions", "dependants"),
            ("채무자 현황", "채권자", "재산", "소득·생계", "부인권 위험", "절차 비교"),
            ("절차 적합성 메모", "채권자·재산 목록", "신청서 초안"),
            ("재산 은닉·편파변제 조언 금지", "면책 제외채권", "최신 법원 양식"),
        ),
        _spec(
            "tax-remedy",
            "과세전적부·이의·심사·심판·조세소송",
            CaseStage.INGESTED,
            "고지·통지와 송달일을 기준으로 조세 불복 경로, 전치와 계산 쟁점을 분석한다.",
            ("notice", "service_date", "tax_type", "calculation", "filings", "evidence"),
            ("처분", "불복기간", "전치", "과세근거", "계산", "증빙", "집행 영향"),
            ("조세 불복 검토서", "청구서·소장 초안", "계산·증빙표"),
            ("불복기간", "필요적 전치", "세액 산식 독립 검산"),
        ),
        _spec(
            "constitutional-remedy",
            "헌법소원·위헌법률심판 쟁점",
            CaseStage.INGESTED,
            "공권력 행사·불행사와 기본권 침해 구조, 보충성 및 청구기간을 검토한다.",
            ("public_action", "awareness_date", "rights", "other_remedies", "decision_record"),
            ("공권력", "기본권", "자기관련성", "현재성", "보충성", "청구기간"),
            ("헌법 쟁점 검토서", "청구서 초안", "요건 체크리스트"),
            ("청구기간 최고우선", "보충성", "결정례 P1 원문"),
        ),
        _spec(
            "criminal-defense-pleading",
            "형사 피의자·피고인 방어와 의견서",
            CaseStage.INDEPENDENTLY_ANALYZED,
            "공소·혐의 사실과 증거를 구성요건·증거능력·양형 쟁점으로 나눈다.",
            ("allegations", "record", "statements", "evidence", "procedure_stage", "deadlines"),
            ("혐의별 의견", "구성요건", "증거능력·신빙성", "위법수집", "정상관계", "요청사항"),
            ("변호인 의견서 형식 초안", "증거·모순표", "신문·공판 준비표"),
            ("진술 창작 금지", "구속·압수수색 최고위험", "열람 가능한 기록 범위 표시"),
        ),
        _spec(
            "detention-relief",
            "체포·구속·보석·적부심 대응 준비",
            CaseStage.INGESTED,
            "신체구속 상태와 영장·결정문을 기준으로 즉시 가능한 절차를 선별한다.",
            ("custody_status", "warrant", "dates", "charges", "ties", "risk_factors"),
            ("구속 현황", "기한", "도주·증거인멸 위험", "대체조건", "절차 선택", "자료"),
            ("긴급 대응표", "신청서·의견서 초안", "자료 체크리스트"),
            ("최고위험 표시", "모든 시간·송달 즉시 확인", "사용자의 즉시 외부 행동 필요"),
        ),
        _spec(
            "mediation-arbitration",
            "조정·중재·ADR 준비",
            CaseStage.INDEPENDENTLY_ANALYZED,
            "합의 권한과 절차 규칙을 확인하고 주장·양보·이행 조건을 설계한다.",
            ("agreement", "forum_rules", "claims", "evidence", "settlement_range"),
            ("관할·합의", "주요 쟁점", "합의 범위", "세션 전략", "이행", "불성립 시 대안"),
            ("조정안·중재 서면 초안", "협상표", "합의서 초안"),
            ("중재합의 유효성", "합의 수락은 사용자만", "집행 가능성"),
        ),
        _spec(
            "corporate-governance",
            "회사 의사결정·주주·임원 법무",
            CaseStage.RESEARCHED,
            "정관·등기·기관 권한을 기준으로 결의와 책임·절차 위험을 검토한다.",
            ("articles", "registry", "ownership", "board", "transaction", "conflicts"),
            ("권한", "소집·결의", "이해상충", "임원 책임", "공시·등기", "시정"),
            ("이사회·주주총회 문안", "법률검토서", "절차 체크리스트"),
            ("최신 등기·정관", "특별이해관계", "공증·등기 실행은 사용자"),
        ),
        _spec(
            "registration-filing",
            "등기·등록·인허가 서류 준비",
            CaseStage.RESEARCHED,
            "최신 법정서식과 요건을 기준으로 제출서류와 보정 위험을 정리한다.",
            ("filing_type", "applicant", "authority", "documents", "fees", "deadlines"),
            ("요건", "관할기관", "서식", "첨부", "수수료", "보정·불복"),
            ("신청서 초안", "첨부·비용 manifest", "보정 체크리스트"),
            ("공식 최신 서식", "서명·인감 사용자 확인", "실제 제출 금지"),
        ),
        _spec(
            "privacy-ip-remedy",
            "개인정보·IT·지식재산 분쟁 대응",
            CaseStage.INDEPENDENTLY_ANALYZED,
            "데이터·저작물·표지·기술과 침해 행위를 특정해 보전·신고·청구 경로를 준비한다.",
            ("protected_subject", "ownership", "conduct", "systems", "evidence", "harm"),
            ("권리·법적 지위", "침해", "예외·항변", "보전", "중단·삭제", "손해·구제"),
            ("침해 검토서", "중단요청·신고·신청 초안", "디지털 증거 목록"),
            ("위법한 시스템 접근 금지", "메타데이터·원본 보존", "표현의 자유·공정이용 반론"),
        ),
        _spec(
            "public-information-petition",
            "정보공개·진정·신고·청원",
            CaseStage.INGESTED,
            "기관과 요청 목적을 기준으로 정보공개·진정·신고와 불복 절차를 구분한다.",
            ("agency", "requested_information", "conduct", "dates", "prior_response"),
            ("절차 선택", "요청 범위", "사실", "근거", "비공개 예외", "불복"),
            ("청구·진정·신고서 초안", "첨부자료 목록", "불복 일정표"),
            ("기관 권한 확인", "개인정보 최소화", "허위 신고 금지"),
        ),
        _spec(
            "case-management",
            "사건 일정·자료·업무 관리",
            CaseStage.INGESTED,
            "사건의 일정, 제출물, 증거, 미결 과제와 위험을 관리한다.",
            ("deadlines", "documents", "tasks", "hearings"),
            ("일정", "제출물", "자료", "미결 과제", "위험", "다음 검토"),
            ("사건 현황표", "기한표", "업무 체크리스트"),
            ("공식 기산일 없는 확정기한 금지",),
        ),
    )
}


def list_services() -> list[dict[str, Any]]:
    return [SERVICES[key].to_dict() for key in sorted(SERVICES)]


def build_service_bundle(
    case_id: str,
    service_type: str,
    *,
    worksets_home: Path | None = None,
) -> Path:
    if service_type not in SERVICES:
        raise ValueError(f"지원하지 않는 변호사 업무 유형입니다: {service_type}")
    spec = SERVICES[service_type]
    store = store_for(case_id, worksets_home)
    case = store.get_case()
    current = CaseStage(case["stage"])
    if STAGE_ORDER.index(current) < STAGE_ORDER.index(spec.minimum_stage):
        raise ValueError(f"{spec.label}에는 최소 {spec.minimum_stage} 단계가 필요합니다. 현재: {current}")
    payload = {
        "format": "legal-workbench-lawyer-service-v1",
        "service": spec.to_dict(),
        "case": case,
        "facts": store.list_payloads("facts"),
        "evidence": store.list_payloads("evidence"),
        "authorities": store.list_payloads("authorities"),
        "issues": store.list_payloads("issues"),
        "deadlines": store.list_payloads("deadlines"),
        "opinions": store.list_payloads("opinions"),
        "unavailable_actions": [
            "변호사 명의 사용",
            "선임계 제출과 법정 출석",
            "사용자 대신 서명·제출·결제",
            "사용자 승인 없는 상대방·기관 연락",
        ],
        "created_at": utc_now(),
    }
    destination = store.case_dir / "bundles" / f"service-{service_type}.json"
    atomic_json_write(destination, payload)
    return destination

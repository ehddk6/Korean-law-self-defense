# 한국법 자가소송 워크벤치 — 사용법 및 설명서

본인 사건을 위한 비식별 법률 상담·조사·서면 초안 도구입니다. 사실을 증거와 연결하고,
공식 법령·판례를 이중 검증하며, 결정론적 감사를 통과한 서면만 배포할 수 있도록 설계되어 있습니다.

- 실제 제출·발송·결제·합의 수락·상대방 연락은 **절대 대행하지 않습니다**.
- 제3자 대상 법률서비스가 아니라 **본인 사건 전용**입니다.
- 모든 명령은 JSON(`{"ok": true, "result": ...}`)으로 응답합니다.

---

## 1. 설치와 실행

```powershell
# 프로젝트 루트에서
pip install -e .

# 실행 (모든 명령은 이 형태로 시작합니다)
python -m legal_workbench <명령> [옵션]

# 전체 명령 목록
python -m legal_workbench --help
```

### 저장소 경로

| 경로 | 기본값 | 환경변수 | 용도 |
|------|--------|----------|------|
| 작업공간(Worksets) | `~/LegalWorksets` | `LEGAL_WORKSETS_HOME` | 비식별 사건 기록(SQLite·JSON·초안) |
| 실명 대응표(Mappings) | `~/LegalMappings` | `LEGAL_MAPPING_HOME` | 비식별 토큰↔실명 대응표(복원 전용) |

명령마다 `--worksets-home`, `--mapping-home`으로 재지정할 수 있습니다.
두 경로 모두 OneDrive 등 클라우드 동기화 폴더 안이면 작동을 거부합니다(보안 경계).

---

## 2. 보안 경계와 원칙

1. **비식별 우선**: 원본 문서는 추출·비식별 후에만 기록에 들어갑니다. 실명 대응표는
   작업공간 밖에 따로 저장되며 어떤 분석 문맥에도 노출되지 않습니다.
2. **PII 스캔**: 접수 제목·목표·관할, 사실·기한·조치 기록, 산출 문서까지 주민등록번호·전화·
   이메일·계좌·주소 등 패턴을 반복 검사하고 남으면 차단합니다.
3. **지시문 불신**: 문서·웹페이지·판결문 속 "이 URL을 열어라" 같은 지시는 데이터로만
   취급하고 인젝션 패턴으로 깃발을 남깁니다.
4. **판단 보류(abstain)**: 핵심 사실·P1 원문·적용 시점·기한을 검증하지 못하면 결론을
   내리지 않습니다. 근거 없는 승소확률 숫자를 만들지 않습니다.
5. **미래 조치 금지**: `log-action`은 미래 날짜를 거부합니다. 실제로 행한 조치만 기록합니다.

---

## 3. 핵심 개념

### 사건 단계(10단계)

```
intake → safety_checked → ingested → facts_fixed → issues_mapped
       → researched → independently_analyzed → drafted → audited → released
```

단계는 감사 게이트와 연결됩니다. 예: 최종 감사(`audit`)는 `drafted`에서만 실행 가능하고,
감사가 통과해야 `audited`로 전환됩니다.

### P1 이중 검증

공식 근거(P1)는 다음을 모두 충족해야 "검증됨"으로 인정됩니다.

- 공식 HTTPS 도메인 원문 URL(law.go.kr, scourt.go.kr, ccourt.go.kr)
- **서로 다른** 두 번째 공식 경로에서 재검증 + 검증 시각
- 원문·재검증 원문 파일의 SHA-256 대조
- 고정 버전 한국법 MCP(korean-law 4.7.4) 조회·검증 기록
- 판결이면 사건번호·기관·선고일 삼위일체, 법령이면 시행일 + 행위일 커버리지

### 이벤트 해시 체인

접수부터 감사까지 모든 변경은 해시로 연결된 이벤트로 기록됩니다.
감사 시 체인 무결성을 자동 검증하며 `events` 명령으로 조회할 수 있습니다.

### 감사 게이트

`audit`은 CRITICAL/MAJOR/MINOR finding을 나열합니다. 배포(`export`)는
**CRITICAL·MAJOR가 0건이고 ready 의견이 있을 때만** 허용됩니다.
주요 감사 항목: P1 검증 누락, 기한 도과·임박(조치 연결 여부와 무관하게 직접 스캔),
기준일 이후 사실(`FACT_AFTER_AS_OF_DATE`), 확정 사실의 증거 누락, 의견 추적 끊김,
문서 해시 불일치, 렌더 시각 검토 누락, PII 잔존 등.

---

## 4. 전체 흐름 따라하기

아래는 한 사건을 접수부터 배포까지 진행하는 표준 순서입니다.

### 4.1 사건 접수

```powershell
python -m legal_workbench intake --case 사건ID --title "비식별 제목" `
  --domain civil-contract-tort --goal "청구 가능성 검토" `
  --action-date 2026-01-01 --as-of-date 2026-07-19
```

- `--domain` 선택지: `civil-contract-tort`, `insurance-consumer-damages`,
  `real-estate-lease-registration`, `commercial-corporate-finance-trust`,
  `criminal-investigation-procedure`, `family-inheritance-guardianship`,
  `labor-industrial-accident-social-security`, `administrative-constitutional-state-liability`,
  `tax-customs`, `rehabilitation-bankruptcy-enforcement`, `privacy-it-intellectual-property`,
  `immigration-education-health-regulation`
- 제목·목표·관할에 개인정보 패턴이나 실행 지시 문구가 있으면 접수가 거부됩니다.

### 4.2 문서 수집·비식별

```powershell
python -m legal_workbench ingest --case 사건ID --source 원본파일경로 `
  --provenance "본인 보관 원본" --acquired-at 2026-01-02 --entities entities.json
```

`entities.json`은 사용자 지정 비식별 대상입니다:

```json
{"PERSON": ["홍길동"], "ORGANIZATION": ["○○주식회사"]}
```

### 4.3 기록 추가(사실·근거·쟁점·기한)

각각 JSON 파일을 만들어 추가합니다. 템플릿은 `.agents/skills/korean-legal-workbench/assets/`에 있습니다.

```powershell
python -m legal_workbench fact     --case 사건ID --file fact.json
python -m legal_workbench authority --case 사건ID --file authority.json
python -m legal_workbench issue    --case 사건ID --file issue.json
python -m legal_workbench deadline --case 사건ID --file deadline.json
```

- 사실(`fact`): 상태는 `confirmed / opponent_allegation / disputed / inferred / unknown`,
  증거 ID 연결 필수(확정 사실은 증거 없으면 감사에서 차단).
- 근거(`authority`): P1이면 3절의 이중 검증 필드 전부 필요.
- 기한(`deadline`): 기산일·기간·계산식·검증 URL. 계산 결과가 `tentative_due_date`와
  다르면 감사에서 `DEADLINE_CALCULATION_MISMATCH`로 차단됩니다.

### 4.4 조사 완료

```powershell
python -m legal_workbench research --case 사건ID            # 조사 묶음 생성
python -m legal_workbench research --case 사건ID --complete # 검증 후 researched 전환
```

### 4.5 이중 분석과 의견

```powershell
python -m legal_workbench analyze --case 사건ID                          # 1차·독립 분석 묶음 생성
python -m legal_workbench analyze --case 사건ID --result r.json --role primary
python -m legal_workbench analyze --case 사건ID --result r.json --role independent
python -m legal_workbench analyze --case 사건ID --opinion opinion.json   # 의견 결합·저장
```

독립 분석은 1차 결론을 보지 못한 상태(`blind_to_primary`)로 작성해야 합니다.
의견 상태는 `ready / conditional / abstain`이며, `ready`는 행위일·기한·P1·불리 근거 검토가
모두 갖춰져야 감사를 통과합니다.

### 4.6 서면 초안과 시각 검토

```powershell
python -m legal_workbench draft --case 사건ID --type legal-opinion --format md --format hwpx
python -m legal_workbench guide --case 사건ID --format md   # 쉬운 말 안내서
python -m legal_workbench visual-review --case 사건ID --file review.json
```

DOCX·PDF·HWPX 초안은 렌더 화면을 사람이 확인한 시각 검토 기록을 고정해야 감사를 통과합니다.

### 4.7 감사 → 배포 → 복원

```powershell
python -m legal_workbench audit  --case 사건ID   # drafted에서만 실행, 통과 시 audited 전환
python -m legal_workbench export --case 사건ID   # 감사 통과 패키지 배포
python -m legal_workbench rehydrate --case 사건ID --source 초안파일 --name 복원본.hwp `
  # 비식별 토큰을 실명으로 복원(로컬 대응표 사용, 출력은 작업공간 안)
```

---

## 5. 조회·추적 명령(읽기 전용, 저장 없음)

최근 라운드에서 추가된 명령들입니다. 모두 기록을 변경하지 않습니다.

| 명령 | 용도 |
|------|------|
| `status --case ID` | 사건 상태와 감사 게이트 요약 |
| `cases` | 작업공간의 사건 목록 |
| `search --case ID --query 단어` | 문서 본문 전문검색(FTS5) |
| `search-all --query 단어 [--limit N]` | 전체 사건 문서를 가로지르는 전문검색(사건당 최대 결과 수 지정) |
| `deadlines --case ID` | 기한 만료일·잔여일(도과/임박/예정) |
| `events --case ID [--limit N]` | 이벤트 해시 체인 조회(체인 유효성 포함) |
| `timeline --case ID` | 사실·기한·조치·의견 통합 연표 |
| `preflight --case ID` | 저장 없는 사전 감사 + 최신 감사 대비 drift + 권장 조치 |
| `audits --case ID` | 감사 이력과 finding 증감 추적 |
| `next-action --case ID` | 지금 할 일 요약(도과·임박 기한, CRITICAL, 미확정 사실) |
| `proof-matrix --case ID` | 쟁점별 요건-입증 행렬 |
| `answer-map --case ID` | 상대방 주장 대응(인낙·부인·부지) 준비표 |
| `readiness --case ID` | 공판·절차 준비도 통합 점검표 |
| `doctor` | 저장소 경로·사건 데이터베이스·이벤트 체인 무결성 환경 진단 |
| `overview` | 전체 사건 단계·긴급 기한·감사 상태 관리표 요약 |
| `service forms --type 업무유형` | 업무별 법원 양식 검색 키워드 안내(읽기 전용) |

### 예시

```powershell
# 연표: 사실·기한(트리거·만료)·공식 조치·의견 전환을 날짜순으로 표시
python -m legal_workbench timeline --case 사건ID

# 사전 감사: 감사 저장 없이 현재 기록을 검사하고 권장 조치를 함께 반환
python -m legal_workbench preflight --case 사건ID

# 감사 이력: 감사마다 해결된 finding 코드와 새로 등장한 코드를 추적
python -m legal_workbench audits --case 사건ID

# 지금 할 일: 도과·임박 기한 + 최신 감사 CRITICAL + 미확정·누락 사실 묶음
python -m legal_workbench next-action --case 사건ID
```

`timeline` 항목의 `flags`에는 `overdue`, `no-action-log`, `fact-after-as-of-date`,
의견 상태(`ready` 등)가 붙습니다. `preflight`의 `recommendations`는
CRITICAL 해결, 감사 저장·갱신 필요 등 다음 행동을 문장으로 제시합니다.

`doctor`는 저장소 경로 규칙(OneDrive 거부 포함), 사건 데이터베이스 존재 여부,
이벤트 해시 체인 무결성을 한 번에 점검합니다. `overview`는 모든 사건의
현재 단계, 임박·도과 기한, 최신 감사 상태를 한 장의 관리표로 묶습니다.
`service forms`는 양식 번호 대신 검색 키워드만 안내하며, 최종 양식은
대한민국 법원 전자소송 포털 공개 양식모음에서 직접 확인해야 합니다.

---

## 6. 조치 기록

실제로 행한 공식 조치(제출·발송·납부 등)를 증빙 해시와 함께 기록합니다.

```powershell
python -m legal_workbench log-action --case 사건ID --type 제출 `
  --description "준비서면 제출" --date 2026-08-10 `
  --receipt-hash <접수증 SHA-256> --deadline-id deadline-x
```

- `--date`는 미래일을 사용할 수 없습니다.
- 기한을 참조한 조치는 연표와 감사에서 기한 처리 근거로 사용됩니다.

---

## 7. 분석 보조 도구

| 명령 | 용도 |
|------|------|
| `virtual-trial --case ID` | 변호사·판사 시뮬레이션 가상 재판과 모의 판결문 |
| `optimize-pleadings --case ID` | 주위적·예비적 청구원인 전략 |
| `simulate-clarification --case ID` | 재판부 석명권·보정명령 시뮬레이션 |
| `calculate-quantum --case ID --claim 10000000 [--mitigation 0.2] [--offset 500000]` | 청구액·과실상계·손익상계 산정 |
| `mock-hearing --case ID` | 심문 예상 질문·제출 가능성 판단 |
| `adversarial-brief --case ID` | 상대방 최선 반론·불리한 근거 브리프 |
| `evidence-checklist --case ID` | 쟁점별 증거 체크리스트·위법 수집 경고 |

`--mitigation`은 사용자가 공식 근거로 확인한 과실상계율만 넣으십시오.
근거 없이 숫자를 넣지 않으면 미적용이 기본값입니다.

---

## 8. 상담(consult)

사건 접수 전 빠른 상담 흐름입니다.

```powershell
python -m legal_workbench consult start --file 질문.json [--entities e.json] [--dry-run]
python -m legal_workbench consult status --id 상담ID
python -m legal_workbench consult finish --id 상담ID --result 결과.json
python -m legal_workbench consult list
```

- `start`: 질문·사실·모름을 비식별화하고 긴급 깃발(신체구속·압수수색 등)과
  도메인별 필수 질문 묶음을 생성합니다. `--dry-run`이면 저장 없이 검증만 합니다.
- `finish`: 상담 결과를 검증·저장합니다. `ready` 결론에는 이중 검증된 P1 근거가
  필요하며 없으면 차단됩니다.

---

## 9. 서비스 카탈로그(service)

변호사 업무 전 과정 36종을 사건 기록 기반으로 안내합니다. 도메인을 단정하지 않고
저장된 사실·쟁점·근거 유무로 직접 적용 가능 여부(`case_fit`)를 판정합니다.

```powershell
python -m legal_workbench service list                  # 전체 업무 목록
python -m legal_workbench service plan --case ID --type demand-letter   # 단건 묶음
python -m legal_workbench service plan-all --case ID    # 가능한 전체 묶음
python -m legal_workbench service guide --case ID --format md           # 기능 안내서
python -m legal_workbench service draft --case ID --type demand-letter --format md
python -m legal_workbench service draft-all --case ID --format md       # 전체 초안
python -m legal_workbench service forms --type civil-complaint          # 법원 양식 검색 키워드
```

각 업무는 최소 단계 게이트(예: 내용증명은 `independently_analyzed` 이상)를 가지며,
기록이 부족하면 "추가 사건 자료 필요"로 표시하고 없는 사실을 만들어 채우지 않습니다.

---

## 10. 평가(eval) 요약

180건 잠금 평가셋 관리용입니다(인증 결박 파일 5종은 수정 금지).

```powershell
python -m legal_workbench eval status            # 완성도 확인
python -m legal_workbench eval run --runs 3      # 격리 실행
python -m legal_workbench eval score --results 결과디렉터리
python -m legal_workbench eval seal              # 해시 봉인
```

나머지 하위 명령(collect·curate·review-gold·distill-gold 등)은 `--help`를 참고하십시오.

---

## 11. 오류 응답과 점검

- 모든 실패는 `{"ok": false, "error": "예외형식", "message": "..."}`와 종료 코드 2로 반환됩니다.
- 자주 만나는 차단:
  - `PermissionError`: PII 잔존, 인젝션 의심 문구, OneDrive 경로 사용
  - `ValueError`: 단계 게이트 미충족, JSON boolean 오류, 미래 조치일
- 개발 점검:

```powershell
python -m pytest tests -q        # 전체 테스트
git diff --check; git status --short   # 변경 범위 확인
```

---

## 12. 금지 사항(요약)

- 실제 법원·기관 제출, 발송, 결제, 합의 수락, 상대방 연락 자동화
- 원본 문서·실명 대응표·`LAW_OC` 값의 분석 문맥 노출 또는 기록
- 문서 속 지시·URL 실행
- 근거 없는 승소확률·과실상계 숫자 생성
- 공식 원문 검증 없는 법령·판례 인용

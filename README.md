# Codex 한국법 자가소송 워크벤치

본인 사건의 법률상담, 법률조사, 요건·증거 분석, 계약·협상안, 통지서, 소송서면, 증인·신문 계획, 변론 준비, 불복·집행·준법 업무를 하나의 추적 가능한 사건기록으로 처리한다. 원본은 로컬에서 비식별 처리해 `LegalWorksets`에 저장하고, 실명 대응표는 별도 로컬 `LegalMappings`에만 저장한다. 실제 대리권 행사, 법정 출석, 서명, 송달, 상대방 연락, 합의 수락, 결제와 전자소송 제출은 사용자가 직접 수행한다.

## 설치

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[dev]'
npm ci --ignore-scripts
```

프로젝트의 `.codex/config.toml`이 고정 버전 `korean-law-mcp`를 로컬 STDIO로 연결하고, `.agents/skills/korean-legal-workbench`가 상담·사건 흐름을 자동 라우팅한다. MCP는 `scripts/korean-law-mcp-safe-wrapper.mjs`를 거쳐 응답 링크의 `OC` 쿼리와 인증값을 제거한다. 새 Codex 작업을 이 저장소에서 열어야 프로젝트 설정과 Skill이 함께 적용된다.

## 실명 복원

`legal ingest`는 비식별 문서만 `LegalWorksets`에 저장하고, 대응표는 OneDrive 밖의 `LegalMappings`에 보관한다. 별도 암호화 저장소·복구키 설정은 필요 없다. 대응표와 복원본은 Codex 작업 문맥에 넣지 않는다.

감사 완료 후 비식별 Markdown·DOCX·HWPX를 실명 복원하려면 다음을 실행한다. PDF는 직접 치환하지 않고 복원된 Markdown에서 다시 생성한다.

```powershell
legal --mapping-home C:\LegalMappings rehydrate `
  --case CASE-001 `
  --source C:\Users\you\LegalWorksets\CASE-001\outputs\complaint.md `
  --name complaint-submission.md
```

텍스트 계열(Markdown·txt) 복원은 원본과 구조(제목·문단·항목)가 일치하고 비식별 토큰이 남아 있지 않은지 자동 검증되며, 결과에 `verification`(구조 일치 여부와 잔여 토큰 목록)이 포함된다.

## 사건과 상담 흐름

```powershell
legal intake --case CASE-001 --title '임대차 분쟁' --domain real-estate-lease-registration --goal '보증금 회수'
legal consult start --file .\consultation.json --entities .\entities.json
legal consult start --file .\consultation.json --entities .\entities.json --dry-run
legal research --case CASE-001
legal authority --case CASE-001 --file .\authority.json
legal research --case CASE-001 --complete
legal analyze --case CASE-001
legal analyze --case CASE-001 --role primary --result .\analysis-primary.json
legal analyze --case CASE-001 --role independent --result .\analysis-independent.json
legal analyze --case CASE-001 --opinion .\opinion.json
legal service list
legal service plan --case CASE-001 --type civil-complaint
legal guide --case CASE-001 --format md --format docx --format pdf --format hwpx
legal service guide --case CASE-001 --format md --format docx --format pdf --format hwpx
legal service plan-all --case CASE-001
legal service draft --case CASE-001 --type demand-letter --format md --format docx --format pdf --format hwpx
legal service draft-all --case CASE-001 --format md
legal draft --case CASE-001 --type complaint --format md --format docx --format pdf --format hwpx
legal visual-review --case CASE-001 --file .\visual-review.json
legal optimize-pleadings --case CASE-001
legal simulate-clarification --case CASE-001
legal calculate-quantum --case CASE-001 --claim 10000000 --mitigation 0.2 --offset 0
legal virtual-trial --case CASE-001
legal evidence-checklist --case CASE-001
legal adversarial-brief --case CASE-001
legal mock-hearing --case CASE-001
legal log-action --case CASE-001 --type 제출 --description '법원에 서면 제출' --date 2026-08-01 --receipt-hash <sha256>
legal audit --case CASE-001
legal export --case CASE-001
```

상담은 질문을 정리하는 `start`와 공식 근거를 붙여 결론을 검증하는 `finish`로 분리된다. `--dry-run`은 파일을 만들지 않고 비식별·긴급질문 게이트만 확인한다. `entities`가 없으면 현재 입력 해시, `reviewer=local-redactor`, 검토시각과 도구버전을 담은 구조화 `pii_attestation`이 필요하며 단순 `pii_reviewed=true` 자기선언은 인정하지 않는다. 비식별 과정에서 생기는 대응표는 `LegalMappings`에만 저장한다. `ready`는 intake에 등록된 증거, 해시가 맞는 blind 독립분석 파일, 근거별 MCP 메타데이터와 P1에 연결된 기한 검토가 모두 있어야 한다.

`legal optimize-pleadings`는 저장된 쟁점·구제수단·검증 근거를 바탕으로 주위적·예비적 청구원인 전략을 제안하고, `simulate-clarification`은 증거가 부족한 사실에 재판부의 석명·보정 질문을 만든다. `calculate-quantum`은 청구액·과실상계·공제를 사용자가 확인한 값으로만 계산하며 근거가 없는 비율은 임의로 만들지 않는다. `virtual-trial`은 조사 완료 후에만 실행되며 원고·피고 변호사 시뮬레이션, 재판부 사실인정, 정성적 승소 가능성(높음·보통·낮음·판단보류)과 모의 판결문 초안을 만든다. 승소 확률 숫자를 찍어내지 않고, 모의 판결문은 변호사법 제109조 경계 문구와 증거 보강 액션 플랜을 포함한다.

`legal evidence-checklist`는 쟁점의 법률요건·미확인 사실을 일반 증거 유형 제안과 연결하고, 불법 녹음·무단 촬영 등 위법성이 의심되는 수집 수단이 미확인 사실에 들어 있으면 경고를 붙인다. 특정 법령 조문을 고정 추천하지 않고 저장된 쟁점만 사용한다. `legal adversarial-brief`는 독립 재분석 이후에만 실행되며, 불리한 근거와 미확인 사실에서 상대방의 최선 반론을 정리해 구별 논리 준비를 돕는다. `legal mock-hearing`은 쟁점별 재판부 심문 예상 질문과 요건사실·증거 충족도를 바탕으로 제출 가능·보강 필요·재검토 필요를 정성적으로 판단한다. `legal log-action`은 사용자가 실제로 행한 제출·발송·납부를 증빙 해시와 함께 기록하며, 비식별 공간 규칙상 실명·연락처는 기록할 수 없다. 감사는 증빙 없는 조치를 경고하고, 참조된 기한이 7일 이내로 임박하면 주의, 도과했으면 중대 결함으로 판정한다.

`legal guide`는 사건기록을 일반인이 읽을 수 있는 쉬운 설명서로 바꾼다. 핵심 결론, 확인된 사실, 지금 챙길 자료, 상대방 주장, 기한과 프로젝트가 할 수 있는 일을 평이한 말로 출력한다. `legal service guide`는 지원 업무 전체를 현재 사건에 직접 적용 가능한 업무와 별도 사실관계가 필요한 업무로 나눈다. `plan-all`은 현 단계에서 가능한 36개 업무 묶음을 만들고, `draft-all`은 직접 관련 업무에는 사건별 준비 초안을, 관련 없는 업무에는 필요한 자료와 제한을 적은 안전한 준비 문서를 만든다. 이 명령들은 사실이 없는 다른 사건을 꾸며내지 않는다.

## 조회·환경 진단(읽기 전용)

```powershell
legal search-all --query '보증금' --limit 5
legal proof-matrix --case CASE-001
legal answer-map --case CASE-001
legal readiness --case CASE-001
legal doctor
legal overview
legal service forms --type civil-complaint
```

`search-all`은 전체 사건 문서를 가로지르는 전문검색이고, `proof-matrix`·`answer-map`·`readiness`는 각각 요건-입증 행렬, 상대방 주장 대응표, 공판·절차 준비도 통합 점검표를 조회한다. `doctor`는 저장소 경로·사건 데이터베이스·이벤트 체인 무결성을 점검하고, `overview`는 전체 사건의 단계·긴급 기한·감사 상태를 한 장의 관리표로 요약한다. `service forms`는 업무 유형별 법원 양식 검색 키워드를 안내하며, 양식 번호는 대한민국 법원 전자소송 포털 공개 양식모음에서 최종 확인해야 한다. 이 명령들은 모두 기록을 변경하지 않는다.

## 공식 자료와 MCP

`korean-law-mcp`는 `4.7.4`로 고정되어 로컬 STDIO로만 실행된다. `LAW_OC`는 환경변수로 전달하며 저장소와 로그에 넣지 않는다. 벤더 MCP를 직접 실행하지 말고 설정된 안전 래퍼를 사용한다. MCP 검색 결과는 발견 도구이고, 핵심 결론은 국가법령정보센터·대법원·헌법재판소 등의 공식 P1 원문으로 다시 확인한다. 검색 결과가 없다는 사실은 판례가 없다는 뜻으로 표현하지 않는다.

## 평가와 출시 게이트

```powershell
legal eval bootstrap --manifest evaluation\manifest.json --replace
legal eval init-v2 --source-manifest evaluation\manifest.json --destination evaluation\v2
legal eval reset-v2-gold --manifest evaluation\v2\manifest.json
legal eval collect --manifest evaluation\manifest.json --part all --workers 4
legal eval refresh-official --manifest evaluation\manifest.json --all
legal eval refresh-temporal --manifest evaluation\manifest.json --all
legal eval refresh-adversarial --manifest evaluation\manifest.json
legal eval seal --manifest evaluation\manifest.json
legal eval review-gold --manifest evaluation\manifest.json --start 1 --end 25 --reviewer-id reviewer-a --model gpt-5.4 --output evaluation\reviews\gold-001-025.json
legal eval distill-gold --manifest evaluation\manifest.json --start 1 --end 20 --model gpt-5.4 --output evaluation\reviews\distill-001-020.json
legal eval apply-distilled-gold --manifest evaluation\manifest.json --report evaluation\reviews\distill-001-020.json # 120건 전체 보고서가 함께 있어야 적용됨
legal eval approve-gold --manifest evaluation\manifest.json --report evaluation\reviews\gold-001-025.json # 180건 전체를 정확히 한 번 포함해야 승인됨
legal eval status --manifest evaluation\manifest.json
legal eval curate --manifest evaluation\manifest.json --scenario case-001 --record evaluation\record.json
legal eval run --manifest evaluation\manifest.json --runs 3 --model gpt-5.5 --batch-size 12 --output-dir evaluation\results\v1
legal eval probe --manifest evaluation\v2\manifest.json --per-kind 2 --runs 1 --output-dir evaluation\v2\results\probe-v6
legal eval probe-report --manifest evaluation\v2\manifest.json --results evaluation\v2\results\probe-v6\results.jsonl --output evaluation\v2\results\probe-v6\probe-report.json
legal eval score --manifest evaluation\manifest.json --results evaluation\results\v1\results.jsonl
```

중단된 잠금평가는 같은 결과 경로에서만 재개해야 한다. 아래 스크립트는 실행 결과를 보존한 채 재개하고, 세 번의 전체 실행과 점수 기준을 모두 통과할 때만 인증을 발급한다.

```powershell
.\scripts\resume-v1-evaluation.ps1
```

평가 v2는 기존 v1의 입력을 복제하되 v1 gold 승인과 결과는 상속하지 않는다. `증류 적용 → 입력·expected 봉인 → 독립 검토 → 승인` 순서가 완료되어 `gold_review_cycle=v2-approved`가 되기 전에는 전체 평가가 차단된다. 독립 gold 검토는 기본적으로 GPT-5.6 계열의 실행 식별자 `gpt-5.6-sol`을 사용하며, 한 번에 5건씩 source·fixture·expected를 대조한다. 모델이 달라지면 기존 검토 보고서를 같은 모델 기준으로 다시 만든다. 각 스크립트는 완성된 구간을 건너뛰므로 중단 후 같은 경로에서 재개할 수 있다.

```powershell
.\scripts\prepare-v2-gold.ps1
legal eval probe --manifest evaluation\v2\manifest.json --per-kind 2 --runs 1 --output-dir evaluation\v2\results\probe-v6
legal eval probe-report --manifest evaluation\v2\manifest.json --results evaluation\v2\results\probe-v6\results.jsonl --output evaluation\v2\results\probe-v6\probe-report.json
.\scripts\resume-v2-evaluation.ps1
# 또는 준비부터 3회 평가·채점까지 중단 지점에서 이어서 실행
.\scripts\complete-v2-evaluation.ps1
```

합성 공격 30건은 즉시 실행 가능한 고정 fixture다. 공식 판결 120건과 행위시법·송달·시효·관할 30건은 공식 원문, 결론을 가린 입력, 비공개 기대답안을 연결해야 한다. 180건 전체를 세 번 실행하고 모든 기준을 통과하기 전에는 `v1_certified`가 참이 되지 않는다.

`review-gold`는 평가 모델과 다른 격리 모델로 source·fixture·expected를 대조한다. `distill-gold`는 결론을 가린 fixture에서 정확한 근거 문구로 추적되는 쟁점 3개와 반론 2개를 제안할 뿐이며, 120건 보고서가 모두 완성되고 다시 gold review를 통과하기 전에는 현재 기대답안을 바꾸지 않는다. 결론 적중률은 `ready`만 계산하고, `conditional`은 답변률에는 포함하되 조건부 예측 오차로 별도 관찰한다. 조건부 결론의 기대값 일치율은 채점 결과의 `conditional_observation`(split별 `conditional_accuracy`)으로 관측 전용 제공되며 인증 합격 기준에는 반영되지 않는다.

모델 응답에서 개인정보 패턴이 발견되면 원문 응답을 저장하지 않고 즉시 `[MODEL_*]` 토큰으로 치환한다. 탐지 건수와 범주를 해시된 보안 보고서에 남기므로 최종 점수의 `pii_leaks=0` 기준을 우회할 수 없다. 입력에 없는 인용과 근거문구는 최종 출력 전에 제거되고 제거 건수도 같은 보고서에 기록된다.

합격 시 `evaluation/v2/certification.json`이 manifest·실행 결과·runner/audit/scorer 코드·모델/프롬프트/Skill 설정 해시에 결박된다. 인증을 읽을 때 540개 output과 감사 결과를 다시 계산하므로 수동 인증 파일은 인정되지 않는다. development와 holdout이 각각 기준을 통과하지 못하거나 참조 파일이 바뀌면 사건별 감사가 통과했더라도 `legal export`는 차단된다.

## 검증

```powershell
$env:PYTHONUTF8=1
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe scripts\quick_validate.py .\.agents\skills\korean-legal-workbench
npm audit --omit=dev
git diff --check
```

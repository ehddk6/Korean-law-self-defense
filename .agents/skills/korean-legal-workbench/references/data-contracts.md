# JSON 데이터 계약

Skill assets의 템플릿을 복사해 값만 채운다. 식별자는 생략하면 CLI가 생성한다.

- FactRecord: `text`, `status` 필수. confirmed이면 `evidence_ids` 필수.
- AuthorityRecord: `title`, `source_tier`, `official_url`, `citation` 필수. P1은 `source_text_file`, `verification_text_file`, 서로 다른 공식 URL, `verified_at`, 시행일 또는 판결 메타데이터가 필요하며 CLI가 파일 SHA-256을 계산한다.
- IssueRecord: `title`, `legal_elements`, `burden` 필수. 유리·불리 근거 ID, 사실 ID, 누락 사실, 구제수단 구분.
- DeadlineRecord: verified이면 기산일, 근거, 산식, Authority ID, 잠정 만료일, 휴일 보정 검토가 필수다. boolean은 문자열이 아닌 JSON boolean으로 쓴다.
- OpinionRecord: 상태, 결론, 세 시나리오, 사실·근거·쟁점 ID, 결론 변경 조건 필수. 모든 상태에 고정된 1차·독립 분석 결과 참조가 필요하고, ready이면 행위시법·불리한 근거 검토 완료도 필수다.

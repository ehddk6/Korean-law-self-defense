# 문서 출력 절차

1. `legal draft`로 비식별 Markdown을 만든다.
2. DOCX·PDF·HWPX 파생본을 생성한다.
3. DOCX는 ZIP/XML과 필수 part를 검증한다.
4. PDF는 페이지 수를 검사하고 PNG로 렌더링해 잘림·겹침·한글 폰트를 확인한다.
5. HWPX는 mimetype 첫 엔트리, ZIP_STORED, 필수 XML, 네임스페이스와 XML 유효성을 검증한다.
6. `legal audit` 통과 후 OneDrive 밖의 `LegalMappings`에 저장된 대응표로 `legal rehydrate`를 실행한다.
7. 복원된 PDF를 직접 치환하지 말고 복원된 원문에서 다시 생성한다.
8. 전자소송 manifest의 파일명, 크기, 해시와 첨부 순서를 사용자가 최종 확인한다.

실제 제출, 전자서명, 송달료·인지대 결제는 자동화하지 않는다.

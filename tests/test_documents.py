from pathlib import Path

from legal_workbench.documents import (
    create_docx,
    create_hwpx,
    create_pdf,
    extract_document,
    validate_docx,
    validate_hwpx,
    validate_pdf,
)


MARKDOWN = """# 법률의견서

## 결론

[PERSON_001]의 사건에 관한 사용자 검토용 문서다.

## 쟁점

- 공식 근거 확인
- 반대 논리 검토
"""


def test_docx_and_pdf_generation(tmp_path: Path) -> None:
    docx = create_docx(MARKDOWN, tmp_path / "opinion.docx", title="검증 사건")
    pdf = create_pdf(MARKDOWN, tmp_path / "opinion.pdf", title="검증 사건")
    assert validate_docx(docx)["valid"] is True
    assert validate_pdf(pdf)["page_count"] >= 1
    assert "법률의견서" in extract_document(docx).text
    assert "법률의견서" in extract_document(pdf).text


def test_hwpx_generation_with_installed_skill(tmp_path: Path) -> None:
    hwpx = create_hwpx(MARKDOWN, tmp_path / "opinion.hwpx", title="검증 사건")
    assert validate_hwpx(hwpx)["valid"] is True
    assert "법률의견서" in extract_document(hwpx).text


def test_leading_markdown_title_is_not_duplicated_in_docx(tmp_path: Path) -> None:
    title = "사건 제목"
    output = create_docx(f"# {title}\n\n## 결론\n내용", tmp_path / "deduplicated.docx", title=title)
    assert extract_document(output).text.count(title) == 1

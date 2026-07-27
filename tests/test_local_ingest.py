import json
from pathlib import Path

import pytest

from legal_workbench.cli import build_parser, dispatch
from legal_workbench.workflow import ingest_document, intake_case


def test_ingest_and_rehydrate_with_separate_local_mapping(tmp_path: Path) -> None:
    worksets = tmp_path / "worksets"
    mappings = tmp_path / "mappings"
    source = tmp_path / "private-contract.txt"
    entities = tmp_path / "entities.json"
    source.write_text("홍길동의 연락처는 010-1234-5678이다.", encoding="utf-8")
    entities.write_text(json.dumps({"PERSON": ["홍길동"]}, ensure_ascii=False), encoding="utf-8")
    intake_case(
        case_id="case-local-ingest",
        title="계약 분쟁",
        domain="civil-contract-tort",
        goal="증거 정리",
        forum=None,
        action_date=None,
        as_of_date="2026-07-26",
        worksets_home=worksets,
    )

    metadata = ingest_document(
        case_id="case-local-ingest",
        source=source,
        provenance="본인 보관 원본",
        acquired_at="2026-07-26",
        entities_file=entities,
        mapping_home=mappings,
        worksets_home=worksets,
    )

    assert metadata["source_path_token"] == "[LOCAL_SOURCE]"
    assert metadata["source_filename"] == "[SOURCE_FILENAME]"
    sanitized = next((worksets / "case-local-ingest" / "documents").glob("*.sanitized.txt")).read_text(encoding="utf-8")
    assert "홍길동" not in sanitized
    assert "010-1234-5678" not in sanitized
    assert str(source) not in json.dumps(metadata, ensure_ascii=False)
    mapping = mappings / "mappings" / "case-local-ingest.json"
    assert mapping.is_file()
    assert all("홍길동" not in item.read_text(encoding="utf-8") for item in worksets.rglob("*.json"))

    sanitized_path = next((worksets / "case-local-ingest" / "documents").glob("*.sanitized.txt"))
    args = build_parser().parse_args(
        [
            "--mapping-home", str(mappings),
            "--worksets-home", str(worksets),
            "rehydrate",
            "--case", "case-local-ingest",
            "--source", str(sanitized_path),
            "--name", "submission.txt",
        ]
    )
    output = Path(dispatch(args)["output"])
    assert output.is_file()
    assert output.read_text(encoding="utf-8") == "홍길동의 연락처는 010-1234-5678이다."
    assert output.is_relative_to(mappings / "rehydrated")


def test_ingest_refuses_a_source_stored_in_worksets(tmp_path: Path) -> None:
    worksets = tmp_path / "worksets"
    source = worksets / "source.txt"
    entities = tmp_path / "entities.json"
    worksets.mkdir()
    source.write_text("원본", encoding="utf-8")
    entities.write_text("{}", encoding="utf-8")
    intake_case(
        case_id="case-reject-source",
        title="계약 분쟁",
        domain="civil-contract-tort",
        goal="증거 정리",
        forum=None,
        action_date=None,
        as_of_date="2026-07-26",
        worksets_home=worksets,
    )

    with pytest.raises(PermissionError, match="LegalWorksets 밖"):
        ingest_document(
            case_id="case-reject-source",
            source=source,
            provenance="본인 보관 원본",
            acquired_at="2026-07-26",
            entities_file=entities,
            worksets_home=worksets,
        )

from __future__ import annotations

import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _run_node(source: str) -> dict[str, object]:
    completed = subprocess.run(
        ["node", "--input-type=module", "-e", source],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return json.loads(completed.stdout)


def test_precedent_search_links_never_retain_api_key() -> None:
    result = _run_node(
        "import { sanitizePrecedentSearchResult as clean } from './scripts/law-api-guard.mjs';"
        "const out=clean({hits:[{id:'603539',link:'/DRF/lawService.do?OC=super-secret&target=prec'}]});"
        "console.log(JSON.stringify(out));"
    )
    link = str(result["hits"][0]["link"])  # type: ignore[index]
    assert "OC=" not in link
    assert "super-secret" not in link
    assert link == "https://www.law.go.kr/LSW/precInfoP.do?precSeq=603539"


def test_official_api_failure_is_not_misreported_as_no_results() -> None:
    result = _run_node(
        "import { assertOfficialApiSuccess as check } from './scripts/law-api-guard.mjs';"
        "let error='';try{check('<LawSearch><totalCnt>0</totalCnt><resultCode>01</resultCode><resultMsg>fail</resultMsg></LawSearch>','search');}"
        "catch(e){error=String(e.message)}console.log(JSON.stringify({error}));"
    )
    assert "resultCode=01" in str(result["error"])
    assert "검색 결과 없음" not in str(result["error"])


def test_mcp_output_sanitizer_removes_oc_and_secret_recursively() -> None:
    result = _run_node(
        "import { sanitizeMcpValue as clean } from './scripts/mcp-output-sanitizer.mjs';"
        "const out=clean({content:[{text:'https://www.law.go.kr/DRF/lawService.do?OC=super-secret&amp;target=prec&amp;ID=1'}],nested:{token:'super-secret'}},'super-secret');"
        "console.log(JSON.stringify(out));"
    )
    serialized = json.dumps(result, ensure_ascii=False)
    assert "super-secret" not in serialized
    assert "OC=" not in serialized
    assert "target=prec" in serialized

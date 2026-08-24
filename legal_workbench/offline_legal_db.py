from __future__ import annotations

"""로컬 법률 원문 스냅샷을 발견 도구로만 사용하는 안전한 폴백 검색기."""

import sqlite3
from pathlib import Path
from typing import Any, Callable

from .security import scan_mcp_query, scan_prompt_injection


class OfflineLegalDbError(RuntimeError):
    """오프라인 법률 DB가 발견 도구로 안전하게 쓰일 수 없을 때 발생한다."""


REQUIRED_METADATA = frozenset(
    {
        "dataset_id",
        "dataset_version",
        "created_at",
        "license",
        "p1_verification_required",
    }
)
REQUIRED_SOURCE_COLUMNS = frozenset(
    {
        "source_id",
        "title",
        "content",
        "source_type",
        "official_url",
        "effective_from",
        "retrieved_at",
        "source_sha256",
    }
)


def search_offline_legal_db(
    query: str,
    *,
    database_path: Path,
    limit: int = 10,
) -> dict[str, Any]:
    """검색용 스냅샷에서 후보를 찾되, P1 근거로 확정하지는 않는다.

    DB는 ``metadata(key, value)``와 ``legal_sources`` 테이블을 가져야 한다.
    결과는 AuthorityRecord로 바로 넣을 수 없고, 각 결과의 공식 원문과 별도
    공식 경로를 P1 게이트에서 다시 확인해야 한다.
    """

    normalized_query = _validate_query(query)
    normalized_limit = _validate_limit(limit)
    path = Path(database_path).expanduser().resolve()
    if not path.is_file():
        raise OfflineLegalDbError(f"오프라인 법률 DB를 찾을 수 없습니다: {path}")

    try:
        connection = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise OfflineLegalDbError("오프라인 법률 DB를 읽기 전용으로 열 수 없습니다.") from exc

    try:
        metadata = _load_metadata(connection)
        _validate_schema(connection)
        pattern = f"%{normalized_query.lower()}%"
        rows = connection.execute(
            """
            SELECT source_id, title, content, source_type, official_url,
                   effective_from, retrieved_at, source_sha256
            FROM legal_sources
            WHERE lower(title) LIKE ? OR lower(content) LIKE ?
            ORDER BY title COLLATE NOCASE, source_id
            LIMIT ?
            """,
            (pattern, pattern, normalized_limit),
        ).fetchall()
    except sqlite3.Error as exc:
        raise OfflineLegalDbError("오프라인 법률 DB 검색 중 스키마 또는 조회 오류가 발생했습니다.") from exc
    finally:
        connection.close()

    results = [
        {
            "source_id": str(row[0]),
            "title": str(row[1]),
            "snippet": _snippet(str(row[2]), normalized_query),
            "source_type": str(row[3]),
            "official_url": str(row[4]),
            "effective_from": str(row[5] or ""),
            "retrieved_at": str(row[6]),
            "source_sha256": str(row[7]),
            "offline_source": True,
            "discovery_only": True,
            "p1_verification_required": True,
            "status": "needs-p1-dual-verification",
        }
        for row in rows
    ]
    return {
        "format": "legal-workbench-offline-legal-search-v1",
        "query": normalized_query,
        "database": {
            "dataset_id": metadata["dataset_id"],
            "dataset_version": metadata["dataset_version"],
            "created_at": metadata["created_at"],
            "license": metadata["license"],
        },
        "results": results,
        "result_count": len(results),
        "status": "needs-p1-dual-verification",
        "notice": (
            "오프라인 DB 결과는 조사 단서일 뿐입니다. 사건 결론이나 AuthorityRecord의 P1 근거로 "
            "사용하기 전에 서로 다른 공식 HTTPS 원문 두 곳, 원문 해시, 적용 시점을 다시 검증해야 합니다."
        ),
    }


def search_with_offline_fallback(
    query: str,
    *,
    primary_search: Callable[[str], Any],
    database_path: Path,
    limit: int = 10,
) -> dict[str, Any]:
    """외부 검색 장애 시에만 오프라인 발견 결과로 전환한다.

    이 함수는 외부 검색 자체를 수행하거나 성공을 P1 검증으로 간주하지 않는다.
    호출자가 MCP 결과를 사용하려면 기존의 독립 P1 검증 게이트를 통과해야 한다.
    """

    normalized_query = _validate_query(query)
    try:
        return {
            "mode": "primary",
            "primary_result": primary_search(normalized_query),
            "p1_verification_required": True,
        }
    except (ConnectionError, TimeoutError, OSError) as exc:
        try:
            fallback = search_offline_legal_db(
                normalized_query,
                database_path=database_path,
                limit=limit,
            )
        except OfflineLegalDbError as fallback_exc:
            return {
                "mode": "abstain",
                "primary_error": type(exc).__name__,
                "fallback_error": str(fallback_exc),
                "p1_verification_required": True,
                "status": "abstain",
                "notice": "외부 검색과 오프라인 발견 DB를 모두 검증 가능한 상태로 사용할 수 없어 결론을 보류합니다.",
            }
        return {
            "mode": "offline-fallback",
            "primary_error": type(exc).__name__,
            "fallback": fallback,
            "p1_verification_required": True,
            "status": "needs-p1-dual-verification",
        }


def _validate_query(query: str) -> str:
    normalized = str(query).strip()
    if len(normalized) < 2:
        raise ValueError("오프라인 법률 검색어는 두 글자 이상이어야 합니다.")
    findings = [*scan_mcp_query(normalized), *scan_prompt_injection(normalized)]
    if findings:
        categories = ", ".join(sorted({item.category for item in findings}))
        raise PermissionError(f"검색어에 개인정보 또는 실행 지시 형태의 텍스트가 있습니다: {categories}")
    return normalized


def _validate_limit(limit: int) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
        raise ValueError("검색 결과 수는 1~50 사이의 정수여야 합니다.")
    return limit


def _load_metadata(connection: sqlite3.Connection) -> dict[str, str]:
    try:
        rows = connection.execute("SELECT key, value FROM metadata").fetchall()
    except sqlite3.Error as exc:
        raise OfflineLegalDbError("오프라인 법률 DB에 metadata(key, value) 테이블이 필요합니다.") from exc
    metadata = {str(key): str(value) for key, value in rows}
    missing = sorted(REQUIRED_METADATA - set(metadata))
    if missing:
        raise OfflineLegalDbError("오프라인 법률 DB 메타데이터가 부족합니다: " + ", ".join(missing))
    if metadata["p1_verification_required"].strip().lower() not in {"1", "true", "yes"}:
        raise OfflineLegalDbError("오프라인 법률 DB는 P1 재검증 필수 정책을 명시해야 합니다.")
    return metadata


def _validate_schema(connection: sqlite3.Connection) -> None:
    try:
        rows = connection.execute("PRAGMA table_info(legal_sources)").fetchall()
    except sqlite3.Error as exc:
        raise OfflineLegalDbError("오프라인 법률 DB의 legal_sources 테이블을 확인할 수 없습니다.") from exc
    columns = {str(row[1]) for row in rows}
    missing = sorted(REQUIRED_SOURCE_COLUMNS - columns)
    if missing:
        raise OfflineLegalDbError("legal_sources 테이블에 필요한 열이 없습니다: " + ", ".join(missing))


def _snippet(content: str, query: str, *, width: int = 240) -> str:
    compact = " ".join(content.split())
    location = compact.lower().find(query.lower())
    if location < 0:
        return compact[:width]
    start = max(0, location - width // 3)
    end = min(len(compact), start + width)
    prefix = "…" if start else ""
    suffix = "…" if end < len(compact) else ""
    return prefix + compact[start:end] + suffix

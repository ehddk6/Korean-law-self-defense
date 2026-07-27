from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator

from .models import (
    AuthorityRecord,
    CaseRecord,
    CaseStage,
    DeadlineRecord,
    EvidenceRecord,
    FactRecord,
    IssueRecord,
    OpinionRecord,
    STAGE_ORDER,
    utc_now,
)
from .security import validate_safe_identifier


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    domain TEXT NOT NULL,
    jurisdiction TEXT NOT NULL,
    forum TEXT,
    goal TEXT NOT NULL,
    action_date TEXT,
    as_of_date TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    stage TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS documents (
    document_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    media_type TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    sanitized_path TEXT NOT NULL,
    extraction_status TEXT NOT NULL,
    extraction_confidence REAL,
    injection_flags_json TEXT NOT NULL,
    residual_pii_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
    document_id UNINDEXED,
    case_id UNINDEXED,
    content,
    tokenize = 'unicode61'
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS facts (
    fact_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS authorities (
    authority_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS issues (
    issue_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS deadlines (
    deadline_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS opinions (
    opinion_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_reports (
    audit_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    payload_json TEXT NOT NULL,
    passed INTEGER NOT NULL,
    release_allowed INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_documents_case ON documents(case_id);
CREATE INDEX IF NOT EXISTS idx_facts_case ON facts(case_id);
CREATE INDEX IF NOT EXISTS idx_authorities_case ON authorities(case_id);
CREATE INDEX IF NOT EXISTS idx_issues_case ON issues(case_id);
CREATE INDEX IF NOT EXISTS idx_deadlines_case ON deadlines(case_id);
CREATE INDEX IF NOT EXISTS idx_opinions_case ON opinions(case_id);
CREATE INDEX IF NOT EXISTS idx_audits_case ON audit_reports(case_id);
"""


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class CaseStore:
    def __init__(self, worksets_home: Path, case_id: str):
        self.worksets_home = Path(worksets_home).expanduser().resolve()
        self.case_id = validate_safe_identifier(case_id, field="case_id")
        self.case_dir = self.worksets_home / self.case_id
        self.db_path = self.case_dir / "case.db"

    def initialize_directories(self) -> None:
        self.case_dir.mkdir(parents=True, exist_ok=True)
        for name in ("documents", "authorities", "drafts", "visual", "audits", "bundles", "exports"):
            (self.case_dir / name).mkdir(exist_ok=True)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.initialize_directories()
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def create_case(self, record: CaseRecord) -> None:
        if record.case_id != self.case_id:
            raise ValueError("case_id가 저장소와 일치하지 않습니다.")
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO cases (
                    case_id,title,domain,jurisdiction,forum,goal,action_date,
                    as_of_date,risk_level,stage,created_at,updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    record.case_id,
                    record.title,
                    record.domain,
                    record.jurisdiction,
                    record.forum,
                    record.goal,
                    record.action_date,
                    record.as_of_date,
                    str(record.risk_level),
                    str(record.stage),
                    record.created_at,
                    record.updated_at,
                ),
            )
            self._append_event(conn, "case_created", record.to_dict())

    def get_case(self) -> dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM cases WHERE case_id=?", (self.case_id,)).fetchone()
        if row is None:
            raise KeyError(f"사건을 찾을 수 없습니다: {self.case_id}")
        return dict(row)

    def transition(self, target: CaseStage, *, reason: str) -> None:
        with self.connect() as conn:
            row = conn.execute("SELECT stage FROM cases WHERE case_id=?", (self.case_id,)).fetchone()
            if row is None:
                raise KeyError(f"사건을 찾을 수 없습니다: {self.case_id}")
            current = CaseStage(row["stage"])
            current_index = STAGE_ORDER.index(current)
            target_index = STAGE_ORDER.index(target)
            if target_index < current_index:
                raise ValueError(f"사건 상태를 되돌릴 수 없습니다: {current} -> {target}")
            if target_index > current_index + 1:
                raise ValueError(f"사건 상태를 건너뛸 수 없습니다: {current} -> {target}")
            if target_index == current_index:
                return
            now = utc_now()
            conn.execute(
                "UPDATE cases SET stage=?,updated_at=? WHERE case_id=?",
                (str(target), now, self.case_id),
            )
            self._append_event(
                conn,
                "stage_transition",
                {"from": str(current), "to": str(target), "reason": reason},
            )

    def add_document(
        self,
        *,
        document_id: str,
        filename: str,
        media_type: str,
        sha256: str,
        sanitized_path: str,
        content: str,
        extraction_status: str,
        extraction_confidence: float | None,
        injection_flags: list[dict[str, Any]],
        residual_pii: list[dict[str, Any]],
    ) -> None:
        document_id = validate_safe_identifier(document_id, field="document_id")
        created_at = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO documents VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    document_id,
                    self.case_id,
                    filename,
                    media_type,
                    sha256,
                    sanitized_path,
                    extraction_status,
                    extraction_confidence,
                    canonical_json(injection_flags),
                    canonical_json(residual_pii),
                    created_at,
                ),
            )
            conn.execute(
                "INSERT INTO documents_fts(document_id,case_id,content) VALUES (?,?,?)",
                (document_id, self.case_id, content),
            )
            self._append_event(
                conn,
                "document_ingested",
                {
                    "document_id": document_id,
                    "filename": filename,
                    "sha256": sha256,
                    "injection_flag_count": len(injection_flags),
                    "residual_pii_count": len(residual_pii),
                },
            )

    def add_evidence(self, record: EvidenceRecord) -> None:
        self._insert_payload("evidence", "evidence_id", record.evidence_id, record.to_dict())

    def add_fact(self, record: FactRecord) -> None:
        self._insert_payload("facts", "fact_id", record.fact_id, record.to_dict())

    def add_authority(self, record: AuthorityRecord) -> None:
        self._insert_payload("authorities", "authority_id", record.authority_id, record.to_dict())

    def add_issue(self, record: IssueRecord) -> None:
        self._insert_payload("issues", "issue_id", record.issue_id, record.to_dict())

    def add_deadline(self, record: DeadlineRecord) -> None:
        self._insert_payload("deadlines", "deadline_id", record.deadline_id, record.to_dict())

    def add_opinion(self, record: OpinionRecord) -> None:
        self._insert_payload("opinions", "opinion_id", record.opinion_id, record.to_dict())

    def add_audit_report(self, payload: dict[str, Any]) -> None:
        validate_safe_identifier(str(payload["audit_id"]), field="audit_id")
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_reports(
                    audit_id,case_id,payload_json,passed,release_allowed,created_at
                ) VALUES (?,?,?,?,?,?)
                """,
                (
                    payload["audit_id"],
                    self.case_id,
                    canonical_json(payload),
                    int(bool(payload["passed"])),
                    int(bool(payload["release_allowed"])),
                    payload["created_at"],
                ),
            )
            self._append_event(
                conn,
                "audit_completed",
                {
                    "audit_id": payload["audit_id"],
                    "passed": payload["passed"],
                    "release_allowed": payload["release_allowed"],
                },
            )

    def list_documents(self) -> list[dict[str, Any]]:
        return self._list_rows("documents")

    def list_payloads(self, table: str) -> list[dict[str, Any]]:
        allowed = {
            "evidence",
            "facts",
            "authorities",
            "issues",
            "deadlines",
            "opinions",
            "audit_reports",
        }
        if table not in allowed:
            raise ValueError(f"허용되지 않은 테이블: {table}")
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT payload_json FROM {table} WHERE case_id=? ORDER BY created_at",
                (self.case_id,),
            ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def search_documents(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT document_id, snippet(documents_fts,2,'[',']','…',18) AS snippet,
                       bm25(documents_fts) AS score
                FROM documents_fts
                WHERE documents_fts MATCH ? AND case_id=?
                ORDER BY score LIMIT ?
                """,
                (query, self.case_id, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def latest_audit(self) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT payload_json FROM audit_reports
                WHERE case_id=? ORDER BY created_at DESC LIMIT 1
                """,
                (self.case_id,),
            ).fetchone()
        return json.loads(row["payload_json"]) if row else None

    def verify_event_chain(self) -> bool:
        previous_hash = "GENESIS"
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE case_id=? ORDER BY sequence",
                (self.case_id,),
            ).fetchall()
        for row in rows:
            if row["previous_hash"] != previous_hash:
                return False
            material = canonical_json(
                {
                    "case_id": row["case_id"],
                    "event_type": row["event_type"],
                    "payload_json": row["payload_json"],
                    "previous_hash": row["previous_hash"],
                    "created_at": row["created_at"],
                }
            )
            expected = hashlib.sha256(material.encode("utf-8")).hexdigest()
            if expected != row["event_hash"]:
                return False
            previous_hash = row["event_hash"]
        return True

    def integrity_check(self) -> list[str]:
        with self.connect() as conn:
            rows = conn.execute("PRAGMA integrity_check").fetchall()
        return [row[0] for row in rows]

    def _list_rows(self, table: str) -> list[dict[str, Any]]:
        if table != "documents":
            raise ValueError("지원하지 않는 행 조회입니다.")
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM documents WHERE case_id=? ORDER BY created_at",
                (self.case_id,),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["injection_flags"] = json.loads(item.pop("injection_flags_json"))
            item["residual_pii"] = json.loads(item.pop("residual_pii_json"))
            result.append(item)
        return result

    def _insert_payload(self, table: str, id_column: str, record_id: str, payload: dict[str, Any]) -> None:
        allowed = {
            ("evidence", "evidence_id"),
            ("facts", "fact_id"),
            ("authorities", "authority_id"),
            ("issues", "issue_id"),
            ("deadlines", "deadline_id"),
            ("opinions", "opinion_id"),
        }
        if (table, id_column) not in allowed:
            raise ValueError("허용되지 않은 payload 테이블입니다.")
        record_id = validate_safe_identifier(record_id, field=id_column)
        created_at = payload.get("created_at", utc_now())
        with self.connect() as conn:
            conn.execute(
                f"INSERT INTO {table}({id_column},case_id,payload_json,created_at) VALUES (?,?,?,?)",
                (record_id, self.case_id, canonical_json(payload), created_at),
            )
            self._append_event(conn, f"{table}_added", {id_column: record_id})

    def _append_event(self, conn: sqlite3.Connection, event_type: str, payload: dict[str, Any]) -> None:
        row = conn.execute(
            "SELECT event_hash FROM events WHERE case_id=? ORDER BY sequence DESC LIMIT 1",
            (self.case_id,),
        ).fetchone()
        previous_hash = row["event_hash"] if row else "GENESIS"
        created_at = utc_now()
        payload_json = canonical_json(payload)
        material = canonical_json(
            {
                "case_id": self.case_id,
                "event_type": event_type,
                "payload_json": payload_json,
                "previous_hash": previous_hash,
                "created_at": created_at,
            }
        )
        event_hash = hashlib.sha256(material.encode("utf-8")).hexdigest()
        conn.execute(
            """
            INSERT INTO events(case_id,event_type,payload_json,previous_hash,event_hash,created_at)
            VALUES (?,?,?,?,?,?)
            """,
            (self.case_id, event_type, payload_json, previous_hash, event_hash, created_at),
        )


def discover_cases(worksets_home: Path) -> Iterable[str]:
    root = Path(worksets_home).expanduser()
    if not root.exists():
        return []
    return sorted(path.name for path in root.iterdir() if (path / "case.db").is_file())

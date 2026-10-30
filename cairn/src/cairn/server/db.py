from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

DEFAULT_DB = Path.home() / ".local" / "share" / "cairn" / "cairn.db"

_db_path: Path | None = None

SCHEMA = """\
CREATE TABLE IF NOT EXISTS settings (
    intent_timeout INTEGER NOT NULL DEFAULT 15,
    reason_timeout INTEGER NOT NULL DEFAULT 15
);

INSERT OR IGNORE INTO settings (rowid, intent_timeout, reason_timeout) VALUES (1, 15, 15);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    bootstrap_enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    reason_worker TEXT,
    reason_trigger TEXT,
    reason_started_at TEXT,
    reason_last_heartbeat_at TEXT,
    reason_lease_id TEXT
);

CREATE TABLE IF NOT EXISTS facts (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'verified',
    category TEXT,
    target TEXT,
    component TEXT,
    version TEXT,
    confidence REAL,
    created_by TEXT,
    created_at TEXT,
    verification_summary TEXT,
    verified_by TEXT,
    verified_at TEXT,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    fact_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    summary TEXT NOT NULL,
    artifact_path TEXT,
    source_url TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id, project_id),
    FOREIGN KEY (fact_id, project_id) REFERENCES facts(id, project_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS evidence_fact_idx
ON evidence(project_id, fact_id, created_at);

CREATE TABLE IF NOT EXISTS attempts (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    intent_id TEXT NOT NULL,
    worker TEXT NOT NULL,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    summary TEXT NOT NULL,
    artifact_path TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id, project_id),
    FOREIGN KEY (intent_id, project_id) REFERENCES intents(id, project_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS attempts_intent_idx
ON attempts(project_id, intent_id, created_at);

CREATE TABLE IF NOT EXISTS intents (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    to_fact_id TEXT,
    description TEXT NOT NULL,
    creator TEXT NOT NULL,
    worker TEXT,
    lease_id TEXT,
    last_heartbeat_at TEXT,
    created_at TEXT NOT NULL,
    concluded_at TEXT,
    PRIMARY KEY (id, project_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS open_verify_intent_idx
ON intents(project_id, description)
WHERE creator = 'dispatcher.verify' AND to_fact_id IS NULL;

CREATE TABLE IF NOT EXISTS intent_sources (
    intent_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    fact_id TEXT NOT NULL,
    PRIMARY KEY (intent_id, project_id, fact_id),
    FOREIGN KEY (intent_id, project_id) REFERENCES intents(id, project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS hints (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    creator TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS counters (
    name TEXT PRIMARY KEY,
    value INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO counters (name, value) VALUES ('project', 0);

CREATE TABLE IF NOT EXISTS scoped_counters (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, kind)
);

CREATE TABLE IF NOT EXISTS task_runs (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    intent_id TEXT,
    task_type TEXT NOT NULL,
    worker TEXT NOT NULL,
    status TEXT NOT NULL,
    outcome TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE INDEX IF NOT EXISTS task_runs_project_started_idx
ON task_runs(project_id, started_at);
"""


def configure(path: Path) -> None:
    global _db_path
    if _db_path is not None:
        return
    _db_path = path
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        _ensure_schema_columns(conn)


def _ensure_schema_columns(conn: sqlite3.Connection) -> None:
    project_columns = {row["name"] for row in conn.execute("PRAGMA table_info(projects)")}
    if "bootstrap_enabled" not in project_columns:
        conn.execute("ALTER TABLE projects ADD COLUMN bootstrap_enabled INTEGER NOT NULL DEFAULT 1")
        if "bootstrap_mode" in project_columns:
            conn.execute(
                "UPDATE projects SET bootstrap_enabled = CASE WHEN bootstrap_mode = 'disabled' THEN 0 ELSE 1 END"
            )
    if "reason_lease_id" not in project_columns:
        conn.execute("ALTER TABLE projects ADD COLUMN reason_lease_id TEXT")

    intent_columns = {row["name"] for row in conn.execute("PRAGMA table_info(intents)")}
    if intent_columns and "lease_id" not in intent_columns:
        conn.execute("ALTER TABLE intents ADD COLUMN lease_id TEXT")

    fact_columns = {row["name"] for row in conn.execute("PRAGMA table_info(facts)")}
    fact_migrations = {
        "status": "TEXT NOT NULL DEFAULT 'verified'",
        "category": "TEXT",
        "target": "TEXT",
        "component": "TEXT",
        "version": "TEXT",
        "confidence": "REAL",
        "created_by": "TEXT",
        "created_at": "TEXT",
        "verification_summary": "TEXT",
        "verified_by": "TEXT",
        "verified_at": "TEXT",
    }
    for name, declaration in fact_migrations.items():
        if fact_columns and name not in fact_columns:
            conn.execute(f"ALTER TABLE facts ADD COLUMN {name} {declaration}")


@contextmanager
def get_conn() -> Generator[sqlite3.Connection, None, None]:
    assert _db_path is not None
    conn = sqlite3.connect(str(_db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

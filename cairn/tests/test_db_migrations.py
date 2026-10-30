from __future__ import annotations

import sqlite3

from cairn.server import db


def test_configure_adds_bootstrap_enabled_to_legacy_projects_table(tmp_path, monkeypatch) -> None:
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE projects (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                reason_worker TEXT,
                reason_trigger TEXT,
                reason_started_at TEXT,
                reason_last_heartbeat_at TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO projects (id, title, created_at) VALUES ('proj_001', 'legacy', '2026-01-01T00:00:00Z')"
        )

    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)

    with db.get_conn() as conn:
        row = conn.execute("SELECT bootstrap_enabled FROM projects WHERE id = 'proj_001'").fetchone()
    assert row["bootstrap_enabled"] == 1


def test_configure_maps_disabled_bootstrap_mode_to_false(tmp_path, monkeypatch) -> None:
    path = tmp_path / "intermediate.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE projects (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                bootstrap_mode TEXT NOT NULL DEFAULT 'auto',
                created_at TEXT NOT NULL,
                reason_worker TEXT,
                reason_trigger TEXT,
                reason_started_at TEXT,
                reason_last_heartbeat_at TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO projects (id, title, bootstrap_mode, created_at) VALUES ('proj_001', 'disabled', 'disabled', '2026-01-01T00:00:00Z')"
        )
        conn.execute(
            "INSERT INTO projects (id, title, bootstrap_mode, created_at) VALUES ('proj_002', 'enabled', 'enabled', '2026-01-01T00:00:00Z')"
        )

    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)

    with db.get_conn() as conn:
        rows = conn.execute("SELECT id, bootstrap_enabled FROM projects ORDER BY id").fetchall()
    assert [(row["id"], row["bootstrap_enabled"]) for row in rows] == [
        ("proj_001", 0),
        ("proj_002", 1),
    ]


def test_configure_adds_lease_columns_and_task_runs_to_legacy_database(tmp_path, monkeypatch) -> None:
    path = tmp_path / "legacy-leases.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE projects (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                reason_worker TEXT,
                reason_trigger TEXT,
                reason_started_at TEXT,
                reason_last_heartbeat_at TEXT
            )
            """
        )

    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)

    with db.get_conn() as conn:
        project_columns = {row["name"] for row in conn.execute("PRAGMA table_info(projects)")}
        intent_columns = {row["name"] for row in conn.execute("PRAGMA table_info(intents)")}
        tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        busy_timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]

    assert "reason_lease_id" in project_columns
    assert "lease_id" in intent_columns
    assert "task_runs" in tables
    assert busy_timeout == 5000


def test_configure_adds_fact_verification_schema_without_downgrading_legacy_facts(tmp_path, monkeypatch) -> None:
    path = tmp_path / "legacy-facts.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE projects (id TEXT PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', "
            "created_at TEXT NOT NULL, reason_worker TEXT, reason_trigger TEXT, reason_started_at TEXT, "
            "reason_last_heartbeat_at TEXT)"
        )
        conn.execute(
            "CREATE TABLE facts (id TEXT NOT NULL, project_id TEXT NOT NULL, description TEXT NOT NULL, "
            "PRIMARY KEY (id, project_id))"
        )
        conn.execute(
            "INSERT INTO projects (id, title, created_at) VALUES ('proj_001', 'legacy', '2026-01-01T00:00:00Z')"
        )
        conn.execute(
            "INSERT INTO facts (id, project_id, description) VALUES ('f001', 'proj_001', 'trusted legacy fact')"
        )

    monkeypatch.setattr(db, "_db_path", None)
    db.configure(path)

    with db.get_conn() as conn:
        fact_columns = {row["name"] for row in conn.execute("PRAGMA table_info(facts)")}
        tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        fact = conn.execute("SELECT status FROM facts WHERE id = 'f001'").fetchone()

    assert {"status", "confidence", "verification_summary", "verified_at"} <= fact_columns
    assert {"evidence", "attempts"} <= tables
    assert fact["status"] == "verified"

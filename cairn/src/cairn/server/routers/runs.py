from fastapi import APIRouter, HTTPException

from cairn.server.db import get_conn
from cairn.server.models import CreateTaskRunRequest, FinishTaskRunRequest, TaskRun
from cairn.server.services import (
    check_project_active,
    get_intent_or_404,
    get_project_or_404,
    utcnow,
)


router = APIRouter(tags=["runs"])


def _task_run(row) -> TaskRun:
    return TaskRun(**dict(row))


@router.get("/projects/{project_id}/runs", response_model=list[TaskRun])
def list_task_runs(project_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        rows = conn.execute(
            "SELECT * FROM task_runs WHERE project_id = ? ORDER BY started_at, id",
            (project_id,),
        ).fetchall()
        return [_task_run(row) for row in rows]


@router.post("/projects/{project_id}/runs", response_model=TaskRun, status_code=201)
def create_task_run(project_id: str, body: CreateTaskRunRequest):
    with get_conn() as conn:
        project = check_project_active(conn, project_id)
        if body.task_type == "reason":
            if project["reason_worker"] != body.worker:
                raise HTTPException(409, "Reason task run does not match the active claim")
        else:
            assert body.intent_id is not None
            intent = get_intent_or_404(conn, project_id, body.intent_id)
            if intent["to_fact_id"] is not None or intent["worker"] != body.worker:
                raise HTTPException(409, "Task run does not match the active intent claim")
        existing = conn.execute(
            "SELECT * FROM task_runs WHERE id = ?", (body.id,)
        ).fetchone()
        if existing is not None:
            expected = (project_id, body.intent_id, body.task_type, body.worker)
            actual = (
                existing["project_id"],
                existing["intent_id"],
                existing["task_type"],
                existing["worker"],
            )
            if actual != expected:
                raise HTTPException(409, "Task run id is already used by another task")
            return _task_run(existing)

        now = utcnow()
        conn.execute(
            """
            INSERT INTO task_runs
                (id, project_id, intent_id, task_type, worker, status, outcome, started_at, finished_at)
            VALUES (?, ?, ?, ?, ?, 'running', NULL, ?, NULL)
            """,
            (body.id, project_id, body.intent_id, body.task_type, body.worker, now),
        )
        row = conn.execute("SELECT * FROM task_runs WHERE id = ?", (body.id,)).fetchone()
        return _task_run(row)


@router.put("/projects/{project_id}/runs/{run_id}", response_model=TaskRun)
def finish_task_run(project_id: str, run_id: str, body: FinishTaskRunRequest):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        row = conn.execute(
            "SELECT * FROM task_runs WHERE id = ? AND project_id = ?",
            (run_id, project_id),
        ).fetchone()
        if row is None:
            raise HTTPException(404, "Task run not found")
        if row["status"] == "finished":
            if row["outcome"] != body.outcome:
                raise HTTPException(409, "Task run already finished with a different outcome")
            return _task_run(row)

        conn.execute(
            "UPDATE task_runs SET status = 'finished', outcome = ?, finished_at = ? WHERE id = ?",
            (body.outcome, utcnow(), run_id),
        )
        updated = conn.execute("SELECT * FROM task_runs WHERE id = ?", (run_id,)).fetchone()
        return _task_run(updated)

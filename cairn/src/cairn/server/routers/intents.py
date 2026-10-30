import sqlite3

from fastapi import APIRouter, HTTPException, Response

from cairn.server.db import get_conn
from cairn.server.models import (
    ConcludeRequest,
    ConcludeResponse,
    CreateIntentRequest,
    Fact,
    HeartbeatRequest,
    Intent,
)
from cairn.server.services import (
    check_project_active,
    get_claimable_open_intent_or_404,
    get_project_or_404,
    get_releasable_open_intent_or_404,
    intent_to_model,
    fact_to_model,
    insert_attempts,
    insert_evidence,
    new_lease_id,
    require_matching_lease,
    next_fact_id,
    next_intent_id,
    utcnow,
    validate_facts_exist,
    validate_intent_creator_worker,
    validate_goal_not_in_sources,
)

router = APIRouter(tags=["intents"])


@router.post(
    "/projects/{project_id}/intents",
    response_model=Intent,
    status_code=201,
)
def create_intent(project_id: str, body: CreateIntentRequest, response: Response):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        validate_facts_exist(conn, project_id, body.from_)
        validate_goal_not_in_sources(body.from_)
        validate_intent_creator_worker(body.creator, body.worker)
        if body.creator == "dispatcher.verify":
            if len(body.from_) != 1 or body.description != f"verify:{body.from_[0]}":
                raise HTTPException(400, "Verification intents require one matching candidate fact")
            candidate = conn.execute(
                "SELECT status FROM facts WHERE id = ? AND project_id = ?",
                (body.from_[0], project_id),
            ).fetchone()
            if candidate["status"] != "candidate":
                raise HTTPException(409, "Verification intents can only target candidate facts")
        project = get_project_or_404(conn, project_id)
        if project["reason_worker"] == body.creator:
            require_matching_lease(
                project["reason_lease_id"], body.lease_id, scope="Project reason"
            )

        if body.creator == "dispatcher.verify":
            existing = conn.execute(
                "SELECT * FROM intents WHERE project_id = ? AND creator = ? AND description = ? "
                "AND to_fact_id IS NULL",
                (project_id, body.creator, body.description),
            ).fetchone()
            if existing is not None:
                return intent_to_model(conn, existing, project_id)

        now = utcnow()
        iid = next_intent_id(conn, project_id)
        claimed = body.worker is not None
        lease_id = new_lease_id() if claimed else None
        try:
            conn.execute(
                "INSERT INTO intents (id, project_id, to_fact_id, description, creator, worker, lease_id, last_heartbeat_at, created_at, concluded_at) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, NULL)",
                (
                    iid,
                    project_id,
                    body.description,
                    body.creator,
                    body.worker,
                    lease_id,
                    now if claimed else None,
                    now,
                ),
            )
        except sqlite3.IntegrityError:
            if body.creator != "dispatcher.verify":
                raise
            existing = conn.execute(
                "SELECT * FROM intents WHERE project_id = ? AND creator = ? AND description = ? "
                "AND to_fact_id IS NULL",
                (project_id, body.creator, body.description),
            ).fetchone()
            if existing is None:
                raise
            return intent_to_model(conn, existing, project_id)
        for fid in body.from_:
            conn.execute(
                "INSERT INTO intent_sources (intent_id, project_id, fact_id) VALUES (?, ?, ?)",
                (iid, project_id, fid),
            )
        if lease_id is not None:
            response.headers["X-Cairn-Lease-Id"] = lease_id

        return Intent(
            id=iid,
            **{"from": body.from_},
            to=None,
            description=body.description,
            creator=body.creator,
            worker=body.worker,
            last_heartbeat_at=now if claimed else None,
            created_at=now,
            concluded_at=None,
        )


@router.post(
    "/projects/{project_id}/intents/{intent_id}/heartbeat",
    response_model=Intent,
)
def heartbeat(project_id: str, intent_id: str, body: HeartbeatRequest, response: Response):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        row = get_claimable_open_intent_or_404(
            conn, project_id, intent_id, body.worker, body.lease_id
        )

        now = utcnow()
        # A fresh server-generated token fences off every previous owner after expiry/release.
        lease_id = row["lease_id"] or new_lease_id()
        conn.execute(
            "UPDATE intents SET worker = ?, lease_id = ?, last_heartbeat_at = ? WHERE id = ? AND project_id = ?",
            (body.worker, lease_id, now, intent_id, project_id),
        )
        response.headers["X-Cairn-Lease-Id"] = lease_id

        updated = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?",
            (intent_id, project_id),
        ).fetchone()
        return intent_to_model(conn, updated, project_id)


@router.post(
    "/projects/{project_id}/intents/{intent_id}/release",
    response_model=Intent,
)
def release(project_id: str, intent_id: str, body: HeartbeatRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        row = get_releasable_open_intent_or_404(
            conn, project_id, intent_id, body.worker, body.lease_id
        )

        if row["worker"] == body.worker:
            conn.execute(
                "UPDATE intents SET worker = NULL, lease_id = NULL WHERE id = ? AND project_id = ?",
                (intent_id, project_id),
            )
            row = conn.execute(
                "SELECT * FROM intents WHERE id = ? AND project_id = ?",
                (intent_id, project_id),
            ).fetchone()

        return intent_to_model(conn, row, project_id)


@router.post(
    "/projects/{project_id}/intents/{intent_id}/conclude",
    response_model=ConcludeResponse,
)
def conclude(project_id: str, intent_id: str, body: ConcludeRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        intent_row = get_claimable_open_intent_or_404(
            conn, project_id, intent_id, body.worker, body.lease_id
        )
        if body.status == "verified" and not (
            intent_row["creator"] == "dispatcher.bootstrap"
            and intent_row["description"] == "bootstrap"
        ):
            raise HTTPException(409, "Only the trusted bootstrap intent may create a verified fact")

        now = utcnow()
        fid = next_fact_id(conn, project_id)

        verified = body.status == "verified"
        conn.execute(
            """
            INSERT INTO facts
                (id, project_id, description, status, category, target, component, version,
                 confidence, created_by, created_at, verification_summary, verified_by, verified_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fid,
                project_id,
                body.description,
                body.status,
                body.category,
                body.target,
                body.component,
                body.version,
                body.confidence,
                body.worker,
                now,
                "Trusted bootstrap result" if verified else None,
                body.worker if verified else None,
                now if verified else None,
            ),
        )
        insert_evidence(conn, project_id, fid, body.evidence, created_at=now)
        insert_attempts(
            conn,
            project_id,
            intent_id,
            body.worker,
            body.attempts,
            created_at=now,
        )
        conn.execute(
            "UPDATE intents SET to_fact_id = ?, worker = ?, last_heartbeat_at = ?, concluded_at = ? WHERE id = ? AND project_id = ?",
            (fid, body.worker, now, now, intent_id, project_id),
        )

        updated = conn.execute(
            "SELECT * FROM intents WHERE id = ? AND project_id = ?",
            (intent_id, project_id),
        ).fetchone()

        return ConcludeResponse(
            fact=fact_to_model(
                conn,
                conn.execute(
                    "SELECT * FROM facts WHERE id = ? AND project_id = ?", (fid, project_id)
                ).fetchone(),
                project_id,
            ),
            intent=intent_to_model(conn, updated, project_id),
        )

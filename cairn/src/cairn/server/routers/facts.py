from fastapi import APIRouter, HTTPException

from cairn.server.db import get_conn
from cairn.server.models import Fact, VerifyFactRequest
from cairn.server.services import (
    check_project_active,
    fact_to_model,
    get_claimable_open_intent_or_404,
    insert_evidence,
    utcnow,
)


router = APIRouter(tags=["facts"])
VERIFY_INTENT_CREATOR = "dispatcher.verify"


@router.post("/projects/{project_id}/facts/{fact_id}/verify", response_model=Fact)
def verify_fact(project_id: str, fact_id: str, body: VerifyFactRequest):
    with get_conn() as conn:
        check_project_active(conn, project_id)
        fact = conn.execute(
            "SELECT * FROM facts WHERE id = ? AND project_id = ?", (fact_id, project_id)
        ).fetchone()
        if fact is None:
            raise HTTPException(404, "Fact not found")
        if fact["status"] != "candidate":
            raise HTTPException(409, f"Fact is already {fact['status']}")

        intent = get_claimable_open_intent_or_404(
            conn, project_id, body.intent_id, body.worker, body.lease_id
        )
        if intent["creator"] != VERIFY_INTENT_CREATOR or intent["description"] != f"verify:{fact_id}":
            raise HTTPException(409, "Intent is not the verification intent for this fact")
        source_rows = conn.execute(
            "SELECT fact_id FROM intent_sources WHERE intent_id = ? AND project_id = ? ORDER BY rowid",
            (body.intent_id, project_id),
        ).fetchall()
        if [row["fact_id"] for row in source_rows] != [fact_id]:
            raise HTTPException(409, "Verification intent source does not match the fact")
        if body.verdict == "verified" and not body.evidence:
            existing_evidence = conn.execute(
                "SELECT 1 FROM evidence WHERE project_id = ? AND fact_id = ? LIMIT 1",
                (project_id, fact_id),
            ).fetchone()
            if existing_evidence is None:
                raise HTTPException(409, "A verified fact requires supporting evidence")

        now = utcnow()
        conn.execute(
            """
            UPDATE facts
            SET status = ?, verification_summary = ?, verified_by = ?, verified_at = ?
            WHERE id = ? AND project_id = ?
            """,
            (body.verdict, body.summary, body.worker, now, fact_id, project_id),
        )
        insert_evidence(conn, project_id, fact_id, body.evidence, created_at=now)
        conn.execute(
            """
            UPDATE intents
            SET to_fact_id = ?, worker = ?, last_heartbeat_at = ?, concluded_at = ?
            WHERE id = ? AND project_id = ?
            """,
            (fact_id, body.worker, now, now, body.intent_id, project_id),
        )
        updated = conn.execute(
            "SELECT * FROM facts WHERE id = ? AND project_id = ?", (fact_id, project_id)
        ).fetchone()
        return fact_to_model(conn, updated, project_id)

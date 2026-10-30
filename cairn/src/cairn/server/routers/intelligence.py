from fastapi import APIRouter

from cairn.server.db import get_conn
from cairn.server.intelligence import build_project_intelligence
from cairn.server.models import ProjectIntelligence
from cairn.server.services import get_project_or_404


router = APIRouter(tags=["intelligence"])


@router.get("/projects/{project_id}/intelligence", response_model=ProjectIntelligence)
def project_intelligence(project_id: str):
    with get_conn() as conn:
        get_project_or_404(conn, project_id)
        facts = conn.execute(
            "SELECT * FROM facts WHERE project_id = ? ORDER BY id", (project_id,)
        ).fetchall()
        return build_project_intelligence(dict(fact) for fact in facts)

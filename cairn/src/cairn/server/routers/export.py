from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from datetime import datetime
import yaml

from cairn.server.db import get_conn
from cairn.server.intelligence import build_project_intelligence
from cairn.server.services import expire_reason_leases, expire_workers, get_project_or_404

router = APIRouter(tags=["export"])


def format_export_timestamp(value: str | None) -> str | None:
    if not value:
        return value
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _load_project_data(conn, project_id: str):
    expire_workers(conn, project_id)
    expire_reason_leases(conn, project_id)
    proj = get_project_or_404(conn, project_id)

    facts = conn.execute(
        "SELECT * FROM facts WHERE project_id = ?", (project_id,)
    ).fetchall()
    hints = conn.execute(
        "SELECT content, creator, created_at FROM hints WHERE project_id = ? ORDER BY created_at",
        (project_id,),
    ).fetchall()
    intents = conn.execute(
        "SELECT * FROM intents WHERE project_id = ? ORDER BY created_at",
        (project_id,),
    ).fetchall()

    sources_by_intent = {}
    for i in intents:
        rows = conn.execute(
            "SELECT fact_id FROM intent_sources WHERE intent_id = ? AND project_id = ? ORDER BY rowid",
            (i["id"], project_id),
        ).fetchall()
        sources_by_intent[i["id"]] = [r["fact_id"] for r in rows]

    evidence_by_fact = {}
    for fact in facts:
        rows = conn.execute(
            "SELECT kind, summary, artifact_path, source_url, created_at FROM evidence "
            "WHERE project_id = ? AND fact_id = ? ORDER BY created_at, id",
            (project_id, fact["id"]),
        ).fetchall()
        evidence_by_fact[fact["id"]] = [dict(row) for row in rows]

    attempts = conn.execute(
        "SELECT intent_id, worker, action, outcome, summary, artifact_path, created_at "
        "FROM attempts WHERE project_id = ? ORDER BY created_at, id",
        (project_id,),
    ).fetchall()

    return proj, facts, hints, intents, sources_by_intent, evidence_by_fact, attempts


def _export_yaml(conn, project_id: str) -> str:
    proj, facts, hints, intents, sources_by_intent, evidence_by_fact, attempts = _load_project_data(conn, project_id)

    origin_desc = ""
    goal_desc = ""
    for f in facts:
        if f["id"] == "origin":
            origin_desc = f["description"]
        elif f["id"] == "goal":
            goal_desc = f["description"]

    data: dict = {
        "project": {
            "title": proj["title"],
            "origin": origin_desc,
            "goal": goal_desc,
            "bootstrap_enabled": bool(proj["bootstrap_enabled"]),
        }
    }

    if hints:
        data["hints"] = [
            {
                "content": h["content"],
                "creator": h["creator"],
                "created_at": format_export_timestamp(h["created_at"]),
            }
            for h in hints
        ]

    intelligence = build_project_intelligence(dict(fact) for fact in facts)
    if intelligence.entities:
        data["asset_intelligence"] = intelligence.model_dump(mode="json", exclude_none=True)

    data["facts"] = []
    for fact in facts:
        entry = {
            "id": fact["id"],
            "description": fact["description"],
            "status": fact["status"],
        }
        for key in (
            "category", "target", "component", "version", "confidence", "created_by",
            "verification_summary", "verified_by",
        ):
            if fact[key] is not None:
                entry[key] = fact[key]
        if fact["created_at"] is not None:
            entry["created_at"] = format_export_timestamp(fact["created_at"])
        if fact["verified_at"] is not None:
            entry["verified_at"] = format_export_timestamp(fact["verified_at"])
        if evidence_by_fact.get(fact["id"]):
            entry["evidence"] = [
                {
                    **{key: value for key, value in evidence.items() if value is not None and key != "created_at"},
                    "created_at": format_export_timestamp(evidence["created_at"]),
                }
                for evidence in evidence_by_fact[fact["id"]]
            ]
        data["facts"].append(entry)

    if attempts:
        data["attempts"] = [
            {
                **{key: value for key, value in dict(attempt).items() if value is not None and key != "created_at"},
                "created_at": format_export_timestamp(attempt["created_at"]),
            }
            for attempt in attempts
        ]

    intent_list = []
    for i in intents:
        entry: dict = {
            "from": sources_by_intent.get(i["id"], []),
            "to": i["to_fact_id"],
            "description": i["description"],
            "creator": i["creator"],
            "worker": i["worker"],
            "created_at": format_export_timestamp(i["created_at"]),
            "concluded_at": format_export_timestamp(i["concluded_at"]),
        }
        intent_list.append(entry)

    if intent_list:
        data["intents"] = intent_list

    return yaml.dump(data, allow_unicode=True, default_flow_style=False, sort_keys=False)


def _export_timeline(conn, project_id: str) -> str:
    proj, facts, hints, intents, sources_by_intent, evidence_by_fact, attempts = _load_project_data(conn, project_id)

    facts_by_id = {f["id"]: f["description"] for f in facts}
    fact_status_by_id = {f["id"]: f["status"] for f in facts}

    events: list[tuple[str, int, str]] = []  # (timestamp, order, text)
    order = 0

    origin_desc = facts_by_id.get("origin", "")
    goal_desc = facts_by_id.get("goal", "")
    ts = format_export_timestamp(proj["created_at"]) or ""
    block = f"[{ts}] PROJECT CREATED\n  origin: {origin_desc}\n  goal: {goal_desc}"
    events.append((proj["created_at"] or "", order, block))
    order += 1

    for h in hints:
        ts = format_export_timestamp(h["created_at"]) or ""
        block = f"[{ts}] HINT by {h['creator']}\n  {h['content']}"
        events.append((h["created_at"] or "", order, block))
        order += 1

    for i in intents:
        src = sources_by_intent.get(i["id"], [])
        from_str = ", ".join(src)

        ts = format_export_timestamp(i["created_at"]) or ""
        meta = f"  from: {from_str}"
        if i["worker"] and not i["concluded_at"]:
            meta += f"\n  worker: {i['worker']} (in progress)"
        block = f"[{ts}] INTENT DECLARED {i['id']} by {i['creator']}\n{meta}\n  {i['description']}"
        events.append((i["created_at"] or "", order, block))
        order += 1

        if not i["concluded_at"] or not i["to_fact_id"]:
            continue

        ts = format_export_timestamp(i["concluded_at"]) or ""
        actor = i["worker"] or i["creator"]

        if i["creator"] == "dispatcher.verify":
            status = fact_status_by_id.get(i["to_fact_id"], "candidate")
            fact_desc = facts_by_id.get(i["to_fact_id"], "")
            block = f"[{ts}] FACT {status.upper()} {i['to_fact_id']} by {actor}\n  {fact_desc}"
        elif i["to_fact_id"] == "goal":
            block = f"[{ts}] PROJECT COMPLETED by {actor}\n  via: {i['id']} from {from_str}"
        else:
            fact_desc = facts_by_id.get(i["to_fact_id"], "")
            status = fact_status_by_id.get(i["to_fact_id"], "verified")
            block = f"[{ts}] INTENT CONCLUDED {i['id']} by {actor}\n  from: {from_str}\n  produced: {i['to_fact_id']} ({status})\n  {fact_desc}"

        events.append((i["concluded_at"] or "", order, block))
        order += 1

    events.sort(key=lambda e: (e[0], e[1]))

    return "\n\n".join(e[2] for e in events) + "\n"


@router.get("/projects/{project_id}/export")
def export_project(project_id: str, format: str = "yaml"):
    if format not in ("yaml", "timeline"):
        raise HTTPException(400, "Supported formats: yaml, timeline")

    with get_conn() as conn:
        if format == "timeline":
            text = _export_timeline(conn, project_id)
        else:
            text = _export_yaml(conn, project_id)

        return Response(content=text, media_type="text/plain")

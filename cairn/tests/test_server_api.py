from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from cairn.server import db
from cairn.server.app import app


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setattr(db, "_db_path", None)
    db.configure(tmp_path / "cairn.db")
    with TestClient(app) as test_client:
        yield test_client


def _create_project(client: TestClient) -> str:
    response = client.post(
        "/projects",
        json={
            "title": "test",
            "origin": "starting point",
            "goal": "finish",
            "hints": [{"content": "initial clue", "creator": "human"}],
        },
    )
    assert response.status_code == 201
    assert response.json()["project"]["bootstrap_enabled"] is True
    return response.json()["project"]["id"]


def test_project_workflow_create_conclude_complete_and_reopen(client: TestClient) -> None:
    project_id = _create_project(client)

    response = client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "investigate", "creator": "reasoner", "worker": None},
    )
    assert response.status_code == 201
    assert response.json()["id"] == "i001"

    response = client.post(
        f"/projects/{project_id}/intents/i001/heartbeat",
        json={"worker": "explorer"},
    )
    assert response.status_code == 200
    assert response.json()["worker"] == "explorer"
    lease_id = response.headers["X-Cairn-Lease-Id"]

    response = client.post(
        f"/projects/{project_id}/intents/i001/conclude",
        json={"worker": "explorer", "description": "new fact", "lease_id": lease_id},
    )
    assert response.status_code == 200
    assert response.json()["fact"]["id"] == "f001"
    assert response.json()["fact"]["description"] == "new fact"
    assert response.json()["fact"]["status"] == "candidate"

    response = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["f001"], "description": "solved", "worker": "reasoner"},
    )
    assert response.status_code == 409

    response = client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["f001"], "description": "verify:f001", "creator": "dispatcher.verify", "worker": None},
    )
    assert response.status_code == 201
    duplicate = client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["f001"], "description": "verify:f001", "creator": "dispatcher.verify", "worker": None},
    )
    assert duplicate.status_code == 201
    assert duplicate.json()["id"] == "i002"
    response = client.post(
        f"/projects/{project_id}/intents/i002/heartbeat",
        json={"worker": "verifier"},
    )
    verify_lease = response.headers["X-Cairn-Lease-Id"]
    response = client.post(
        f"/projects/{project_id}/facts/f001/verify",
        json={
            "intent_id": "i002",
            "worker": "verifier",
            "verdict": "verified",
            "summary": "reproduced independently",
            "evidence": [{"kind": "observation", "summary": "same result reproduced"}],
            "lease_id": verify_lease,
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] == "verified"

    response = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["f001"], "description": "solved", "worker": "reasoner"},
    )
    assert response.status_code == 200
    assert response.json()["to"] == "goal"

    response = client.post(
        f"/projects/{project_id}/reopen",
        json={"description": "human correction", "creator": "human"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["project"]["status"] == "active"
    assert payload["fact"]["id"] == "f002"
    assert payload["fact"]["description"] == "human correction"
    assert payload["fact"]["status"] == "verified"
    assert payload["intent"]["from"] == ["f001"]
    assert payload["intent"]["to"] == "f002"


def test_stopping_project_releases_claims_and_reason_but_keeps_hints_writable(client: TestClient) -> None:
    project_id = _create_project(client)
    client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "work", "creator": "worker-a", "worker": "worker-a"},
    )
    client.post(
        f"/projects/{project_id}/reason/claim",
        json={"worker": "worker-b", "trigger": "facts:2->3"},
    )

    response = client.put(f"/projects/{project_id}/status", json={"status": "stopped"})
    assert response.status_code == 200
    assert response.json()["reason"] is None

    detail = client.get(f"/projects/{project_id}").json()
    assert detail["intents"][0]["worker"] is None
    assert client.post(
        f"/projects/{project_id}/hints",
        json={"content": "manual note", "creator": "human"},
    ).status_code == 201
    assert client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "blocked", "creator": "reasoner", "worker": None},
    ).status_code == 403


def test_intent_creation_rejects_goal_source_and_mismatched_initial_worker(client: TestClient) -> None:
    project_id = _create_project(client)

    assert client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["goal"], "description": "invalid", "creator": "reasoner", "worker": None},
    ).status_code == 400
    assert client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "invalid", "creator": "reasoner", "worker": "explorer"},
    ).status_code == 400


def test_settings_and_export_are_backed_by_the_same_database(client: TestClient) -> None:
    project_id = _create_project(client)

    response = client.put("/settings", json={"intent_timeout": 30, "reason_timeout": 45})
    assert response.status_code == 200
    assert client.get("/settings").json() == {"intent_timeout": 30, "reason_timeout": 45}

    exported = client.get(f"/projects/{project_id}/export?format=yaml")
    assert exported.status_code == 200
    assert "origin: starting point" in exported.text
    assert "goal: finish" in exported.text
    assert client.get(f"/projects/{project_id}/export?format=invalid").status_code == 400


def test_structured_candidate_persists_evidence_attempts_and_fences_stale_verifier(client: TestClient) -> None:
    project_id = _create_project(client)
    assert client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "inspect service", "creator": "reasoner"},
    ).status_code == 201
    claim = client.post(
        f"/projects/{project_id}/intents/i001/heartbeat", json={"worker": "explorer"}
    )
    concluded = client.post(
        f"/projects/{project_id}/intents/i001/conclude",
        json={
            "worker": "explorer",
            "description": "Example Server 1.2.3 exposed the tested behavior",
            "category": "vulnerability",
            "target": "example.local",
            "component": "example-server",
            "version": "1.2.3",
            "confidence": 0.8,
            "evidence": [{"kind": "http", "summary": "response saved", "artifact_path": "/tmp/proof.txt"}],
            "attempts": [{"action": "safe request", "outcome": "success", "summary": "behavior reproduced"}],
            "lease_id": claim.headers["X-Cairn-Lease-Id"],
        },
    )
    assert concluded.status_code == 200
    assert concluded.json()["fact"]["status"] == "candidate"
    assert concluded.json()["fact"]["evidence"][0]["kind"] == "http"

    exported = client.get(f"/projects/{project_id}/export?format=yaml").text
    assert "status: candidate" in exported
    assert "behavior reproduced" in exported
    assert "response saved" in exported
    assert "asset_intelligence:" in exported

    intelligence = client.get(f"/projects/{project_id}/intelligence")
    assert intelligence.status_code == 200
    graph = intelligence.json()
    assert {entity["kind"] for entity in graph["entities"]} == {"host", "component"}
    assert graph["relationships"][0]["relationship"] == "runs"
    assert graph["cve_queries"][0]["product"] == "example-server"
    assert graph["cve_queries"][0]["version"] == "1.2.3"
    assert "cve-intel recommend" in graph["cve_queries"][0]["command"]

    assert client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["f001"], "description": "verify:f001", "creator": "dispatcher.verify"},
    ).status_code == 201
    first_claim = client.post(
        f"/projects/{project_id}/intents/i002/heartbeat",
        json={"worker": "verifier", "lease_id": "a" * 32},
    )
    old_lease = first_claim.headers["X-Cairn-Lease-Id"]
    with db.get_conn() as conn:
        conn.execute(
            "UPDATE intents SET last_heartbeat_at = '2000-01-01T00:00:00Z' "
            "WHERE project_id = ? AND id = 'i002'",
            (project_id,),
        )
    second_claim = client.post(
        f"/projects/{project_id}/intents/i002/heartbeat",
        json={"worker": "verifier", "lease_id": "b" * 32},
    )
    new_lease = second_claim.headers["X-Cairn-Lease-Id"]
    assert new_lease != old_lease

    payload = {
        "intent_id": "i002",
        "worker": "verifier",
        "verdict": "verified",
        "summary": "independently reproduced",
        "evidence": [{"kind": "observation", "summary": "independent reproduction"}],
    }
    stale = client.post(
        f"/projects/{project_id}/facts/f001/verify", json={**payload, "lease_id": old_lease}
    )
    assert stale.status_code == 409
    current = client.post(
        f"/projects/{project_id}/facts/f001/verify", json={**payload, "lease_id": new_lease}
    )
    assert current.status_code == 200
    assert current.json()["status"] == "verified"
    assert current.json()["verified_by"] == "verifier"


def test_expired_intent_and_reason_leases_can_be_reclaimed(client: TestClient) -> None:
    project_id = _create_project(client)
    client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "work", "creator": "worker-a", "worker": "worker-a"},
    )
    client.post(
        f"/projects/{project_id}/reason/claim",
        json={"worker": "worker-a", "trigger": "bootstrap"},
    )
    with db.get_conn() as conn:
        conn.execute(
            "UPDATE intents SET last_heartbeat_at = '2000-01-01T00:00:00Z' WHERE project_id = ?",
            (project_id,),
        )
        conn.execute(
            "UPDATE projects SET reason_last_heartbeat_at = '2000-01-01T00:00:00Z' WHERE id = ?",
            (project_id,),
        )

    response = client.post(
        f"/projects/{project_id}/intents/i001/heartbeat",
        json={"worker": "worker-b"},
    )
    assert response.status_code == 200
    assert response.json()["worker"] == "worker-b"

    response = client.post(
        f"/projects/{project_id}/reason/claim",
        json={"worker": "worker-b", "trigger": "facts:2->3"},
    )
    assert response.status_code == 200
    assert response.json()["reason"]["worker"] == "worker-b"


def test_live_reason_lease_rejects_competing_worker(client: TestClient) -> None:
    project_id = _create_project(client)
    assert client.post(
        f"/projects/{project_id}/reason/claim",
        json={"worker": "worker-a", "trigger": "bootstrap"},
    ).status_code == 200

    response = client.post(
        f"/projects/{project_id}/reason/claim",
        json={"worker": "worker-b", "trigger": "facts:2->3"},
    )

    assert response.status_code == 409
    assert "worker-a" in response.json()["detail"]


def test_project_creation_persists_disabled_bootstrap_and_exports_it(client: TestClient) -> None:
    response = client.post(
        "/projects",
        json={
            "title": "no bootstrap",
            "origin": "start",
            "goal": "finish",
            "bootstrap_enabled": False,
        },
    )

    assert response.status_code == 201
    project_id = response.json()["project"]["id"]
    assert client.get(f"/projects/{project_id}").json()["project"]["bootstrap_enabled"] is False
    assert "bootstrap_enabled: false" in client.get(f"/projects/{project_id}/export?format=yaml").text


def test_project_creation_rejects_invalid_bootstrap_enabled(client: TestClient) -> None:
    response = client.post(
        "/projects",
        json={
            "title": "invalid bootstrap",
            "origin": "start",
            "goal": "finish",
            "bootstrap_enabled": "sometimes",
        },
    )

    assert response.status_code == 422


def test_api_token_protects_api_but_keeps_health_public(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("CAIRN_API_TOKEN", "test-api-token")

    assert client.get("/health").status_code == 200
    unauthorized = client.get("/projects")
    assert unauthorized.status_code == 401
    assert unauthorized.headers["WWW-Authenticate"] == "Bearer"

    authorized = client.get(
        "/projects", headers={"Authorization": "Bearer test-api-token"}
    )
    assert authorized.status_code == 200


def test_expired_intent_lease_rejects_stale_writer_with_same_worker_name(client: TestClient) -> None:
    project_id = _create_project(client)
    client.post(
        f"/projects/{project_id}/intents",
        json={"from": ["origin"], "description": "work", "creator": "reasoner", "worker": None},
    )
    old_lease = "a" * 32
    requested_new_lease = "b" * 32
    assert client.post(
        f"/projects/{project_id}/intents/i001/heartbeat",
        json={"worker": "worker-a", "lease_id": old_lease},
    ).status_code == 200
    with db.get_conn() as conn:
        conn.execute(
            "UPDATE intents SET last_heartbeat_at = '2000-01-01T00:00:00Z' WHERE project_id = ?",
            (project_id,),
        )

    reclaimed = client.post(
        f"/projects/{project_id}/intents/i001/heartbeat",
        json={"worker": "worker-a", "lease_id": requested_new_lease},
    )
    assert reclaimed.status_code == 200
    new_lease = reclaimed.headers["X-Cairn-Lease-Id"]
    assert new_lease not in (old_lease, requested_new_lease)

    stale = client.post(
        f"/projects/{project_id}/intents/i001/conclude",
        json={"worker": "worker-a", "description": "stale", "lease_id": old_lease},
    )
    assert stale.status_code == 409
    assert "lease" in stale.json()["detail"].lower()

    current = client.post(
        f"/projects/{project_id}/intents/i001/conclude",
        json={"worker": "worker-a", "description": "current", "lease_id": new_lease},
    )
    assert current.status_code == 200


def test_task_runs_are_persistent_and_idempotent(client: TestClient) -> None:
    project_id = _create_project(client)
    assert client.post(
        f"/projects/{project_id}/reason/claim",
        json={"worker": "worker-a", "trigger": "test"},
    ).status_code == 200
    payload = {
        "id": "run-1234567890abcdef",
        "task_type": "reason",
        "worker": "worker-a",
        "intent_id": None,
    }

    created = client.post(f"/projects/{project_id}/runs", json=payload)
    assert created.status_code == 201
    assert created.json()["status"] == "running"
    assert client.post(f"/projects/{project_id}/runs", json=payload).status_code == 201

    conflict = client.post(
        f"/projects/{project_id}/runs",
        json={**payload, "worker": "worker-b"},
    )
    assert conflict.status_code == 409

    finished = client.put(
        f"/projects/{project_id}/runs/{payload['id']}", json={"outcome": "success"}
    )
    assert finished.status_code == 200
    assert finished.json()["status"] == "finished"
    assert finished.json()["finished_at"] is not None
    assert client.put(
        f"/projects/{project_id}/runs/{payload['id']}", json={"outcome": "success"}
    ).status_code == 200
    assert client.put(
        f"/projects/{project_id}/runs/{payload['id']}", json={"outcome": "failed"}
    ).status_code == 409

    listed = client.get(f"/projects/{project_id}/runs")
    assert listed.status_code == 200
    assert [run["id"] for run in listed.json()] == [payload["id"]]

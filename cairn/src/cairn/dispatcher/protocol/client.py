from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import logging
import os
import threading
import uuid

from pydantic import TypeAdapter
import requests
from requests.adapters import HTTPAdapter

from cairn.server.models import Intent, ProjectDetail, ProjectSummary, Settings

LOG = logging.getLogger(__name__)


class ProtocolError(RuntimeError):
    def __init__(self, message: str, status_code: int, response_text: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text


@dataclass(slots=True)
class ApiResult:
    status_code: int
    data: Any | None = None
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300


class CairnClient:
    def __init__(self, base_url: str, timeout: float = 10.0, api_token: str | None = None):
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._summary_adapter = TypeAdapter(list[ProjectSummary])
        self._local = threading.local()
        self._sessions: dict[int, requests.Session] = {}
        self._sessions_lock = threading.Lock()
        self._api_token = api_token if api_token is not None else os.environ.get("CAIRN_API_TOKEN")
        self._lease_lock = threading.Lock()
        self._intent_leases: dict[tuple[str, str], str] = {}
        self._reason_leases: dict[str, str] = {}

    def close(self) -> None:
        with self._sessions_lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            session.close()
        with self._lease_lock:
            self._intent_leases.clear()
            self._reason_leases.clear()

    def list_projects(self) -> list[ProjectSummary]:
        response = self._session().get(self._url("/projects"), timeout=self._timeout)
        response.raise_for_status()
        return self._summary_adapter.validate_python(response.json())

    def get_project(self, project_id: str) -> ProjectDetail:
        response = self._session().get(self._url(f"/projects/{project_id}"), timeout=self._timeout)
        response.raise_for_status()
        return ProjectDetail.model_validate(response.json())

    def get_settings(self) -> Settings:
        response = self._session().get(self._url("/settings"), timeout=self._timeout)
        response.raise_for_status()
        return Settings.model_validate(response.json())

    def export_project(self, project_id: str) -> str:
        response = self._session().get(
            self._url(f"/projects/{project_id}/export"),
            params={"format": "yaml"},
            timeout=self._timeout,
        )
        response.raise_for_status()
        return response.text

    def heartbeat(self, project_id: str, intent_id: str, worker: str) -> ApiResult:
        key = (project_id, intent_id)
        with self._lease_lock:
            lease_id = self._intent_leases.setdefault(key, uuid.uuid4().hex)
        result = self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/heartbeat",
            json={"worker": worker, "lease_id": lease_id},
        )
        self._remember_lease(result, intent_key=key)
        return result

    def claim_reason(self, project_id: str, worker: str, trigger: str) -> ApiResult:
        with self._lease_lock:
            lease_id = self._reason_leases.setdefault(project_id, uuid.uuid4().hex)
        result = self._request_json(
            "POST",
            f"/projects/{project_id}/reason/claim",
            json={"worker": worker, "trigger": trigger, "lease_id": lease_id},
        )
        self._remember_lease(result, reason_project_id=project_id)
        return result

    def reason_heartbeat(self, project_id: str, worker: str) -> ApiResult:
        with self._lease_lock:
            lease_id = self._reason_leases.get(project_id)
        return self._request_json(
            "POST",
            f"/projects/{project_id}/reason/heartbeat",
            json={"worker": worker, "lease_id": lease_id},
        )

    def release_reason(self, project_id: str, worker: str) -> ApiResult:
        with self._lease_lock:
            lease_id = self._reason_leases.get(project_id)
        result = self._request_json(
            "POST",
            f"/projects/{project_id}/reason/release",
            json={"worker": worker, "lease_id": lease_id},
        )
        if result.ok:
            with self._lease_lock:
                self._reason_leases.pop(project_id, None)
        return result

    def release(self, project_id: str, intent_id: str, worker: str) -> ApiResult:
        key = (project_id, intent_id)
        with self._lease_lock:
            lease_id = self._intent_leases.get(key)
        result = self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/release",
            json={"worker": worker, "lease_id": lease_id},
        )
        if result.ok:
            with self._lease_lock:
                self._intent_leases.pop(key, None)
        return result

    def conclude(
        self,
        project_id: str,
        intent_id: str,
        worker: str,
        finding: dict[str, Any],
        *,
        status: str = "candidate",
    ) -> ApiResult:
        key = (project_id, intent_id)
        with self._lease_lock:
            lease_id = self._intent_leases.get(key)
        result = self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/conclude",
            json={"worker": worker, "status": status, "lease_id": lease_id, **finding},
        )
        if result.ok:
            with self._lease_lock:
                self._intent_leases.pop(key, None)
        return result

    def verify_fact(
        self,
        project_id: str,
        fact_id: str,
        intent_id: str,
        worker: str,
        verdict: str,
        summary: str,
        evidence: list[dict[str, Any]],
    ) -> ApiResult:
        key = (project_id, intent_id)
        with self._lease_lock:
            lease_id = self._intent_leases.get(key)
        result = self._request_json(
            "POST",
            f"/projects/{project_id}/facts/{fact_id}/verify",
            json={
                "intent_id": intent_id,
                "worker": worker,
                "verdict": verdict,
                "summary": summary,
                "evidence": evidence,
                "lease_id": lease_id,
            },
        )
        if result.ok:
            with self._lease_lock:
                self._intent_leases.pop(key, None)
        return result

    def complete(self, project_id: str, from_ids: list[str], description: str, worker: str) -> ApiResult:
        with self._lease_lock:
            lease_id = self._reason_leases.get(project_id)
        result = self._request_json(
            "POST",
            f"/projects/{project_id}/complete",
            json={"from": from_ids, "description": description, "worker": worker, "lease_id": lease_id},
        )
        if result.ok:
            with self._lease_lock:
                self._reason_leases.pop(project_id, None)
        return result

    def create_intent(self, project_id: str, from_ids: list[str], description: str, creator: str) -> ApiResult:
        with self._lease_lock:
            lease_id = self._reason_leases.get(project_id)
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents",
            json={
                "from": from_ids,
                "description": description,
                "creator": creator,
                "worker": None,
                "lease_id": lease_id,
            },
        )

    def start_task_run(
        self,
        project_id: str,
        run_id: str,
        task_type: str,
        worker: str,
        intent_id: str | None,
    ) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/runs",
            json={
                "id": run_id,
                "task_type": task_type,
                "worker": worker,
                "intent_id": intent_id,
            },
        )

    def finish_task_run(self, project_id: str, run_id: str, outcome: str) -> ApiResult:
        return self._request_json(
            "PUT",
            f"/projects/{project_id}/runs/{run_id}",
            json={"outcome": outcome},
        )

    def _remember_lease(
        self,
        result: ApiResult,
        *,
        intent_key: tuple[str, str] | None = None,
        reason_project_id: str | None = None,
    ) -> None:
        if not result.ok:
            return
        lease_id = result.headers.get("x-cairn-lease-id")
        if not lease_id:
            return
        with self._lease_lock:
            if intent_key is not None:
                self._intent_leases[intent_key] = lease_id
            if reason_project_id is not None:
                self._reason_leases[reason_project_id] = lease_id

    def _request_json(self, method: str, path: str, json: dict[str, Any]) -> ApiResult:
        try:
            response = self._session().request(
                method,
                self._url(path),
                json=json,
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            LOG.warning("request failed method=%s path=%s error=%s", method, path, exc)
            return ApiResult(status_code=0, text=str(exc))
        data: Any | None = None
        if response.headers.get("content-type", "").startswith("application/json"):
            data = response.json()
        return ApiResult(
            status_code=response.status_code,
            data=data,
            text=response.text,
            headers={key.lower(): value for key, value in response.headers.items()},
        )

    def _url(self, path: str) -> str:
        return f"{self._base_url}{path}"

    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is not None:
            return session

        session = requests.Session()
        if self._api_token:
            session.headers["Authorization"] = f"Bearer {self._api_token}"
        adapter = HTTPAdapter(pool_connections=64, pool_maxsize=64, pool_block=False)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        self._local.session = session
        with self._sessions_lock:
            self._sessions[threading.get_ident()] = session
        return session

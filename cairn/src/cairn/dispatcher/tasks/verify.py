from __future__ import annotations

import json
import logging
import time

from cairn.dispatcher.config import DispatchConfig, WorkerConfig
from cairn.dispatcher.contracts import parse_json_output, validate_verify_payload
from cairn.dispatcher.prompting import load_prompt, render_prompt
from cairn.dispatcher.protocol.client import CairnClient
from cairn.dispatcher.runtime.cancellation import TaskCancellation
from cairn.dispatcher.runtime.containers import ContainerManager
from cairn.dispatcher.runtime.heartbeat import HeartbeatLease
from cairn.dispatcher.tasks.common import (
    best_effort_release,
    cancel_reason,
    did_timeout,
    preview,
    run_worker_process,
    task_healthcheck_enabled,
    write_graph_snapshot_reference,
)
from cairn.dispatcher.workers.registry import get_driver
from cairn.server.models import Fact, Intent, ProjectDetail


LOG = logging.getLogger(__name__)


def run_verify_task(
    config: DispatchConfig,
    client: CairnClient,
    container_manager: ContainerManager,
    project: ProjectDetail,
    export_yaml: str,
    fact: Fact,
    intent: Intent,
    worker: WorkerConfig,
    cancellation: TaskCancellation,
) -> str:
    driver = get_driver(worker.type, config.runtime.execution)
    lease = HeartbeatLease.for_intent(
        client, project.project.id, intent.id, worker.name, config.runtime.interval
    )
    lease.start()
    started = time.perf_counter()
    try:
        container_name = container_manager.ensure_running(project.project.id)
        if task_healthcheck_enabled(config):
            health = driver.check_health(worker, timeout=config.runtime.healthcheck_timeout)
            if cancellation.is_cancelled:
                best_effort_release(client, project.project.id, intent.id, worker.name)
                return "cancelled"
            if lease.failure is not None:
                best_effort_release(client, project.project.id, intent.id, worker.name)
                return "failed"
            if not health.ok:
                best_effort_release(client, project.project.id, intent.id, worker.name)
                return "unhealthy"

        prompt = render_prompt(
            load_prompt(config.runtime.prompt_group, "verify.md"),
            {
                "graph_yaml": write_graph_snapshot_reference(
                    container_manager,
                    container_name,
                    export_yaml.strip(),
                    phase="verify",
                ),
                "fact_id": fact.id,
                "fact_json": json.dumps(fact.model_dump(mode="json"), ensure_ascii=False),
            },
        )
        command = driver.build_execute(worker, prompt, driver.prepare_session())
        result = run_worker_process(
            container_manager,
            container_name,
            worker,
            command.argv,
            phase="verify",
            timeout_seconds=config.tasks.verify.timeout,
            lease=lease,
            cancellation=cancellation,
        )
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        cancelled = cancel_reason(result, cancellation)
        if cancelled is not None:
            LOG.info(
                "verify cancelled project=%s fact=%s worker=%s reason=%s",
                project.project.id,
                fact.id,
                worker.name,
                cancelled,
            )
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return "cancelled"
        if lease.failure is not None:
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return "failed"
        if did_timeout(result) or result.returncode != 0:
            LOG.warning(
                "verify command failed project=%s fact=%s worker=%s code=%s timed_out=%s elapsed_ms=%s stdout_preview=%s stderr_preview=%s",
                project.project.id,
                fact.id,
                worker.name,
                result.returncode,
                did_timeout(result),
                elapsed_ms,
                preview(result.stdout),
                preview(result.stderr),
            )
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return "failed"
        try:
            payload = parse_json_output(driver.extract_response_text(result.stdout, result.stderr))
            kind, data = validate_verify_payload(payload)
        except Exception as exc:
            LOG.warning(
                "verify parse failed project=%s fact=%s worker=%s error=%s stdout_preview=%s",
                project.project.id,
                fact.id,
                worker.name,
                exc,
                preview(result.stdout),
            )
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return "failed"
        if kind == "rejected":
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return "rejected"
        response = client.verify_fact(
            project.project.id,
            fact.id,
            intent.id,
            worker.name,
            data["verdict"],
            data["summary"],
            data["evidence"],
        )
        if not response.ok:
            LOG.warning(
                "verify write failed project=%s fact=%s worker=%s status=%s body=%s",
                project.project.id,
                fact.id,
                worker.name,
                response.status_code,
                response.text,
            )
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return "failed"
        LOG.info(
            "fact verification concluded project=%s fact=%s verdict=%s worker=%s elapsed_ms=%s",
            project.project.id,
            fact.id,
            data["verdict"],
            worker.name,
            elapsed_ms,
        )
        return "success"
    except Exception:
        LOG.exception(
            "verify task crashed project=%s fact=%s intent=%s worker=%s",
            project.project.id,
            fact.id,
            intent.id,
            worker.name,
        )
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return "failed"
    finally:
        lease.stop()

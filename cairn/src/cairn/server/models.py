from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class Settings(BaseModel):
    intent_timeout: int = Field(ge=5)
    reason_timeout: int = Field(ge=5)


class Evidence(BaseModel):
    id: str
    kind: str
    summary: str
    artifact_path: str | None = None
    source_url: str | None = None
    created_at: str


class Attempt(BaseModel):
    id: str
    intent_id: str
    worker: str
    action: str
    outcome: Literal["success", "failed", "inconclusive"]
    summary: str
    artifact_path: str | None = None
    created_at: str


class Fact(BaseModel):
    id: str
    description: str
    status: Literal["candidate", "verified", "rejected"] = "verified"
    category: str | None = None
    target: str | None = None
    component: str | None = None
    version: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    created_by: str | None = None
    created_at: str | None = None
    verification_summary: str | None = None
    verified_by: str | None = None
    verified_at: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class AssetEntity(BaseModel):
    id: str
    kind: Literal["host", "component", "service", "application", "credential", "artifact", "other"]
    name: str
    normalized_name: str
    status: Literal["candidate", "verified", "rejected"]
    statuses: list[Literal["candidate", "verified", "rejected"]]
    confidence: float | None = Field(default=None, ge=0, le=1)
    conflicted: bool = False
    attributes: dict[str, Any] = Field(default_factory=dict)
    source_fact_ids: list[str] = Field(default_factory=list)


class AssetRelationship(BaseModel):
    id: str
    from_entity: str
    relationship: Literal["runs", "exposes", "depends_on", "reachable_from", "authenticates_to"]
    to_entity: str
    source_fact_ids: list[str] = Field(default_factory=list)


class CVEQuery(BaseModel):
    vendor: str | None = None
    product: str
    version: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    source_fact_ids: list[str] = Field(default_factory=list)
    command: str


class ProjectIntelligence(BaseModel):
    entities: list[AssetEntity]
    relationships: list[AssetRelationship]
    cve_queries: list[CVEQuery]


class Intent(BaseModel):
    id: str
    from_: list[str] = Field(alias="from")
    to: str | None = None
    description: str
    creator: str
    worker: str | None = None
    last_heartbeat_at: str | None = None
    created_at: str
    concluded_at: str | None = None

    model_config = {"populate_by_name": True}


class Hint(BaseModel):
    id: str
    content: str
    creator: str
    created_at: str


class ProjectReason(BaseModel):
    worker: str
    trigger: str
    started_at: str
    last_heartbeat_at: str


class ProjectMeta(BaseModel):
    id: str
    title: str
    status: Literal["active", "stopped", "completed"]
    bootstrap_enabled: bool
    created_at: str
    reason: ProjectReason | None = None


class ProjectSummary(ProjectMeta):
    fact_count: int
    intent_count: int
    working_intent_count: int
    unclaimed_intent_count: int
    hint_count: int


class ProjectDetail(BaseModel):
    project: ProjectMeta
    facts: list[Fact]
    intents: list[Intent]
    hints: list[Hint]


class CreateHintInline(BaseModel):
    content: str
    creator: str

    @field_validator("content", "creator")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CreateProjectRequest(BaseModel):
    title: str
    origin: str
    goal: str
    bootstrap_enabled: bool = True
    hints: list[CreateHintInline] | None = None

    @field_validator("title", "origin", "goal")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CreateHintRequest(BaseModel):
    content: str
    creator: str

    @field_validator("content", "creator")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CreateIntentRequest(BaseModel):
    from_: list[str] = Field(alias="from", min_length=1)
    description: str
    creator: str
    worker: str | None = None
    lease_id: str | None = Field(default=None, min_length=16, max_length=200)

    model_config = {"populate_by_name": True}

    @field_validator("description", "creator", "worker")
    @classmethod
    def validate_non_empty_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("from_")
    @classmethod
    def validate_fact_ids(cls, value: list[str]) -> list[str]:
        cleaned = []
        for item in value:
            text = item.strip()
            if not text:
                raise ValueError("fact ids must not be empty")
            cleaned.append(text)
        return cleaned


class HeartbeatRequest(BaseModel):
    worker: str
    lease_id: str | None = Field(default=None, min_length=16, max_length=200)

    @field_validator("worker")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ReasonClaimRequest(BaseModel):
    worker: str
    trigger: str
    lease_id: str | None = Field(default=None, min_length=16, max_length=200)

    @field_validator("worker", "trigger")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class EvidenceInput(BaseModel):
    kind: str
    summary: str
    artifact_path: str | None = None
    source_url: str | None = None

    @field_validator("kind", "summary", "artifact_path", "source_url")
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class AttemptInput(BaseModel):
    action: str
    outcome: Literal["success", "failed", "inconclusive"]
    summary: str
    artifact_path: str | None = None

    @field_validator("action", "summary", "artifact_path")
    @classmethod
    def validate_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ConcludeRequest(BaseModel):
    worker: str
    description: str
    status: Literal["candidate", "verified"] = "candidate"
    category: str | None = None
    target: str | None = None
    component: str | None = None
    version: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    evidence: list[EvidenceInput] = Field(default_factory=list)
    attempts: list[AttemptInput] = Field(default_factory=list)
    lease_id: str | None = Field(default=None, min_length=16, max_length=200)

    @field_validator("worker", "description", "category", "target", "component", "version")
    @classmethod
    def validate_non_empty_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class VerifyFactRequest(BaseModel):
    intent_id: str
    worker: str
    verdict: Literal["verified", "rejected"]
    summary: str
    evidence: list[EvidenceInput] = Field(default_factory=list)
    lease_id: str | None = Field(default=None, min_length=16, max_length=200)

    @field_validator("intent_id", "worker", "summary")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CompleteRequest(BaseModel):
    from_: list[str] = Field(alias="from", min_length=1)
    description: str
    worker: str
    lease_id: str | None = Field(default=None, min_length=16, max_length=200)

    model_config = {"populate_by_name": True}

    @field_validator("description", "worker")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("from_")
    @classmethod
    def validate_fact_ids(cls, value: list[str]) -> list[str]:
        cleaned = []
        for item in value:
            text = item.strip()
            if not text:
                raise ValueError("fact ids must not be empty")
            cleaned.append(text)
        return cleaned


class ConcludeResponse(BaseModel):
    fact: Fact
    intent: Intent


class UpdateProjectStatusRequest(BaseModel):
    status: Literal["active", "stopped"]


class UpdateProjectTitleRequest(BaseModel):
    title: str

    @field_validator("title")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ReopenRequest(BaseModel):
    description: str
    creator: str

    @field_validator("description", "creator")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ReopenResponse(BaseModel):
    project: ProjectMeta
    fact: Fact
    intent: Intent


class TaskRun(BaseModel):
    id: str
    project_id: str
    intent_id: str | None = None
    task_type: Literal["bootstrap", "reason", "explore", "verify"]
    worker: str
    status: Literal["running", "finished"]
    outcome: str | None = None
    started_at: str
    finished_at: str | None = None


class CreateTaskRunRequest(BaseModel):
    id: str = Field(min_length=16, max_length=200)
    intent_id: str | None = None
    task_type: Literal["bootstrap", "reason", "explore", "verify"]
    worker: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_intent_scope(self) -> "CreateTaskRunRequest":
        if self.task_type == "reason" and self.intent_id is not None:
            raise ValueError("reason task runs must not have an intent_id")
        if self.task_type != "reason" and self.intent_id is None:
            raise ValueError(f"{self.task_type} task runs require an intent_id")
        return self


class FinishTaskRunRequest(BaseModel):
    outcome: str = Field(min_length=1, max_length=100)

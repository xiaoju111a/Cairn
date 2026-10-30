from __future__ import annotations

from typing import Any

from cairn.dispatcher.output_parser import extract_json_object


def parse_json_output(stdout: str) -> dict[str, Any]:
    return extract_json_object(stdout)


def _unwrap_wrapped_payload(payload: dict[str, Any]) -> tuple[bool | None, dict[str, Any] | None]:
    accepted = payload.get("accepted")
    if accepted is False:
        return False, None
    if accepted is True:
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ValueError("data must be an object")
        return True, data
    return None, None


def _is_dict(value: Any) -> bool:
    return isinstance(value, dict)


def _looks_like_reason_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    keys = set(payload)
    if keys == {"complete"}:
        complete = payload["complete"]
        return isinstance(complete, dict) and "from" in complete and "description" in complete
    if keys == {"intents"}:
        return isinstance(payload["intents"], list)
    if keys == {"intent"}:
        intent = payload["intent"]
        return isinstance(intent, dict) and "from" in intent and "description" in intent
    return False


def _looks_like_bootstrap_execute_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict) or set(payload) != {"fact", "complete"}:
        return False
    return _is_dict(payload.get("fact")) and _is_dict(payload.get("complete"))


def _looks_like_bootstrap_conclude_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    keys = set(payload)
    if keys not in ({"fact"}, {"fact", "complete"}):
        return False
    return _is_dict(payload.get("fact"))


def _looks_like_explore_data(payload: dict[str, Any]) -> bool:
    return isinstance(payload, dict) and (
        set(payload) == {"description"} or "finding" in payload
    )


def _validate_evidence(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("evidence must be an array")
    result = []
    for index, entry in enumerate(value):
        if not isinstance(entry, dict):
            raise ValueError(f"evidence[{index}] must be an object")
        kind = entry.get("kind")
        summary = entry.get("summary")
        if not isinstance(kind, str) or not kind.strip():
            raise ValueError(f"evidence[{index}].kind is required")
        if not isinstance(summary, str) or not summary.strip():
            raise ValueError(f"evidence[{index}].summary is required")
        normalized = {"kind": kind.strip(), "summary": summary.strip()}
        for key in ("artifact_path", "source_url"):
            item = entry.get(key)
            if item is not None:
                if not isinstance(item, str) or not item.strip():
                    raise ValueError(f"evidence[{index}].{key} must be a non-empty string")
                normalized[key] = item.strip()
        result.append(normalized)
    return result


def _validate_attempts(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("attempts must be an array")
    result = []
    for index, entry in enumerate(value):
        if not isinstance(entry, dict):
            raise ValueError(f"attempts[{index}] must be an object")
        action = entry.get("action")
        outcome = entry.get("outcome")
        summary = entry.get("summary")
        if not isinstance(action, str) or not action.strip():
            raise ValueError(f"attempts[{index}].action is required")
        if outcome not in {"success", "failed", "inconclusive"}:
            raise ValueError(f"attempts[{index}].outcome is invalid")
        if not isinstance(summary, str) or not summary.strip():
            raise ValueError(f"attempts[{index}].summary is required")
        normalized = {
            "action": action.strip(),
            "outcome": outcome,
            "summary": summary.strip(),
        }
        artifact_path = entry.get("artifact_path")
        if artifact_path is not None:
            if not isinstance(artifact_path, str) or not artifact_path.strip():
                raise ValueError(f"attempts[{index}].artifact_path must be a non-empty string")
            normalized["artifact_path"] = artifact_path.strip()
        result.append(normalized)
    return result


def _validate_finding(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("finding must be an object")
    description = value.get("description")
    if not isinstance(description, str) or not description.strip():
        raise ValueError("finding.description is required")
    result: dict[str, Any] = {"description": description.strip()}
    for key in ("category", "target", "component", "version"):
        item = value.get(key)
        if item is not None:
            if not isinstance(item, str) or not item.strip():
                raise ValueError(f"finding.{key} must be a non-empty string")
            result[key] = item.strip()
    confidence = value.get("confidence")
    if confidence is not None:
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise ValueError("finding.confidence must be a number")
        if not 0 <= float(confidence) <= 1:
            raise ValueError("finding.confidence must be between 0 and 1")
        result["confidence"] = float(confidence)
    result["evidence"] = _validate_evidence(value.get("evidence"))
    return result


def validate_reason_payload(
    payload: dict[str, Any], open_intents_empty: bool, max_intents: int,
) -> tuple[str, dict[str, Any] | list[dict[str, Any]] | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_reason_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")
    complete = data.get("complete")
    intents = data.get("intents")
    # backward compat: accept singular "intent" key from LLMs
    if intents is None:
        singular = data.get("intent")
        if isinstance(singular, dict):
            intents = [singular]
    if complete is not None:
        if intents is not None:
            raise ValueError("complete and intents cannot coexist")
        if not isinstance(complete, dict) or "from" not in complete or "description" not in complete:
            raise ValueError("invalid complete payload")
        return "complete", complete
    if intents is not None:
        if not isinstance(intents, list):
            raise ValueError("intents must be an array")
        for i, intent in enumerate(intents):
            if not isinstance(intent, dict) or "from" not in intent or "description" not in intent:
                raise ValueError(f"invalid intent at index {i}")
        if not intents and open_intents_empty:
            raise ValueError("intents must not be empty when open_intents is empty")
        intents = intents[:max_intents]
        if not intents:
            return "noop", None
        return "intents", intents
    if open_intents_empty:
        raise ValueError("intents is required when open_intents is empty")
    return "noop", None


def validate_bootstrap_execute_payload(payload: dict[str, Any]) -> tuple[str, dict[str, str] | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_bootstrap_execute_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")

    fact = data.get("fact")
    if not isinstance(fact, dict):
        raise ValueError("fact is required")
    fact_description = fact.get("description")
    if not isinstance(fact_description, str) or not fact_description.strip():
        raise ValueError("fact.description is required")

    result = {"fact_description": fact_description.strip()}
    complete = data.get("complete")
    if complete is None:
        raise ValueError("complete is required")
    if not isinstance(complete, dict):
        raise ValueError("complete must be an object")
    complete_description = complete.get("description")
    if not isinstance(complete_description, str) or not complete_description.strip():
        raise ValueError("complete.description is required")
    result["complete_description"] = complete_description.strip()
    return "complete", result


def validate_bootstrap_conclude_payload(payload: dict[str, Any]) -> tuple[str, str | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_bootstrap_conclude_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")
    extra_keys = set(data) - {"fact", "complete"}
    if extra_keys:
        raise ValueError("unexpected keys in conclude payload")
    fact = data.get("fact")
    if not isinstance(fact, dict):
        raise ValueError("fact is required")
    fact_description = fact.get("description")
    if not isinstance(fact_description, str) or not fact_description.strip():
        raise ValueError("fact.description is required")
    return "fact", fact_description.strip()


def validate_explore_payload(payload: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_explore_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")
    if "finding" in data:
        finding = _validate_finding(data["finding"])
        finding["attempts"] = _validate_attempts(data.get("attempts"))
        return "fact", finding
    description = data.get("description")
    if not isinstance(description, str) or not description.strip():
        raise ValueError("description is required")
    return "fact", {"description": description.strip(), "evidence": [], "attempts": []}


def validate_verify_payload(payload: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")
    verdict = data.get("verdict")
    if verdict not in {"verified", "rejected"}:
        raise ValueError("verdict must be verified or rejected")
    summary = data.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        raise ValueError("summary is required")
    return "verdict", {
        "verdict": verdict,
        "summary": summary.strip(),
        "evidence": _validate_evidence(data.get("evidence")),
    }

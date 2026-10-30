from __future__ import annotations

import hashlib
import ipaddress
import re
import shlex
from typing import Any, Iterable
from urllib.parse import urlsplit

from cairn.server.models import AssetEntity, AssetRelationship, CVEQuery, ProjectIntelligence


COMPONENT_ALIASES: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("apache http server", "apache httpd", "apache2", "httpd"), "Apache", "Apache HTTP Server"),
    (("openssh", "open ssh"), "OpenBSD", "OpenSSH"),
    (("nginx", "nginx plus"), "F5", "nginx"),
    (("wordpress", "word press"), "WordPress", "WordPress"),
    (("microsoft iis", "internet information services", "iis"), "Microsoft", "Internet Information Services"),
    (("tomcat", "apache tomcat"), "Apache", "Apache Tomcat"),
    (("struts", "apache struts"), "Apache", "Apache Struts"),
    (("spring boot",), "VMware", "Spring Boot"),
    (("spring framework", "spring mvc"), "VMware", "Spring Framework"),
    (("jenkins",), "Jenkins Project", "Jenkins"),
    (("gitlab",), "GitLab", "GitLab"),
    (("redis",), "Redis", "Redis"),
    (("elasticsearch", "elastic search"), "Elastic", "Elasticsearch"),
    (("kubernetes", "k8s"), "Kubernetes", "Kubernetes"),
    (("docker engine", "docker"), "Docker", "Docker Engine"),
)

_VERSION_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])v?(\d+(?:\.\d+){1,4}(?:(?:[A-Za-z]|[-+._])[0-9A-Za-z.-]*)?)"
)
_STATUS_RANK = {"rejected": 0, "candidate": 1, "verified": 2}


def _stable_id(prefix: str, *values: str) -> str:
    raw = "\x1f".join(value.strip().lower() for value in values)
    return f"{prefix}_{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]}"


def _clean_version(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    match = _VERSION_TOKEN.search(text)
    if match:
        return match.group(1)
    return text.removeprefix("v").strip() or None


def normalize_target(value: str) -> dict[str, Any]:
    original = value.strip()
    candidate = original if "://" in original else f"//{original}"
    parsed = urlsplit(candidate)
    host = (parsed.hostname or original).strip(".[]").lower()
    try:
        ipaddress.ip_address(host)
        kind = "host"
        host_type = "ip"
    except ValueError:
        kind = "host"
        host_type = "domain" if "." in host else "hostname"
    attributes: dict[str, Any] = {"host_type": host_type, "observed": original}
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is not None:
        attributes["port"] = port
    if parsed.scheme:
        attributes["scheme"] = parsed.scheme.lower()
    normalized = host if port is None else f"{host}:{port}"
    return {"kind": kind, "name": original, "normalized_name": normalized, "attributes": attributes}


def normalize_component(value: str, version: str | None = None) -> dict[str, Any]:
    original = value.strip()
    observed_product = _VERSION_TOKEN.sub(" ", original)
    observed_product = re.sub(r"\s+", " ", observed_product).strip(" ./_-") or original
    lowered = re.sub(r"[^a-z0-9]+", " ", observed_product.lower()).strip()
    detected_version = _clean_version(version)
    if detected_version is None:
        detected_version = _clean_version(original)
    name_without_version = re.sub(r"\s+", " ", lowered).strip(" -_/.")
    vendor = None
    product = observed_product
    aliases: list[str] = []
    for candidates, canonical_vendor, canonical_product in COMPONENT_ALIASES:
        if any(alias == name_without_version or alias in name_without_version for alias in candidates):
            vendor = canonical_vendor
            product = canonical_product
            aliases = list(candidates)
            break
    normalized_name = f"{vendor or 'unknown'}::{product}".lower()
    return {
        "kind": "component",
        "name": product,
        "normalized_name": normalized_name,
        "vendor": vendor,
        "product": product,
        "version": detected_version,
        "attributes": {"observed": original, "aliases": aliases},
    }


def _merge_entity(store: dict[str, dict[str, Any]], incoming: dict[str, Any], fact: dict[str, Any]) -> None:
    entity = store.get(incoming["id"])
    status = str(fact.get("status") or "verified")
    confidence = fact.get("confidence")
    if entity is None:
        store[incoming["id"]] = {
            **incoming,
            "status": status,
            "statuses": [status],
            "confidence": confidence,
            "source_fact_ids": [fact["id"]],
            "conflicted": False,
        }
        return
    if fact["id"] not in entity["source_fact_ids"]:
        entity["source_fact_ids"].append(fact["id"])
    if status not in entity["statuses"]:
        entity["statuses"].append(status)
    if _STATUS_RANK.get(status, 0) > _STATUS_RANK.get(entity["status"], 0):
        entity["status"] = status
    if confidence is not None:
        current = entity.get("confidence")
        entity["confidence"] = max(float(confidence), float(current)) if current is not None else confidence
    entity["conflicted"] = "verified" in entity["statuses"] and "rejected" in entity["statuses"]


def build_project_intelligence(facts: Iterable[dict[str, Any]]) -> ProjectIntelligence:
    entities: dict[str, dict[str, Any]] = {}
    relationships: dict[tuple[str, str, str], dict[str, Any]] = {}
    component_queries: dict[tuple[str | None, str, str | None], dict[str, Any]] = {}

    ordered_facts = sorted(
        (dict(raw) for raw in facts), key=lambda item: str(item.get("id") or "")
    )
    for fact in ordered_facts:
        fact_id = str(fact.get("id") or "")
        if fact_id in {"origin", "goal"}:
            continue
        target_id = None
        target = fact.get("target")
        if isinstance(target, str) and target.strip():
            normalized_target = normalize_target(target)
            target_id = _stable_id("asset", normalized_target["normalized_name"])
            _merge_entity(entities, {"id": target_id, **normalized_target}, fact)

        component = fact.get("component")
        if isinstance(component, str) and component.strip():
            normalized_component = normalize_component(component, fact.get("version"))
            component_scope = target_id or "global"
            component_id = _stable_id(
                "component", component_scope, normalized_component["normalized_name"], normalized_component.get("version") or ""
            )
            attributes = dict(normalized_component.pop("attributes"))
            attributes.update(
                {
                    key: normalized_component[key]
                    for key in ("vendor", "product", "version")
                    if normalized_component.get(key) is not None
                }
            )
            entity_payload = {
                "id": component_id,
                "kind": "component",
                "name": normalized_component["name"],
                "normalized_name": normalized_component["normalized_name"],
                "attributes": attributes,
            }
            _merge_entity(entities, entity_payload, fact)
            if target_id is not None:
                relation_key = (target_id, "runs", component_id)
                relation = relationships.setdefault(
                    relation_key,
                    {
                        "id": _stable_id("rel", *relation_key),
                        "from_entity": target_id,
                        "relationship": "runs",
                        "to_entity": component_id,
                        "source_fact_ids": [],
                    },
                )
                if fact_id not in relation["source_fact_ids"]:
                    relation["source_fact_ids"].append(fact_id)

            if fact.get("status") == "rejected":
                continue
            query_key = (
                normalized_component.get("vendor"),
                normalized_component["product"],
                normalized_component.get("version"),
            )
            query = component_queries.setdefault(
                query_key,
                {
                    "vendor": query_key[0],
                    "product": query_key[1],
                    "version": query_key[2],
                    "confidence": fact.get("confidence"),
                    "source_fact_ids": [],
                },
            )
            if fact_id not in query["source_fact_ids"]:
                query["source_fact_ids"].append(fact_id)
            if fact.get("confidence") is not None:
                current = query.get("confidence")
                query["confidence"] = max(float(current or 0), float(fact["confidence"]))

    cve_queries = []
    for query in component_queries.values():
        parts = ["cve-intel", "recommend"]
        if query["vendor"]:
            parts.extend(["--vendor", shlex.quote(query["vendor"])])
        parts.extend(["--product", shlex.quote(query["product"])])
        if query["version"]:
            parts.extend(["--version", shlex.quote(query["version"])])
        query["command"] = " ".join(parts)
        cve_queries.append(CVEQuery(**query))

    return ProjectIntelligence(
        entities=[AssetEntity(**value) for value in sorted(entities.values(), key=lambda item: item["id"])],
        relationships=[
            AssetRelationship(**value)
            for value in sorted(relationships.values(), key=lambda item: item["id"])
        ],
        cve_queries=sorted(cve_queries, key=lambda item: (item.product.lower(), item.version or "")),
    )

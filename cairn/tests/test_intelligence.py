from __future__ import annotations

from cairn.server.intelligence import (
    build_project_intelligence,
    normalize_component,
    normalize_target,
)


def test_target_and_component_fingerprints_are_normalized() -> None:
    target = normalize_target("https://Example.COM:8443/admin")
    component = normalize_component("apache2 2.4.49")

    assert target["normalized_name"] == "example.com:8443"
    assert target["attributes"]["scheme"] == "https"
    assert target["attributes"]["port"] == 8443
    assert component["vendor"] == "Apache"
    assert component["product"] == "Apache HTTP Server"
    assert component["version"] == "2.4.49"

    openssh = normalize_component("OpenSSH_9.2p1")
    unknown = normalize_component("Example Gateway 3.1.4")
    assert openssh["product"] == "OpenSSH"
    assert openssh["version"] == "9.2p1"
    assert unknown["product"] == "Example Gateway"
    assert unknown["version"] == "3.1.4"


def test_project_intelligence_merges_evidence_and_builds_cve_query() -> None:
    intelligence = build_project_intelligence(
        [
            {
                "id": "f001",
                "description": "initial fingerprint",
                "status": "candidate",
                "target": "https://example.com:8443/path",
                "component": "apache2",
                "version": "2.4.49",
                "confidence": 0.7,
            },
            {
                "id": "f002",
                "description": "independently verified fingerprint",
                "status": "verified",
                "target": "example.com:8443",
                "component": "Apache HTTP Server",
                "version": "2.4.49",
                "confidence": 0.95,
            },
        ]
    )

    assert len(intelligence.entities) == 2
    host = next(entity for entity in intelligence.entities if entity.kind == "host")
    component = next(entity for entity in intelligence.entities if entity.kind == "component")
    assert host.status == "verified"
    assert component.status == "verified"
    assert component.source_fact_ids == ["f001", "f002"]
    assert component.confidence == 0.95
    assert intelligence.relationships[0].relationship == "runs"
    assert intelligence.relationships[0].source_fact_ids == ["f001", "f002"]
    query = intelligence.cve_queries[0]
    assert query.vendor == "Apache"
    assert query.product == "Apache HTTP Server"
    assert query.version == "2.4.49"
    assert query.command == (
        "cve-intel recommend --vendor Apache --product 'Apache HTTP Server' --version 2.4.49"
    )


def test_verified_and_rejected_observations_mark_entity_conflicted() -> None:
    intelligence = build_project_intelligence(
        [
            {
                "id": "f001",
                "status": "verified",
                "target": "example.test",
                "description": "verified",
            },
            {
                "id": "f002",
                "status": "rejected",
                "target": "example.test",
                "description": "rejected",
            },
        ]
    )

    assert intelligence.entities[0].conflicted is True
    assert set(intelligence.entities[0].statuses) == {"verified", "rejected"}


def test_rejected_component_does_not_generate_cve_work() -> None:
    intelligence = build_project_intelligence(
        [
            {
                "id": "f001",
                "status": "rejected",
                "component": "OpenSSH",
                "version": "9.2",
                "description": "disproved fingerprint",
            }
        ]
    )

    assert intelligence.entities[0].status == "rejected"
    assert intelligence.cve_queries == []

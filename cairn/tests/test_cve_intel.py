from __future__ import annotations

import importlib.util
import json
from pathlib import Path


SCRIPT = Path(__file__).parents[2] / "container" / "cve_intel.py"
SPEC = importlib.util.spec_from_file_location("cve_intel", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
cve_intel = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cve_intel)


def _record(
    cve_id: str,
    *,
    vendor: str,
    product: str,
    versions: list[dict],
    score: float = 9.8,
) -> dict:
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {
            "cveId": cve_id,
            "state": "PUBLISHED",
            "datePublished": "2026-01-01T00:00:00Z",
            "dateUpdated": "2026-01-02T00:00:00Z",
        },
        "containers": {
            "cna": {
                "title": f"Test vulnerability in {product}",
                "descriptions": [{"lang": "en", "value": "A test vulnerability."}],
                "affected": [
                    {
                        "vendor": vendor,
                        "product": product,
                        "defaultStatus": "unaffected",
                        "versions": versions,
                    }
                ],
                "metrics": [
                    {"cvssV3_1": {"baseScore": score, "baseSeverity": "CRITICAL"}}
                ],
                "problemTypes": [
                    {"descriptions": [{"lang": "en", "cweId": "CWE-78"}]}
                ],
                "references": [{"url": "https://example.test/advisory"}],
            }
        },
    }


def _write_record(cves: Path, cve_id: str, payload: dict) -> Path:
    path = cves / "2026" / "1xxx" / f"{cve_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_index_searches_exact_and_range_versions(tmp_path: Path) -> None:
    repository = tmp_path / "cvelistV5"
    cves = repository / "cves"
    database = tmp_path / "cve-index.sqlite3"
    _write_record(
        cves,
        "CVE-2026-1001",
        _record(
            "CVE-2026-1001",
            vendor="Apache",
            product="HTTP Server",
            versions=[{"version": "2.4.49", "status": "affected"}],
        ),
    )
    _write_record(
        cves,
        "CVE-2026-1002",
        _record(
            "CVE-2026-1002",
            vendor="OpenBSD",
            product="OpenSSH",
            versions=[
                {
                    "version": "8.5",
                    "lessThan": "9.8",
                    "versionType": "semver",
                    "status": "affected",
                }
            ],
            score=8.1,
        ),
    )

    assert cve_intel.build_index(cves, database, source_commit="abc123") == 2

    exact = cve_intel.search_database(
        database, product="HTTP Server", version="2.4.49"
    )
    ranged = cve_intel.search_database(database, product="OpenSSH", version="9.2")
    unaffected = cve_intel.search_database(database, product="OpenSSH", version="9.9")

    assert exact["results"][0]["version_match"] == "exact"
    assert exact["results"][0]["cwes"] == ["CWE-78"]
    assert ranged["results"][0]["version_match"] == "range"
    assert unaffected["count"] == 0


def test_incremental_index_replaces_and_deletes_records(tmp_path: Path) -> None:
    repository = tmp_path / "cvelistV5"
    cves = repository / "cves"
    database = tmp_path / "cve-index.sqlite3"
    path = _write_record(
        cves,
        "CVE-2026-1003",
        _record(
            "CVE-2026-1003",
            vendor="Example",
            product="Widget",
            versions=[{"version": "1.0", "status": "affected"}],
        ),
    )
    cve_intel.build_index(cves, database, source_commit="first")

    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["containers"]["cna"]["title"] = "Updated title"
    path.write_text(json.dumps(payload), encoding="utf-8")
    source_path = path.relative_to(repository).as_posix()
    assert cve_intel.update_index(
        cves, database, [source_path], source_commit="second"
    ) == 1
    result = cve_intel.search_database(database, cve_id="CVE-2026-1003")
    assert result["results"][0]["title"] == "Updated title"

    path.unlink()
    cve_intel.update_index(cves, database, [source_path], source_commit="third")
    assert cve_intel.search_database(database, cve_id="CVE-2026-1003")["count"] == 0


def test_health_reports_commit_record_count_and_freshness(tmp_path: Path) -> None:
    repository = tmp_path / "cvelistV5"
    cves = repository / "cves"
    database = tmp_path / "cve-index.sqlite3"
    _write_record(
        cves,
        "CVE-2026-1004",
        _record(
            "CVE-2026-1004",
            vendor="Example",
            product="Healthy",
            versions=[{"version": "1.0", "status": "affected"}],
        ),
    )
    cve_intel.build_index(cves, database, source_commit="healthy-commit")

    status = cve_intel.database_status(database, max_age=60)

    assert status["healthy"] is True
    assert status["record_count"] == 1
    assert status["source_commit"] == "healthy-commit"


def test_affected_match_wins_over_overlapping_unaffected_entry() -> None:
    item = {
        "default_status": "unaffected",
        "versions": [
            {"version": "1.0", "lessThan": "3.0", "status": "unaffected"},
            {"version": "2.0", "lessThan": "2.5", "status": "affected"},
        ],
    }

    assert cve_intel.assess_version("2.3", item) == "range"


def test_version_comparison_uses_semver_and_pep440_rules() -> None:
    semver_item = {
        "default_status": "unaffected",
        "versions": [
            {
                "version": "1.0.0-rc.1",
                "lessThan": "1.0.0",
                "versionType": "semver",
                "status": "affected",
            }
        ],
    }
    python_item = {
        "default_status": "unaffected",
        "versions": [
            {
                "version": "1.0rc1",
                "lessThan": "1.0",
                "versionType": "python",
                "status": "affected",
            }
        ],
    }

    assert cve_intel.assess_version("1.0.0-rc.2", semver_item) == "range"
    assert cve_intel.assess_version("1.0rc2", python_item) == "range"


def test_unknown_ecosystem_range_is_not_reported_as_a_match() -> None:
    item = {
        "default_status": "unknown",
        "versions": [
            {
                "version": "1:1.0-1",
                "lessThan": "1:2.0-1",
                "versionType": "deb",
                "status": "affected",
            }
        ],
    }

    assert cve_intel.assess_version("1:1.5-1", item) == "candidate"


def test_schema_change_rebuilds_index_atomically(tmp_path: Path) -> None:
    repository = tmp_path / "cvelistV5"
    cves = repository / "cves"
    database = tmp_path / "cve-index.sqlite3"
    _write_record(
        cves,
        "CVE-2026-1005",
        _record(
            "CVE-2026-1005",
            vendor="Example",
            product="Schema",
            versions=[{"version": "1.0", "status": "affected"}],
        ),
    )
    cve_intel.build_index(cves, database, source_commit="old")
    with cve_intel._connect(database) as connection:
        connection.execute(
            "UPDATE metadata SET value = 'old-schema' WHERE key = 'schema_version'"
        )

    cve_intel.update_index(cves, database, [], source_commit="new")
    status = cve_intel.database_status(database)

    assert status["schema_version"] == cve_intel.SCHEMA_VERSION
    assert status["source_commit"] == "new"


def test_version_match_is_limited_to_the_queried_product(tmp_path: Path) -> None:
    repository = tmp_path / "cvelistV5"
    cves = repository / "cves"
    database = tmp_path / "cve-index.sqlite3"
    payload = _record(
        "CVE-2026-1006",
        vendor="Example",
        product="Server",
        versions=[{"version": "1.0", "status": "affected"}],
    )
    payload["containers"]["cna"]["affected"].append(
        {
            "vendor": "Example",
            "product": "Client",
            "defaultStatus": "unaffected",
            "versions": [{"version": "2.0", "status": "affected"}],
        }
    )
    _write_record(cves, "CVE-2026-1006", payload)
    cve_intel.build_index(cves, database, source_commit="multi-product")

    server = cve_intel.search_database(
        database, vendor="Example", product="Server", version="2.0"
    )
    client = cve_intel.search_database(
        database, vendor="Example", product="Client", version="2.0"
    )

    assert server["count"] == 0
    assert client["results"][0]["version_match"] == "exact"
    assert [item["product"] for item in client["results"][0]["affected"]] == ["Client"]


def test_cisa_kev_enrichment_marks_known_exploited_cves(tmp_path: Path) -> None:
    repository = tmp_path / "cvelistV5"
    cves = repository / "cves"
    database = tmp_path / "cve-index.sqlite3"
    _write_record(
        cves,
        "CVE-2026-1007",
        _record(
            "CVE-2026-1007",
            vendor="Example",
            product="Exploited",
            versions=[{"version": "1.0", "status": "affected"}],
        ),
    )
    cve_intel.build_index(cves, database, source_commit="kev")
    matched = cve_intel.apply_kev_catalog(
        database,
        {
            "catalogVersion": "2026.10.30",
            "dateReleased": "2026-10-30T00:00:00Z",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-1007",
                    "dateAdded": "2026-10-29",
                    "dueDate": "2026-11-15",
                    "requiredAction": "Apply mitigations.",
                    "knownRansomwareCampaignUse": "Known",
                },
                {"cveID": "CVE-2026-9999", "dateAdded": "2026-10-30"},
            ],
        },
    )

    result = cve_intel.search_database(database, cve_id="CVE-2026-1007")

    assert matched == 1
    assert result["results"][0]["known_exploited"] is True
    assert result["results"][0]["kev"]["known_ransomware_campaign_use"] == "Known"
    assert cve_intel.database_status(database)["kev_catalog_count"] == "2"


def _nvd_payload(cve_id: str) -> dict:
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "vulnStatus": "Analyzed",
                    "lastModified": "2026-10-30T00:00:00.000Z",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                },
                            }
                        ]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:example:nvd_product:*:*:*:*:*:*:*:*",
                                            "matchCriteriaId": "00000000-0000-0000-0000-000000000001",
                                            "versionStartIncluding": "1.0",
                                            "versionEndExcluding": "2.0",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            }
        ],
    }


def test_nvd_enrichment_adds_cvss_status_and_cpe_matches(tmp_path: Path) -> None:
    repository = tmp_path / "cvelistV5"
    cves = repository / "cves"
    database = tmp_path / "cve-index.sqlite3"
    _write_record(
        cves,
        "CVE-2026-1008",
        _record(
            "CVE-2026-1008",
            vendor="Example",
            product="NVD Product",
            versions=[{"version": "1.5", "status": "affected"}],
        ),
    )
    cve_intel.build_index(cves, database, source_commit="nvd")

    matched = cve_intel.apply_nvd_page(
        database,
        _nvd_payload("CVE-2026-1008"),
        next_index=1,
        full_sync=True,
        sync_end="2026-10-30T00:00:00+00:00",
    )
    result = cve_intel.search_database(database, cve_id="CVE-2026-1008")

    assert matched == 1
    assert result["results"][0]["nvd"]["cvss"] == 9.8
    assert result["results"][0]["nvd"]["status"] == "Analyzed"
    assert result["results"][0]["nvd"]["cpe_matches"][0]["version_end_excluding"] == "2.0"


def test_core_incremental_update_preserves_nvd_enrichment(tmp_path: Path) -> None:
    repository = tmp_path / "cvelistV5"
    cves = repository / "cves"
    database = tmp_path / "cve-index.sqlite3"
    path = _write_record(
        cves,
        "CVE-2026-1009",
        _record(
            "CVE-2026-1009",
            vendor="Example",
            product="Preserved",
            versions=[{"version": "1.0", "status": "affected"}],
        ),
    )
    cve_intel.build_index(cves, database, source_commit="before")
    cve_intel.apply_nvd_page(
        database,
        _nvd_payload("CVE-2026-1009"),
        next_index=1,
        full_sync=True,
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["containers"]["cna"]["title"] = "Core record updated"
    path.write_text(json.dumps(payload), encoding="utf-8")

    cve_intel.update_index(
        cves,
        database,
        [path.relative_to(repository).as_posix()],
        source_commit="after",
    )
    result = cve_intel.search_database(database, cve_id="CVE-2026-1009")

    assert result["results"][0]["title"] == "Core record updated"
    assert result["results"][0]["nvd"]["cvss"] == 9.8


def test_nvd_full_sync_resumes_by_page_and_marks_completion(
    tmp_path: Path, monkeypatch
) -> None:
    repository = tmp_path / "cvelistV5"
    cves = repository / "cves"
    database = tmp_path / "cve-index.sqlite3"
    for number in (1010, 1011):
        _write_record(
            cves,
            f"CVE-2026-{number}",
            _record(
                f"CVE-2026-{number}",
                vendor="Example",
                product=f"Page {number}",
                versions=[{"version": "1.0", "status": "affected"}],
            ),
        )
    cve_intel.build_index(cves, database, source_commit="nvd-pages")
    requested_indexes: list[int] = []

    def fake_request(_url, params, *, api_key, retries=5):
        del api_key, retries
        index = int(params["startIndex"])
        requested_indexes.append(index)
        payload = _nvd_payload(f"CVE-2026-{1010 + index}")
        payload["startIndex"] = index
        payload["totalResults"] = 2
        return payload

    monkeypatch.setattr(cve_intel, "_nvd_request", fake_request)

    result = cve_intel.sync_nvd(database, delay=0)
    status = cve_intel.database_status(database)

    assert requested_indexes == [0, 1]
    assert result == {"mode": "full", "pages": 2, "matched": 2}
    assert status["nvd_full_sync_complete"] == "true"
    assert status["nvd_bootstrap_start_index"] == "2"


def test_recommend_normalizes_fingerprint_and_explains_ranking(tmp_path: Path) -> None:
    cves = tmp_path / "cvelistV5" / "cves"
    database = tmp_path / "cve-index.sqlite3"
    _write_record(
        cves,
        "CVE-2026-2001",
        _record(
            "CVE-2026-2001",
            vendor="Apache",
            product="HTTP Server",
            versions=[{"version": "2.4.49", "status": "affected"}],
        ),
    )
    candidate = _record(
        "CVE-2026-2002",
        vendor="Apache",
        product="HTTP Server",
        versions=[{"version": "unknown", "status": "affected"}],
        score=7.5,
    )
    candidate["containers"]["cna"]["affected"][0]["defaultStatus"] = "unknown"
    _write_record(cves, "CVE-2026-2002", candidate)
    cve_intel.build_index(cves, database, source_commit="recommend")
    cve_intel.apply_kev_catalog(
        database,
        {
            "catalogVersion": "test",
            "vulnerabilities": [{"cveID": "CVE-2026-2001", "dateAdded": "2026-10-30"}],
        },
    )

    result = cve_intel.recommend_database(
        database,
        vendor=None,
        product="apache2",
        version="v2.4.49",
        confidence=0.9,
        limit=10,
    )

    assert result["fingerprint"]["vendor"] == "Apache"
    assert result["fingerprint"]["product"] == "Apache HTTP Server"
    assert result["fingerprint"]["version"] == "2.4.49"
    assert [item["cve_id"] for item in result["results"]] == [
        "CVE-2026-2001",
        "CVE-2026-2002",
    ]
    exact, unverified = result["results"]
    assert exact["version_match"] == "exact"
    assert exact["applicability"] == "matched"
    assert exact["relevance_score"] > unverified["relevance_score"]
    assert {reason["signal"] for reason in exact["score_reasons"]} >= {
        "version_exact",
        "known_exploited",
        "cvss",
    }
    assert unverified["version_match"] == "candidate"
    assert unverified["applicability"] == "needs_verification"
    assert "independent verification" in result["interpretation"]


def test_recommend_command_requires_product_and_accepts_confidence() -> None:
    args = cve_intel._parser().parse_args(
        [
            "recommend",
            "--product",
            "OpenSSH",
            "--version",
            "9.2",
            "--confidence",
            "0.75",
        ]
    )

    assert args.command == "recommend"
    assert args.product == "OpenSSH"
    assert args.version == "9.2"
    assert args.confidence == 0.75

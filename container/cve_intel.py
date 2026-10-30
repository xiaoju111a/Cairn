#!/usr/bin/env python3
"""Synchronize, index, and query the official CVE JSON 5 repository."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

try:
    from packaging.version import InvalidVersion, Version
except ImportError:  # pragma: no cover - the worker image installs packaging explicitly
    InvalidVersion = ValueError
    Version = None


DEFAULT_REPOSITORY = Path(os.environ.get("CVE_REPOSITORY", "/home/kali/cve/cvelistV5"))
DEFAULT_DATABASE = Path(os.environ.get("CVE_DATABASE", "/home/kali/cve/cve-index.sqlite3"))
DEFAULT_KEV_FILE = Path(os.environ.get("CVE_KEV_FILE", "/home/kali/cve/cisa-kev.json"))
DEFAULT_KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)
DEFAULT_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SCHEMA_VERSION = "3"


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE cves (
    cve_id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    published TEXT,
    updated TEXT,
    title TEXT,
    description TEXT,
    cvss REAL,
    severity TEXT,
    cwes TEXT NOT NULL,
    references_json TEXT NOT NULL,
    known_exploited INTEGER NOT NULL DEFAULT 0,
    kev_date_added TEXT,
    kev_due_date TEXT,
    kev_required_action TEXT,
    kev_ransomware TEXT,
    nvd_cvss REAL,
    nvd_severity TEXT,
    nvd_status TEXT,
    nvd_last_modified TEXT,
    source_path TEXT NOT NULL UNIQUE
);
CREATE TABLE affected (
    id INTEGER PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    vendor TEXT,
    product TEXT,
    package_name TEXT,
    default_status TEXT,
    versions_json TEXT NOT NULL
);
CREATE INDEX affected_cve_id_idx ON affected(cve_id);
CREATE INDEX affected_vendor_product_idx ON affected(vendor, product);
CREATE TABLE nvd_cpes (
    id INTEGER PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    vulnerable INTEGER NOT NULL,
    criteria TEXT NOT NULL,
    match_criteria_id TEXT,
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including TEXT,
    version_end_excluding TEXT
);
CREATE INDEX nvd_cpes_cve_id_idx ON nvd_cpes(cve_id);
CREATE INDEX nvd_cpes_criteria_idx ON nvd_cpes(criteria);
CREATE VIRTUAL TABLE search_docs USING fts5(
    cve_id UNINDEXED,
    vendor,
    product,
    package_name,
    title,
    description,
    tokenize='unicode61 remove_diacritics 2'
);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect(path: Path, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    else:
        connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _metadata(connection: sqlite3.Connection, key: str, value: str) -> None:
    connection.execute(
        "INSERT INTO metadata(key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def _english_text(items: Any, key: str = "value") -> str:
    if not isinstance(items, list):
        return ""
    for item in items:
        if isinstance(item, dict) and item.get("lang") == "en" and item.get(key):
            return str(item[key])
    for item in items:
        if isinstance(item, dict) and item.get(key):
            return str(item[key])
    return ""


def _extract_metrics(containers: Iterable[dict[str, Any]]) -> tuple[float | None, str | None]:
    candidates: list[tuple[float, str | None]] = []
    for container in containers:
        for metric in container.get("metrics", []) or []:
            if not isinstance(metric, dict):
                continue
            for name, value in metric.items():
                if not name.lower().startswith("cvss") or not isinstance(value, dict):
                    continue
                score = value.get("baseScore")
                if isinstance(score, (int, float)):
                    severity = value.get("baseSeverity")
                    candidates.append((float(score), str(severity) if severity else None))
    return max(candidates, default=(None, None), key=lambda item: item[0] or -1)


def _extract_cwes(cna: dict[str, Any]) -> list[str]:
    values: set[str] = set()
    for problem in cna.get("problemTypes", []) or []:
        if not isinstance(problem, dict):
            continue
        for description in problem.get("descriptions", []) or []:
            if not isinstance(description, dict):
                continue
            cwe = description.get("cweId") or description.get("description")
            if cwe and str(cwe).upper().startswith("CWE-"):
                values.add(str(cwe).upper())
    return sorted(values)


def _delete_source(connection: sqlite3.Connection, source_path: str) -> None:
    row = connection.execute(
        "SELECT cve_id FROM cves WHERE source_path = ?", (source_path,)
    ).fetchone()
    if row is None:
        return
    connection.execute("DELETE FROM search_docs WHERE cve_id = ?", (row["cve_id"],))
    connection.execute("DELETE FROM cves WHERE cve_id = ?", (row["cve_id"],))


def _index_record(connection: sqlite3.Connection, path: Path, source_path: str) -> bool:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"skip invalid CVE record {path}: {exc}", file=sys.stderr)
        return False

    metadata = payload.get("cveMetadata", {})
    cve_id = metadata.get("cveId")
    if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
        return False

    containers = payload.get("containers", {})
    cna = containers.get("cna", {}) if isinstance(containers, dict) else {}
    adp = containers.get("adp", []) if isinstance(containers, dict) else []
    metric_containers = [cna] + [item for item in adp if isinstance(item, dict)]
    cvss, severity = _extract_metrics(metric_containers)
    title = str(cna.get("title") or "")
    description = _english_text(cna.get("descriptions", []))
    cwes = _extract_cwes(cna)
    references = [
        str(item["url"])
        for item in cna.get("references", []) or []
        if isinstance(item, dict) and item.get("url")
    ]

    source_owner = connection.execute(
        "SELECT cve_id FROM cves WHERE source_path = ?", (source_path,)
    ).fetchone()
    if source_owner is not None and source_owner["cve_id"] != cve_id:
        _delete_source(connection, source_path)

    existing = connection.execute(
        "SELECT 1 FROM cves WHERE cve_id = ?", (cve_id,)
    ).fetchone()
    values = (
        str(metadata.get("state") or ""),
        metadata.get("datePublished"),
        metadata.get("dateUpdated"),
        title,
        description,
        cvss,
        severity,
        json.dumps(cwes, ensure_ascii=False),
        json.dumps(references, ensure_ascii=False),
        source_path,
    )
    if existing is None:
        connection.execute(
            """
            INSERT INTO cves(
                cve_id, state, published, updated, title, description, cvss, severity,
                cwes, references_json, source_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (cve_id, *values),
        )
    else:
        connection.execute("DELETE FROM search_docs WHERE cve_id = ?", (cve_id,))
        connection.execute("DELETE FROM affected WHERE cve_id = ?", (cve_id,))
        connection.execute(
            """
            UPDATE cves
            SET state = ?, published = ?, updated = ?, title = ?, description = ?,
                cvss = ?, severity = ?, cwes = ?, references_json = ?, source_path = ?
            WHERE cve_id = ?
            """,
            (*values, cve_id),
        )

    affected_items = cna.get("affected", []) or []
    if not affected_items:
        affected_items = [{}]
    for item in affected_items:
        if not isinstance(item, dict):
            continue
        package_name = ""
        package = item.get("packageName")
        if isinstance(package, str):
            package_name = package
        elif isinstance(package, dict):
            package_name = str(package.get("name") or "")
        vendor = str(item.get("vendor") or "")
        product = str(item.get("product") or "")
        versions = item.get("versions", []) or []
        connection.execute(
            """
            INSERT INTO affected(
                cve_id, vendor, product, package_name, default_status, versions_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                cve_id,
                vendor,
                product,
                package_name,
                str(item.get("defaultStatus") or "unknown"),
                json.dumps(versions, ensure_ascii=False),
            ),
        )
        connection.execute(
            """
            INSERT INTO search_docs(cve_id, vendor, product, package_name, title, description)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (cve_id, vendor, product, package_name, title, description),
        )
    return True


def _prepare_atomic_database(database: Path, *, keep_existing: bool) -> Path:
    database.parent.mkdir(parents=True, exist_ok=True)
    temporary = database.with_name(f".{database.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    if keep_existing and database.exists():
        shutil.copy2(database, temporary)
    return temporary


def build_index(cves_dir: Path, database: Path, *, source_commit: str = "unknown") -> int:
    temporary = _prepare_atomic_database(database, keep_existing=False)
    count = 0
    try:
        with _connect(temporary) as connection:
            connection.executescript(SCHEMA)
            for path in cves_dir.rglob("CVE-*.json"):
                source_path = path.relative_to(cves_dir.parent).as_posix()
                if _index_record(connection, path, source_path):
                    count += 1
                if count and count % 1000 == 0:
                    connection.commit()
            _metadata(connection, "schema_version", SCHEMA_VERSION)
            _metadata(connection, "source_commit", source_commit)
            _metadata(connection, "last_successful_sync", _now_iso())
            _metadata(connection, "record_count", str(count))
            connection.commit()
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise RuntimeError("CVE index failed SQLite integrity check")
        os.replace(temporary, database)
        return count
    finally:
        temporary.unlink(missing_ok=True)


def update_index(
    cves_dir: Path,
    database: Path,
    changed_paths: Iterable[str],
    *,
    source_commit: str,
) -> int:
    if not database.exists():
        return build_index(cves_dir, database, source_commit=source_commit)
    temporary = _prepare_atomic_database(database, keep_existing=True)
    changed = 0
    rebuild = False
    try:
        with _connect(temporary) as connection:
            schema_row = connection.execute(
                "SELECT value FROM metadata WHERE key = 'schema_version'"
            ).fetchone()
            if schema_row is None or schema_row["value"] != SCHEMA_VERSION:
                rebuild = True
            else:
                ordered_paths = sorted(
                    set(changed_paths),
                    key=lambda value: not (cves_dir.parent / value).is_file(),
                )
                for source_path in ordered_paths:
                    if not source_path.startswith("cves/") or not source_path.endswith(".json"):
                        continue
                    path = cves_dir.parent / source_path
                    if path.is_file():
                        _index_record(connection, path, source_path)
                    else:
                        _delete_source(connection, source_path)
                    changed += 1
                count = connection.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
                _metadata(connection, "source_commit", source_commit)
                _metadata(connection, "last_successful_sync", _now_iso())
                _metadata(connection, "record_count", str(count))
                connection.commit()
                if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise RuntimeError("CVE index failed SQLite integrity check")
        if rebuild:
            temporary.unlink(missing_ok=True)
            return build_index(cves_dir, database, source_commit=source_commit)
        os.replace(temporary, database)
        return changed
    finally:
        temporary.unlink(missing_ok=True)


def _download_json(url: str, destination: Path) -> dict[str, Any]:
    request = Request(url, headers={"User-Agent": "Cairn-CVE-Intel/1.0"})
    with urlopen(request, timeout=60) as response:
        payload = json.load(response)
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise RuntimeError("CISA KEV response is not a valid catalog")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return payload


def apply_kev_catalog(database: Path, payload: dict[str, Any]) -> int:
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("CISA KEV catalog has no vulnerabilities list")
    temporary = _prepare_atomic_database(database, keep_existing=True)
    matched = 0
    try:
        with _connect(temporary) as connection:
            connection.execute(
                """
                UPDATE cves
                SET known_exploited = 0,
                    kev_date_added = NULL,
                    kev_due_date = NULL,
                    kev_required_action = NULL,
                    kev_ransomware = NULL
                """
            )
            for item in vulnerabilities:
                if not isinstance(item, dict) or not item.get("cveID"):
                    continue
                cursor = connection.execute(
                    """
                    UPDATE cves
                    SET known_exploited = 1,
                        kev_date_added = ?,
                        kev_due_date = ?,
                        kev_required_action = ?,
                        kev_ransomware = ?
                    WHERE cve_id = ?
                    """,
                    (
                        item.get("dateAdded"),
                        item.get("dueDate"),
                        item.get("requiredAction"),
                        item.get("knownRansomwareCampaignUse"),
                        str(item["cveID"]).upper(),
                    ),
                )
                matched += cursor.rowcount
            _metadata(connection, "kev_catalog_version", str(payload.get("catalogVersion") or ""))
            _metadata(connection, "kev_date_released", str(payload.get("dateReleased") or ""))
            _metadata(connection, "kev_catalog_count", str(len(vulnerabilities)))
            _metadata(connection, "kev_matched_count", str(matched))
            _metadata(connection, "kev_last_successful_sync", _now_iso())
            connection.commit()
        os.replace(temporary, database)
        return matched
    finally:
        temporary.unlink(missing_ok=True)


def sync_kev_catalog(url: str, destination: Path, database: Path) -> int:
    payload = _download_json(url, destination)
    return apply_kev_catalog(database, payload)


def _nvd_metrics(cve: dict[str, Any]) -> tuple[float | None, str | None]:
    candidates: list[tuple[float, str | None]] = []
    metrics = cve.get("metrics", {})
    if not isinstance(metrics, dict):
        return None, None
    for entries in metrics.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            data = entry.get("cvssData")
            if not isinstance(data, dict):
                continue
            score = data.get("baseScore")
            if isinstance(score, (int, float)):
                severity = data.get("baseSeverity")
                candidates.append((float(score), str(severity) if severity else None))
    return max(candidates, default=(None, None), key=lambda item: item[0] or -1)


def _iter_nvd_cpe_matches(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        matches = value.get("cpeMatch")
        if isinstance(matches, list):
            for match in matches:
                if isinstance(match, dict):
                    yield match
        for key in ("configurations", "nodes", "children"):
            if key in value:
                yield from _iter_nvd_cpe_matches(value[key])
    elif isinstance(value, list):
        for item in value:
            yield from _iter_nvd_cpe_matches(item)


def apply_nvd_page(
    database: Path,
    payload: dict[str, Any],
    *,
    next_index: int,
    full_sync: bool,
    sync_end: str | None = None,
) -> int:
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("NVD response has no vulnerabilities list")
    matched = 0
    with _connect(database) as connection:
        for wrapper in vulnerabilities:
            if not isinstance(wrapper, dict) or not isinstance(wrapper.get("cve"), dict):
                continue
            cve = wrapper["cve"]
            cve_id = str(cve.get("id") or "").upper()
            if not cve_id.startswith("CVE-"):
                continue
            score, severity = _nvd_metrics(cve)
            cursor = connection.execute(
                """
                UPDATE cves
                SET nvd_cvss = ?,
                    nvd_severity = ?,
                    nvd_status = ?,
                    nvd_last_modified = ?
                WHERE cve_id = ?
                """,
                (
                    score,
                    severity,
                    cve.get("vulnStatus"),
                    cve.get("lastModified"),
                    cve_id,
                ),
            )
            if cursor.rowcount == 0:
                continue
            matched += 1
            connection.execute("DELETE FROM nvd_cpes WHERE cve_id = ?", (cve_id,))
            for match in _iter_nvd_cpe_matches(cve.get("configurations", [])):
                criteria = match.get("criteria")
                if not criteria:
                    continue
                connection.execute(
                    """
                    INSERT INTO nvd_cpes(
                        cve_id, vulnerable, criteria, match_criteria_id,
                        version_start_including, version_start_excluding,
                        version_end_including, version_end_excluding
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cve_id,
                        int(bool(match.get("vulnerable"))),
                        str(criteria),
                        match.get("matchCriteriaId"),
                        match.get("versionStartIncluding"),
                        match.get("versionStartExcluding"),
                        match.get("versionEndIncluding"),
                        match.get("versionEndExcluding"),
                    ),
                )
        if full_sync:
            _metadata(connection, "nvd_bootstrap_start_index", str(next_index))
        if sync_end is not None:
            _metadata(connection, "nvd_last_successful_sync", sync_end)
        _metadata(connection, "nvd_last_page_matched", str(matched))
        connection.commit()
    return matched


def _read_metadata(database: Path) -> dict[str, str]:
    with _connect(database, read_only=True) as connection:
        return {
            row["key"]: row["value"]
            for row in connection.execute("SELECT key, value FROM metadata")
        }


def _nvd_request(
    url: str,
    params: dict[str, str | int],
    *,
    api_key: str | None,
    retries: int = 5,
) -> dict[str, Any]:
    headers = {"User-Agent": "Cairn-CVE-Intel/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    request_url = f"{url}?{urlencode(params)}"
    for attempt in range(retries):
        try:
            with urlopen(Request(request_url, headers=headers), timeout=90) as response:
                payload = json.load(response)
            if not isinstance(payload, dict) or not isinstance(
                payload.get("vulnerabilities"), list
            ):
                raise RuntimeError("NVD response is not valid CVE API 2.0 data")
            return payload
        except HTTPError as exc:
            if exc.code not in {429, 500, 502, 503, 504} or attempt + 1 >= retries:
                raise
            retry_after = exc.headers.get("Retry-After")
            delay = int(retry_after) if retry_after and retry_after.isdigit() else 2**attempt
        except (URLError, TimeoutError):
            if attempt + 1 >= retries:
                raise
            delay = 2**attempt
        time.sleep(delay)
    raise RuntimeError("NVD request retry loop exited unexpectedly")


def _nvd_pages(
    database: Path,
    *,
    url: str,
    api_key: str | None,
    delay: float,
    params: dict[str, str | int],
    start_index: int,
    full_sync: bool,
    sync_end: str | None,
) -> tuple[int, int]:
    pages = 0
    matched = 0
    while True:
        page_params = {**params, "resultsPerPage": 2000, "startIndex": start_index}
        payload = _nvd_request(url, page_params, api_key=api_key)
        results_per_page = int(payload.get("resultsPerPage") or 0)
        total_results = int(payload.get("totalResults") or 0)
        page_count = len(payload["vulnerabilities"])
        if results_per_page <= 0:
            results_per_page = page_count
        next_index = start_index + page_count
        is_last = next_index >= total_results or page_count == 0
        matched += apply_nvd_page(
            database,
            payload,
            next_index=next_index,
            full_sync=full_sync,
            sync_end=sync_end if is_last else None,
        )
        pages += 1
        if is_last:
            return pages, matched
        start_index = next_index
        time.sleep(delay)


def sync_nvd(
    database: Path,
    *,
    url: str = DEFAULT_NVD_URL,
    api_key: str | None = None,
    delay: float | None = None,
) -> dict[str, Any]:
    metadata = _read_metadata(database)
    request_delay = delay if delay is not None else (0.7 if api_key else 6.5)
    if metadata.get("nvd_full_sync_complete") != "true":
        start_index = int(metadata.get("nvd_bootstrap_start_index", "0"))
        completed_at = _now_iso()
        pages, matched = _nvd_pages(
            database,
            url=url,
            api_key=api_key,
            delay=request_delay,
            params={},
            start_index=start_index,
            full_sync=True,
            sync_end=completed_at,
        )
        with _connect(database) as connection:
            _metadata(connection, "nvd_full_sync_complete", "true")
            _metadata(connection, "nvd_last_successful_sync", completed_at)
            connection.commit()
        return {"mode": "full", "pages": pages, "matched": matched}

    end = datetime.now(timezone.utc)
    last_sync = datetime.fromisoformat(metadata["nvd_last_successful_sync"])
    cursor = last_sync - timedelta(minutes=5)
    pages = 0
    matched = 0
    while cursor < end:
        window_end = min(cursor + timedelta(days=119), end)
        end_iso = window_end.isoformat()
        window_pages, window_matched = _nvd_pages(
            database,
            url=url,
            api_key=api_key,
            delay=request_delay,
            params={
                "lastModStartDate": cursor.isoformat(),
                "lastModEndDate": end_iso,
            },
            start_index=0,
            full_sync=False,
            sync_end=end_iso,
        )
        pages += window_pages
        matched += window_matched
        cursor = window_end
    return {"mode": "incremental", "pages": pages, "matched": matched}


def _run_git(*args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


def sync_once(
    repository_url: str,
    repository: Path,
    database: Path,
    *,
    kev_url: str = DEFAULT_KEV_URL,
    kev_file: Path = DEFAULT_KEV_FILE,
    nvd_enabled: bool = False,
    nvd_url: str = DEFAULT_NVD_URL,
    nvd_api_key: str | None = None,
    nvd_delay: float | None = None,
) -> dict[str, Any]:
    result: dict[str, Any]
    if not (repository / ".git").is_dir():
        repository.parent.mkdir(parents=True, exist_ok=True)
        _run_git("clone", "--depth=1", repository_url, str(repository))
        commit = _run_git("rev-parse", "HEAD", cwd=repository)
        count = build_index(repository / "cves", database, source_commit=commit)
        result = {"mode": "full", "commit": commit, "records": count}
    else:
        before = _run_git("rev-parse", "HEAD", cwd=repository)
        _run_git("pull", "--ff-only", cwd=repository)
        after = _run_git("rev-parse", "HEAD", cwd=repository)
        if before == after:
            changed = update_index(repository / "cves", database, [], source_commit=after)
        else:
            try:
                output = _run_git(
                    "diff", "--name-only", before, after, "--", "cves", cwd=repository
                )
                changed_paths = output.splitlines()
                changed = update_index(
                    repository / "cves", database, changed_paths, source_commit=after
                )
            except subprocess.CalledProcessError:
                changed = build_index(repository / "cves", database, source_commit=after)
                result = {"mode": "full", "commit": after, "records": changed}
            else:
                result = {"mode": "incremental", "commit": after, "changed": changed}
        if before == after:
            result = {"mode": "incremental", "commit": after, "changed": changed}

    try:
        result["kev_matched"] = sync_kev_catalog(kev_url, kev_file, database)
    except Exception as exc:
        result["kev_warning"] = str(exc)
        print(f"CISA KEV synchronization failed: {exc}", file=sys.stderr, flush=True)
        if kev_file.is_file():
            try:
                cached_payload = json.loads(kev_file.read_text(encoding="utf-8"))
                result["kev_cached_matched"] = apply_kev_catalog(database, cached_payload)
            except Exception as cached_exc:
                result["kev_cache_warning"] = str(cached_exc)
                print(
                    f"cached CISA KEV enrichment failed: {cached_exc}",
                    file=sys.stderr,
                    flush=True,
                )
    if nvd_enabled:
        try:
            result["nvd"] = sync_nvd(
                database,
                url=nvd_url,
                api_key=nvd_api_key,
                delay=nvd_delay,
            )
        except Exception as exc:
            result["nvd_warning"] = str(exc)
            print(f"NVD synchronization failed: {exc}", file=sys.stderr, flush=True)
    return result


def sync_loop(
    repository_url: str,
    repository: Path,
    database: Path,
    *,
    kev_url: str,
    kev_file: Path,
    nvd_enabled: bool,
    nvd_url: str,
    nvd_api_key: str | None,
    nvd_delay: float | None,
    interval: int,
    once: bool,
) -> int:
    failures = 0
    while True:
        try:
            result = sync_once(
                repository_url,
                repository,
                database,
                kev_url=kev_url,
                kev_file=kev_file,
                nvd_enabled=nvd_enabled,
                nvd_url=nvd_url,
                nvd_api_key=nvd_api_key,
                nvd_delay=nvd_delay,
            )
            print(json.dumps(result, ensure_ascii=False), flush=True)
            failures = 0
        except Exception as exc:
            failures += 1
            print(f"CVE synchronization failed: {exc}", file=sys.stderr, flush=True)
            if once:
                return 1
        if once:
            return 0
        delay = interval if failures == 0 else min(interval, 30 * (2 ** min(failures - 1, 6)))
        time.sleep(delay)


_SIMPLE_VERSION = re.compile(r"^v?\d+(?:\.\d+)*(?:[-+._]?[0-9A-Za-z]+)*$")
_SEMVER = re.compile(
    r"^v?(?P<core>\d+(?:\.\d+){0,2})"
    r"(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def _version_key(value: str) -> tuple[tuple[int, int | str], ...] | None:
    value = value.strip().lower().lstrip("v")
    if not value or not _SIMPLE_VERSION.fullmatch(value):
        return None
    parts = re.findall(r"\d+|[a-z]+", value)
    return tuple((0, int(part)) if part.isdigit() else (1, part) for part in parts)


def _semver_key(value: str) -> tuple[tuple[int, int, int], tuple[Any, ...] | None] | None:
    match = _SEMVER.fullmatch(value.strip())
    if match is None:
        return None
    core_values = [int(part) for part in match.group("core").split(".")]
    core = tuple((core_values + [0, 0])[:3])
    pre = match.group("pre")
    if pre is None:
        return core, None
    identifiers = tuple(
        (0, int(part)) if part.isdigit() else (1, part.lower())
        for part in pre.split(".")
    )
    return core, identifiers


def _compare_semver(left: str, right: str) -> int | None:
    left_key = _semver_key(left)
    right_key = _semver_key(right)
    if left_key is None or right_key is None:
        return None
    if left_key[0] != right_key[0]:
        return (left_key[0] > right_key[0]) - (left_key[0] < right_key[0])
    left_pre, right_pre = left_key[1], right_key[1]
    if left_pre is None or right_pre is None:
        if left_pre is None and right_pre is None:
            return 0
        return 1 if left_pre is None else -1
    return (left_pre > right_pre) - (left_pre < right_pre)


def _compare_versions(left: str, right: str, version_type: str | None = None) -> int | None:
    normalized_type = (version_type or "").lower()
    if normalized_type == "semver":
        return _compare_semver(left, right)
    if normalized_type in {"python", "pep440"}:
        if Version is None:
            return None
        try:
            left_version = Version(left)
            right_version = Version(right)
        except InvalidVersion:
            return None
        return (left_version > right_version) - (left_version < right_version)
    if normalized_type in {"git", "rpm", "deb", "debian", "maven"}:
        return None
    left_key = _version_key(left)
    right_key = _version_key(right)
    if left_key is None or right_key is None:
        return None
    length = max(len(left_key), len(right_key))
    padding = (0, 0)
    padded_left = left_key + (padding,) * (length - len(left_key))
    padded_right = right_key + (padding,) * (length - len(right_key))
    return (padded_left > padded_right) - (padded_left < padded_right)


def _entry_matches_version(target: str, entry: dict[str, Any]) -> tuple[str, str] | None:
    declared = str(entry.get("version") or "")
    status = str(entry.get("status") or "unknown")
    if declared == target:
        return status, "exact"

    upper = entry.get("lessThan")
    inclusive_upper = entry.get("lessThanOrEqual")
    version_type = str(entry.get("versionType") or "")
    if not upper and not inclusive_upper:
        return None
    lower_ok = True
    if declared and declared not in {"*", "0"}:
        comparison = _compare_versions(target, declared, version_type)
        if comparison is None:
            return None
        lower_ok = comparison >= 0
    upper_value = str(upper or inclusive_upper)
    upper_comparison = _compare_versions(target, upper_value, version_type)
    if upper_comparison is None:
        return None
    upper_ok = upper_comparison < 0 if upper else upper_comparison <= 0
    if not (lower_ok and upper_ok):
        return None

    effective_status = status
    changes = entry.get("changes", []) or []
    for change in changes:
        if not isinstance(change, dict) or not change.get("at"):
            continue
        comparison = _compare_versions(target, str(change["at"]), version_type)
        if comparison is not None and comparison >= 0:
            effective_status = str(change.get("status") or effective_status)
    return effective_status, "range"


def assess_version(target: str | None, item: dict[str, Any]) -> str:
    if not target:
        return "candidate"
    versions = item.get("versions", [])
    matched: list[tuple[str, str]] = []
    for entry in versions:
        if not isinstance(entry, dict):
            continue
        result = _entry_matches_version(target, entry)
        if result is not None:
            matched.append(result)
    affected_matches = [match_type for status, match_type in matched if status == "affected"]
    if "exact" in affected_matches:
        return "exact"
    if "range" in affected_matches:
        return "range"
    if any(status == "unaffected" for status, _match_type in matched):
        return "unaffected"
    default_status = item.get("default_status")
    if default_status == "unaffected":
        return "unaffected"
    return "candidate"


def _search_tokens(value: str) -> list[str]:
    return [token.lower() for token in re.findall(r"[\w]+", value, flags=re.UNICODE)]


def _fts_terms(value: str) -> list[str]:
    return [f'"{token}"' for token in _search_tokens(value)]


def _affected_matches_query(
    item: dict[str, Any], *, vendor: str | None, product: str | None
) -> bool:
    vendor_text = str(item.get("vendor") or "")
    product_text = " ".join(
        str(item.get(key) or "") for key in ("vendor", "product", "package_name")
    )
    if vendor and not set(_search_tokens(vendor)).issubset(_search_tokens(vendor_text)):
        return False
    if product and not set(_search_tokens(product)).issubset(_search_tokens(product_text)):
        return False
    return True


def _compact_versions(versions: list[Any], target: str | None) -> tuple[list[Any], bool]:
    if target:
        matching = [
            entry
            for entry in versions
            if isinstance(entry, dict) and _entry_matches_version(target, entry) is not None
        ]
        if matching:
            return matching, len(matching) < len(versions)
    limit = 10
    return versions[:limit], len(versions) > limit


def search_database(
    database: Path,
    *,
    cve_id: str | None = None,
    vendor: str | None = None,
    product: str | None = None,
    keyword: str | None = None,
    version: str | None = None,
    limit: int = 20,
    include_unaffected: bool = False,
) -> dict[str, Any]:
    with _connect(database, read_only=True) as connection:
        if cve_id:
            rows = connection.execute(
                "SELECT * FROM cves WHERE cve_id = ?", (cve_id.upper(),)
            ).fetchall()
        else:
            terms = [
                term
                for value in (vendor, product, keyword)
                if value
                for term in _fts_terms(value)
            ]
            if not terms:
                raise ValueError("provide --cve, --vendor, --product, or --keyword")
            rows = connection.execute(
                """
                SELECT DISTINCT c.*
                FROM search_docs
                JOIN cves AS c ON c.cve_id = search_docs.cve_id
                WHERE search_docs MATCH ?
                ORDER BY c.known_exploited DESC, c.cvss DESC, c.updated DESC
                LIMIT ?
                """,
                (" AND ".join(terms), max(limit * 5, 100)),
            ).fetchall()

        results: list[dict[str, Any]] = []
        for row in rows:
            affected_rows = connection.execute(
                "SELECT * FROM affected WHERE cve_id = ? ORDER BY vendor, product",
                (row["cve_id"],),
            ).fetchall()
            nvd_cpes = [
                {
                    "vulnerable": bool(cpe["vulnerable"]),
                    "criteria": cpe["criteria"],
                    "match_criteria_id": cpe["match_criteria_id"],
                    "version_start_including": cpe["version_start_including"],
                    "version_start_excluding": cpe["version_start_excluding"],
                    "version_end_including": cpe["version_end_including"],
                    "version_end_excluding": cpe["version_end_excluding"],
                }
                for cpe in connection.execute(
                    """
                    SELECT * FROM nvd_cpes
                    WHERE cve_id = ?
                    ORDER BY vulnerable DESC, criteria
                    LIMIT 20
                    """,
                    (row["cve_id"],),
                )
            ]
            affected: list[dict[str, Any]] = []
            best = "unaffected"
            rank = {"unaffected": 0, "candidate": 1, "range": 2, "exact": 3}
            for affected_row in affected_rows:
                all_versions = json.loads(affected_row["versions_json"])
                item = {
                    "vendor": affected_row["vendor"],
                    "product": affected_row["product"],
                    "package_name": affected_row["package_name"],
                    "default_status": affected_row["default_status"],
                    "versions": all_versions,
                }
                if not cve_id and not _affected_matches_query(
                    item, vendor=vendor, product=product
                ):
                    continue
                match = assess_version(version, item)
                compact_versions, truncated = _compact_versions(all_versions, version)
                item["versions"] = compact_versions
                item["version_rules_total"] = len(all_versions)
                item["versions_truncated"] = truncated
                item["version_match"] = match
                if rank[match] > rank[best]:
                    best = match
                affected.append(item)
            if not affected:
                continue
            if version and best == "unaffected" and not include_unaffected:
                continue
            results.append(
                {
                    "cve_id": row["cve_id"],
                    "state": row["state"],
                    "published": row["published"],
                    "updated": row["updated"],
                    "title": row["title"],
                    "description": row["description"],
                    "cvss": row["cvss"],
                    "severity": row["severity"],
                    "cwes": json.loads(row["cwes"]),
                    "references": json.loads(row["references_json"]),
                    "known_exploited": bool(row["known_exploited"]),
                    "kev": {
                        "date_added": row["kev_date_added"],
                        "due_date": row["kev_due_date"],
                        "required_action": row["kev_required_action"],
                        "known_ransomware_campaign_use": row["kev_ransomware"],
                    }
                    if row["known_exploited"]
                    else None,
                    "nvd": {
                        "cvss": row["nvd_cvss"],
                        "severity": row["nvd_severity"],
                        "status": row["nvd_status"],
                        "last_modified": row["nvd_last_modified"],
                        "cpe_matches": nvd_cpes,
                    }
                    if row["nvd_last_modified"] or nvd_cpes
                    else None,
                    "source_path": row["source_path"],
                    "version_match": best,
                    "affected": affected,
                }
            )
            if len(results) >= limit:
                break
        return {"query_version": version, "count": len(results), "results": results}


FINGERPRINT_ALIASES: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("apache http server", "apache httpd", "apache2", "httpd", "http server"), "Apache", "Apache HTTP Server"),
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

_FINGERPRINT_VERSION = re.compile(
    r"(?<![A-Za-z0-9])v?(\d+(?:\.\d+){1,4}(?:(?:[A-Za-z]|[-+._])[0-9A-Za-z.-]*)?)"
)


def normalize_fingerprint(
    *, vendor: str | None, product: str, version: str | None
) -> dict[str, Any]:
    observed_product = product.strip()
    observed_vendor = vendor.strip() if vendor else None
    combined = " ".join(value for value in (observed_vendor, observed_product) if value)
    normalized_text = re.sub(r"[^a-z0-9]+", " ", combined.lower()).strip()
    normalized_product = observed_product
    normalized_vendor = observed_vendor
    aliases: list[str] = []
    for candidates, canonical_vendor, canonical_product in FINGERPRINT_ALIASES:
        if any(alias == normalized_text or alias in normalized_text for alias in candidates):
            normalized_vendor = canonical_vendor
            normalized_product = canonical_product
            aliases = list(candidates)
            break

    normalized_version = None
    if version and version.strip():
        match = _FINGERPRINT_VERSION.search(version.strip())
        normalized_version = match.group(1) if match else version.strip().removeprefix("v")
    else:
        match = _FINGERPRINT_VERSION.search(observed_product)
        if match:
            normalized_version = match.group(1)

    return {
        "vendor": normalized_vendor,
        "product": normalized_product,
        "version": normalized_version,
        "observed": {
            "vendor": observed_vendor,
            "product": observed_product,
            "version": version,
        },
        "aliases": aliases,
    }


def _candidate_score(
    result: dict[str, Any], *, fingerprint: dict[str, Any], confidence: float
) -> dict[str, Any]:
    reasons: list[dict[str, Any]] = []
    score = 0.0

    version_match = str(result.get("version_match") or "candidate")
    version_weights = {"exact": 0.46, "range": 0.40, "candidate": 0.08, "unaffected": 0.0}
    version_weight = version_weights.get(version_match, 0.0)
    if version_weight:
        detail = {
            "exact": "observed version exactly matches an affected rule",
            "range": "observed version falls inside an affected range",
            "candidate": "product matches, but version applicability still needs verification",
        }[version_match]
        reasons.append({"signal": f"version_{version_match}", "weight": version_weight, "detail": detail})
        score += version_weight

    affected = result.get("affected") or []
    product_matches = any(
        _affected_matches_query(item, vendor=None, product=fingerprint["product"])
        for item in affected
    )
    if product_matches:
        product_weight = 0.13
        reasons.append(
            {
                "signal": "product_match",
                "weight": product_weight,
                "detail": f"affected product matches {fingerprint['product']}",
            }
        )
        score += product_weight

    vendor_matches = bool(fingerprint.get("vendor")) and any(
        _affected_matches_query(item, vendor=fingerprint["vendor"], product=None)
        for item in affected
    )
    if vendor_matches:
        vendor_weight = 0.06
        reasons.append(
            {
                "signal": "vendor_match",
                "weight": vendor_weight,
                "detail": f"affected vendor matches {fingerprint['vendor']}",
            }
        )
        score += vendor_weight

    if result.get("known_exploited"):
        kev_weight = 0.13
        reasons.append(
            {
                "signal": "known_exploited",
                "weight": kev_weight,
                "detail": "listed in CISA Known Exploited Vulnerabilities",
            }
        )
        score += kev_weight

    cvss_values = [result.get("cvss"), (result.get("nvd") or {}).get("cvss")]
    numeric_cvss = [float(value) for value in cvss_values if value is not None]
    if numeric_cvss:
        cvss = max(numeric_cvss)
        cvss_weight = round(min(max(cvss, 0.0), 10.0) / 100.0, 3)
        reasons.append(
            {
                "signal": "cvss",
                "weight": cvss_weight,
                "detail": f"maximum available CVSS base score is {cvss:g}",
            }
        )
        score += cvss_weight

    if str(result.get("state") or "").upper() == "PUBLISHED":
        reasons.append({"signal": "published", "weight": 0.02, "detail": "CVE state is PUBLISHED"})
        score += 0.02

    confidence_weight = round(min(max(confidence, 0.0), 1.0) * 0.05, 3)
    if confidence_weight:
        reasons.append(
            {
                "signal": "fingerprint_confidence",
                "weight": confidence_weight,
                "detail": f"component fingerprint confidence is {confidence:.2f}",
            }
        )
        score += confidence_weight

    score = round(min(score, 1.0), 3)
    if score >= 0.85:
        priority = "critical"
    elif score >= 0.68:
        priority = "high"
    elif score >= 0.40:
        priority = "medium"
    else:
        priority = "low"
    applicability = "matched" if version_match in {"exact", "range"} else "needs_verification"
    return {
        **result,
        "relevance_score": score,
        "priority": priority,
        "applicability": applicability,
        "score_reasons": reasons,
    }


def recommend_database(
    database: Path,
    *,
    vendor: str | None,
    product: str,
    version: str | None,
    confidence: float = 1.0,
    limit: int = 20,
) -> dict[str, Any]:
    fingerprint = normalize_fingerprint(vendor=vendor, product=product, version=version)
    search_limit = max(limit * 3, 20)
    search = search_database(
        database,
        vendor=fingerprint["vendor"],
        product=fingerprint["product"],
        version=fingerprint["version"],
        limit=search_limit,
    )
    if not search["results"] and fingerprint.get("vendor"):
        search = search_database(
            database,
            product=fingerprint["product"],
            version=fingerprint["version"],
            limit=search_limit,
        )
    if not search["results"] and fingerprint["product"] != product.strip():
        search = search_database(
            database,
            product=product.strip(),
            version=fingerprint["version"],
            limit=search_limit,
        )

    scored = [
        _candidate_score(item, fingerprint=fingerprint, confidence=confidence)
        for item in search["results"]
    ]
    scored.sort(
        key=lambda item: (
            item["relevance_score"],
            bool(item.get("known_exploited")),
            float(item.get("cvss") or 0),
            item.get("updated") or "",
        ),
        reverse=True,
    )
    results = scored[:limit]
    return {
        "fingerprint": fingerprint,
        "count": len(results),
        "results": results,
        "interpretation": (
            "relevance_score prioritizes review; only exact/range version matches are marked matched. "
            "Candidate matches require independent verification before being treated as applicable."
        ),
    }


def database_status(database: Path, *, max_age: int | None = None) -> dict[str, Any]:
    if not database.is_file():
        raise RuntimeError(f"CVE index does not exist: {database}")
    with _connect(database, read_only=True) as connection:
        metadata = {
            row["key"]: row["value"]
            for row in connection.execute("SELECT key, value FROM metadata")
        }
        count = connection.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    if count <= 0:
        raise RuntimeError("CVE index contains no records")
    synced = datetime.fromisoformat(metadata["last_successful_sync"])
    age = int((datetime.now(timezone.utc) - synced).total_seconds())
    if max_age is not None and age > max_age:
        raise RuntimeError(f"CVE index is stale: {age}s old, maximum is {max_age}s")
    return {**metadata, "record_count": count, "age_seconds": max(age, 0), "healthy": True}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    sync = subparsers.add_parser("sync", help="update cvelistV5 and its SQLite index")
    sync.add_argument("--repository-url", default="https://github.com/CVEProject/cvelistV5.git")
    sync.add_argument("--repository", type=Path, default=DEFAULT_REPOSITORY)
    sync.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    sync.add_argument("--kev-url", default=DEFAULT_KEV_URL)
    sync.add_argument("--kev-file", type=Path, default=DEFAULT_KEV_FILE)
    sync.add_argument("--nvd", action="store_true", help="enable NVD CVE API 2.0 enrichment")
    sync.add_argument("--nvd-url", default=DEFAULT_NVD_URL)
    sync.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"))
    sync.add_argument("--nvd-delay", type=float)
    sync.add_argument("--interval", type=int, default=3600)
    sync.add_argument("--once", action="store_true")

    search = subparsers.add_parser("search", help="search indexed CVE records")
    search.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    search.add_argument("--cve")
    search.add_argument("--vendor")
    search.add_argument("--product")
    search.add_argument("--keyword")
    search.add_argument("--version")
    search.add_argument("--limit", type=int, default=20)
    search.add_argument("--include-unaffected", action="store_true")

    recommend = subparsers.add_parser(
        "recommend", help="normalize a component fingerprint and rank relevant CVEs"
    )
    recommend.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    recommend.add_argument("--vendor")
    recommend.add_argument("--product", required=True)
    recommend.add_argument("--version")
    recommend.add_argument("--confidence", type=float, default=1.0)
    recommend.add_argument("--limit", type=int, default=20)

    show = subparsers.add_parser("show", help="show one CVE by ID")
    show.add_argument("cve_id")
    show.add_argument("--database", type=Path, default=DEFAULT_DATABASE)

    status = subparsers.add_parser("status", help="show index metadata")
    status.add_argument("--database", type=Path, default=DEFAULT_DATABASE)

    health = subparsers.add_parser("health", help="check index integrity and freshness")
    health.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    health.add_argument("--max-age", type=int, default=7200)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "sync":
            return sync_loop(
                args.repository_url,
                args.repository,
                args.database,
                kev_url=args.kev_url,
                kev_file=args.kev_file,
                nvd_enabled=args.nvd,
                nvd_url=args.nvd_url,
                nvd_api_key=args.nvd_api_key,
                nvd_delay=args.nvd_delay,
                interval=args.interval,
                once=args.once,
            )
        if args.command == "search":
            result = search_database(
                args.database,
                cve_id=args.cve,
                vendor=args.vendor,
                product=args.product,
                keyword=args.keyword,
                version=args.version,
                limit=max(1, min(args.limit, 100)),
                include_unaffected=args.include_unaffected,
            )
        elif args.command == "recommend":
            result = recommend_database(
                args.database,
                vendor=args.vendor,
                product=args.product,
                version=args.version,
                confidence=min(max(args.confidence, 0.0), 1.0),
                limit=max(1, min(args.limit, 100)),
            )
        elif args.command == "show":
            result = search_database(args.database, cve_id=args.cve_id, limit=1)
        elif args.command == "status":
            result = database_status(args.database)
        else:
            result = database_status(args.database, max_age=args.max_age)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

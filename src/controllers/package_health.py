# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Resolve package upstream repositories and cache their OpenSSF Scorecard results.

Repositories come from SBOM evidence first, then deps.dev (ecosystem PURLs),
then OSV ``GIT`` ranges of the package's CVEs. Scores are an informational
maintenance signal and never influence assessments.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import urllib.error
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable

from packageurl import PackageURL
from sqlalchemy import delete, select, tuple_

from ..extensions import db, write_lock
from ..helpers.active_scans import (
    active_package_ids_for_scans, active_sbom_scan_ids_for_variant, active_scan_ids_for_variant,
)
from ..helpers.repository_urls import normalize_repository, scorecard_supported
from ..models import (
    Finding, Observation, Package, PackageRepository, RepositoryScorecard, SBOMDocument, SBOMPackage, Scan,
)
from .job_context import JobContext, OperationError
from .package_health_sources import DEPSDEV_API, GITHUB_API, OSV_API, SCORECARD_API, JsonApi

REPOSITORY_TTL = datetime.timedelta(days=30)
# Scorecard republishes its public dataset weekly.
SCORECARD_TTL = datetime.timedelta(days=7)
MAX_CVES_PER_PACKAGE = 3
MAX_CONSECUTIVE_FAILURES = 5
COMMIT_EVERY = 50
DB_CHUNK = 500
ENABLED_ENV = "VULNSCOUT_SCORECARD_ENABLED"
# GitHub accounts that only mirror projects hosted elsewhere; their scores say nothing about the maintainers.
MIRROR_OWNERS = frozenset({"mirror", "mirrors", "bminor"})
DEPSDEV_SYSTEMS = {
    "npm": "NPM", "pypi": "PYPI", "cargo": "CARGO", "golang": "GO",
    "maven": "MAVEN", "nuget": "NUGET", "gem": "RUBYGEMS",
}


def scorecard_enabled() -> bool:
    return os.getenv(ENABLED_ENV, "1").strip().lower() not in {"0", "false", "no", "off"}


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _iso(value: datetime.datetime) -> str:
    return value.replace(tzinfo=datetime.timezone.utc).isoformat()


def is_mirror(repository: str) -> bool:
    parts = repository.split("/")
    return parts[0] == "github.com" and parts[1].lower() in MIRROR_OWNERS


def cpe_product(cpe: object) -> tuple[str, str] | None:
    """Return ``(vendor, product)`` from a CPE 2.3 string."""
    if not isinstance(cpe, str):
        return None
    parts = cpe.split(":")
    if len(parts) < 5 or parts[0] != "cpe" or parts[4] in {"", "*", "-"}:
        return None
    return parts[3].lower(), parts[4].lower()


def sbom_repository(purls: Iterable[str], source_urls: Iterable[str],
                    upstream_urls: Iterable[str]) -> tuple[str, str] | None:
    """Return ``(repository, evidence)`` from SBOM identifiers, preferring Scorecard-covered hosts per tier."""
    for tier in (purls, source_urls, upstream_urls):
        candidates = [(repository, value) for value in sorted(tier)
                      if (repository := normalize_repository(value)) is not None and not is_mirror(repository)]
        if candidates:
            return next((item for item in candidates if scorecard_supported(item[0])), candidates[0])
    return None


def depsdev_key(purl: str) -> tuple[str, str, str] | None:
    """Return the deps.dev ``(system, name, version)`` for an ecosystem PURL."""
    try:
        parsed = PackageURL.from_string(purl)
    except ValueError:
        return None
    system = DEPSDEV_SYSTEMS.get(parsed.type)
    if system is None or not parsed.version:
        return None
    name = parsed.name
    if parsed.type == "maven":
        if not parsed.namespace:
            return None
        name = f"{parsed.namespace}:{name}"
    elif parsed.type == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    elif parsed.namespace:
        name = f"{parsed.namespace}/{name}"
    return system, name, parsed.version


def depsdev_repository(payload: dict) -> str | None:
    """Pick the source repository from a deps.dev version, attested links first."""
    projects = [project for project in payload.get("relatedProjects") or []
                if isinstance(project, dict) and project.get("relationType") == "SOURCE_REPO"]
    projects.sort(key=lambda project: project.get("relationProvenance") == "UNVERIFIED_METADATA")
    for project in projects:
        repository = normalize_repository(f"https://{(project.get('projectKey') or {}).get('id', '')}")
        if repository is not None and not is_mirror(repository):
            return repository
    return None


def osv_repository(payload: dict, name: str, cpes: Iterable[str]) -> str | None:
    """Return the ``GIT`` range repository of an OSV record when it matches the package's CPE or name."""
    products = {pair for cpe in cpes if (pair := cpe_product(cpe)) is not None}
    names = {name.lower(), *(product for _, product in products)}
    candidates: set[str] = set()
    for affected in payload.get("affected") or []:
        for item in (affected or {}).get("ranges") or []:
            if not isinstance(item, dict) or item.get("type") != "GIT":
                continue
            repository = normalize_repository(item.get("repo"), assume_git=True)
            if repository is None or is_mirror(repository):
                continue
            events = (item.get("database_specific") or {}).get("extracted_events") or []
            affected_products = {found for event in events if isinstance(event, dict)
                                 if (found := cpe_product(event.get("cpe"))) is not None}
            if affected_products:
                if any(product == affected_product and vendor in {"*", affected_vendor}
                       for vendor, product in products for affected_vendor, affected_product in affected_products):
                    candidates.add(repository)
            elif repository.rsplit("/", 1)[-1].lower() in names:
                candidates.add(repository)
    if not candidates:
        return None

    vendors = {vendor for vendor, _ in products}
    return min(candidates, key=lambda repository: (
        repository.rsplit("/", 1)[-1].lower() not in names,
        repository.rsplit("/", 2)[-2].lower() not in vendors,
        repository,
    ))


def _scorecard_checks(payload: dict) -> list[dict]:
    checks = []
    for check in payload.get("checks") or []:
        if not isinstance(check, dict) or not isinstance(check.get("name"), str):
            continue
        documentation = check.get("documentation") or {}
        url = documentation.get("url")
        checks.append({
            "name": check["name"],
            "score": check.get("score") if isinstance(check.get("score"), (int, float)) else None,
            "reason": check.get("reason") if isinstance(check.get("reason"), str) else None,
            "description": documentation.get("short") if isinstance(documentation.get("short"), str) else None,
            "url": url if isinstance(url, str) and url.startswith("https://") else None,
        })
    return checks


@dataclass
class _Evidence:
    purls: set[str]
    cpes: set[str]
    source_urls: set[str]
    upstream_urls: set[str]
    documents: set[str] = field(default_factory=set)

    def key(self, cve_ids: list[str]) -> str:
        values = [sorted(values) for values in (
            self.documents, self.purls, self.cpes, self.source_urls, self.upstream_urls, set(cve_ids),
        )]
        return hashlib.sha256(json.dumps(values).encode()).hexdigest()


class PackageHealthRefresher:
    """Resolve repositories and refresh Scorecard results for a set of packages."""

    def __init__(self, scorecard: JsonApi | None = None, depsdev: JsonApi | None = None,
                 osv: JsonApi | None = None, github: JsonApi | None = None) -> None:
        self.scorecard = scorecard or JsonApi(SCORECARD_API)
        self.depsdev = depsdev or JsonApi(DEPSDEV_API)
        self.osv = osv or JsonApi(OSV_API)
        self.github = github or JsonApi(GITHUB_API, retries=1, headers=_github_headers())
        self.now = _utcnow()
        self._osv_cache: dict[str, dict | None] = {}
        self._failures = 0
        self._github_available = True

    def _get(self, api: JsonApi, *segments: str) -> tuple[bool, dict | None]:
        try:
            payload = api.get(*segments)
        except Exception as exc:
            print(f"[scorecard refresh] {api.base_url} request failed: {exc}", flush=True)
            self._failures += 1
            if self._failures >= MAX_CONSECUTIVE_FAILURES:
                raise OperationError(
                    f"Stopped after {self._failures} consecutive failures reaching {api.base_url}; "
                    f"check network access or set {ENABLED_ENV}=0"
                )
            return False, None
        self._failures = 0
        return True, payload

    def resolve(self, package: Package, evidence: _Evidence, cve_ids: list[str],
                existing: PackageRepository | None, force: bool) -> bool:
        """Create or update the package's repository row; return whether it changed."""
        sbom = sbom_repository(evidence.purls, evidence.source_urls, evidence.upstream_urls)
        if existing is not None and not force and existing.resolved_at > self.now - REPOSITORY_TTL:
            if sbom is None and existing.source != "sbom":
                return False
            if sbom is not None and existing.source == "sbom" and existing.repository == sbom[0]:
                return False
        repository, source, proof = (sbom[0], "sbom", sbom[1]) if sbom else (None, "none", None)
        deprecated: bool | None = None
        deprecated_reason: str | None = None
        complete = True
        keys = [version_key for purl in sorted(evidence.purls)
                if (version_key := depsdev_key(purl)) is not None]
        if keys:
            key = keys[0]
            ok, payload = self._get(self.depsdev, "systems", key[0], "packages", key[1], "versions", key[2])
            complete = ok
            if payload is not None:
                deprecated = payload.get("isDeprecated") is True
                deprecated_reason = payload.get("deprecatedReason") or None
                found = depsdev_repository(payload) if repository is None else None
                if found is not None:
                    repository, source, proof = found, "deps_dev", f"{key[0].lower()}:{key[1]}@{key[2]}"
        for cve_id in cve_ids[:MAX_CVES_PER_PACKAGE] if repository is None else []:
            if cve_id not in self._osv_cache:
                ok, self._osv_cache[cve_id] = self._get(self.osv, "vulns", cve_id)
                complete = complete and ok
            payload = self._osv_cache[cve_id]
            found = osv_repository(payload, package.name or "", evidence.cpes) \
                if payload is not None else None
            if found is not None:
                repository, source, proof = found, "osv", cve_id
                break
        if not complete and repository is None:
            return False
        row = existing or PackageRepository(package_id=package.id, evidence_key=evidence.key(cve_ids))
        row.repository, row.source, row.evidence = repository, source, proof
        row.deprecated, row.deprecated_reason, row.resolved_at = deprecated, deprecated_reason, self.now
        if existing is None:
            db.session.add(row)
        return True

    def _github_name(self, repository: str) -> str | None:
        """Return GitHub's canonical ``github.com/Owner/Repo`` (case, renames), when the API is reachable."""
        host, owner, name = repository.split("/")
        if host != "github.com" or not self._github_available:
            return None
        try:
            payload = self.github.get("repos", owner, name)
        except urllib.error.HTTPError as exc:
            # Anonymous clients get 60 requests per hour; stop asking once limited.
            self._github_available = exc.code not in (403, 429)
            return None
        except Exception:
            self._github_available = False
            return None
        full_name = (payload or {}).get("full_name")
        return normalize_repository(f"https://github.com/{full_name}") if isinstance(full_name, str) else None

    def refresh_scorecard(self, repository: str, existing: RepositoryScorecard | None) -> None:
        ok, payload = self._get(self.scorecard, "projects", *repository.split("/"))
        if ok and payload is None and repository.lower() != repository:
            # Published names keep their original case, which SBOMs and PURLs do not always preserve.
            ok, payload = self._get(self.scorecard, "projects", *repository.lower().split("/"))
        if ok and payload is None:
            canonical = self._github_name(repository)
            if canonical is not None and canonical not in {repository, repository.lower()}:
                ok, payload = self._get(self.scorecard, "projects", *canonical.split("/"))
        if not ok and existing is not None and existing.status == "scored":
            return
        row = existing or RepositoryScorecard(repository=repository)
        row.fetched_at = self.now
        row.status, row.published_repository, row.score = "error" if not ok else "not_found", None, None
        row.checks, row.scorecard_date, row.commit = None, None, None
        if payload is not None:
            score = payload.get("score")
            published = (payload.get("repo") or {}).get("name")
            row.status = "scored"
            row.published_repository = normalize_repository(f"https://{published}") \
                if isinstance(published, str) else None
            row.score = float(score) if isinstance(score, (int, float)) else None
            row.checks = _scorecard_checks(payload)
            row.scorecard_date = str(payload.get("date") or "")[:32] or None
            row.commit = str((payload.get("repo") or {}).get("commit") or "")[:64] or None
        if existing is None:
            db.session.add(row)

    def scorecard_is_stale(self, row: RepositoryScorecard | None, force: bool) -> bool:
        return force or row is None or row.status == "error" or row.fetched_at <= self.now - SCORECARD_TTL


def _chunks(values: list, size: int = DB_CHUNK) -> Iterable[list]:
    for start in range(0, len(values), size):
        yield values[start:start + size]


def _evidence_by_package(package_ids: list[uuid.UUID],
                         scan_ids: list[uuid.UUID]) -> dict[tuple[uuid.UUID, uuid.UUID], _Evidence]:
    evidence: dict[tuple[uuid.UUID, uuid.UUID], _Evidence] = {}
    for chunk in _chunks(package_ids):
        for package_id, purls, cpes, source_urls, upstream_urls, document_id, variant_id in db.session.execute(
            select(SBOMPackage.package_id, SBOMPackage.purl, SBOMPackage.cpe, SBOMPackage.source_urls,
                   SBOMPackage.upstream_urls, SBOMPackage.sbom_document_id, Scan.variant_id)
            .join(SBOMDocument, SBOMDocument.id == SBOMPackage.sbom_document_id)
            .join(Scan, Scan.id == SBOMDocument.scan_id)
            .where(SBOMPackage.package_id.in_(chunk), SBOMDocument.scan_id.in_(scan_ids))
        ):
            item = evidence.setdefault((package_id, variant_id), _Evidence(set(), set(), set(), set()))
            item.purls.update(purls or [])
            item.cpes.update(cpes or [])
            item.source_urls.update(source_urls or [])
            item.upstream_urls.update(upstream_urls or [])
            item.documents.add(str(document_id))
    return evidence


def _cve_ids_by_package(package_ids: list[uuid.UUID],
                        scan_ids: list[uuid.UUID]) -> dict[tuple[uuid.UUID, uuid.UUID], list[str]]:
    result: dict[tuple[uuid.UUID, uuid.UUID], list[str]] = {}
    variant_ids = db.session.scalars(select(Scan.variant_id).where(Scan.id.in_(scan_ids))).all()
    active_ids = sorted({scan_id for variant_id in variant_ids
                         for scan_id in active_scan_ids_for_variant(variant_id)})
    for chunk in _chunks(package_ids):
        for package_id, variant_id, vulnerability_id in db.session.execute(
            select(Finding.package_id, Scan.variant_id, Finding.vulnerability_id)
            .join(Observation, Observation.finding_id == Finding.id)
            .join(Scan, Scan.id == Observation.scan_id)
            .where(Finding.package_id.in_(chunk), Finding.vulnerability_id.like("CVE-%"),
                   Observation.scan_id.in_(active_ids)).distinct()
        ):
            result.setdefault((package_id, variant_id), []).append(vulnerability_id)
    # Recent CVEs are the likeliest to carry OSV git ranges.
    return {package_id: sorted(ids, reverse=True) for package_id, ids in result.items()}


def scoped_package_ids(variant_ids: Iterable[str]) -> list[uuid.UUID]:
    package_ids: set[uuid.UUID] = set()
    for variant_id in variant_ids:
        package_ids |= active_package_ids_for_scans(active_sbom_scan_ids_for_variant(uuid.UUID(variant_id)))
    return sorted(package_ids)


def _checkpoint(ctx: JobContext) -> None:
    if ctx.is_cancelled():
        with write_lock():
            db.session.commit()
        ctx.check_cancelled()


def _repository_rows_for_keys(keys: dict[tuple[uuid.UUID, uuid.UUID], str]) -> list[PackageRepository]:
    pairs = [(package_id, evidence_key) for (package_id, _variant_id), evidence_key in keys.items()]
    rows: list[PackageRepository] = []
    for chunk in _chunks(pairs, DB_CHUNK // 2):
        rows.extend(db.session.scalars(select(PackageRepository).where(
            tuple_(PackageRepository.package_id, PackageRepository.evidence_key).in_(chunk))))
    return rows


def _repository_values_for_keys(keys: dict[tuple[uuid.UUID, uuid.UUID], str]) -> list[str]:
    pairs = [(package_id, evidence_key) for (package_id, _variant_id), evidence_key in keys.items()]
    repositories: list[str] = []
    for chunk in _chunks(pairs, DB_CHUNK // 2):
        repositories.extend(repository for repository in db.session.scalars(select(PackageRepository.repository).where(
            tuple_(PackageRepository.package_id, PackageRepository.evidence_key).in_(chunk))) if repository)
    return repositories


def _scorecard_rows(repositories: list[str]) -> dict[str, RepositoryScorecard]:
    rows: dict[str, RepositoryScorecard] = {}
    for chunk in _chunks(repositories):
        rows.update({row.repository: row for row in db.session.scalars(
            select(RepositoryScorecard).where(RepositoryScorecard.repository.in_(chunk)))})
    return rows


def _stale_scorecard_repositories(repositories: list[str], refresher: PackageHealthRefresher,
                                  force: bool) -> list[str]:
    cached: dict[str, tuple[str, datetime.datetime]] = {}
    for chunk in _chunks(repositories):
        cached.update({repository: (status, fetched_at) for repository, status, fetched_at in db.session.execute(
            select(RepositoryScorecard.repository, RepositoryScorecard.status, RepositoryScorecard.fetched_at)
            .where(RepositoryScorecard.repository.in_(chunk)))})
    return [repository for repository in repositories
            if force or repository not in cached or cached[repository][0] == "error"
            or cached[repository][1] <= refresher.now - SCORECARD_TTL]


def run_scorecard_refresh(ctx: JobContext, refresher: PackageHealthRefresher | None = None) -> None:
    """Resolve package repositories for the selected variants, then refresh stale Scorecard results."""
    if not scorecard_enabled():
        ctx.report(0, 0, f"OpenSSF Scorecard lookups are disabled ({ENABLED_ENV}=0)")
        return
    refresher = refresher or PackageHealthRefresher()
    force = ctx.options.get("force") is True
    with write_lock():
        db.session.execute(delete(PackageRepository).where(PackageRepository.package_id.not_in(select(Package.id))))
        db.session.commit()

    scan_ids = sorted({scan_id for variant_id in ctx.options.get("variant_ids") or []
                       for scan_id in active_sbom_scan_ids_for_variant(uuid.UUID(variant_id))})
    package_ids = sorted(active_package_ids_for_scans(scan_ids))
    evidence = _evidence_by_package(package_ids, scan_ids)
    cve_ids = _cve_ids_by_package(package_ids, scan_ids)
    keys = {key: item.key(cve_ids.get(key, [])) for key, item in evidence.items()}
    evidence_items = list(evidence.items())
    total = len(evidence_items)
    ctx.report(0, total, f"Resolving upstream repositories: 0/{total}")
    done = 0
    for batch in _chunks(evidence_items, COMMIT_EVERY):
        batch_keys = {key: keys[key] for key, _item in batch}
        batch_package_ids = sorted({key[0] for key in batch_keys})
        rows = {(row.package_id, row.evidence_key): row for row in _repository_rows_for_keys(batch_keys)}
        packages = {package.id: package for package in db.session.scalars(
            select(Package).where(Package.id.in_(batch_package_ids)))}
        for key, item in batch:
            _checkpoint(ctx)
            package_id, _variant_id = key
            refresher.resolve(packages[package_id], item, cve_ids.get(key, []),
                              rows.get((package_id, batch_keys[key])), force)
            done += 1
            ctx.report(done, total, f"Resolving upstream repositories: {done}/{total}")
        with write_lock():
            db.session.commit()

    resolved = _repository_values_for_keys(keys)
    repositories = sorted({repository for repository in resolved if scorecard_supported(repository)})
    stale = _stale_scorecard_repositories(repositories, refresher, force)
    ctx.report(0, len(stale), f"Fetching OpenSSF Scorecard results: 0/{len(stale)}")
    done = 0
    for batch in _chunks(stale, COMMIT_EVERY):
        cached = _scorecard_rows(batch)
        for repository in batch:
            _checkpoint(ctx)
            refresher.refresh_scorecard(repository, cached.get(repository))
            done += 1
            ctx.report(done, len(stale), f"Fetching OpenSSF Scorecard results: {done}/{len(stale)}")
        with write_lock():
            db.session.commit()
    ctx.report(len(stale), len(stale),
               f"OpenSSF Scorecard refresh complete ({len(resolved)}/{total} packages with a repository, "
               f"{len(stale)} repositories fetched)")


def _scorecard_view(repository: str | None, row: RepositoryScorecard | None, details: bool) -> dict | None:
    if repository is None:
        return None
    if not scorecard_supported(repository):
        return {"status": "unsupported"}
    if row is None:
        return None
    checks = row.checks or []
    maintained = next((check for check in checks if check.get("name") == "Maintained"), None)
    view: dict[str, Any] = {
        "status": row.status,
        "repository": row.published_repository,
        "score": row.score,
        "date": row.scorecard_date,
        "commit": row.commit,
        "fetched_at": _iso(row.fetched_at),
        "maintained": {"score": maintained.get("score"), "reason": maintained.get("reason")} if maintained else None,
    }
    if details:
        view["checks"] = checks
    return view


def package_health(package_ids: Iterable[uuid.UUID], scan_ids: list[uuid.UUID],
                   details: bool = False) -> dict[uuid.UUID, dict]:
    """Return the cached repository and Scorecard state for each package that has been resolved."""
    ids = list(package_ids)
    evidence = _evidence_by_package(ids, scan_ids)
    cve_ids = _cve_ids_by_package(ids, scan_ids)
    keys = {key: item.key(cve_ids.get(key, [])) for key, item in evidence.items()}
    rows = {(row.package_id, row.evidence_key): row for row in _repository_rows_for_keys(keys)}
    by_package: dict[uuid.UUID, list[PackageRepository]] = {}
    for key in keys:
        row = rows.get((key[0], keys[key]))
        if row is not None:
            by_package.setdefault(key[0], []).append(row)
    expected_counts: dict[uuid.UUID, int] = {}
    for package_id, _variant_id in keys:
        expected_counts[package_id] = expected_counts.get(package_id, 0) + 1
    complete_rows = {package_id: matching for package_id, matching in by_package.items()
                     if len(matching) == expected_counts[package_id]}
    selected = {
        package_id: min(matching, key=lambda row: (
            {"sbom": 0, "deps_dev": 1, "osv": 2, "none": 3}.get(row.source, 4),
            not scorecard_supported(row.repository) if row.repository else True,
            row.repository or "",
        ))
        for package_id, matching in complete_rows.items()
    }
    scorecards = _scorecard_rows(sorted({row.repository for row in selected.values() if row.repository is not None}))
    return {
        package_id: {
            "repository": row.repository,
            "repository_source": row.source,
            "repository_evidence": row.evidence,
            "deprecated": row.deprecated,
            "deprecated_reason": row.deprecated_reason,
            "resolved_at": _iso(row.resolved_at),
            "scorecard": _scorecard_view(
                row.repository, scorecards.get(row.repository) if row.repository else None, details),
        }
        for package_id, row in selected.items()
    }

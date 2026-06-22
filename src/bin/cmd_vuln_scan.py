# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Vulnerability scanning commands: ``flask nvd-scan`` and ``flask osv-scan``."""

from ..controllers.nvd_db import NVD_DB
from ..controllers.osv_client import OSVClient
from ..models.scan import Scan as ScanModel
from ..models.finding import Finding as FindingModel
from ..models.observation import Observation
from ..models.vulnerability import Vulnerability as VulnModel
from ..models.metrics import Metrics as MetricsModel
from ..models.cvss import CVSS
from ..models.assessment import Assessment, STATUS_TO_SIMPLIFIED
from ..models.package import Package
from ..extensions import db as _db
from ..extensions import write_lock as _write_lock
from ..helpers.active_scans import active_sbom_scan_ids_for_variant, active_package_ids_for_scans
from ._common import DEFAULT_VARIANT_NAME, resolve_project_variant
import click
import os
import uuid
from datetime import datetime, timezone
from sqlalchemy import inspect as sa_inspect
from flask.cli import with_appcontext


# ---------------------------------------------------------------------------
# Shared helpers for vuln scan commands
# ---------------------------------------------------------------------------

def _resolve_active_packages(variant_uuid):
    """Resolve active packages for a variant, raising on failure."""
    click.echo("Resolving active packages…")
    latest_ids = active_sbom_scan_ids_for_variant(variant_uuid)
    if not latest_ids:
        raise click.ClickException("No scans found for variant")
    all_pkg_ids = active_package_ids_for_scans(latest_ids)
    if not all_pkg_ids:
        raise click.ClickException("No packages found for variant")
    return _db.session.execute(
        _db.select(Package).where(Package.id.in_(all_pkg_ids))
    ).scalars().all()


def _create_tool_scan(variant_uuid, scan_source: str):
    """Create a new tool scan for the given variant."""
    return ScanModel.create(
        description="empty description",
        variant_id=variant_uuid,
        scan_type="tool",
        scan_source=scan_source,
    )


def _echo_query_results(idx: int, total: int, label: str, vuln_ids: list[str],
                        noun: str = "vuln(s)", no_results: str = "no vulnerabilities"):
    """Print progress line for a query result."""
    if vuln_ids:
        ids_str = ', '.join(vuln_ids[:10])
        ellip = '…' if len(vuln_ids) > 10 else ''
        click.echo(
            f"[{idx}/{total}] {label} → "
            f"{len(vuln_ids)} {noun}: {ids_str}{ellip}"
        )
    else:
        click.echo(f"[{idx}/{total}] {label} → {no_results}")


def _persist_finding(pkg_id, vuln_id, scan_id, variant_uuid, origin: str,
                     observation_pairs: set, assessed_findings: set):
    """Create Finding, Observation and initial Assessment (if missing) for a package+vuln pair."""
    finding = FindingModel.get_or_create(pkg_id, vuln_id)
    pair = (finding.id, scan_id)
    if pair not in observation_pairs:
        observation_pairs.add(pair)
        Observation.create(finding_id=finding.id, scan_id=scan_id, commit=False)
    fv_key = (finding.id, variant_uuid)
    if fv_key not in assessed_findings:
        assessed_findings.add(fv_key)
        has_assess = _db.session.execute(
            _db.select(Assessment.id).where(
                Assessment.finding_id == finding.id,
                Assessment.variant_id == variant_uuid,
            ).limit(1)
        ).scalar_one_or_none()
        if has_assess is None:
            Assessment.create(
                status="under_investigation",
                simplified_status="Pending Assessment",
                finding_id=finding.id,
                variant_id=variant_uuid,
                origin=origin,
                commit=False,
            )


@click.command("nvd-scan")
@click.option("--project", "-p", required=True, help="Project name.")
@click.option("--variant", "-v", default=None,
              help=f"Variant name (defaults to '{DEFAULT_VARIANT_NAME}').")
@with_appcontext
def nvd_scan_command(project: str, variant: str | None) -> None:
    """Run an NVD CPE-based vulnerability scan for the given project/variant.

    Queries the NVD API for every CPE found in the variant's active packages
    and creates findings/observations in a new tool scan.
    """
    project_obj, variant_obj = resolve_project_variant(project, variant, create=True)
    variant_uuid = variant_obj.id

    nvd_api_key = os.getenv("NVD_API_KEY")
    nvd = NVD_DB(nvd_api_key=nvd_api_key)

    packages = _resolve_active_packages(variant_uuid)

    # Collect CPE names from packages
    # Accept any CPE with a non-wildcard product (parts[4]).
    # Wildcard part/vendor/version are handled via virtualMatchString.
    cpe_to_pkgs: dict = {}
    for pkg in packages:
        for cpe in (pkg.cpe or []):
            parts = cpe.split(":")
            if len(parts) >= 6 and parts[4] != "*":
                cpe_to_pkgs.setdefault(cpe, []).append(pkg)

    if not cpe_to_pkgs:
        raise click.ClickException(
            "No packages with valid CPE identifiers"
        )

    click.echo(
        f"Found {len(packages)} packages with "
        f"{len(cpe_to_pkgs)} unique CPEs to query"
    )

    scan = _create_tool_scan(variant_uuid, "nvd")
    total_cpes = len(cpe_to_pkgs)
    cves_found: set = set()
    observation_pairs: set = set()
    assessed_findings: set = set()

    for idx, (cpe_name, pkgs) in enumerate(cpe_to_pkgs.items(), 1):
        click.echo(f"[{idx}/{total_cpes}] Querying {cpe_name}…")
        try:
            cpe_parts = cpe_name.split(":")
            has_wildcards = (
                len(cpe_parts) >= 6
                and (cpe_parts[2] == "*"
                     or cpe_parts[3] == "*"
                     or cpe_parts[5] == "*")
            )
            nvd_vulns = nvd.api_get_cves_by_cpe(
                cpe_name,
                results_per_page=100,
                use_virtual_match=has_wildcards,
            )
        except Exception as e:
            click.echo(
                f"[{idx}/{total_cpes}] ERROR {cpe_name}: {str(e)[:200]}",
                err=True,
            )
            continue

        cpe_cves = [
            v.get("cve", {}).get("id", "")
            for v in nvd_vulns if v.get("cve", {}).get("id")
        ]
        _echo_query_results(idx, total_cpes, cpe_name, cpe_cves, "CVE(s)", "no CVEs")

        for nvd_vuln in nvd_vulns:
            cve = nvd_vuln.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            cves_found.add(cve_id)
            details = NVD_DB.extract_cve_details(cve)

            existing_vuln = _db.session.get(VulnModel, cve_id.upper())
            if existing_vuln is None:
                existing_vuln = VulnModel.create_record(
                    id=cve_id,
                    description=details.get("description"),
                    status=details.get("status"),
                    publish_date=details.get("publish_date"),
                    attack_vector=details.get("attack_vector"),
                    links=details.get("links"),
                    weaknesses=details.get("weaknesses"),
                    nvd_last_modified=details.get("nvd_last_modified"),
                )
                existing_vuln.add_found_by("nvd")
            else:
                existing_vuln.add_found_by("nvd")
                _update = {}
                if not existing_vuln.description and details.get("description"):
                    _update["description"] = details["description"]
                if not existing_vuln.status and details.get("status"):
                    _update["status"] = details["status"]
                if not existing_vuln.publish_date and details.get("publish_date"):
                    _update["publish_date"] = details["publish_date"]
                if not existing_vuln.attack_vector and details.get("attack_vector"):
                    _update["attack_vector"] = details["attack_vector"]
                if not existing_vuln.links and details.get("links"):
                    _update["links"] = details["links"]
                if not existing_vuln.weaknesses and details.get("weaknesses"):
                    _update["weaknesses"] = details["weaknesses"]
                if _update:
                    existing_vuln.update_record(**_update, commit=False)

            # Persist CVSS metrics
            if details.get("base_score") is not None:
                _cvss_v = details.get("cvss_version")
                _cvss_s = details["base_score"]
                _cvss_vec = details.get("cvss_vector")
                _dedup = (cve_id.upper(), _cvss_v, float(_cvss_s))
                if _dedup not in MetricsModel._seen:
                    try:
                        MetricsModel.from_cvss(
                            CVSS(
                                version=_cvss_v or "",
                                vector_string=_cvss_vec or "",
                                author="nvd",
                                base_score=float(_cvss_s),
                                exploitability_score=(
                                    float(details["cvss_exploitability"])
                                    if details.get("cvss_exploitability") is not None
                                    else 0
                                ),
                                impact_score=(
                                    float(details["cvss_impact"])
                                    if details.get("cvss_impact") is not None
                                    else 0
                                ),
                            ),
                            existing_vuln.id,
                        )
                    except Exception:
                        pass

            for pkg in pkgs:
                _persist_finding(pkg.id, cve_id, scan.id, variant_uuid, "nvd",
                                 observation_pairs, assessed_findings)

    _db.session.commit()
    click.echo(
        f"✓ Scan complete — found {len(cves_found)} unique CVEs "
        f"across {total_cpes} CPEs"
    )


@click.command("osv-scan")
@click.option("--project", "-p", required=True, help="Project name.")
@click.option("--variant", "-v", default=None,
              help=f"Variant name (defaults to '{DEFAULT_VARIANT_NAME}').")
@with_appcontext
def osv_scan_command(project: str, variant: str | None) -> None:
    """Run an OSV PURL-based vulnerability scan for the given project/variant.

    Queries the OSV.dev API for every PURL found in the variant's active
    packages and creates findings/observations in a new tool scan.
    """

    project_obj, variant_obj = resolve_project_variant(project, variant, create=True)
    variant_uuid = variant_obj.id

    osv = OSVClient()

    packages = _resolve_active_packages(variant_uuid)

    # Collect packages with PURL identifiers
    pkg_purl_list: list[tuple] = []
    seen_purls: set = set()
    for pkg in packages:
        for purl in (pkg.purl or []):
            purl_str = str(purl).strip()
            if purl_str and purl_str.startswith("pkg:") and purl_str not in seen_purls:
                seen_purls.add(purl_str)
                pkg_purl_list.append((purl_str, pkg))
                break

    if not pkg_purl_list:
        raise click.ClickException(
            "No packages with valid PURL identifiers"
        )

    total_pkgs = len(pkg_purl_list)
    click.echo(
        f"Found {len(packages)} packages, "
        f"{total_pkgs} with PURL identifiers to query"
    )

    scan = _create_tool_scan(variant_uuid, "osv")
    vulns_found: set = set()
    observation_pairs: set = set()
    assessed_findings: set = set()

    for idx, (purl_str, pkg) in enumerate(pkg_purl_list, 1):
        pkg_label = f"{pkg.name}@{pkg.version}" if pkg.name else purl_str
        click.echo(f"[{idx}/{total_pkgs}] Querying {pkg_label}…")
        try:
            osv_vulns = osv.query_by_purl(purl_str)
        except Exception as e:
            click.echo(
                f"[{idx}/{total_pkgs}] ERROR {pkg_label}: {str(e)[:200]}",
                err=True,
            )
            continue

        vuln_ids = [v.get("id", "") for v in osv_vulns if v.get("id")]
        _echo_query_results(idx, total_pkgs, pkg_label, vuln_ids)

        for osv_vuln in osv_vulns:
            vuln_id = osv_vuln.get("id", "")
            if not vuln_id:
                continue

            all_ids = [vuln_id] + [
                a for a in osv_vuln.get("aliases", [])
                if a.startswith("CVE-")
            ]
            vulns_found.add(vuln_id)
            osv_desc = osv_vuln.get("summary") or osv_vuln.get("details")

            for vid in all_ids:
                existing_vuln = _db.session.get(VulnModel, vid.upper())
                if existing_vuln is None:
                    existing_vuln = VulnModel.create_record(
                        id=vid,
                        description=osv_desc,
                        links=[
                            r.get("url")
                            for r in osv_vuln.get("references", [])
                            if r.get("url")
                        ] or None,
                    )
                    existing_vuln.add_found_by("osv")
                else:
                    existing_vuln.add_found_by("osv")
                    if not existing_vuln.description and osv_desc:
                        existing_vuln.update_record(
                            description=osv_desc, commit=False,
                        )

                _persist_finding(pkg.id, vid, scan.id, variant_uuid, "osv",
                                 observation_pairs, assessed_findings)

    _db.session.commit()
    click.echo(
        f"✓ Scan complete — found {len(vulns_found)} unique vulnerabilities "
        f"across {total_pkgs} packages"
    )


# ---------------------------------------------------------------------------
# sbom-cve-check-scan: local NVD-FKIE + CVEList engine with version-range evaluation
# ---------------------------------------------------------------------------

# OpenVEX status → human-readable simplified label (mirrors Assessment model).
def _simplified_label(status: str | None) -> str:
    """Canonical simplified label for a status, collapsing OpenVEX/CDX synonyms.

    Both an engine OpenVEX verdict (``affected``) and a CDX-VEX status carrying
    the same meaning (``exploitable``) map to the same label (``Exploitable``),
    so a finding's recorded state can be compared regardless of which vocabulary
    produced it.
    """
    return STATUS_TO_SIMPLIFIED.get(status or "", "Pending Assessment")


def _ts_key(ts) -> str:
    """Normalise a timestamp (str, datetime or None) to a comparable string."""
    if ts is None:
        return ""
    if isinstance(ts, str):
        return ts
    try:
        return ts.isoformat()
    except Exception:
        return str(ts)


def _scc_cvss_version(metric) -> str:
    """Render an engine ``CvssMetric.cvss_ver`` tuple as a ``"major.minor"`` string."""
    value = getattr(metric.cvss_ver, "value", (0, 0))
    try:
        major, minor = value
    except (TypeError, ValueError):
        return ""
    if not major:
        return ""
    return f"{major}.{minor}"


class _SccBulkWriter:
    """Buffered bulk persister for sbom-cve-check-scan findings.

    The previous implementation persisted every engine finding with its own
    ``get_or_create`` round-trips (vuln SELECT, finding SELECT + savepoint INSERT,
    observation INSERT, assessment SELECT + INSERT) and committed once per
    package.  A Yocto kernel recipe expands into hundreds of ``kernel-module-*``
    sub-packages that each carry the full ``linux_kernel`` CVE set, so the scan
    produced millions of findings and the row-at-a-time persistence dominated the
    runtime (hours).

    This writer instead accumulates plain row dictionaries and flushes them with
    ``bulk_insert_mappings`` in foreign-key order (vulnerabilities → metrics →
    findings → observations → assessments), committing once per chunk.  Duplicate
    work is avoided in memory:

    * ``(package_id, cve)`` pairs that already have a finding (from a prior
      nvd/osv scan) are pre-loaded so existing findings are reused, never
      re-inserted;
    * a fresh scan owns brand-new finding UUIDs, so newly created findings are
      globally unique and need no run-internal dedup tracking (kept out of the
      in-memory index to bound memory on the kernel explosion);
    * metrics are inserted only alongside a newly created vulnerability, deduped
      by ``(version, score)``;
    * an assessment is recorded only when the engine verdict changes a finding's
      most recent state: every finding's latest assessment (for this variant) is
      pre-loaded as a simplified label, and a new assessment is appended only
      when the engine's verdict maps to a different label (a finding with no
      prior assessment always counts as a change).  Every verdict the engine
      emits is considered — ``affected``, ``under_investigation``,
      ``not_affected`` and ``fixed`` — so the full VEX state is captured;
    * ``found_by`` is a transient (non-persisted) attribute, so dropping the
      per-vuln ``add_found_by``/enrichment updates changes nothing on disk.
    """

    FLUSH_THRESHOLD = 5000
    _SELECT_CHUNK = 500

    def __init__(self, scan_id, variant_uuid, packages):
        self._scan_id = scan_id
        self._variant_uuid = variant_uuid
        self.cves_found: set[str] = set()

        # CVE ids already observed in this variant across any previous scan.
        self._variant_existing_cves: set[str] = set()
        # CVE ids first seen in this run for this variant.
        self._variant_new_cves: set[str] = set()

        # Confirmed-present (existing or already-inserted) vulnerability ids.
        self._known_vuln_ids: set[str] = set()
        # cve_id -> (vuln_row, [metric_row, ...]) awaiting existence resolution.
        self._pending_vulns: dict[str, tuple[dict, list[dict]]] = {}

        # Pre-loaded existing findings, plus the simplified status (and its
        # timestamp key) of each finding's most recent assessment for this
        # variant.  This lets a re-scan record a fresh assessment only when the
        # engine verdict actually changes the finding's state.
        self._finding_index: dict[tuple, uuid.UUID] = {}
        self._last_simplified: dict[uuid.UUID, str] = {}
        self._last_ts: dict[uuid.UUID, str] = {}

        # Row buffers for the current chunk.
        self._vuln_rows: list[dict] = []
        self._metric_rows: list[dict] = []
        self._finding_rows: list[dict] = []
        self._obs_rows: list[dict] = []
        self._assess_rows: list[dict] = []
        self._buffered_findings = 0

        self._preload(packages)

    # ------------------------------------------------------------------
    # Pre-loading
    # ------------------------------------------------------------------

    def _preload(self, packages) -> None:
        """Load existing findings and each one's most recent assessment status."""
        pkg_ids = [pkg.id for pkg in packages]
        for i in range(0, len(pkg_ids), self._SELECT_CHUNK):
            chunk = pkg_ids[i:i + self._SELECT_CHUNK]
            rows = _db.session.execute(
                _db.select(
                    FindingModel.id,
                    FindingModel.package_id,
                    FindingModel.vulnerability_id,
                ).where(FindingModel.package_id.in_(chunk))
            ).all()
            for fid, package_id, vuln_id in rows:
                self._finding_index[(package_id, vuln_id.upper())] = fid

        # CVEs already present in this variant (via any finding observed by any
        # scan tied to the variant). Pending assessment must only be added for
        # truly new CVEs, not for existing CVEs appearing on additional packages.
        existing_variant_cves = _db.session.execute(
            _db.select(FindingModel.vulnerability_id)
            .join(Observation, Observation.finding_id == FindingModel.id)
            .join(ScanModel, ScanModel.id == Observation.scan_id)
            .where(ScanModel.variant_id == self._variant_uuid)
            .distinct()
        ).all()
        self._variant_existing_cves = {
            vuln_id.upper() for (vuln_id,) in existing_variant_cves if vuln_id
        }

        # For every pre-existing finding remember the simplified status of its
        # most recent assessment for this variant, so the writer only records a
        # new assessment when the engine verdict changes that state.
        finding_ids = list(self._finding_index.values())
        for i in range(0, len(finding_ids), self._SELECT_CHUNK):
            chunk = finding_ids[i:i + self._SELECT_CHUNK]
            rows = _db.session.execute(
                _db.select(
                    Assessment.finding_id,
                    Assessment.status,
                    Assessment.timestamp,
                ).where(
                    Assessment.finding_id.in_(chunk),
                    Assessment.variant_id == self._variant_uuid,
                )
            ).all()
            for fid, status, ts in rows:
                ts_key = _ts_key(ts)
                if ts_key >= self._last_ts.get(fid, ""):
                    self._last_ts[fid] = ts_key
                    self._last_simplified[fid] = _simplified_label(status)

    # ------------------------------------------------------------------
    # Row building
    # ------------------------------------------------------------------

    @staticmethod
    def _build_vuln(cve_id: str, computed) -> tuple[dict, list[dict]]:
        publish_date = (
            computed.date_published.date() if computed.date_published is not None else None
        )
        links = sorted({ref.url for ref in computed.external_refs if getattr(ref, "url", None)})
        nvd_last_modified = (
            computed.date_modified.isoformat() if computed.date_modified is not None else None
        )
        vuln_row = {
            "id": cve_id,
            "description": computed.description,
            "publish_date": publish_date,
            "links": links or None,
            "nvd_last_modified": nvd_last_modified,
        }

        metric_rows: list[dict] = []
        seen_metric: set[tuple] = set()
        for metric in computed.cvss_metrics:
            if metric.score is None:
                continue
            version = _scc_cvss_version(metric)
            score = float(metric.score)
            dk = (version, score)
            if dk in seen_metric:
                continue
            seen_metric.add(dk)
            metric_rows.append({
                "id": uuid.uuid4(),
                "vulnerability_id": cve_id,
                "variant_id": None,
                "version": version,
                "score": score,
                "vector": metric.vector_str or "",
                "author": metric.source or "sbom-cve-check",
                "origin": None,
            })
        return vuln_row, metric_rows

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(self, pkg, computed, status, seen_keys: set) -> str | None:
        """Queue one engine finding for bulk insertion.

        Returns the CVE id when the finding was queued, or ``None`` if it was a
        duplicate already handled for this package in the current run.
        """
        cve_id = str(computed.identifier).upper()
        key = (pkg.id, cve_id)
        if key in seen_keys:
            return None
        seen_keys.add(key)
        self.cves_found.add(cve_id)

        # Ensure the vulnerability exists (or is queued) before its finding.
        if cve_id not in self._known_vuln_ids and cve_id not in self._pending_vulns:
            self._pending_vulns[cve_id] = self._build_vuln(cve_id, computed)

        finding_id = self._finding_index.get(key)
        is_new_finding = finding_id is None
        if is_new_finding:
            finding_id = uuid.uuid4()
            self._finding_rows.append({
                "id": finding_id,
                "package_id": pkg.id,
                "vulnerability_id": cve_id,
            })
            self._buffered_findings += 1

        # The scan is freshly created, so every finding gets one observation.
        self._obs_rows.append({
            "id": uuid.uuid4(),
            "finding_id": finding_id,
            "scan_id": self._scan_id,
        })

        # Only record an initial "Pending Assessment" for brand-new CVEs in the
        # variant. Existing CVEs must not be modified, even if this scan creates
        # a new finding for a different package.
        assert finding_id is not None
        if is_new_finding and cve_id not in self._variant_existing_cves and cve_id not in self._variant_new_cves:
            self._variant_new_cves.add(cve_id)
            self._last_simplified[finding_id] = "Pending Assessment"
            self._assess_rows.append({
                "id": uuid.uuid4(),
                "status": "under_investigation",
                "simplified_status": "Pending Assessment",
                "finding_id": finding_id,
                "variant_id": self._variant_uuid,
                "origin": "scc",
                "status_notes": None,
                "timestamp": datetime.now(timezone.utc),
                "responses": [],
            })

        return cve_id

    def maybe_flush(self) -> None:
        if self._buffered_findings >= self.FLUSH_THRESHOLD:
            self.flush()

    def flush(self) -> None:
        """Resolve pending vulnerabilities and bulk-insert the buffered chunk."""
        if self._pending_vulns:
            pending_ids = list(self._pending_vulns.keys())
            existing = self._existing_vuln_ids(pending_ids)
            for cid in pending_ids:
                vuln_row, metric_rows = self._pending_vulns.pop(cid)
                self._known_vuln_ids.add(cid)
                if cid in existing:
                    continue
                self._vuln_rows.append(vuln_row)
                self._metric_rows.extend(metric_rows)

        if not (self._vuln_rows or self._metric_rows or self._finding_rows
                or self._obs_rows or self._assess_rows):
            return

        # Insert in foreign-key dependency order.  Bulk operations bypass the
        # before_flush write-lock hook, so serialise explicitly for SQLite.
        with _write_lock():
            if self._vuln_rows:
                _db.session.bulk_insert_mappings(sa_inspect(VulnModel), self._vuln_rows)
            if self._metric_rows:
                _db.session.bulk_insert_mappings(sa_inspect(MetricsModel), self._metric_rows)
            if self._finding_rows:
                _db.session.bulk_insert_mappings(sa_inspect(FindingModel), self._finding_rows)
            if self._obs_rows:
                _db.session.bulk_insert_mappings(sa_inspect(Observation), self._obs_rows)
            if self._assess_rows:
                _db.session.bulk_insert_mappings(sa_inspect(Assessment), self._assess_rows)
            _db.session.commit()

        self._vuln_rows.clear()
        self._metric_rows.clear()
        self._finding_rows.clear()
        self._obs_rows.clear()
        self._assess_rows.clear()
        self._buffered_findings = 0

    def _existing_vuln_ids(self, ids: list[str]) -> set[str]:
        found: set[str] = set()
        for i in range(0, len(ids), self._SELECT_CHUNK):
            chunk = [x.upper() for x in ids[i:i + self._SELECT_CHUNK]]
            rows = _db.session.execute(
                _db.select(VulnModel.id).where(VulnModel.id.in_(chunk))
            ).all()
            found.update(r[0] for r in rows)
        return found


@click.command("sbom-cve-check-scan")
@click.option("--project", "-p", required=True, help="Project name.")
@click.option("--variant", "-v", default=None,
              help=f"Variant name (defaults to '{DEFAULT_VARIANT_NAME}').")
@with_appcontext
def sbom_cve_check_scan_command(project: str, variant: str | None) -> None:
    """Run a local CVE-database scan (NVD-FKIE + CVEList V5) with version-range evaluation.

    Unlike the live ``nvd-scan`` / ``osv-scan`` paths, this command matches every
    active package against locally-cloned advisory databases, applies product-name
    aliasing and semantic version-range analysis, and records the engine's VEX
    verdict.  It detects vulnerabilities the CPE/PURL API scans miss (notably the
    Linux kernel) and works against the existing clones.

    Every verdict is recorded — including ``not_affected`` and ``fixed`` — so the
    full VEX picture is captured.  A new assessment is written only when the
    verdict changes a finding's most recent state.
    """
    from ..controllers.scc_engine import get_engine

    project_obj, variant_obj = resolve_project_variant(project, variant, create=True)
    variant_uuid = variant_obj.id

    packages = _resolve_active_packages(variant_uuid)
    click.echo(f"Resolved {len(packages)} active packages")

    click.echo("Loading local CVE databases (NVD-FKIE + CVEList) and building index…")
    engine = get_engine()
    click.echo("Index ready — scanning packages")

    scan = _create_tool_scan(variant_uuid, "scc")
    total_pkgs = len(packages)
    writer = _SccBulkWriter(scan.id, variant_uuid, packages)

    for idx, pkg in enumerate(packages, 1):
        pkg_label = f"{pkg.name}@{pkg.version}" if pkg.name else str(pkg.id)
        persisted_ids: list[str] = []
        seen_keys: set = set()
        try:
            for computed, status in engine.applicable_vulns(pkg):
                cve_id = writer.add(pkg, computed, status, seen_keys)
                if cve_id is not None:
                    persisted_ids.append(cve_id)
        except Exception as e:
            click.echo(
                f"[{idx}/{total_pkgs}] ERROR {pkg_label}: {str(e)[:200]}",
                err=True,
            )
            continue

        _echo_query_results(idx, total_pkgs, pkg_label, persisted_ids,
                            "vuln(s)", "no vulnerabilities")
        # Flush in large bulk-inserted chunks to bound memory/transaction size.
        writer.maybe_flush()

    writer.flush()
    click.echo(
        f"✓ Scan complete — found {len(writer.cves_found)} unique vulnerabilities "
        f"across {total_pkgs} packages"
    )

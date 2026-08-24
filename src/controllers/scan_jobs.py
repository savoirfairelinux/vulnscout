# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Scan job bodies executed by the operation queue.

Each ``run_*_scan`` runs inside an application context on the ``pipeline``
lane and reports through its :class:`~src.controllers.job_context.JobContext`.
Raising propagates to the queue, which records the operation as failed.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import uuid as uuid_module
from typing import Callable, Dict, List, Sequence, Set, Tuple

from ..extensions import db
from ..helpers.scan_filters import is_kernel_package_name
from ..models.finding import Finding
from ..models.package import Package
from ..models.project import Project
from ..models.sbom_document import SBOMDocument
from ..models.sbom_package import SBOMPackage
from ..models.scan import Scan
from ..models.variant import Variant
from ..routes._scan_helpers import (
    create_observation_and_assessment,
    resolve_active_packages,
)
from ..views.grype_vulns import GrypeVulns
from .job_context import JobContext

GRYPE_EXPORT_TIMEOUT = 120
GRYPE_SCAN_TIMEOUT = 600
GRYPE_MERGE_TIMEOUT = 120
GRYPE_PROCESS_TIMEOUT = 300

FLASK_APP = "src.bin.webapp"
EMPTY_DESCRIPTION = "empty description"
RESOLVING_PACKAGES = "Resolving active packages…"


def _preview(identifiers: Sequence[str], limit: int = 10) -> str:
    ellipsis = "…" if len(identifiers) > limit else ""
    return f"{', '.join(identifiers[:limit])}{ellipsis}"


def _engine_progress(ctx: JobContext) -> Callable[[str], None]:
    """Surface advisory-database sync messages as both status line and log."""
    def report(message: str) -> None:
        ctx.message(message)
        ctx.log(message)
    return report


def _variant_uuid(ctx: JobContext) -> uuid_module.UUID:
    return uuid_module.UUID(str(ctx.options["variant_id"]))


def _exclude_kernel(ctx: JobContext) -> bool:
    return bool(ctx.options.get("exclude_kernel", True))


def _active_packages(ctx: JobContext) -> Sequence[Package]:
    packages, error = resolve_active_packages(
        _variant_uuid(ctx), exclude_kernel=_exclude_kernel(ctx)
    )
    if error:
        raise RuntimeError(error)
    return packages


def _detect_memory_ceiling() -> int:
    """Bytes of memory available, from cgroup v2, cgroup v1, then /proc."""
    sources = (
        ("/sys/fs/cgroup/memory.max", lambda value: int(value) > 0),
        # cgroup v1 uses PAGE_COUNTER_MAX as the "unconstrained" sentinel.
        (
            "/sys/fs/cgroup/memory/memory.limit_in_bytes",
            lambda value: 0 < int(value) < 9223372036854771712,
        ),
    )
    for path, accept in sources:
        try:
            with open(path) as handle:
                value = handle.read().strip()
        except OSError:
            continue
        if value.isdigit() and accept(value):
            return int(value)

    try:
        with open("/proc/meminfo") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    return 0


def _resolve_grype_memlimit() -> str | None:
    """Translate ``GRYPE_MEMLIMIT`` into a ``GOMEMLIMIT`` value.

    ``off``/``0``/``disabled`` means no limit, an explicit value is passed
    through verbatim, and an unset value auto-detects ~80 % of the cgroup or
    ``/proc/meminfo`` ceiling.
    """
    raw = os.environ.get("GRYPE_MEMLIMIT", "").strip()

    if raw.lower() in ("off", "0", "disabled"):
        return None
    if raw:
        return raw

    mem_bytes = _detect_memory_ceiling()
    return str(mem_bytes * 80 // 100) if mem_bytes > 0 else None


# ---------------------------------------------------------------------------
# Grype
# ---------------------------------------------------------------------------

def _variant_sbom_packages(variant_uuid: uuid_module.UUID) -> Set[Tuple[str, str]]:
    """Name/version pairs from the variant's latest SBOM scan."""
    sbom_scan_id = db.session.execute(
        db.select(Scan.id)
        .where(Scan.variant_id == variant_uuid)
        .where(db.or_(Scan.scan_type == "sbom", Scan.scan_type.is_(None)))
        .order_by(Scan.timestamp.desc())
        .limit(1)
    ).scalar()
    if sbom_scan_id is None:
        return set()
    rows = db.session.execute(
        db.select(Package.name, Package.version)
        .join(SBOMPackage, SBOMPackage.package_id == Package.id)
        .join(SBOMDocument, SBOMPackage.sbom_document_id == SBOMDocument.id)
        .where(SBOMDocument.scan_id == sbom_scan_id)
    ).all()
    return {(row[0], row[1]) for row in rows}


def _deduplicate_cyclonedx(
    ctx: JobContext, export_path: str, exclude_kernel: bool
) -> None:
    """Collapse supplier-duplicated components before handing the SBOM to Grype.

    The export emits one row per package, so a package appears several times
    when it differs only by supplier. Keying on the raw name@version is
    deliberate: normalising would over-collapse genuinely distinct packages.
    """
    with open(export_path, "r") as handle:
        data = json.load(handle)

    components = data.get("components", [])
    original_count = len(components)
    kept: List[dict] = []
    kept_refs: Set[str] = set()
    seen: Set[Tuple[str, str]] = set()
    kernel_dropped = 0

    for component in components:
        name = component.get("name", "")
        version = component.get("version", "")
        if exclude_kernel and is_kernel_package_name(name):
            kernel_dropped += 1
            continue
        if (name, version) in seen:
            continue
        seen.add((name, version))
        kept.append(component)
        ref = component.get("bom-ref")
        if ref:
            kept_refs.add(ref)

    data["components"] = kept
    if isinstance(data.get("dependencies"), list):
        data["dependencies"] = [
            dep for dep in data["dependencies"] if dep.get("ref") in kept_refs
        ]
    with open(export_path, "w") as handle:
        json.dump(data, handle)

    suffix = f" ({kernel_dropped} kernel modules excluded)" if kernel_dropped else ""
    ctx.log(f"[1/4] De-duplicated components: {len(kept)}/{original_count} kept{suffix}")


def _filter_grype_matches(
    ctx: JobContext, results_path: str, sbom_packages: Set[Tuple[str, str]]
) -> None:
    """Drop matches for artifacts Grype synthesised outside the variant SBOM."""
    with open(results_path, "r") as handle:
        data = json.load(handle)

    matches = data.get("matches", [])
    kept = []
    for match in matches:
        artifact = match.get("artifact", {})
        name = GrypeVulns._normalize_artifact_name(
            artifact.get("name", ""), artifact.get("purl")
        )
        if (name, artifact.get("version", "")) in sbom_packages:
            kept.append(match)
    data["matches"] = kept
    with open(results_path, "w") as handle:
        json.dump(data, handle)

    ctx.log(
        f"[2/4] Filtered: {len(kept)}/{len(matches)} matches kept "
        f"(variant SBOM packages only)"
    )


def _run_cancellable(
    ctx: JobContext, command: List[str], cwd: str, timeout: int, **kwargs
) -> None:
    """Run a subprocess that a cancel request can terminate."""
    process = subprocess.Popen(
        command, cwd=cwd, text=True,
        stdout=kwargs.pop("stdout", subprocess.PIPE),
        stderr=subprocess.PIPE, **kwargs,
    )
    ctx.set_cancel_hook(process.terminate)
    try:
        _, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise
    finally:
        ctx.set_cancel_hook(None)
    ctx.check_cancelled()
    if process.returncode != 0:
        detail = (stderr or "")[:500] or f"exit code {process.returncode}"
        raise RuntimeError(f"Command failed: {detail}")


def run_grype_scan(ctx: JobContext) -> None:
    """Export the variant as CycloneDX, run Grype on it, merge the results."""
    if shutil.which("grype") is None:
        raise RuntimeError("grype binary not found on this system")

    variant_uuid = _variant_uuid(ctx)
    variant = db.session.get(Variant, variant_uuid)
    if variant is None:
        raise RuntimeError("Variant not found")
    project = db.session.get(Project, variant.project_id)
    project_name = project.name if project else "unknown"
    vid_str = str(variant_uuid)

    sbom_packages = _variant_sbom_packages(variant_uuid)
    exclude_kernel = _exclude_kernel(ctx)
    base_dir = os.environ.get(
        "BASE_DIR",
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    )

    def _run(command: List[str], timeout: int, **kwargs) -> None:
        _run_cancellable(ctx, command, base_dir, timeout, **kwargs)

    grype_tmp = tempfile.mkdtemp(prefix="vulnscout_grype_")
    try:
        ctx.report(0, 4, "1/4 Exporting CycloneDX")
        ctx.log("[1/4] Exporting variant packages as CycloneDX…")
        _run(
            ["flask", "--app", FLASK_APP, "export", "--format", "cdx16",
             "--output-dir", grype_tmp, "--variant-id", vid_str],
            GRYPE_EXPORT_TIMEOUT,
        )
        ctx.report(1, 4, "1/4 Exporting CycloneDX")

        exported_cdx = os.path.join(grype_tmp, "sbom_cyclonedx_v1_6.cdx.json")
        if not os.path.isfile(exported_cdx):
            raise RuntimeError("CycloneDX export produced no file")
        ctx.log("[1/4] CycloneDX export complete")

        if sbom_packages:
            _deduplicate_cyclonedx(ctx, exported_cdx, exclude_kernel)

        ctx.check_cancelled()
        ctx.report(1, 4, "2/4 Running Grype")
        ctx.log("[2/4] Running Grype vulnerability scanner…")
        grype_out = os.path.join(grype_tmp, "grype_results.grype.json")
        grype_env = os.environ.copy()
        memlimit = _resolve_grype_memlimit()
        if memlimit is not None:
            grype_env["GOMEMLIMIT"] = memlimit
            ctx.log(f"[2/4] Grype memory limit (GOMEMLIMIT): {memlimit}")
        with open(grype_out, "w") as handle:
            _run(
                ["grype", "--add-cpes-if-none", f"sbom:{exported_cdx}", "-o", "json"],
                GRYPE_SCAN_TIMEOUT, stdout=handle, env=grype_env,
            )
        ctx.report(2, 4, "2/4 Running Grype")

        if not os.path.isfile(grype_out) or os.path.getsize(grype_out) == 0:
            raise RuntimeError("Grype produced no output")
        ctx.log("[2/4] Grype scan complete")

        if sbom_packages:
            _filter_grype_matches(ctx, grype_out, sbom_packages)

        ctx.check_cancelled()
        ctx.report(2, 4, "3/4 Merging results")
        ctx.log("[3/4] Merging Grype results into database…")
        _run(
            ["flask", "--app", FLASK_APP, "merge", "--project", project_name,
             "--variant", variant.name, "--grype", grype_out],
            GRYPE_MERGE_TIMEOUT,
        )
        ctx.report(3, 4, "3/4 Merging results")
        ctx.log("[3/4] Merge complete")

        ctx.check_cancelled()
        ctx.report(3, 4, "4/4 Processing")
        ctx.log("[4/4] Processing scan results…")
        _run(["flask", "--app", FLASK_APP, "process"], GRYPE_PROCESS_TIMEOUT)

        ctx.report(4, 4, "Scan complete")
        ctx.log("✓ Grype scan complete")
    except subprocess.TimeoutExpired:
        raise RuntimeError("Grype scan timed out")
    finally:
        shutil.rmtree(grype_tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------

def _run_nvd_scan_local(ctx: JobContext, packages: List[Package]) -> None:
    from ..bin.cmd_vuln_scan import _SccBulkWriter
    from .scc_engine import get_engine

    variant_uuid = _variant_uuid(ctx)
    ctx.log("Loading local NVD advisory database…")
    try:
        engine = get_engine(progress=_engine_progress(ctx))
    except Exception as error:
        raise RuntimeError(f"Failed to load local NVD database: {error}")

    scan = Scan.create(
        description=EMPTY_DESCRIPTION, variant_id=variant_uuid,
        scan_type="tool", scan_source="nvd",
    )
    total = len(packages)
    writer = _SccBulkWriter(scan.id, variant_uuid, packages)
    seen_keys: set = set()

    for index, package in enumerate(packages, 1):
        ctx.check_cancelled()
        ctx.report(index, total, f"{index}/{total} packages")
        try:
            for computed, status in engine.applicable_vulns(package):
                writer.add(package, computed, status, seen_keys)
        except Exception as error:
            ctx.log(f"[{index}/{total}] ERROR {package.name}: {str(error)[:200]}")

    writer.flush()
    found = len(seen_keys)
    ctx.report(total, total, f"Found {found} CVEs across {total} packages")
    ctx.log(f"✓ Scan complete — found {found} unique CVEs across {total} packages")


def _query_cpe(ctx: JobContext, nvd, cpe_name: str) -> List[dict] | None:
    """Return NVD records for *cpe_name*, or ``None`` when the query failed."""
    parts = cpe_name.split(":")
    has_wildcards = len(parts) >= 6 and (
        parts[2] == "*" or parts[3] == "*" or parts[5] == "*"
    )
    try:
        return nvd.api_get_cves_by_cpe(
            cpe_name, results_per_page=100, use_virtual_match=has_wildcards
        )
    except Exception as error:
        ctx.log(f"ERROR {cpe_name}: {str(error)[:200]}")
        return None


def _collect_cpes(packages: List[Package]) -> Dict[str, List[Package]]:
    """Index packages by the CPEs that carry a concrete version field."""
    cpe_to_packages: Dict[str, List[Package]] = {}
    for package in packages:
        for cpe in (package.cpe or []):
            parts = cpe.split(":")
            if len(parts) >= 6 and parts[4] != "*":
                cpe_to_packages.setdefault(cpe, []).append(package)
    return cpe_to_packages


def _persist_nvd_records(
    nvd_vulns: List[dict],
    matched: List[Package],
    scan: Scan,
    variant_uuid: uuid_module.UUID,
    observation_pairs: Set[Tuple[uuid_module.UUID, uuid_module.UUID]],
    assessed_findings: Set[Tuple[uuid_module.UUID, uuid_module.UUID]],
) -> Set[str]:
    from .nvd_db import NVD_DB
    from .nvd_persist import persist_nvd_cve

    recorded: Set[str] = set()
    for nvd_vuln in nvd_vulns:
        cve = nvd_vuln.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        recorded.add(cve_id)
        persist_nvd_cve(cve_id, NVD_DB.extract_cve_details(cve))
        for package in matched:
            finding = Finding.get_or_create(package.id, cve_id)
            create_observation_and_assessment(
                finding, scan, variant_uuid, "nvd",
                observation_pairs, assessed_findings,
            )
    return recorded


def _run_nvd_scan_api(ctx: JobContext, packages: List[Package]) -> None:
    from .nvd_db import NVD_DB

    variant_uuid = _variant_uuid(ctx)
    nvd = NVD_DB(nvd_api_key=os.getenv("NVD_API_KEY"))
    cpe_to_packages = _collect_cpes(packages)

    if not cpe_to_packages:
        raise RuntimeError("No packages with valid CPE identifiers")

    total = len(cpe_to_packages)
    ctx.log(f"Found {len(packages)} packages with {total} unique CPEs to query")

    scan = Scan.create(
        description=EMPTY_DESCRIPTION, variant_id=variant_uuid,
        scan_type="tool", scan_source="nvd",
    )
    cves_found: Set[str] = set()
    observation_pairs: Set[Tuple[uuid_module.UUID, uuid_module.UUID]] = set()
    assessed_findings: Set[Tuple[uuid_module.UUID, uuid_module.UUID]] = set()

    for index, (cpe_name, matched) in enumerate(cpe_to_packages.items(), 1):
        ctx.check_cancelled()
        ctx.report(index - 1, total, f"{index}/{total} CPEs")
        ctx.log(f"[{index}/{total}] Querying {cpe_name}…")
        nvd_vulns = _query_cpe(ctx, nvd, cpe_name)
        ctx.report(index, total, f"{index}/{total} CPEs")
        if nvd_vulns is None:
            continue

        cve_ids = [
            vuln.get("cve", {}).get("id", "")
            for vuln in nvd_vulns
            if vuln.get("cve", {}).get("id")
        ]
        if cve_ids:
            ctx.log(
                f"[{index}/{total}] {cpe_name} → {len(cve_ids)} CVE(s): "
                f"{_preview(cve_ids)}"
            )
        else:
            ctx.log(f"[{index}/{total}] {cpe_name} → no CVEs")

        cves_found |= _persist_nvd_records(
            nvd_vulns, matched, scan, variant_uuid,
            observation_pairs, assessed_findings,
        )

    db.session.commit()
    ctx.report(total, total, f"Found {len(cves_found)} CVEs across {total} CPEs")
    ctx.log(
        f"✓ Scan complete — found {len(cves_found)} unique CVEs across {total} CPEs"
    )


def run_nvd_scan(ctx: JobContext) -> None:
    """Match package CPEs against NVD, locally or through the REST API."""
    from .scc_engine import serialized_engine_operation

    @serialized_engine_operation
    def _scan() -> None:
        try:
            ctx.log(RESOLVING_PACKAGES)
            packages = list(_active_packages(ctx))
            if ctx.options.get("mode") == "api":
                _run_nvd_scan_api(ctx, packages)
            else:
                _run_nvd_scan_local(ctx, packages)
        except Exception:
            db.session.rollback()
            raise

    _scan()


# ---------------------------------------------------------------------------
# OSV
# ---------------------------------------------------------------------------

def _collect_purls(
    packages: List[Package],
) -> Tuple[Dict[str, List[Package]], Set[uuid_module.UUID]]:
    """Index packages by PURL.

    A package may carry several PURLs (generic plus ecosystem-specific); all
    of them are queried so ecosystem-only advisories are not missed.
    """
    purl_to_packages: Dict[str, List[Package]] = {}
    packages_with_purls: Set[uuid_module.UUID] = set()
    for package in packages:
        for purl in (package.purl or []):
            purl_str = str(purl).strip()
            if purl_str.startswith("pkg:"):
                purl_to_packages.setdefault(purl_str, []).append(package)
                packages_with_purls.add(package.id)
    return purl_to_packages, packages_with_purls


def _persist_osv_vulnerability(
    osv_vuln: dict,
    matched: List[Package],
    scan: Scan,
    variant_uuid: uuid_module.UUID,
    observation_pairs: Set[Tuple[uuid_module.UUID, uuid_module.UUID]],
    assessed_findings: Set[Tuple[uuid_module.UUID, uuid_module.UUID]],
) -> str | None:
    """Record one OSV advisory and its CVE aliases against every matched package."""
    from ..models.vulnerability import Vulnerability as VulnModel

    vuln_id = osv_vuln.get("id", "")
    if not vuln_id:
        return None

    aliases = [
        alias for alias in osv_vuln.get("aliases", []) if alias.startswith("CVE-")
    ]
    description = osv_vuln.get("summary") or osv_vuln.get("details")
    links = [
        ref.get("url") for ref in osv_vuln.get("references", []) if ref.get("url")
    ] or None

    for identifier in [vuln_id] + aliases:
        existing = db.session.get(VulnModel, identifier.upper())
        if existing is None:
            existing = VulnModel.create_record(
                id=identifier, description=description, links=links
            )
            existing.add_found_by("osv")
        else:
            existing.add_found_by("osv")
            if not existing.description and description:
                existing.update_record(description=description, commit=False)

        for package in matched:
            finding = Finding.get_or_create(package.id, identifier)
            create_observation_and_assessment(
                finding, scan, variant_uuid, "osv",
                observation_pairs, assessed_findings,
            )
    return vuln_id


def run_osv_scan(ctx: JobContext) -> None:
    """Query OSV.dev for every PURL carried by the variant's packages."""
    from .osv_client import OSVClient

    variant_uuid = _variant_uuid(ctx)
    try:
        osv = OSVClient()

        ctx.log(RESOLVING_PACKAGES)
        packages = list(_active_packages(ctx))
        purl_to_packages, packages_with_purls = _collect_purls(packages)

        if not purl_to_packages:
            raise RuntimeError("No packages with valid PURL identifiers")

        total = len(purl_to_packages)
        ctx.log(
            f"Found {len(packages)} packages, {len(packages_with_purls)} with "
            f"PURL identifiers ({total} unique PURLs to query)"
        )

        scan = Scan.create(
            description=EMPTY_DESCRIPTION, variant_id=variant_uuid,
            scan_type="tool", scan_source="osv",
        )
        vulns_found: Set[str] = set()
        observation_pairs: Set[Tuple[uuid_module.UUID, uuid_module.UUID]] = set()
        assessed_findings: Set[Tuple[uuid_module.UUID, uuid_module.UUID]] = set()

        for index, (purl_str, matched) in enumerate(purl_to_packages.items(), 1):
            ctx.check_cancelled()
            ctx.report(index - 1, total, f"{index}/{total} PURLs")
            ctx.log(f"[{index}/{total}] Querying {purl_str}…")
            try:
                osv_vulns = osv.query_by_purl(purl_str)
            except Exception as error:
                ctx.log(f"[{index}/{total}] ERROR {purl_str}: {str(error)[:200]}")
                ctx.report(index, total, f"{index}/{total} PURLs")
                continue

            vuln_ids = [vuln.get("id", "") for vuln in osv_vulns if vuln.get("id")]
            if vuln_ids:
                ctx.log(
                    f"[{index}/{total}] {purl_str} → {len(vuln_ids)} vuln(s): "
                    f"{_preview(vuln_ids)}"
                )
            else:
                ctx.log(f"[{index}/{total}] {purl_str} → no vulnerabilities")
            ctx.report(index, total, f"{index}/{total} PURLs")

            for osv_vuln in osv_vulns:
                recorded = _persist_osv_vulnerability(
                    osv_vuln, matched, scan, variant_uuid,
                    observation_pairs, assessed_findings,
                )
                if recorded:
                    vulns_found.add(recorded)

        db.session.commit()
        ctx.report(
            total, total,
            f"Found {len(vulns_found)} vulnerabilities across {total} PURLs",
        )
        ctx.log(
            f"✓ Scan complete — found {len(vulns_found)} unique vulnerabilities "
            f"across {total} PURLs ({len(packages_with_purls)} packages)"
        )
    except Exception:
        db.session.rollback()
        raise


# ---------------------------------------------------------------------------
# sbom-cve-check
# ---------------------------------------------------------------------------

class _SccLogForwarder(logging.Handler):
    """Pipes sbom_cve_check library logs into the operation's log stream."""

    def __init__(self, ctx: JobContext) -> None:
        super().__init__(logging.INFO)
        self._ctx = ctx

    def emit(self, record: logging.LogRecord) -> None:
        self._ctx.log(self.format(record))


def _load_scc_engine(ctx: JobContext):
    """Load the shared advisory index, forwarding library logs to the client."""
    from .scc_engine import get_engine

    forwarder = _SccLogForwarder(ctx)
    forwarder.setFormatter(logging.Formatter("%(message)s"))
    scc_logger = logging.getLogger("sbom_cve_check")
    scc_logger.addHandler(forwarder)
    previous_level = scc_logger.level
    scc_logger.setLevel(logging.INFO)
    ctx.log("Loading CVE databases — this might take several minutes on first run…")
    try:
        return get_engine(progress=_engine_progress(ctx))
    except Exception as error:
        raise RuntimeError(f"Failed to load CVE databases: {str(error)[:300]}")
    finally:
        scc_logger.removeHandler(forwarder)
        scc_logger.setLevel(previous_level)


def _scan_package_with_engine(
    ctx: JobContext, engine, writer, package: Package, index: int, total: int
) -> None:
    label = f"{package.name}@{package.version}" if package.name else str(package.id)
    ctx.report(index - 1, total, f"{index}/{total} packages")

    persisted: List[str] = []
    seen_keys: Set[Tuple[uuid_module.UUID, str]] = set()
    try:
        for computed, status in engine.applicable_vulns(package):
            cve_id = writer.add(package, computed, status, seen_keys)
            if cve_id is not None:
                persisted.append(cve_id)
    except Exception as error:
        ctx.log(f"[{index}/{total}] ERROR {label}: {str(error)[:200]}")
        ctx.report(index, total, f"{index}/{total} packages")
        return

    if persisted:
        ctx.log(
            f"[{index}/{total}] {label} → {len(persisted)} vuln(s): "
            f"{_preview(persisted)}"
        )
    else:
        ctx.log(f"[{index}/{total}] {label} → no vulnerabilities")
    ctx.report(index, total, f"{index}/{total} packages")


def run_scc_scan(ctx: JobContext) -> None:
    """Match packages against the local NVD-FKIE and CVEList databases."""
    from ..bin.cmd_vuln_scan import _SccBulkWriter
    from .scc_engine import serialized_engine_operation

    variant_uuid = _variant_uuid(ctx)

    @serialized_engine_operation
    def _scan() -> None:
        try:
            ctx.log(RESOLVING_PACKAGES)
            packages = list(_active_packages(ctx))
            total = len(packages)
            ctx.report(0, total, f"0/{total} packages")
            ctx.log(f"Resolved {total} active packages")

            engine = _load_scc_engine(ctx)
            ctx.log("Index ready — scanning packages")

            scan = Scan.create(
                description=EMPTY_DESCRIPTION, variant_id=variant_uuid,
                scan_type="tool", scan_source="scc",
            )
            writer = _SccBulkWriter(scan.id, variant_uuid, packages)

            for index, package in enumerate(packages, 1):
                ctx.check_cancelled()
                _scan_package_with_engine(ctx, engine, writer, package, index, total)
                # Bulk-insert in chunks to bound transaction size.
                writer.maybe_flush()

            writer.flush()
            found = len(writer.cves_found)
            ctx.report(
                total, total,
                f"Found {found} vulnerabilities across {total} packages",
            )
            ctx.log(
                f"✓ Scan complete — found {found} unique vulnerabilities "
                f"across {total} packages"
            )
        except Exception:
            db.session.rollback()
            raise

    _scan()


SCAN_JOBS = {
    "grype": run_grype_scan,
    "nvd": run_nvd_scan,
    "osv": run_osv_scan,
    "scc": run_scc_scan,
}

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Vulnerability scanning commands: ``flask nvd-scan`` and ``flask osv-scan``."""

from ..controllers.projects import ProjectController
from ..controllers.variants import VariantController
from ..models.scan import Scan as ScanModel
from ..models.finding import Finding as FindingModel
from ..models.observation import Observation
from ..extensions import db as _db
from .cmd_process import DEFAULT_VARIANT_NAME
import click
import os
from flask.cli import with_appcontext


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
    from ..controllers.nvd_db import NVD_DB
    from ..models.vulnerability import Vulnerability as VulnModel
    from ..models.metrics import Metrics as MetricsModel
    from ..models.cvss import CVSS
    from ..models.assessment import Assessment
    from ..models.package import Package

    variant_name = variant or DEFAULT_VARIANT_NAME
    project_obj = ProjectController.get_or_create(project)
    variant_obj = VariantController.get_or_create(variant_name, project_obj.id)
    variant_uuid = variant_obj.id

    nvd_api_key = os.getenv("NVD_API_KEY")
    nvd = NVD_DB(nvd_api_key=nvd_api_key)

    # 1. Get active packages for this variant
    click.echo("Resolving active packages…")
    latest_rows = _db.session.execute(
        _db.select(ScanModel.id, ScanModel.scan_type)
        .where(ScanModel.variant_id == variant_uuid)
        .order_by(ScanModel.timestamp.desc())
    ).all()
    latest_ids: list = []
    seen_types: set = set()
    for sid, stype in latest_rows:
        st = stype or "sbom"
        if st not in seen_types:
            seen_types.add(st)
            latest_ids.append(sid)
        if len(seen_types) >= 2:
            break

    if not latest_ids:
        raise click.ClickException("No scans found for variant")

    from ..routes._scan_queries import _packages_by_scan_ids
    pkg_sets = _packages_by_scan_ids(latest_ids)
    all_pkg_ids: set = set()
    for s in pkg_sets.values():
        all_pkg_ids |= s

    if not all_pkg_ids:
        raise click.ClickException("No packages found for variant")

    packages = _db.session.execute(
        _db.select(Package).where(Package.id.in_(all_pkg_ids))
    ).scalars().all()

    # 2. Collect CPE names from packages
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

    # 3. Create a tool scan
    scan = ScanModel.create(
        description="empty description",
        variant_id=variant_uuid,
        scan_type="tool",
        scan_source="nvd",
    )
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
        if cpe_cves:
            ids_str = ', '.join(cpe_cves[:10])
            ellip = '…' if len(cpe_cves) > 10 else ''
            click.echo(
                f"[{idx}/{total_cpes}] {cpe_name} → "
                f"{len(cpe_cves)} CVE(s): {ids_str}{ellip}"
            )
        else:
            click.echo(f"[{idx}/{total_cpes}] {cpe_name} → no CVEs")

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
                finding = FindingModel.get_or_create(pkg.id, cve_id)
                pair = (finding.id, scan.id)
                if pair not in observation_pairs:
                    observation_pairs.add(pair)
                    Observation.create(
                        finding_id=finding.id, scan_id=scan.id, commit=False,
                    )
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
                            origin="nvd",
                            commit=False,
                        )

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
    from ..controllers.osv_client import OSVClient
    from ..models.vulnerability import Vulnerability as VulnModel
    from ..models.assessment import Assessment
    from ..models.package import Package

    variant_name = variant or DEFAULT_VARIANT_NAME
    project_obj = ProjectController.get_or_create(project)
    variant_obj = VariantController.get_or_create(variant_name, project_obj.id)
    variant_uuid = variant_obj.id

    osv = OSVClient()

    # 1. Get active packages for this variant
    click.echo("Resolving active packages…")
    latest_rows = _db.session.execute(
        _db.select(ScanModel.id, ScanModel.scan_type)
        .where(ScanModel.variant_id == variant_uuid)
        .order_by(ScanModel.timestamp.desc())
    ).all()
    latest_ids: list = []
    seen_types: set = set()
    for sid, stype in latest_rows:
        st = stype or "sbom"
        if st not in seen_types:
            seen_types.add(st)
            latest_ids.append(sid)
        if len(seen_types) >= 2:
            break

    if not latest_ids:
        raise click.ClickException("No scans found for variant")

    from ..routes._scan_queries import _packages_by_scan_ids
    pkg_sets = _packages_by_scan_ids(latest_ids)
    all_pkg_ids: set = set()
    for s in pkg_sets.values():
        all_pkg_ids |= s

    if not all_pkg_ids:
        raise click.ClickException("No packages found for variant")

    packages = _db.session.execute(
        _db.select(Package).where(Package.id.in_(all_pkg_ids))
    ).scalars().all()

    # 2. Collect packages with PURL identifiers
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

    # 3. Create a tool scan
    scan = ScanModel.create(
        description="empty description",
        variant_id=variant_uuid,
        scan_type="tool",
        scan_source="osv",
    )
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
        if vuln_ids:
            ids_str = ', '.join(vuln_ids[:10])
            ellip = '…' if len(vuln_ids) > 10 else ''
            click.echo(
                f"[{idx}/{total_pkgs}] {pkg_label} → "
                f"{len(vuln_ids)} vuln(s): {ids_str}{ellip}"
            )
        else:
            click.echo(f"[{idx}/{total_pkgs}] {pkg_label} → no vulnerabilities")

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

                finding = FindingModel.get_or_create(pkg.id, vid)
                pair = (finding.id, scan.id)
                if pair not in observation_pairs:
                    observation_pairs.add(pair)
                    Observation.create(
                        finding_id=finding.id, scan_id=scan.id, commit=False,
                    )
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
                            origin="osv",
                            commit=False,
                        )

    _db.session.commit()
    click.echo(
        f"✓ Scan complete — found {len(vulns_found)} unique vulnerabilities "
        f"across {total_pkgs} packages"
    )

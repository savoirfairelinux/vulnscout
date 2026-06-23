# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Scan trigger routes — Grype, NVD CPE, and OSV PURL scans.

Each trigger spawns background work in a thread and exposes a ``/status``
endpoint for polling progress.
"""

import os
import threading
import uuid

from flask import Flask, jsonify
from flask.typing import ResponseReturnValue

from ..models.scan import Scan
from ..models.finding import Finding
from ..models.package import Package
from ..models.project import Project
from ..models.sbom_package import SBOMPackage
from ..models.sbom_document import SBOMDocument
from ..extensions import db
from ..views.grype_vulns import GrypeVulns
from ..helpers.scan_filters import is_kernel_package_name

from ._scan_helpers import (
    validate_trigger,
    scan_status_response,
    init_progress,
    set_error,
    resolve_active_packages,
    create_observation_and_assessment,
)


def init_app(app: Flask) -> None:

    # ------------------------------------------------------------------
    # Grype Scan
    # ------------------------------------------------------------------

    _grype_scans_in_progress: dict = {}

    @app.route('/api/variants/<variant_id>/grype-scan', methods=['POST'])
    def trigger_grype_scan(variant_id: str) -> ResponseReturnValue:
        """Trigger a Grype vulnerability scan for the given variant.

        Exports the variant's packages as CycloneDX, runs ``grype`` on the
        export, and merges the results back into the DB as a tool scan.
        """
        import subprocess
        import tempfile
        import shutil

        variant_uuid, variant, err = validate_trigger(
            variant_id, _grype_scans_in_progress, "Grype scan")
        if err is not None:
            return err
        if variant_uuid is None or variant is None:
            return jsonify({"error": "Internal error"}), 500

        # Check that grype is available
        if shutil.which("grype") is None:
            return jsonify({"error": "grype binary not found on this system"}), 503

        project = db.session.get(Project, variant.project_id)
        project_name = project.name if project else "unknown"
        variant_name = variant.name
        vid_str = str(variant_uuid)

        # Collect the variant's SBOM package (name, version) set so we can
        # filter the grype output to only this variant's packages.  We query
        # here (in request context) because the background thread has no DB
        # session.
        sbom_pkg_set: set = set()
        sbom_scan_id = db.session.execute(
            db.select(Scan.id)
            .where(Scan.variant_id == variant_uuid)
            .where(db.or_(Scan.scan_type == "sbom", Scan.scan_type.is_(None)))
            .order_by(Scan.timestamp.desc())
            .limit(1)
        ).scalar()
        if sbom_scan_id is not None:
            pkg_rows = db.session.execute(
                db.select(Package.name, Package.version)
                .join(SBOMPackage, SBOMPackage.package_id == Package.id)
                .join(SBOMDocument, SBOMPackage.sbom_document_id == SBOMDocument.id)
                .where(SBOMDocument.scan_id == sbom_scan_id)
            ).all()
            sbom_pkg_set = {(r[0], r[1]) for r in pkg_rows}

        init_progress(_grype_scans_in_progress, vid_str, total=4)

        def _run_grype_scan() -> None:
            try:
                base_dir = os.environ.get(
                    "BASE_DIR",
                    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                )
                grype_tmp = tempfile.mkdtemp(prefix="vulnscout_grype_")
                try:
                    # 1. Export this variant's DB packages as CycloneDX.
                    #    The export is scoped to the project/variant so it only
                    #    emits this variant's packages — Grype never sees the
                    #    other projects'/variants' components.
                    _grype_scans_in_progress[vid_str]["progress"] = "1/4 Exporting CycloneDX"
                    _grype_scans_in_progress[vid_str]["logs"].append(
                        "[1/4] Exporting variant packages as CycloneDX…"
                    )
                    subprocess.run(
                        ["flask", "--app", "src.bin.webapp", "export",
                         "--format", "cdx16", "--output-dir", grype_tmp,
                         "--variant-id", vid_str],
                        cwd=base_dir, check=True, capture_output=True, text=True,
                        timeout=120,
                    )
                    _grype_scans_in_progress[vid_str]["done_count"] = 1

                    exported_cdx = os.path.join(grype_tmp, "sbom_cyclonedx_v1_6.cdx.json")
                    if not os.path.isfile(exported_cdx):
                        set_error(_grype_scans_in_progress, vid_str,
                                  "CycloneDX export produced no file")
                        return
                    _grype_scans_in_progress[vid_str]["logs"].append(
                        "[1/4] CycloneDX export complete"
                    )

                    # 1.5 De-duplicate components that share the same
                    #     name@version before running Grype.  Even when scoped
                    #     to a single variant, the export emits one row per
                    #     package, so a package appears multiple times when it
                    #     differs only by supplier (the supplier-less
                    #     Grype/NOASSERTION base alongside the SBOM-declared
                    #     supplier).  Grype only needs one, and feeding
                    #     duplicates just multiplies its work and produces
                    #     duplicate matches.  Key on the *raw* name@version:
                    #     supplier duplicates carry an identical raw name,
                    #     whereas normalising would over-collapse genuinely
                    #     distinct packages that happen to share a normalised
                    #     name.
                    if sbom_pkg_set:
                        import json as _json
                        with open(exported_cdx, "r") as cf:
                            cdx_data = _json.load(cf)
                        components = cdx_data.get("components", [])
                        orig_components = len(components)
                        kept = []
                        kept_refs = set()
                        seen_nv: set = set()
                        kernel_modules_dropped = 0
                        for comp in components:
                            name = comp.get("name", "")
                            version = comp.get("version", "")
                            # Skip kernel companion packages: they expand to
                            # thousands of entries in SPDX 3 SBOMs and all inherit
                            # the base kernel CPE, so they make Grype crawl with
                            # no useful results.
                            if is_kernel_package_name(name):
                                kernel_modules_dropped += 1
                                continue
                            nv = (name, version)
                            if nv in seen_nv:
                                continue
                            seen_nv.add(nv)
                            kept.append(comp)
                            ref = comp.get("bom-ref")
                            if ref:
                                kept_refs.add(ref)
                        cdx_data["components"] = kept
                        # Prune dependency edges that reference dropped components.
                        if isinstance(cdx_data.get("dependencies"), list):
                            cdx_data["dependencies"] = [
                                dep for dep in cdx_data["dependencies"]
                                if dep.get("ref") in kept_refs
                            ]
                        with open(exported_cdx, "w") as cf:
                            _json.dump(cdx_data, cf)
                        _grype_scans_in_progress[vid_str]["logs"].append(
                            f"[1/4] De-duplicated components: "
                            f"{len(kept)}/{orig_components} kept"
                            + (f" ({kernel_modules_dropped} kernel modules excluded)"
                               if kernel_modules_dropped else "")
                        )

                    # 2. Run grype on the exported SBOM
                    _grype_scans_in_progress[vid_str]["progress"] = "2/4 Running Grype"
                    _grype_scans_in_progress[vid_str]["logs"].append(
                        "[2/4] Running Grype vulnerability scanner…"
                    )
                    grype_out = os.path.join(grype_tmp, "grype_results.grype.json")
                    with open(grype_out, "w") as gf:
                        subprocess.run(
                            ["grype", "--add-cpes-if-none",
                             f"sbom:{exported_cdx}", "-o", "json"],
                            cwd=base_dir, check=True, text=True,
                            stdout=gf, stderr=subprocess.PIPE,
                            timeout=600,
                        )
                    _grype_scans_in_progress[vid_str]["done_count"] = 2

                    if not os.path.isfile(grype_out) or os.path.getsize(grype_out) == 0:
                        set_error(_grype_scans_in_progress, vid_str,
                                  "Grype produced no output")
                        return
                    _grype_scans_in_progress[vid_str]["logs"].append(
                        "[2/4] Grype scan complete"
                    )

                    # 2.5 Defensive filter: keep only grype matches for
                    #     packages present in this variant's SBOM.  The
                    #     CycloneDX input is already scoped to the variant, so
                    #     this is normally a no-op, but it guards against any
                    #     stray artifact grype might synthesise.
                    if sbom_pkg_set:
                        import json as _json
                        with open(grype_out, "r") as gf:
                            grype_data = _json.load(gf)
                        orig_count = len(grype_data.get("matches", []))
                        filtered = []
                        for match in grype_data.get("matches", []):
                            artifact = match.get("artifact", {})
                            name = GrypeVulns._normalize_artifact_name(
                                artifact.get("name", ""),
                                artifact.get("purl"),
                            )
                            version = artifact.get("version", "")
                            if (name, version) in sbom_pkg_set:
                                filtered.append(match)
                        grype_data["matches"] = filtered
                        with open(grype_out, "w") as gf:
                            _json.dump(grype_data, gf)
                        _grype_scans_in_progress[vid_str]["logs"].append(
                            f"[2/4] Filtered: {len(filtered)}/{orig_count}"
                            f" matches kept (variant SBOM packages only)"
                        )

                    # 3. Merge Grype results as a tool scan
                    _grype_scans_in_progress[vid_str]["progress"] = "3/4 Merging results"
                    _grype_scans_in_progress[vid_str]["logs"].append(
                        "[3/4] Merging Grype results into database…"
                    )
                    subprocess.run(
                        ["flask", "--app", "src.bin.webapp", "merge",
                         "--project", project_name, "--variant", variant_name,
                         "--grype", grype_out],
                        cwd=base_dir, check=True, capture_output=True, text=True,
                        timeout=120,
                    )
                    _grype_scans_in_progress[vid_str]["done_count"] = 3
                    _grype_scans_in_progress[vid_str]["logs"].append(
                        "[3/4] Merge complete"
                    )

                    # 4. Process
                    _grype_scans_in_progress[vid_str]["progress"] = "4/4 Processing"
                    _grype_scans_in_progress[vid_str]["logs"].append(
                        "[4/4] Processing scan results…"
                    )
                    subprocess.run(
                        ["flask", "--app", "src.bin.webapp", "process"],
                        cwd=base_dir, check=True, capture_output=True, text=True,
                        timeout=300,
                    )
                    _grype_scans_in_progress[vid_str]["done_count"] = 4

                    done_logs = _grype_scans_in_progress[vid_str].get("logs", [])
                    done_logs.append("✓ Grype scan complete")
                    _grype_scans_in_progress[vid_str] = {
                        "status": "done", "error": None,
                        "progress": "Scan complete",
                        "logs": done_logs, "total": 4, "done_count": 4,
                    }
                finally:
                    shutil.rmtree(grype_tmp, ignore_errors=True)
            except subprocess.TimeoutExpired:
                set_error(_grype_scans_in_progress, vid_str, "Grype scan timed out")
            except subprocess.CalledProcessError as e:
                err_msg = f"Command failed: {e.stderr[:500] if e.stderr else str(e)}"
                set_error(_grype_scans_in_progress, vid_str, err_msg)
            except Exception as e:
                set_error(_grype_scans_in_progress, vid_str, str(e)[:500])

        thread = threading.Thread(
            target=_run_grype_scan,
            name=f"grype-scan-{vid_str}",
            daemon=True,
        )
        thread.start()

        return jsonify({"status": "started", "variant_id": vid_str}), 202

    @app.route('/api/variants/<variant_id>/grype-scan/status')
    def grype_scan_status(variant_id: str) -> ResponseReturnValue:
        """Check the status of a running Grype scan for the given variant."""
        return scan_status_response(variant_id, _grype_scans_in_progress)

    # ------------------------------------------------------------------
    # NVD CPE Scan
    # ------------------------------------------------------------------

    _nvd_scans_in_progress: dict = {}

    @app.route('/api/variants/<variant_id>/nvd-scan', methods=['POST'])
    def trigger_nvd_scan(variant_id: str) -> ResponseReturnValue:
        """Trigger an NVD CPE-based vulnerability scan for the given variant.

        For every active package that has CPE identifiers, query the NVD CVE
        API (``cpeName=…``) and create findings/observations for any CVEs
        returned.  The result is stored as a tool scan.
        """
        variant_uuid, variant, err = validate_trigger(
            variant_id, _nvd_scans_in_progress, "NVD scan")
        if err is not None:
            return err
        if variant_uuid is None:
            return jsonify({"error": "Internal error"}), 500

        vid_str = str(variant_uuid)
        init_progress(_nvd_scans_in_progress, vid_str)

        def _run_nvd_scan() -> None:
            with app.app_context():
                _do_nvd_scan(vid_str, variant_uuid)

        def _do_nvd_scan(vid_str: str, variant_uuid: uuid.UUID) -> None:
            try:
                from ..controllers.nvd_db import NVD_DB
                from ..models.vulnerability import Vulnerability as VulnModel
                from ..models.metrics import Metrics as MetricsModel
                from ..models.cvss import CVSS

                nvd_api_key = os.getenv("NVD_API_KEY")
                nvd = NVD_DB(nvd_api_key=nvd_api_key)

                # 1. Get active packages
                _nvd_scans_in_progress[vid_str]["logs"].append(
                    "Resolving active packages…"
                )
                packages, pkg_err = resolve_active_packages(
                    variant_uuid, _nvd_scans_in_progress, vid_str)
                if pkg_err:
                    return

                # 2. Collect CPE names from packages
                cpe_to_pkgs: dict = {}
                for pkg in packages:
                    for cpe in (pkg.cpe or []):
                        parts = cpe.split(":")
                        if len(parts) >= 6 and parts[4] != "*":
                            cpe_to_pkgs.setdefault(cpe, []).append(pkg)

                if not cpe_to_pkgs:
                    set_error(_nvd_scans_in_progress, vid_str,
                              "No packages with valid CPE identifiers")
                    return

                _nvd_scans_in_progress[vid_str]["logs"].append(
                    f"Found {len(packages)} packages with "
                    f"{len(cpe_to_pkgs)} unique CPEs to query"
                )

                # 3. Create a tool scan
                scan = Scan.create(
                    description="empty description",
                    variant_id=variant_uuid,
                    scan_type="tool",
                    scan_source="nvd",
                )
                total_cpes = len(cpe_to_pkgs)
                _nvd_scans_in_progress[vid_str]["total"] = total_cpes
                cves_found: set = set()
                observation_pairs: set = set()
                assessed_findings: set = set()

                for idx, (cpe_name, pkgs) in enumerate(
                    cpe_to_pkgs.items(), 1
                ):
                    _nvd_scans_in_progress[vid_str]["progress"] = (
                        f"{idx}/{total_cpes} CPEs"
                    )
                    _nvd_scans_in_progress[vid_str]["logs"].append(
                        f"[{idx}/{total_cpes}] Querying {cpe_name}…"
                    )
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
                        log_entry = (
                            f"[{idx}/{total_cpes}] ERROR "
                            f"{cpe_name}: {str(e)[:200]}"
                        )
                        _nvd_scans_in_progress[vid_str]["logs"].append(log_entry)
                        _nvd_scans_in_progress[vid_str]["done_count"] = idx
                        print(f"[NVD Scan] Error querying CPE {cpe_name}: {e}", flush=True)
                        continue

                    cpe_cves = [
                        v.get("cve", {}).get("id", "")
                        for v in nvd_vulns
                        if v.get("cve", {}).get("id")
                    ]
                    if cpe_cves:
                        ids_str = ', '.join(cpe_cves[:10])
                        ellip = '…' if len(cpe_cves) > 10 else ''
                        log_entry = (
                            f"[{idx}/{total_cpes}] {cpe_name} → "
                            f"{len(cpe_cves)} CVE(s): {ids_str}{ellip}"
                        )
                    else:
                        log_entry = (
                            f"[{idx}/{total_cpes}] {cpe_name} → no CVEs"
                        )
                    _nvd_scans_in_progress[vid_str]["logs"].append(log_entry)
                    _nvd_scans_in_progress[vid_str]["done_count"] = idx

                    for nvd_vuln in nvd_vulns:
                        cve = nvd_vuln.get("cve", {})
                        cve_id = cve.get("id", "")
                        if not cve_id:
                            continue

                        cves_found.add(cve_id)
                        details = NVD_DB.extract_cve_details(cve)

                        existing_vuln = db.session.get(VulnModel, cve_id.upper())
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
                            finding = Finding.get_or_create(pkg.id, cve_id)
                            create_observation_and_assessment(
                                finding, scan, variant_uuid, "nvd",
                                observation_pairs, assessed_findings,
                            )

                db.session.commit()

                done_logs = _nvd_scans_in_progress[vid_str].get("logs", [])
                done_logs.append(
                    f"✓ Scan complete — found {len(cves_found)} "
                    f"unique CVEs across {total_cpes} CPEs"
                )
                _nvd_scans_in_progress[vid_str] = {
                    "status": "done",
                    "error": None,
                    "progress": (
                        f"Found {len(cves_found)} CVEs "
                        f"across {total_cpes} CPEs"
                    ),
                    "logs": done_logs,
                    "total": total_cpes,
                    "done_count": total_cpes,
                }

            except Exception as e:
                db.session.rollback()
                set_error(_nvd_scans_in_progress, vid_str, str(e)[:500])

        thread = threading.Thread(
            target=_run_nvd_scan,
            name=f"nvd-scan-{vid_str}",
            daemon=True,
        )
        thread.start()

        return jsonify({"status": "started", "variant_id": vid_str}), 202

    @app.route('/api/variants/<variant_id>/nvd-scan/status')
    def nvd_scan_status(variant_id: str) -> ResponseReturnValue:
        """Check the status of a running NVD scan for the given variant."""
        return scan_status_response(variant_id, _nvd_scans_in_progress)

    # ------------------------------------------------------------------
    # OSV Scan
    # ------------------------------------------------------------------

    _osv_scans_in_progress: dict = {}

    @app.route('/api/variants/<variant_id>/osv-scan', methods=['POST'])
    def trigger_osv_scan(variant_id: str) -> ResponseReturnValue:
        """Trigger an OSV PURL-based vulnerability scan for the given variant.

        For every active package that has PURL identifiers, query the OSV API
        and create findings/observations for any vulnerabilities returned.
        The result is stored as a tool scan.
        """
        variant_uuid, variant, err = validate_trigger(
            variant_id, _osv_scans_in_progress, "OSV scan")
        if err is not None:
            return err
        if variant_uuid is None:
            return jsonify({"error": "Internal error"}), 500

        vid_str = str(variant_uuid)
        init_progress(_osv_scans_in_progress, vid_str)

        def _run_osv_scan() -> None:
            with app.app_context():
                _do_osv_scan(vid_str, variant_uuid)

        def _do_osv_scan(vid_str: str, variant_uuid: uuid.UUID) -> None:
            try:
                from ..controllers.osv_client import OSVClient
                from ..models.vulnerability import Vulnerability as VulnModel

                osv = OSVClient()

                # 1. Get active packages
                _osv_scans_in_progress[vid_str]["logs"].append(
                    "Resolving active packages…"
                )
                packages, pkg_err = resolve_active_packages(
                    variant_uuid, _osv_scans_in_progress, vid_str)
                if pkg_err:
                    return

                # 2. Collect packages with PURL identifiers
                # A package may carry several PURLs (e.g. generic + apk);
                # query ALL of them so we don't miss vulnerabilities that
                # are only indexed under a specific ecosystem PURL.
                purl_to_pkgs: dict[str, list] = {}
                pkgs_with_purls: set = set()
                for pkg in packages:
                    for purl in (pkg.purl or []):
                        purl_str = str(purl).strip()
                        if (purl_str
                                and purl_str.startswith("pkg:")):
                            purl_to_pkgs.setdefault(purl_str, []).append(pkg)
                            pkgs_with_purls.add(pkg.id)

                if not purl_to_pkgs:
                    set_error(_osv_scans_in_progress, vid_str,
                              "No packages with valid PURL identifiers")
                    return

                total_purls = len(purl_to_pkgs)
                _osv_scans_in_progress[vid_str]["total"] = total_purls
                _osv_scans_in_progress[vid_str]["logs"].append(
                    f"Found {len(packages)} packages, "
                    f"{len(pkgs_with_purls)} with PURL identifiers "
                    f"({total_purls} unique PURLs to query)"
                )

                # 3. Create a tool scan
                scan = Scan.create(
                    description="empty description",
                    variant_id=variant_uuid,
                    scan_type="tool",
                    scan_source="osv",
                )
                vulns_found: set = set()
                observation_pairs: set = set()
                assessed_findings: set = set()

                for idx, (purl_str, pkgs) in enumerate(
                    purl_to_pkgs.items(), 1
                ):
                    _osv_scans_in_progress[vid_str]["progress"] = (
                        f"{idx}/{total_purls} PURLs"
                    )
                    _osv_scans_in_progress[vid_str]["logs"].append(
                        f"[{idx}/{total_purls}] Querying {purl_str}…"
                    )
                    try:
                        osv_vulns = osv.query_by_purl(purl_str)
                    except Exception as e:
                        log_entry = (
                            f"[{idx}/{total_purls}] ERROR "
                            f"{purl_str}: {str(e)[:200]}"
                        )
                        _osv_scans_in_progress[vid_str]["logs"].append(log_entry)
                        _osv_scans_in_progress[vid_str]["done_count"] = idx
                        print(f"[OSV Scan] Error querying PURL {purl_str}: {e}", flush=True)
                        continue

                    vuln_ids = [
                        v.get("id", "") for v in osv_vulns if v.get("id")
                    ]
                    if vuln_ids:
                        ids_str = ', '.join(vuln_ids[:10])
                        ellip = '…' if len(vuln_ids) > 10 else ''
                        log_entry = (
                            f"[{idx}/{total_purls}] {purl_str} → "
                            f"{len(vuln_ids)} vuln(s): {ids_str}{ellip}"
                        )
                    else:
                        log_entry = (
                            f"[{idx}/{total_purls}] {purl_str}"
                            f" → no vulnerabilities"
                        )
                    _osv_scans_in_progress[vid_str]["logs"].append(log_entry)
                    _osv_scans_in_progress[vid_str]["done_count"] = idx

                    for osv_vuln in osv_vulns:
                        vuln_id = osv_vuln.get("id", "")
                        if not vuln_id:
                            continue

                        all_ids = [vuln_id] + [
                            a for a in osv_vuln.get("aliases", [])
                            if a.startswith("CVE-")
                        ]
                        vulns_found.add(vuln_id)

                        osv_desc = (
                            osv_vuln.get("summary") or osv_vuln.get("details")
                        )

                        for vid in all_ids:
                            existing_vuln = db.session.get(VulnModel, vid.upper())
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
                                        description=osv_desc, commit=False)

                            for pkg in pkgs:
                                finding = Finding.get_or_create(pkg.id, vid)
                                create_observation_and_assessment(
                                    finding, scan, variant_uuid, "osv",
                                    observation_pairs, assessed_findings,
                                )

                db.session.commit()

                done_logs = _osv_scans_in_progress[vid_str].get("logs", [])
                done_logs.append(
                    f"✓ Scan complete — found {len(vulns_found)} "
                    f"unique vulnerabilities across {total_purls} PURLs "
                    f"({len(pkgs_with_purls)} packages)"
                )
                _osv_scans_in_progress[vid_str] = {
                    "status": "done",
                    "error": None,
                    "progress": (
                        f"Found {len(vulns_found)} vulnerabilities "
                        f"across {total_purls} PURLs"
                    ),
                    "logs": done_logs,
                    "total": total_purls,
                    "done_count": total_purls,
                }

            except Exception as e:
                db.session.rollback()
                set_error(_osv_scans_in_progress, vid_str, str(e)[:500])

        thread = threading.Thread(
            target=_run_osv_scan,
            name=f"osv-scan-{vid_str}",
            daemon=True,
        )
        thread.start()

        return jsonify({"status": "started", "variant_id": vid_str}), 202

    @app.route('/api/variants/<variant_id>/osv-scan/status')
    def osv_scan_status(variant_id: str) -> ResponseReturnValue:
        """Check the status of a running OSV scan for the given variant."""
        return scan_status_response(variant_id, _osv_scans_in_progress)

    # ------------------------------------------------------------------
    # sbom-cve-check Scan — local NVD-FKIE + CVEList with VEX
    # ------------------------------------------------------------------

    _sbom_cve_check_scans_in_progress: dict = {}

    @app.route('/api/variants/<variant_id>/sbom-cve-check-scan', methods=['POST'])
    def trigger_sbom_cve_check_scan(variant_id: str) -> ResponseReturnValue:
        """Trigger a local CVE-database scan (NVD-FKIE + CVEList V5) for the given variant.

        Matches every active package against locally-cloned advisory databases,
        applies product-name aliasing and semantic version-range analysis, and
        records each engine VEX verdict.  Works once the databases are cloned.
        """
        variant_uuid, variant, err = validate_trigger(
            variant_id, _sbom_cve_check_scans_in_progress, "sbom-cve-check scan")
        if err is not None:
            return err
        if variant_uuid is None:
            return jsonify({"error": "Internal error"}), 500

        vid_str = str(variant_uuid)
        init_progress(_sbom_cve_check_scans_in_progress, vid_str)

        def _run_sbom_cve_check_scan() -> None:
            with app.app_context():
                _do_sbom_cve_check_scan(vid_str, variant_uuid)

        def _do_sbom_cve_check_scan(vid_str: str, variant_uuid: uuid.UUID) -> None:
            try:
                from ..controllers.scc_engine import get_engine
                from ..bin.cmd_vuln_scan import (
                    _SccBulkWriter,
                )

                # 1. Resolve active packages
                _sbom_cve_check_scans_in_progress[vid_str]["logs"].append(
                    "Resolving active packages…"
                )
                packages, pkg_err = resolve_active_packages(
                    variant_uuid, _sbom_cve_check_scans_in_progress, vid_str)
                if pkg_err:
                    return

                total_pkgs = len(packages)
                _sbom_cve_check_scans_in_progress[vid_str]["total"] = total_pkgs
                _sbom_cve_check_scans_in_progress[vid_str]["logs"].append(
                    f"Resolved {total_pkgs} active packages"
                )

                # 2. Load (or reuse cached) engine index — expensive on first call.
                # Forward sbom_cve_check library log records (git clone/fetch
                # progress, indexing steps) directly into the scan log so the
                # UI shows live progress instead of a frozen spinner.
                import logging

                class _SccLogForwarder(logging.Handler):
                    def __init__(self, logs: list) -> None:
                        super().__init__(logging.INFO)
                        self._logs = logs

                    def emit(self, record: logging.LogRecord) -> None:
                        self._logs.append(self.format(record))

                _forwarder = _SccLogForwarder(
                    _sbom_cve_check_scans_in_progress[vid_str]["logs"]
                )
                _forwarder.setFormatter(logging.Formatter("%(message)s"))
                _scc_logger = logging.getLogger("sbom_cve_check")
                _scc_logger.addHandler(_forwarder)
                _scc_prev_level = _scc_logger.level
                _scc_logger.setLevel(logging.INFO)
                _sbom_cve_check_scans_in_progress[vid_str]["logs"].append(
                    "Loading CVE databases — this might take several minutes on first run…"
                )
                try:
                    engine = get_engine()
                except Exception as e:
                    set_error(_sbom_cve_check_scans_in_progress, vid_str,
                              f"Failed to load CVE databases: {str(e)[:300]}")
                    return
                finally:
                    _scc_logger.removeHandler(_forwarder)
                    _scc_logger.setLevel(_scc_prev_level)
                _sbom_cve_check_scans_in_progress[vid_str]["logs"].append(
                    "Index ready — scanning packages"
                )

                # 3. Create a tool scan
                scan = Scan.create(
                    description="empty description",
                    variant_id=variant_uuid,
                    scan_type="tool",
                    scan_source="scc",
                )
                writer = _SccBulkWriter(scan.id, variant_uuid, packages)

                for idx, pkg in enumerate(packages, 1):
                    pkg_label = (
                        f"{pkg.name}@{pkg.version}" if pkg.name else str(pkg.id)
                    )
                    _sbom_cve_check_scans_in_progress[vid_str]["progress"] = (
                        f"{idx}/{total_pkgs} packages"
                    )

                    persisted_ids: list = []
                    seen_keys: set = set()
                    try:
                        for computed, status in engine.applicable_vulns(pkg):
                            cve_id = writer.add(pkg, computed, status, seen_keys)
                            if cve_id is not None:
                                persisted_ids.append(cve_id)
                    except Exception as e:
                        log_entry = (
                            f"[{idx}/{total_pkgs}] ERROR "
                            f"{pkg_label}: {str(e)[:200]}"
                        )
                        _sbom_cve_check_scans_in_progress[vid_str]["logs"].append(log_entry)
                        _sbom_cve_check_scans_in_progress[vid_str]["done_count"] = idx
                        print(f"[sbom-cve-check Scan] Error scanning {pkg_label}: {e}", flush=True)
                        continue

                    if persisted_ids:
                        ids_str = ', '.join(persisted_ids[:10])
                        ellip = '…' if len(persisted_ids) > 10 else ''
                        log_entry = (
                            f"[{idx}/{total_pkgs}] {pkg_label} → "
                            f"{len(persisted_ids)} vuln(s): {ids_str}{ellip}"
                        )
                    else:
                        log_entry = (
                            f"[{idx}/{total_pkgs}] {pkg_label} → no vulnerabilities"
                        )
                    _sbom_cve_check_scans_in_progress[vid_str]["logs"].append(log_entry)
                    _sbom_cve_check_scans_in_progress[vid_str]["done_count"] = idx

                    # Flush in large bulk-inserted chunks to bound transaction size.
                    writer.maybe_flush()

                writer.flush()
                cves_found = writer.cves_found

                done_logs = _sbom_cve_check_scans_in_progress[vid_str].get("logs", [])
                done_logs.append(
                    f"✓ Scan complete — found {len(cves_found)} "
                    f"unique vulnerabilities across {total_pkgs} packages"
                )
                _sbom_cve_check_scans_in_progress[vid_str] = {
                    "status": "done",
                    "error": None,
                    "progress": (
                        f"Found {len(cves_found)} vulnerabilities "
                        f"across {total_pkgs} packages"
                    ),
                    "logs": done_logs,
                    "total": total_pkgs,
                    "done_count": total_pkgs,
                }

            except Exception as e:
                db.session.rollback()
                set_error(_sbom_cve_check_scans_in_progress, vid_str, str(e)[:500])

        thread = threading.Thread(
            target=_run_sbom_cve_check_scan,
            name=f"sbom-cve-check-scan-{vid_str}",
            daemon=True,
        )
        thread.start()

        return jsonify({"status": "started", "variant_id": vid_str}), 202

    @app.route('/api/variants/<variant_id>/sbom-cve-check-scan/status')
    def sbom_cve_check_scan_status(variant_id: str) -> ResponseReturnValue:
        """Check the status of a running sbom-cve-check scan for the given variant."""
        return scan_status_response(variant_id, _sbom_cve_check_scans_in_progress)

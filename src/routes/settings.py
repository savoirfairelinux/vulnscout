# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os
import json
import uuid
import time
import tempfile
import threading
import tarfile
import subprocess
import shutil
from typing import Callable, Protocol, TypeVar, cast, TYPE_CHECKING
import io as _io

from flask import jsonify, request, Flask
from flask.typing import ResponseReturnValue
from sqlalchemy.exc import OperationalError

from ..controllers import (
    ControllersCache,
    ProjectController,
    VariantController,
    ScanController,
    SBOMDocumentController,
)
from ..extensions import db, batch_session
from ..models.scan import Scan as ScanModel
from ..models.project import Project
from ..models.variant import Variant
from ..helpers.verbose import verbose
from ._scan_helpers import parse_uuid_or_400, ErrorResponse

if TYPE_CHECKING:
    from ..models.assessment import Assessment as DBAssessment

T = TypeVar("T")
_C = TypeVar("_C")


class _CrudController(Protocol[_C]):
    @staticmethod
    def get(entity_id: uuid.UUID | str) -> "_C | None":
        ...

    @staticmethod
    def delete(entity: _C) -> None:
        ...


# Tracks in-progress SBOM uploads: upload_id → {status, message, ts}
_upload_status: dict[str, dict] = {}
_UPLOAD_STATUS_TTL = 3600  # seconds – entries older than this are pruned
_REFRESH_SOURCES = {"epss", "nvd", "euvd", "ghsa"}


def _prune_upload_status() -> None:
    """Remove completed/errored entries older than _UPLOAD_STATUS_TTL."""
    now = time.time()
    stale = [
        uid for uid, info in _upload_status.items()
        if info.get("status") in ("done", "error")
        and now - info.get("ts", 0) > _UPLOAD_STATUS_TTL
    ]
    for uid in stale:
        _upload_status.pop(uid, None)


def _retry_on_lock(fn: Callable[[], T], max_retries: int = 5, delay: float = 0.5) -> T:
    """Call *fn* and retry up to *max_retries* times on SQLite 'database is locked'.

    Between retries the session is removed (not just rolled back) so the next
    attempt gets a completely fresh session and connection from the pool.
    """
    for attempt in range(max_retries):
        try:
            return fn()
        except OperationalError as exc:
            if "database is locked" in str(exc) and attempt < max_retries - 1:
                db.session.remove()
                time.sleep(delay * (attempt + 1))
            else:
                raise
    raise RuntimeError("retry loop exhausted without returning")


def _detect_format(filename: str, data: dict) -> str:
    """Guess SBOM format from the filename and parsed JSON content."""
    lower = filename.lower()
    if lower.endswith(".spdx.json"):
        return "spdx"
    if lower.endswith(".cdx.json"):
        return "cdx"
    if "spdxVersion" in data or "spdxId" in data or "SPDXRef" in str(data.get("SPDXID", "")):
        return "spdx"
    if data.get("bomFormat") == "CycloneDX":
        return "cdx"
    ctx = data.get("@context", "")
    if "openvex" in str(ctx):
        return "openvex"
    if "package" in data and "matches" not in data:
        # yocto-vex and yocto cve-check share the same shape; prefer yocto_vex
        # when package-level `cpes` or issue-level `patch-file`/`detail` are
        # present, as those fields are unique to the vex.bbclass output.
        for _pkg in data.get("package", []):
            if _pkg.get("cpes"):
                return "yocto_vex"
            for _issue in _pkg.get("issue", []):
                if "patch-file" in _issue or "detail" in _issue:
                    return "yocto_vex"
        return "yocto_cve_check"
    if "matches" in data:
        return "grype"
    # SPDX 3.0 detection
    if "@context" in data or "spdxDocument" in str(data.get("type", "")):
        return "spdx"
    return "unknown"


def _is_archive(filename: str) -> bool:
    """True when *filename* looks like a tar archive (optionally compressed)."""
    lower = filename.lower()
    return lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.zst"))


def _extract_spdx_archive(archive_path: str, filename: str) -> list[tuple[str, str]]:
    """Extract an SPDX archive (.tar / .tar.gz / .tar.zst) and return the
    contained ``*.spdx.json`` files as a list of ``(tmp_path, member_name)``.

    Used for SPDX2 inputs which are commonly shipped as tar archives.
    """
    lower = filename.lower()
    extract_dir = tempfile.mkdtemp(prefix="vulnscout_archive_")
    tar_path = archive_path
    decompressed: str | None = None
    try:
        if lower.endswith(".tar.zst"):
            # No zstandard python module bundled — use the unzstd CLI.
            decompressed = os.path.join(extract_dir, "archive.tar")
            subprocess.run(
                ["unzstd", "-q", "-f", "-o", decompressed, archive_path],
                check=True,
            )
            tar_path = decompressed

        with tarfile.open(tar_path, "r:*") as tar:
            results: list[tuple[str, str]] = []
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                if not member.name.lower().endswith(".spdx.json"):
                    continue
                src = cast(_io.BufferedReader, tar.extractfile(member))
                base = os.path.basename(member.name)
                fd, out_path = tempfile.mkstemp(suffix=".spdx.json", prefix="vulnscout_upload_")
                with os.fdopen(fd, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                results.append((out_path, base))
            return results
    finally:
        if decompressed and os.path.exists(decompressed):
            try:
                os.unlink(decompressed)
            except OSError:
                pass
        shutil.rmtree(extract_dir, ignore_errors=True)


def _process_sbom_background(
    app: Flask, upload_id: str, file_paths: list[str],
    scan_id: uuid.UUID, variant_id: uuid.UUID, refresh_sources: set[str] | None = None,
) -> None:
    """Run SBOM parsing in a background thread for one or more files."""
    if refresh_sources is None:
        refresh_sources = {"epss"}
    with app.app_context():
        try:
            _upload_status[upload_id] = {"status": "processing", "message": "Parsing SBOM file(s)..."}

            from ..bin.cmd_process import read_inputs, post_treatment, populate_observations

            controllers = ControllersCache()
            vulnCtrl = controllers.vulnerabilities
            assessCtrl = controllers.assessments
            assessCtrl.current_variant_id = variant_id

            with batch_session():
                vulnCtrl.use_savepoints = False
                assessCtrl.use_savepoints = False
                read_inputs(controllers, scan_id=scan_id)
                verbose("settings/upload: Finished reading inputs")

            verbose("settings/upload: DB commit done")

            # Populate observations table
            scan = ScanModel.get_by_id(scan_id) if isinstance(scan_id, uuid.UUID) \
                else ScanModel.get_by_id(uuid.UUID(str(scan_id)))
            populate_observations(scan, vulnCtrl, log_prefix="settings/upload")

            encountered = vulnCtrl._encountered_this_run
            all_vulnerabilities = vulnCtrl.vulnerabilities
            failed_sources: list[str] = []
            try:
                for source in ("epss", "nvd", "euvd", "ghsa"):
                    if source not in refresh_sources:
                        continue
                    prefix = "GHSA-" if source == "ghsa" else "CVE-"
                    vulnCtrl.vulnerabilities = {
                        vuln_id: all_vulnerabilities[vuln_id]
                        for vuln_id in encountered
                        if vuln_id.startswith(prefix) and vuln_id in all_vulnerabilities
                    }
                    if not vulnCtrl.vulnerabilities:
                        continue
                    label = source.upper()
                    _upload_status[upload_id] = {
                        "status": "processing",
                        "message": f"Refreshing {label} data...",
                    }
                    # Each source is isolated so one failure doesn't skip the rest.
                    try:
                        if source == "epss":
                            result = post_treatment(controllers)
                        elif source in {"nvd", "ghsa"}:
                            result = vulnCtrl.fetch_nvd_data()
                        else:
                            result = vulnCtrl.fetch_euvd_data()
                        if result is not None and not result.completed:
                            failed_sources.append(label)
                    except Exception as e:
                        failed_sources.append(label)
                        verbose(f"settings/upload: {label} enrichment failed: {e}")
            finally:
                vulnCtrl.vulnerabilities = all_vulnerabilities

            done_message = "SBOM imported successfully."
            if failed_sources:
                unique_failed = list(dict.fromkeys(failed_sources))
                done_message += f" ({', '.join(unique_failed)} refresh failed; check server logs.)"

            _upload_status[upload_id] = {
                "status": "done",
                "message": done_message,
                "ts": time.time(),
            }

        except Exception as e:
            verbose(f"settings/upload: SBOM import failed: {e}")
            _upload_status[upload_id] = {
                "status": "error",
                "message": "SBOM import failed. Check server logs for details.",
                "ts": time.time(),
            }
        finally:
            # Clean up the temporary files
            for fp in file_paths:
                try:
                    os.unlink(fp)
                except OSError:
                    pass


def init_app(app: Flask) -> None:

    def _validate_name_from_request(entity_label: str) -> tuple[str, None] | tuple[None, ErrorResponse]:
        """Parse and validate the ``name`` field from a JSON request body.

        Returns ``(name, None)`` on success or ``(None, Response)`` on failure.
        """
        data = request.get_json(silent=True)
        if not data or not isinstance(data.get("name"), str):
            return None, (jsonify({"error": "Missing or invalid 'name' field."}), 400)
        name = data["name"].strip()
        if not name:
            return None, (jsonify({"error": f"{entity_label} name must not be empty."}), 400)
        return name, None

    def _delete_entity(
        entity_id: str, controller: "_CrudController[_C]",
        id_label: str, entity_label: str,
    ) -> ResponseReturnValue:
        """Validate, look up and delete an entity by UUID.

        Returns a Flask response tuple.
        """
        _, err = parse_uuid_or_400(entity_id, id_label)
        if err:
            return err

        entity = controller.get(entity_id)
        if entity is None:
            return jsonify({"error": f"{entity_label} not found."}), 404

        def _do_delete() -> None:
            e = controller.get(entity_id)
            if e is not None:
                controller.delete(e)

        _retry_on_lock(_do_delete)
        return jsonify({"message": f"{entity_label} deleted."}), 200

    # ------------------------------------------------------------------
    # Rename project
    # ------------------------------------------------------------------
    @app.route('/api/projects/<project_id>/rename', methods=['PATCH'])
    def rename_project(project_id: str) -> ResponseReturnValue:
        """Rename a project.

        OpenAPI:
        body JsonObject optional JSON object containing the new name.
        response 200 JsonObject Updated project payload.
        response 404 Error Project not found.
        response 409 Error Project name already exists.
        """
        new_name, err = _validate_name_from_request("Project")
        if err:
            return err
        if new_name is None:
            return jsonify({"error": "Internal error"}), 500

        _, err = parse_uuid_or_400(project_id, "project ID")
        if err:
            return err

        project = ProjectController.get(project_id)
        if project is None:
            return jsonify({"error": "Project not found."}), 404

        # Check uniqueness
        existing = ProjectController.get_all()
        for p in existing:
            if p.name == new_name and str(p.id) != project_id:
                return jsonify({"error": f"A project named '{new_name}' already exists."}), 409

        def _do_rename() -> Project:
            p = cast(Project, ProjectController.get(project_id))
            p.update(new_name)
            return p

        project = _retry_on_lock(_do_rename)
        return jsonify(ProjectController.serialize(project))

    # ------------------------------------------------------------------
    # Rename variant
    # ------------------------------------------------------------------
    @app.route('/api/variants/<variant_id>/rename', methods=['PATCH'])
    def rename_variant(variant_id: str) -> ResponseReturnValue:
        """Rename a variant.

        OpenAPI:
        body JsonObject optional JSON object containing the new name.
        response 200 JsonObject Updated variant payload.
        response 404 Error Variant not found.
        response 409 Error Variant name already exists in the project.
        """
        new_name, err = _validate_name_from_request("Variant")
        if err:
            return err
        if new_name is None:
            return jsonify({"error": "Internal error"}), 500

        _, err = parse_uuid_or_400(variant_id, "variant ID")
        if err:
            return err

        variant = VariantController.get(variant_id)
        if variant is None:
            return jsonify({"error": "Variant not found."}), 404

        # Check uniqueness within the same project
        siblings = VariantController.get_by_project(variant.project_id)
        for v in siblings:
            if v.name == new_name and str(v.id) != variant_id:
                return jsonify({"error": f"A variant named '{new_name}' already exists in this project."}), 409

        def _do_rename() -> Variant:
            v = cast(Variant, VariantController.get(variant_id))
            VariantController.update(v, new_name)
            return v

        variant = _retry_on_lock(_do_rename)
        return jsonify(VariantController.serialize(variant))

    # ------------------------------------------------------------------
    # Create project
    # ------------------------------------------------------------------
    @app.route('/api/projects', methods=['POST'])
    def create_project() -> ResponseReturnValue:
        """Create a new project.

        OpenAPI:
        body JsonObject optional JSON object containing the project name.
        response 201 JsonObject Created project payload.
        response 409 Error Project name already exists.
        """
        new_name, err = _validate_name_from_request("Project")
        if err:
            return err
        if new_name is None:
            return jsonify({"error": "Internal error"}), 500

        # Check uniqueness
        existing = ProjectController.get_all()
        for p in existing:
            if p.name == new_name:
                return jsonify({"error": f"A project named '{new_name}' already exists."}), 409

        project = _retry_on_lock(lambda: ProjectController.create(new_name))
        return jsonify(ProjectController.serialize(project)), 201

    # ------------------------------------------------------------------
    # Create variant
    # ------------------------------------------------------------------
    @app.route('/api/projects/<project_id>/variants', methods=['POST'])
    def create_variant(project_id: str) -> ResponseReturnValue:
        """Create a new variant inside a project.

        OpenAPI:
        body JsonObject optional JSON object containing the variant name.
        response 201 JsonObject Created variant payload.
        response 404 Error Project not found.
        response 409 Error Variant name already exists in the project.
        """
        _, err = parse_uuid_or_400(project_id, "project ID")
        if err:
            return err

        new_name, err = _validate_name_from_request("Variant")
        if err:
            return err
        if new_name is None:
            return jsonify({"error": "Internal error"}), 500

        project = ProjectController.get(project_id)
        if project is None:
            return jsonify({"error": "Project not found."}), 404

        # Check uniqueness within the same project
        siblings = VariantController.get_by_project(project_id)
        for v in siblings:
            if v.name == new_name:
                return jsonify({"error": f"A variant named '{new_name}' already exists in this project."}), 409

        variant = _retry_on_lock(lambda: VariantController.create(new_name, project_id))
        return jsonify(VariantController.serialize(variant)), 201

    # ------------------------------------------------------------------
    # Copy custom assessments between two variants
    # ------------------------------------------------------------------
    #
    # match_mode values:
    #   "exact"               – same package name AND version (default)
    #   "ignore_minor_version"– same name, leading version components match
    #                           (precision controls how many: 1=major, 2=major+minor)
    #   "ignore_version"      – same name, any version
    #
    # Return shape for "exact":
    #   { source, target, operations: [(assessment, source_finding, target_finding)],
    #     skipped, empty_message, mode }
    #
    # Return shape for alternative modes:
    #   { source, target,
    #     groups: [{ assessment, source_finding,
    #                candidates: [{ target_finding, already_has_custom, selected }] }],
    #     skipped_count, empty_message, mode }
    # ------------------------------------------------------------------

    def _clone_assessment(
        src: "DBAssessment", finding_id: uuid.UUID, variant_id: uuid.UUID,
    ) -> None:
        """Create a copy of *src* Assessment bound to a new finding and variant."""
        from ..models.assessment import Assessment as DBAssessment
        DBAssessment.create(
            status=src.status or "under_investigation",
            finding_id=finding_id,
            variant_id=variant_id,
            source=src.source,
            origin="custom",
            simplified_status=src.simplified_status,
            status_notes=src.status_notes,
            justification=src.justification,
            impact_statement=src.impact_statement,
            workaround=src.workaround,
            responses=list(src.responses) if src.responses else [],
            commit=False,
        )

    def _serialize_assessment_details(assessment: "DBAssessment") -> dict:
        """Return the user-visible fields of an assessment for the preview popup."""
        return {
            "simplified_status": assessment.simplified_status or "",
            "status": assessment.status or "",
            "justification": assessment.justification or None,
            "status_notes": assessment.status_notes or None,
            "impact_statement": assessment.impact_statement or None,
            "workaround": assessment.workaround or None,
            "responses": list(assessment.responses) if assessment.responses else [],
        }

    def _assessment_value_tuple(a: "DBAssessment") -> tuple:
        """Comparable snapshot of the fields a copy carries over."""
        return (
            (a.status or ""),
            (a.simplified_status or ""),
            (a.justification or ""),
            (a.impact_statement or ""),
            (a.workaround or ""),
            (a.status_notes or ""),
            tuple(a.responses or []),
        )

    def _copy_condition_allows(
        existing_customs: list["DBAssessment"],
        src_assessment: "DBAssessment",
        copy_condition: str,
    ) -> bool:
        """Decide whether a copy should be proposed onto a target finding.

        *existing_customs* is the list of custom-origin assessments already on the
        target finding for the target variant. The three conditions:
          - "no_custom":        only when the target has no custom assessment.
          - "different_status": also when the current custom status differs.
          - "different_value":  also when the current custom differs in any field.
        """
        if not existing_customs:
            return True
        if copy_condition == "no_custom":
            return False
        current = max(existing_customs, key=lambda a: a.timestamp)
        if copy_condition == "different_status":
            return (current.simplified_status or "") != (src_assessment.simplified_status or "")
        if copy_condition == "different_value":
            return _assessment_value_tuple(current) != _assessment_value_tuple(src_assessment)
        return False

    def _compute_copy_assessment_operations(
        source_id: str,
        target_id: str,
        match_mode: str = "exact",
        version_precision: int = 1,
        copy_condition: str = "no_custom",
    ) -> tuple[dict, None] | tuple[None, ErrorResponse]:
        from ..models.assessment import Assessment as DBAssessment
        from ..models.finding import Finding
        from ..models.observation import Observation
        from ..helpers.active_scans import (
            active_sbom_scan_ids_for_variant,
            active_scan_ids_for_variant,
            active_package_ids_for_scans,
        )
        from ..helpers.version_match import versions_match

        source_uuid, err = parse_uuid_or_400(source_id, "source_variant_id")
        if err:
            return None, err
        source_uuid = cast(uuid.UUID, source_uuid)
        target_uuid, err = parse_uuid_or_400(target_id, "target_variant_id")
        if err:
            return None, err
        target_uuid = cast(uuid.UUID, target_uuid)

        source = VariantController.get(source_id)
        target = VariantController.get(target_id)
        if source is None or target is None:
            return None, (jsonify({"error": "Variant not found."}), 404)
        if source.project_id != target.project_id:
            return None, (jsonify({"error": "Both variants must belong to the same project."}), 400)

        source_pkg_ids = active_package_ids_for_scans(
            active_sbom_scan_ids_for_variant(source_uuid))
        target_pkg_ids = active_package_ids_for_scans(
            active_sbom_scan_ids_for_variant(target_uuid))

        # Findings actually detected (observed) in the target variant's active
        # scans — i.e. the target's pool of vulnerabilities. A copy must only be
        # proposed onto a finding that is present in this pool; otherwise we
        # would attach an assessment to a vulnerability the target variant is
        # not affected by.
        target_active_scan_ids = active_scan_ids_for_variant(target_uuid)
        if target_active_scan_ids:
            target_observed_finding_ids: set = set(db.session.execute(
                db.select(Observation.finding_id)
                .where(Observation.scan_id.in_(target_active_scan_ids))
                .distinct()
            ).scalars().all())
        else:
            target_observed_finding_ids = set()

        source_assessments = DBAssessment.get_by_origin([source_uuid])

        # ---- exact mode: original flat-operations behavior ----
        if match_mode == "exact":
            common_pkg_ids = source_pkg_ids & target_pkg_ids
            if not common_pkg_ids:
                return {
                    "source": source, "target": target,
                    "operations": [], "skipped": 0,
                    "empty_message": "No packages in common between the two variants.",
                    "mode": "exact",
                }, None

            operations = []
            skipped = 0
            processed_target_finding_ids: set = set()

            for assessment in source_assessments:
                source_finding = assessment.finding
                if source_finding is None:
                    continue
                if source_finding.package_id not in common_pkg_ids:
                    continue
                # Exact mode: same package_id → same Finding row shared across variants
                target_finding = source_finding
                if source_uuid == target_uuid:
                    continue
                # Only propose the copy if this vulnerability is actually part of
                # the target variant's pool (observed in its active scans).
                if target_finding.id not in target_observed_finding_ids:
                    continue
                if target_finding.id in processed_target_finding_ids:
                    continue
                processed_target_finding_ids.add(target_finding.id)

                existing = DBAssessment.get_by_finding_and_variant(target_finding.id, target_uuid)
                existing_customs = [e for e in existing if e.origin == "custom"]
                already_has_custom = bool(existing_customs)
                selected = _copy_condition_allows(existing_customs, assessment, copy_condition)
                if not selected:
                    skipped += 1

                operations.append((assessment, source_finding, target_finding, already_has_custom, selected))

            return {
                "source": source, "target": target,
                "operations": operations, "skipped": skipped,
                "empty_message": None, "mode": "exact",
            }, None

        # ---- alternative modes: build grouped candidates ----
        source_vuln_ids: set[str] = {
            a.finding.vulnerability_id
            for a in source_assessments
            if a.finding is not None and a.finding.package_id in source_pkg_ids
        }

        if source_vuln_ids:
            target_findings_all: list[Finding] = list(db.session.execute(
                db.select(Finding).where(
                    Finding.package_id.in_(target_pkg_ids),
                    Finding.vulnerability_id.in_(source_vuln_ids),
                )
            ).scalars().all())
            # Restrict to findings present in the target variant's pool (observed
            # in its active scans) so we never propose copying an assessment onto
            # a vulnerability the target is not affected by.
            target_findings_all = [
                f for f in target_findings_all
                if f.id in target_observed_finding_ids
            ]
        else:
            target_findings_all = []

        target_findings_by_vuln: dict[str, list[Finding]] = {}
        for f in target_findings_all:
            target_findings_by_vuln.setdefault(f.vulnerability_id, []).append(f)

        if not target_findings_by_vuln:
            return {
                "source": source, "target": target,
                "groups": [], "skipped_count": 0,
                "empty_message": "No vulnerabilities in common between the two variants.",
                "mode": match_mode,
            }, None

        # Batch-load existing custom assessments for the target variant once
        target_custom_assessments = DBAssessment.get_by_origin([target_uuid])
        target_customs_by_finding: dict = {}
        for a in target_custom_assessments:
            if a.finding_id is not None:
                target_customs_by_finding.setdefault(a.finding_id, []).append(a)

        groups = []
        skipped_count = 0

        for assessment in source_assessments:
            source_finding = assessment.finding
            if source_finding is None:
                continue
            if source_finding.package_id not in source_pkg_ids:
                continue

            vuln_id = source_finding.vulnerability_id
            potential_targets = target_findings_by_vuln.get(vuln_id, [])
            if not potential_targets:
                continue

            source_pkg = source_finding.package
            candidates = []

            for tf in potential_targets:
                if source_uuid == target_uuid and tf.id == source_finding.id:
                    continue
                if source_pkg is None or tf.package is None:
                    continue
                if source_pkg.name != tf.package.name:
                    continue
                if match_mode == "ignore_minor_version":
                    if not versions_match(
                        source_pkg.version, tf.package.version, version_precision,
                    ):
                        continue

                existing_customs = target_customs_by_finding.get(tf.id, [])
                already_has_custom = bool(existing_customs)
                selected = _copy_condition_allows(existing_customs, assessment, copy_condition)
                if not selected:
                    skipped_count += 1

                candidates.append({
                    "target_finding": tf,
                    "already_has_custom": already_has_custom,
                    "selected": selected,
                })

            if not candidates:
                continue

            groups.append({
                "assessment": assessment,
                "source_finding": source_finding,
                "candidates": candidates,
            })

        return {
            "source": source, "target": target,
            "groups": groups, "skipped_count": skipped_count,
            "empty_message": None, "mode": match_mode,
        }, None

    def _resolve_match_mode(payload: dict) -> tuple[str, int] | tuple[None, ErrorResponse]:
        """Extract and validate match_mode and version_precision from a request payload.

        Returns (match_mode, version_precision) on success, or (None, error_response)
        when version_precision cannot be parsed as an integer.
        """
        match_mode = payload.get("match_mode", "exact")
        raw_precision = payload.get("version_precision", 1)
        try:
            version_precision = int(raw_precision)
        except (TypeError, ValueError):
            return None, (jsonify({"error": "version_precision must be an integer."}), 400)
        if version_precision < 1:
            version_precision = 1
        return match_mode, version_precision

    def _resolve_copy_condition(payload: dict) -> tuple[str, None] | tuple[None, ErrorResponse]:
        """Extract and validate the copy_condition from a request payload."""
        copy_condition = payload.get("copy_condition", "no_custom")
        if copy_condition not in ("no_custom", "different_status", "different_value"):
            return None, (jsonify({"error": "Invalid copy_condition."}), 400)
        return copy_condition, None

    @app.route('/api/variants/copy-assessments/preview', methods=['POST'])
    def preview_copy_variant_assessments() -> ResponseReturnValue:
        """Preview assessment copy operations between two variants.

        OpenAPI:
        body JsonObject optional Preview payload describing source, target, and copy mode.
        response 200 JsonObject Assessment copy preview.
        response 400 Error Invalid preview payload.
        response 404 Error Variant not found.
        """
        payload = request.get_json(silent=True) or {}
        source_id = payload.get("source_variant_id")
        target_id = payload.get("target_variant_id")
        if not isinstance(source_id, str) or not isinstance(target_id, str):
            return jsonify({"error": "source_variant_id and target_variant_id are required strings."}), 400

        resolved = _resolve_match_mode(payload)
        if resolved[0] is None:
            return resolved[1]  # type: ignore[return-value]
        match_mode, version_precision = resolved  # type: ignore[misc]
        if match_mode not in ("exact", "ignore_minor_version", "ignore_version"):
            return jsonify({"error": "Invalid match_mode."}), 400

        copy_condition, cond_err = _resolve_copy_condition(payload)
        if cond_err:
            return cond_err
        copy_condition = cast(str, copy_condition)

        result, err = _compute_copy_assessment_operations(
            source_id, target_id, match_mode, version_precision, copy_condition,
        )
        if err:
            return err
        assert result is not None

        mode = result["mode"]

        if mode == "exact":
            operations = result["operations"]
            preview_rows = []
            for assessment, source_finding, target_finding, already_has_custom, selected in operations:
                preview_rows.append({
                    "source_assessment_id": str(assessment.id),
                    "source_finding_id": str(source_finding.id),
                    "target_finding_id": str(target_finding.id),
                    "vulnerability_id": source_finding.vulnerability_id,
                    "source_package": source_finding.package.string_id if source_finding.package else "",
                    "target_package": target_finding.package.string_id if target_finding.package else "",
                    "already_has_custom": already_has_custom,
                    "selected": selected,
                    "assessment_details": _serialize_assessment_details(assessment),
                })

            selectable = sum(1 for r in preview_rows if r["selected"])
            message = result["empty_message"]
            if message is None:
                message = (
                    f"{selectable} assessment{'s' if selectable != 1 else ''} "
                    "would be copied."
                    + (f" {result['skipped']} already present would be skipped." if result["skipped"] else "")
                )

            return jsonify({
                "count": selectable,
                "skipped": result["skipped"],
                "message": message,
                "entries": preview_rows,
                "mode": mode,
            }), 200

        # Alternative modes: return grouped candidates for review popup
        groups = result["groups"]
        skipped_count = result["skipped_count"]

        serialized_groups = []
        for g in groups:
            assessment = g["assessment"]
            sf = g["source_finding"]
            candidates_ser = []
            for c in g["candidates"]:
                tf = c["target_finding"]
                candidates_ser.append({
                    "target_finding_id": str(tf.id),
                    "target_package": tf.package.string_id if tf.package else "",
                    "already_has_custom": c["already_has_custom"],
                    "selected": c["selected"],
                })
            serialized_groups.append({
                "source_assessment_id": str(assessment.id),
                "source_finding_id": str(sf.id),
                "vulnerability_id": sf.vulnerability_id,
                "source_package": sf.package.string_id if sf.package else "",
                "assessment_details": _serialize_assessment_details(assessment),
                "candidates": candidates_ser,
            })

        total_selectable = sum(
            sum(1 for c in g["candidates"] if c["selected"])
            for g in groups
        )

        empty_message = result["empty_message"]
        if empty_message is None:
            message = (
                f"{total_selectable} assessment{'s' if total_selectable != 1 else ''} "
                "would be copied."
                + (f" {skipped_count} already present would be skipped." if skipped_count else "")
            )
        else:
            message = empty_message

        return jsonify({
            "count": total_selectable,
            "skipped": skipped_count,
            "message": message,
            "groups": serialized_groups,
            "mode": mode,
        }), 200

    @app.route('/api/variants/copy-assessments', methods=['POST'])
    def copy_variant_assessments() -> ResponseReturnValue:
        """Copy custom assessments from one variant to another.

        OpenAPI:
        body JsonObject optional Copy payload describing source, target, mode, and selections.
        response 200 JsonObject Assessment copy summary.
        response 400 Error Invalid copy payload.
        response 404 Error Variant not found.
        """
        from ..models.assessment import Assessment as DBAssessment
        from ..models.finding import Finding

        payload = request.get_json(silent=True) or {}
        source_id = payload.get("source_variant_id")
        target_id = payload.get("target_variant_id")
        if not isinstance(source_id, str) or not isinstance(target_id, str):
            return jsonify({"error": "source_variant_id and target_variant_id are required strings."}), 400

        resolved = _resolve_match_mode(payload)
        if resolved[0] is None:
            return resolved[1]  # type: ignore[return-value]
        match_mode, version_precision = resolved  # type: ignore[misc]
        if match_mode not in ("exact", "ignore_minor_version", "ignore_version"):
            return jsonify({"error": "Invalid match_mode."}), 400

        copy_condition, cond_err = _resolve_copy_condition(payload)
        if cond_err:
            return cond_err
        copy_condition = cast(str, copy_condition)

        selections = payload.get("selections")  # list[{source_assessment_id, target_finding_id}]

        # ---- Selections-based copy (from review popup, alternative modes) ----
        if selections is not None:
            if not isinstance(selections, list):
                return jsonify({"error": "selections must be a list."}), 400

            source_uuid, err = parse_uuid_or_400(source_id, "source_variant_id")
            if err:
                return err
            source_uuid = cast(uuid.UUID, source_uuid)
            target_uuid, err = parse_uuid_or_400(target_id, "target_variant_id")
            if err:
                return err
            target_uuid = cast(uuid.UUID, target_uuid)

            source = VariantController.get(source_id)
            target = VariantController.get(target_id)
            if source is None or target is None:
                return jsonify({"error": "Variant not found."}), 404
            if source.project_id != target.project_id:
                return jsonify({"error": "Both variants must belong to the same project."}), 400

            if not selections:
                return jsonify({
                    "copied": 0,
                    "skipped": 0,
                    "message": f"Copied 0 assessments to '{target.name}'.",
                }), 200

            from ..helpers.active_scans import (
                active_sbom_scan_ids_for_variant,
                active_package_ids_for_scans,
            )
            target_pkg_ids = active_package_ids_for_scans(
                active_sbom_scan_ids_for_variant(target_uuid))

            source_assessments = DBAssessment.get_by_origin([source_uuid])
            source_assessment_by_id = {str(a.id): a for a in source_assessments}

            copied = 0
            skipped = 0
            processed_in_batch: set = set()  # prevent duplicate copies within the same call
            with batch_session():
                for sel in selections:
                    if not isinstance(sel, dict):
                        continue
                    src_assessment_id = sel.get("source_assessment_id")
                    tgt_finding_id = sel.get("target_finding_id")
                    if not isinstance(src_assessment_id, str) or not isinstance(tgt_finding_id, str):
                        continue

                    assessment = source_assessment_by_id.get(src_assessment_id)
                    if assessment is None:
                        continue

                    tgt_finding_uuid, ferr = parse_uuid_or_400(tgt_finding_id, "target_finding_id")
                    if ferr:
                        continue
                    tgt_finding = db.session.get(Finding, tgt_finding_uuid)
                    if tgt_finding is None or tgt_finding.package_id not in target_pkg_ids:
                        continue

                    # Reject mismatched vulnerability ids — a fabricated selection
                    # must not copy a verdict for CVE-A onto a finding for CVE-B.
                    src_finding = assessment.finding
                    if (
                        src_finding is None
                        or (source_uuid == target_uuid and tgt_finding.id == src_finding.id)
                        or tgt_finding.vulnerability_id != src_finding.vulnerability_id
                    ):
                        continue

                    if tgt_finding.id in processed_in_batch:
                        continue  # already queued in this batch

                    existing = DBAssessment.get_by_finding_and_variant(tgt_finding.id, target_uuid)
                    existing_customs = [e for e in existing if e.origin == "custom"]
                    if not _copy_condition_allows(existing_customs, assessment, copy_condition):
                        skipped += 1
                        continue

                    processed_in_batch.add(tgt_finding.id)
                    _clone_assessment(assessment, tgt_finding.id, target.id)
                    copied += 1

            return jsonify({
                "copied": copied,
                "skipped": skipped,
                "message": (
                    f"Copied {copied} assessment{'s' if copied != 1 else ''} to "
                    f"'{target.name}'."
                    + (f" Skipped {skipped} already present." if skipped else "")
                ),
            }), 200

        # ---- Recompute-based copy (exact mode, no popup) ----
        result, err = _compute_copy_assessment_operations(
            source_id, target_id, match_mode, version_precision, copy_condition,
        )
        if err:
            return err
        assert result is not None

        if result["mode"] != "exact":
            # Auto-copy: pick all non-skipped candidates from each group
            target = result["target"]
            assert target is not None
            groups = result["groups"]
            skipped = result["skipped_count"]

            if not groups and result["empty_message"]:
                return jsonify({
                    "copied": 0,
                    "skipped": skipped,
                    "message": result["empty_message"],
                }), 200

            copied = 0
            processed_target_finding_ids: set = set()
            with batch_session():
                for g in groups:
                    src_assessment: DBAssessment = g["assessment"]
                    for c in g["candidates"]:
                        if not c["selected"]:
                            continue
                        tf = c["target_finding"]
                        if tf.id in processed_target_finding_ids:
                            continue
                        processed_target_finding_ids.add(tf.id)
                        _clone_assessment(src_assessment, tf.id, target.id)
                        copied += 1

            return jsonify({
                "copied": copied,
                "skipped": skipped,
                "message": (
                    f"Copied {copied} assessment{'s' if copied != 1 else ''} to "
                    f"'{target.name}'."
                    + (f" Skipped {skipped} already present." if skipped else "")
                ),
            }), 200

        target = result["target"]
        assert target is not None
        operations = result["operations"]
        skipped = result["skipped"]

        if not operations and result["empty_message"]:
            return jsonify({
                "copied": 0,
                "skipped": skipped,
                "message": result["empty_message"],
            }), 200

        copied = 0
        with batch_session():
            for a, _source_finding, target_finding, already_has_custom, selected in operations:
                if not selected:
                    continue
                _clone_assessment(a, target_finding.id, target.id)
                copied += 1

        return jsonify({
            "copied": copied,
            "skipped": skipped,
            "message": (
                f"Copied {copied} assessment{'s' if copied != 1 else ''} to "
                f"'{target.name}'."
                + (f" Skipped {skipped} already present." if skipped else "")
            ),
        }), 200

    # ------------------------------------------------------------------
    # Delete project
    # ------------------------------------------------------------------
    @app.route('/api/projects/<project_id>', methods=['DELETE'])
    def delete_project(project_id: str) -> ResponseReturnValue:
        """Delete a project and its related data.

        OpenAPI:
        response 200 JsonObject Deletion summary.
        response 404 Error Project not found.
        """
        return _delete_entity(project_id, ProjectController, "project ID", "Project")

    # ------------------------------------------------------------------
    # Delete variant
    # ------------------------------------------------------------------
    @app.route('/api/variants/<variant_id>', methods=['DELETE'])
    def delete_variant(variant_id: str) -> ResponseReturnValue:
        """Delete a variant and its related scans.

        OpenAPI:
        response 200 JsonObject Deletion summary.
        response 404 Error Variant not found.
        """
        return _delete_entity(variant_id, VariantController, "variant ID", "Variant")

    # ------------------------------------------------------------------
    # Upload SBOM
    # ------------------------------------------------------------------
    @app.route('/api/sbom/upload', methods=['POST'])
    def upload_sbom() -> ResponseReturnValue:
        """Upload one or more SBOM files and process them asynchronously.

        All files are registered under a single scan so they are treated as
        one logical import.

        Expects a multipart/form-data request with:
        - files: one or more SBOM files (.json)  (field name ``files``)
        - project_id: UUID of the target project
        - variant_id: UUID of the target variant

        OpenAPI:
        body multipart optional Multipart request containing files, project_id, variant_id, and optional format.
        response 202 JsonObject Accepted upload summary.
        response 400 Error Invalid upload request.
        response 404 Error Project or variant not found.
        """
        if not (request.content_type and 'multipart/form-data' in request.content_type):
            return jsonify({"error": "Expected multipart/form-data with a file upload."}), 400

        uploaded_files = request.files.getlist('files')
        if not uploaded_files or not any(f.filename for f in uploaded_files):
            return jsonify({"error": "No file uploaded."}), 400

        project_id = request.form.get('project_id', '').strip()
        variant_id = request.form.get('variant_id', '').strip()
        requested_refresh_sources = request.form.getlist('refresh_sources')
        normalized_refresh_sources = {
            source.strip().lower() for source in requested_refresh_sources if source.strip()
        }
        if not requested_refresh_sources:
            # Field omitted entirely (older clients): keep the historical default.
            refresh_sources = {"epss"}
        elif normalized_refresh_sources == {"none"}:
            # Explicit sentinel sent when the user unchecked every source.
            refresh_sources = set()
        else:
            refresh_sources = normalized_refresh_sources

        unknown_refresh_sources = refresh_sources - _REFRESH_SOURCES
        if unknown_refresh_sources:
            return jsonify({
                "error": f"Unknown refresh source(s): {', '.join(sorted(unknown_refresh_sources))}.",
            }), 400

        if not project_id:
            return jsonify({"error": "project_id is required."}), 400
        if not variant_id:
            return jsonify({"error": "variant_id is required."}), 400

        # Validate project and variant exist
        project = ProjectController.get(project_id)
        if project is None:
            return jsonify({"error": "Project not found."}), 404
        variant = VariantController.get(variant_id)
        if variant is None:
            return jsonify({"error": "Variant not found."}), 404
        if str(variant.project_id) != project_id:
            return jsonify({"error": "Variant does not belong to the specified project."}), 400

        # Validate all files and detect formats before creating the scan
        validated_files: list[tuple[str, str, str]] = []  # (tmp_path, filename, fmt)

        def _cleanup_validated() -> None:
            for p, _, _ in validated_files:
                try:
                    os.unlink(p)
                except OSError:
                    pass

        for uploaded in uploaded_files:
            if not uploaded.filename:
                continue
            filename = uploaded.filename
            fmt = request.form.get('format', '').strip() or None

            # Save the uploaded file to a temp location
            suffix = os.path.splitext(filename)[1] or '.json'
            fd, tmp_path = tempfile.mkstemp(suffix=suffix, prefix="vulnscout_upload_")
            try:
                uploaded.save(tmp_path)
                os.close(fd)
            except Exception:
                os.close(fd)
                os.unlink(tmp_path)
                raise

            # Tar archives (commonly used for SPDX2) — extract the contained
            # .spdx.json documents and register each one individually.
            if _is_archive(filename):
                try:
                    members = _extract_spdx_archive(tmp_path, filename)
                except (subprocess.CalledProcessError, tarfile.TarError, OSError) as e:
                    os.unlink(tmp_path)
                    _cleanup_validated()
                    return jsonify({
                        "error": f"Could not extract archive '{filename}': {e}",
                    }), 400
                os.unlink(tmp_path)
                if not members:
                    _cleanup_validated()
                    return jsonify({
                        "error": f"No .spdx.json files found inside archive '{filename}'.",
                    }), 400
                for member_path, member_name in members:
                    validated_files.append((member_path, member_name, "spdx"))
                continue

            # Auto-detect format if not provided
            if not fmt:
                try:
                    with open(tmp_path, "r") as f:
                        data = json.load(f)
                    fmt = _detect_format(filename, data)
                    if fmt == "unknown":
                        _cleanup_validated()
                        os.unlink(tmp_path)
                        return jsonify({
                            "error": f"Unrecognized SBOM format for '{filename}'.",
                        }), 400
                except (json.JSONDecodeError, UnicodeDecodeError):
                    # Clean up all temp files saved so far
                    _cleanup_validated()
                    os.unlink(tmp_path)
                    return jsonify({"error": f"Could not parse '{filename}' as JSON."}), 400

            validated_files.append((tmp_path, filename, fmt))

        if not validated_files:
            return jsonify({"error": "No valid SBOM files provided."}), 400

        # All files validated — now create the scan and register documents
        scan = ScanController.create("empty description", variant.id)
        tmp_paths: list[str] = []

        for tmp_path, filename, fmt in validated_files:
            SBOMDocumentController.create(tmp_path, filename, scan.id, format=fmt)
            tmp_paths.append(tmp_path)

        _prune_upload_status()

        upload_id = str(uuid.uuid4())
        _upload_status[upload_id] = {"status": "processing", "message": "Starting..."}

        # Process in background
        threading.Thread(
            target=_process_sbom_background,
            args=(app, upload_id, tmp_paths, scan.id, variant.id, refresh_sources),
            name=f"sbom-upload-{upload_id}",
            daemon=True,
        ).start()

        return jsonify({
            "upload_id": upload_id,
            "scan_id": str(scan.id),
            "message": "Upload accepted. Processing started.",
        }), 202

    # ------------------------------------------------------------------
    # Upload SBOM status
    # ------------------------------------------------------------------
    @app.route('/api/sbom/upload/<upload_id>/status')
    def upload_sbom_status(upload_id: str) -> ResponseReturnValue:
        """Return the processing status of an asynchronous SBOM upload.

        OpenAPI:
        response 200 JsonObject Upload progress payload.
        response 404 Error Unknown upload identifier.
        """
        status = _upload_status.get(upload_id)
        if status is None:
            return jsonify({"error": "Unknown upload ID."}), 404
        return jsonify(status)

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
from typing import Callable, TypeVar

from flask import jsonify, request
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
from ._scan_helpers import parse_uuid_or_400

T = TypeVar("T")

# Tracks in-progress SBOM uploads: upload_id → {status, message, ts}
_upload_status: dict[str, dict] = {}
_UPLOAD_STATUS_TTL = 3600  # seconds – entries older than this are pruned


def _prune_upload_status():
    """Remove completed/errored entries older than _UPLOAD_STATUS_TTL."""
    now = time.time()
    stale = [
        uid for uid, info in _upload_status.items()
        if info.get("status") in ("done", "error")
        and now - info.get("ts", 0) > _UPLOAD_STATUS_TTL
    ]
    for uid in stale:
        _upload_status.pop(uid, None)


def _regenerate_openvex(app):
    """Re-generate and save the OpenVEX file from current DB state."""
    try:
        from ..views.openvex import OpenVex
        from ..controllers import ControllersCache

        openvex_file = app.config.get("OPENVEX_FILE", "/scan/outputs/openvex.json")
        ctrls = ControllersCache()
        ctrls.packages._preload_cache()
        vex = OpenVex(ctrls)
        with open(openvex_file, "w") as f:
            f.write(json.dumps(vex.to_dict(), indent=2))
    except Exception as e:
        verbose(f"[_regenerate_openvex] {e}")


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
                src = tar.extractfile(member)
                if src is None:
                    continue
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
        try:
            shutil.rmtree(extract_dir, ignore_errors=True)
        except OSError:
            pass


def _process_sbom_background(app, upload_id: str, file_paths: list[str], scan_id, variant_id):
    """Run SBOM parsing in a background thread for one or more files."""
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

            # Run EPSS enrichment
            try:
                _upload_status[upload_id] = {"status": "processing", "message": "Enriching with EPSS scores..."}
                post_treatment(controllers)
            except Exception as e:
                verbose(f"settings/upload: EPSS enrichment failed: {e}")

            _upload_status[upload_id] = {
                "status": "done",
                "message": "SBOM imported successfully.",
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


def init_app(app):

    def _validate_name_from_request(entity_label: str):
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

    def _delete_entity(entity_id, controller, id_label, entity_label):
        """Validate, look up and delete an entity by UUID.

        Returns a Flask response tuple.
        """
        _, err = parse_uuid_or_400(entity_id, id_label)
        if err:
            return err

        entity = controller.get(entity_id)
        if entity is None:
            return jsonify({"error": f"{entity_label} not found."}), 404

        def _do_delete():
            e = controller.get(entity_id)
            if e is not None:
                controller.delete(e)

        _retry_on_lock(_do_delete)
        return jsonify({"message": f"{entity_label} deleted."}), 200

    # ------------------------------------------------------------------
    # Rename project
    # ------------------------------------------------------------------
    @app.route('/api/projects/<project_id>/rename', methods=['PATCH'])
    def rename_project(project_id):
        new_name, err = _validate_name_from_request("Project")
        if err:
            return err

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
            p = ProjectController.get(project_id)
            if p is None:
                raise ValueError("Project not found.")
            p.update(new_name)
            return p

        project = _retry_on_lock(_do_rename)
        return jsonify(ProjectController.serialize(project))

    # ------------------------------------------------------------------
    # Rename variant
    # ------------------------------------------------------------------
    @app.route('/api/variants/<variant_id>/rename', methods=['PATCH'])
    def rename_variant(variant_id):
        new_name, err = _validate_name_from_request("Variant")
        if err:
            return err

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
            v = VariantController.get(variant_id)
            if v is None:
                raise ValueError("Variant not found.")
            VariantController.update(v, new_name)
            return v

        variant = _retry_on_lock(_do_rename)
        return jsonify(VariantController.serialize(variant))

    # ------------------------------------------------------------------
    # Create project
    # ------------------------------------------------------------------
    @app.route('/api/projects', methods=['POST'])
    def create_project():
        new_name, err = _validate_name_from_request("Project")
        if err:
            return err

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
    def create_variant(project_id):
        _, err = parse_uuid_or_400(project_id, "project ID")
        if err:
            return err

        new_name, err = _validate_name_from_request("Variant")
        if err:
            return err

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
    def _compute_copy_assessment_operations(source_id, target_id, ignore_package_version):
        from ..models.assessment import Assessment as DBAssessment
        from ..models.finding import Finding
        from ..helpers.active_scans import (
            active_sbom_scan_ids_for_variant,
            active_package_ids_for_scans,
        )

        source_uuid, err = parse_uuid_or_400(source_id, "source_variant_id")
        if err:
            return None, err
        if source_uuid is None:
            return None, (jsonify({"error": "Invalid source variant ID."}), 400)
        target_uuid, err = parse_uuid_or_400(target_id, "target_variant_id")
        if err:
            return None, err
        if target_uuid is None:
            return None, (jsonify({"error": "Invalid target variant ID."}), 400)

        if source_uuid == target_uuid:
            return None, (jsonify({"error": "Source and target variants must be different."}), 400)

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
        common_pkg_ids = source_pkg_ids & target_pkg_ids

        source_assessments = DBAssessment.get_handmade([source_uuid])

        source_vuln_ids: set[str] = set()
        target_findings_by_vuln: dict[str, list[Finding]] = {}

        if ignore_package_version:
            source_vuln_ids = {
                a.finding.vulnerability_id
                for a in source_assessments
                if a.finding is not None and a.finding.package_id in source_pkg_ids
            }

            if source_vuln_ids:
                target_findings = list(db.session.execute(
                    db.select(Finding).where(
                        Finding.package_id.in_(target_pkg_ids),
                        Finding.vulnerability_id.in_(source_vuln_ids),
                    )
                ).scalars().all())
            else:
                target_findings = []

            for f in target_findings:
                target_findings_by_vuln.setdefault(f.vulnerability_id, []).append(f)

            if not target_findings_by_vuln:
                return {
                    "source": source,
                    "target": target,
                    "operations": [],
                    "skipped": 0,
                    "empty_message": "No vulnerabilities in common between the two variants.",
                }, None
        else:
            if not common_pkg_ids:
                return {
                    "source": source,
                    "target": target,
                    "operations": [],
                    "skipped": 0,
                    "empty_message": "No packages in common between the two variants.",
                }, None

        operations = []
        skipped = 0
        processed_target_finding_ids: set = set()

        for assessment in source_assessments:
            source_finding = assessment.finding
            if source_finding is None:
                continue

            if ignore_package_version:
                target_findings = target_findings_by_vuln.get(source_finding.vulnerability_id, [])
            else:
                if source_finding.package_id not in common_pkg_ids:
                    continue
                target_findings = [source_finding]

            for target_finding in target_findings:
                if target_finding.id in processed_target_finding_ids:
                    continue
                processed_target_finding_ids.add(target_finding.id)

                existing = DBAssessment.get_by_finding_and_variant(target_finding.id, target_uuid)
                if any(e.origin == "custom" for e in existing):
                    skipped += 1
                    continue

                operations.append((assessment, source_finding, target_finding))

        return {
            "source": source,
            "target": target,
            "operations": operations,
            "skipped": skipped,
            "empty_message": None,
        }, None

    @app.route('/api/variants/copy-assessments/preview', methods=['POST'])
    def preview_copy_variant_assessments():
        payload = request.get_json(silent=True) or {}
        source_id = payload.get("source_variant_id")
        target_id = payload.get("target_variant_id")
        ignore_package_version = bool(payload.get("ignore_package_version", False))

        result, err = _compute_copy_assessment_operations(
            source_id,
            target_id,
            ignore_package_version,
        )
        if err:
            return err
        assert result is not None

        operations = result["operations"]
        preview_rows = []
        for assessment, source_finding, target_finding in operations:
            preview_rows.append({
                "source_assessment_id": str(assessment.id),
                "source_finding_id": str(source_finding.id),
                "target_finding_id": str(target_finding.id),
                "vulnerability_id": source_finding.vulnerability_id,
                "source_package": source_finding.package.string_id if source_finding.package else "",
                "target_package": target_finding.package.string_id if target_finding.package else "",
            })

        message = result["empty_message"]
        if message is None:
            message = (
                f"{len(preview_rows)} assessment{'s' if len(preview_rows) != 1 else ''} "
                "would be copied."
                + (f" {result['skipped']} already present would be skipped." if result["skipped"] else "")
            )

        return jsonify({
            "count": len(preview_rows),
            "skipped": result["skipped"],
            "message": message,
            "entries": preview_rows,
        }), 200

    @app.route('/api/variants/copy-assessments', methods=['POST'])
    def copy_variant_assessments():
        from ..models.assessment import Assessment as DBAssessment

        payload = request.get_json(silent=True) or {}
        source_id = payload.get("source_variant_id")
        target_id = payload.get("target_variant_id")
        ignore_package_version = bool(payload.get("ignore_package_version", False))

        result, err = _compute_copy_assessment_operations(
            source_id,
            target_id,
            ignore_package_version,
        )
        if err:
            return err
        assert result is not None

        target = result["target"]
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
            for a, _source_finding, target_finding in operations:
                DBAssessment.create(
                    status=a.status or "under_investigation",
                    finding_id=target_finding.id,
                    variant_id=target.id,
                    source=a.source,
                    origin="custom",
                    simplified_status=a.simplified_status,
                    status_notes=a.status_notes,
                    justification=a.justification,
                    impact_statement=a.impact_statement,
                    workaround=a.workaround,
                    responses=list(a.responses) if a.responses else [],
                    commit=False,
                )
                copied += 1

        if copied:
            _regenerate_openvex(app)

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
    def delete_project(project_id):
        return _delete_entity(project_id, ProjectController, "project ID", "Project")

    # ------------------------------------------------------------------
    # Delete variant
    # ------------------------------------------------------------------
    @app.route('/api/variants/<variant_id>', methods=['DELETE'])
    def delete_variant(variant_id):
        return _delete_entity(variant_id, VariantController, "variant ID", "Variant")

    # ------------------------------------------------------------------
    # Upload SBOM
    # ------------------------------------------------------------------
    @app.route('/api/sbom/upload', methods=['POST'])
    def upload_sbom():
        """Upload one or more SBOM files and process them asynchronously.

        All files are registered under a single scan so they are treated as
        one logical import.

        Expects a multipart/form-data request with:
        - files: one or more SBOM files (.json)  (field name ``files``)
        - project_id: UUID of the target project
        - variant_id: UUID of the target variant
        """
        if not (request.content_type and 'multipart/form-data' in request.content_type):
            return jsonify({"error": "Expected multipart/form-data with a file upload."}), 400

        uploaded_files = request.files.getlist('files')
        if not uploaded_files or not any(f.filename for f in uploaded_files):
            return jsonify({"error": "No file uploaded."}), 400

        project_id = request.form.get('project_id', '').strip()
        variant_id = request.form.get('variant_id', '').strip()

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

        def _cleanup_validated():
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
            args=(app, upload_id, tmp_paths, scan.id, variant.id),
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
    def upload_sbom_status(upload_id):
        status = _upload_status.get(upload_id)
        if status is None:
            return jsonify({"error": "Unknown upload ID."}), 404
        return jsonify(status)

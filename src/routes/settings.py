# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os
import json
import uuid
import time
import tempfile
import threading

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
from ..helpers.verbose import verbose
from ._scan_helpers import parse_uuid_or_400

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


def _retry_on_lock(fn, max_retries=5, delay=0.5):
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

        def _do_rename():
            p = ProjectController.get(project_id)
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

        def _do_rename():
            v = VariantController.get(variant_id)
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
    @app.route('/api/variants/copy-assessments', methods=['POST'])
    def copy_variant_assessments():
        from ..models.assessment import Assessment as DBAssessment
        from ..helpers.active_scans import (
            active_sbom_scan_ids_for_variant,
            active_package_ids_for_scans,
        )

        payload = request.get_json(silent=True) or {}
        source_id = payload.get("source_variant_id")
        target_id = payload.get("target_variant_id")

        source_uuid, err = parse_uuid_or_400(source_id, "source_variant_id")
        if err:
            return err
        target_uuid, err = parse_uuid_or_400(target_id, "target_variant_id")
        if err:
            return err

        if source_uuid == target_uuid:
            return jsonify({"error": "Source and target variants must be different."}), 400

        source = VariantController.get(source_id)
        target = VariantController.get(target_id)
        if source is None or target is None:
            return jsonify({"error": "Variant not found."}), 404
        if source.project_id != target.project_id:
            return jsonify({"error": "Both variants must belong to the same project."}), 400

        # Resolve the package set of each variant (SBOM elements).
        source_pkg_ids = active_package_ids_for_scans(
            active_sbom_scan_ids_for_variant(source_uuid))
        target_pkg_ids = active_package_ids_for_scans(
            active_sbom_scan_ids_for_variant(target_uuid))
        common_pkg_ids = source_pkg_ids & target_pkg_ids

        if not common_pkg_ids:
            return jsonify({
                "copied": 0,
                "skipped": 0,
                "message": "No packages in common between the two variants.",
            }), 200

        # Custom (handmade) assessments belonging to the source variant.
        source_assessments = DBAssessment.get_handmade([source_uuid])

        copied = 0
        skipped = 0
        with batch_session():
            for a in source_assessments:
                finding_id = a.finding_id
                finding = a.finding
                if finding is None or finding.package_id not in common_pkg_ids:
                    continue
                # Skip if the target already has a custom assessment for this finding.
                existing = DBAssessment.get_by_finding_and_variant(finding_id, target_uuid)
                if any(e.origin == "custom" for e in existing):
                    skipped += 1
                    continue
                DBAssessment.create(
                    status=a.status or "under_investigation",
                    finding_id=finding_id,
                    variant_id=target_uuid,
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

            # Auto-detect format if not provided
            if not fmt:
                try:
                    with open(tmp_path, "r") as f:
                        data = json.load(f)
                    fmt = _detect_format(filename, data)
                    if fmt == "unknown":
                        for p, _, _ in validated_files:
                            try:
                                os.unlink(p)
                            except OSError:
                                pass
                        os.unlink(tmp_path)
                        return jsonify({
                            "error": f"Unrecognized SBOM format for '{filename}'.",
                        }), 400
                except (json.JSONDecodeError, UnicodeDecodeError):
                    # Clean up all temp files saved so far
                    for p, _, _ in validated_files:
                        try:
                            os.unlink(p)
                        except OSError:
                            pass
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

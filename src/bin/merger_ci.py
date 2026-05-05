#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This python job aggregates packages, vulnerabilities and assessments from
# source files, enriches them with VEX info and persists everything to the
# database.  Output SBOM files are still generated for downstream consumption
# but packages / vulnerabilities / assessments are no longer written to
# intermediate JSON files — the DB is the single source of truth.
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
#
# This module is the entry point / orchestrator.  The actual logic lives in:
#   cmd_process.py     — ``flask merge`` and ``flask process``
#   cmd_export.py      — ``flask export`` and ``flask report``
#   cmd_assessments.py — ``flask export-custom-assessments`` / ``flask import-custom-assessments``
#   cmd_scans.py       — ``flask list-projects``, ``flask list-scans``, ``flask delete-scan``
#   cmd_vuln_scan.py   — ``flask nvd-scan`` and ``flask osv-scan``

from .cmd_process import (  # noqa: F401 — intentional re-exports for callers
    create_project_context,
    process_command,
    _run_main,
    post_treatment,
    populate_observations,
    evaluate_condition,
    read_inputs,
    DEFAULT_VARIANT_NAME,
    _ts_key,
)
from .cmd_export import export_command, report_command
from .cmd_assessments import (
    export_custom_assessments_command,
    import_custom_assessments_command,
)
from .cmd_scans import (
    list_projects_command,
    list_scans_command,
    delete_scan_command,
)
from .cmd_vuln_scan import nvd_scan_command, osv_scan_command


def init_app(app) -> None:
    """Register all Flask CLI commands with *app*."""
    app.cli.add_command(create_project_context)
    app.cli.add_command(process_command)
    app.cli.add_command(report_command)
    app.cli.add_command(export_command)
    app.cli.add_command(export_custom_assessments_command)
    app.cli.add_command(import_custom_assessments_command)
    app.cli.add_command(list_projects_command)
    app.cli.add_command(list_scans_command)
    app.cli.add_command(delete_scan_command)
    app.cli.add_command(nvd_scan_command)
    app.cli.add_command(osv_scan_command)


def main() -> dict:
    """Entry-point for direct invocation (``python -m src.bin.merger_ci``).

    Returns the controllers dict so callers can inspect in-memory state.
    Prefer running via ``flask --app bin.webapp process`` in production so that
    the DB session is properly initialised.
    """
    return _run_main()


if __name__ == "__main__":
    main()

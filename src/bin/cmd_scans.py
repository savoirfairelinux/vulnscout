# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Project and scan management commands.

Includes scan listing and deletion commands plus global data maintenance.
"""

from ..controllers.projects import ProjectController
from ..controllers.scans import ScanController
from ..models.project import Project as ProjectModel
from ..models.scan import Scan as ScanModel
import click
import json
import typing
import uuid
from flask.cli import with_appcontext

_T = typing.TypeVar("_T")


def _echo_object_list(
    json_format: bool,
    objects: list[_T],
    pretty_format: typing.Callable[[_T], str],
    to_dict: typing.Callable[[_T], dict],
):
    if json_format:
        # cannot use a generator here since the json library cannot dump an
        # array "lazily"
        click.echo_via_pager(json.dumps(
            [to_dict(obj) for obj in objects],
            indent=4)
        )
    else:
        click.echo_via_pager(pretty_format(obj) for obj in objects)


@click.command("list-projects")
@click.option("--json", "json_format", is_flag=True)
@with_appcontext
def list_projects_command(json_format: bool):
    def _format_project_pretty(project: ProjectModel) -> str:
        variants_string = ", ".join(v.name for v in project.variants)
        return (f"{project.name} ({project.id}), "
                f"{len(project.variants)} variants: {variants_string}\n")

    projects = ProjectController.get_all()
    _echo_object_list(json_format, projects, _format_project_pretty, ProjectModel.to_dict)


@click.command("list-scans")
@click.option("--json", "json_format", is_flag=True)
@with_appcontext
def list_scans_command(json_format: bool = False):
    def _format_scan_pretty(scan: ScanModel) -> str:
        return (f"{scan.id} ({scan.description}) at {scan.timestamp}, "
                f"project {scan.variant.project.name}, "
                f"variant {scan.variant.name}, "
                f"{len(scan.sbom_documents)} SBOMs, "
                f"{len(scan.observations)} observations\n")

    scans = ScanController.get_all()
    _echo_object_list(json_format, scans, _format_scan_pretty, ScanModel.to_dict)


@click.command("delete-scan")
@click.argument("scan-id", type=click.UUID)
@with_appcontext
def delete_scan_command(scan_id: uuid.UUID):
    ScanController.delete(scan_id)
    click.echo(f"Successfully deleted scan {scan_id}")


@click.command("delete-outdated")
@with_appcontext
def delete_outdated_command():
    """Permanently remove all package evidence and assessments marked outdated."""
    from ..helpers.outdated_cleanup import delete_outdated_data

    summary = delete_outdated_data()
    click.echo(
        "Deleted outdated data: "
        f"{summary['assessments_deleted']} assessments, "
        f"{summary['observations_deleted']} observations, "
        f"{summary['sbom_packages_deleted']} SBOM package links, "
        f"{summary['sbom_observations_deleted']} SBOM vulnerability records, "
        f"{summary['findings_deleted']} findings, "
        f"{summary['vulnerabilities_deleted']} vulnerabilities, "
        f"{summary['packages_deleted']} packages"
    )


@click.command("delete-empty-scans")
@with_appcontext
def delete_empty_scans_command():
    """Permanently remove non-initial scans with no recorded changes."""
    from ..helpers.outdated_cleanup import delete_empty_scans

    summary = delete_empty_scans()
    click.echo(f"Deleted {summary['scans_deleted']} empty scans")


@click.command("delete-orphaned-vulnerabilities")
@with_appcontext
def delete_orphaned_vulnerabilities_command():
    """Permanently remove CVEs absent from every project and variant."""
    from ..helpers.outdated_cleanup import delete_orphaned_vulnerabilities

    summary = delete_orphaned_vulnerabilities()
    click.echo(
        f"Deleted {summary['vulnerabilities_deleted']} orphaned vulnerabilities, "
        f"{summary['assessments_deleted']} assessments, "
        f"{summary['findings_deleted']} findings"
    )

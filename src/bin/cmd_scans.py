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
from ._console import Command, color_enabled, echo, style
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
            indent=4),
            color=False,
        )
    else:
        click.echo_via_pager((style(pretty_format(obj)) for obj in objects), color=color_enabled())


@click.command("list-projects", cls=Command)
@click.option("--json", "json_format", is_flag=True)
@with_appcontext
def list_projects_command(json_format: bool):
    def _format_project_pretty(project: ProjectModel) -> str:
        variants_string = ", ".join(v.name for v in project.variants)
        return (f"{project.name} ({project.id}), "
                f"{len(project.variants)} variants: {variants_string}\n")

    projects = ProjectController.get_all()
    _echo_object_list(json_format, projects, _format_project_pretty, ProjectModel.to_dict)


@click.command("list-scans", cls=Command)
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


@click.command("delete-scan", cls=Command)
@click.argument("scan-id", type=click.UUID)
@click.option("--dry-run", is_flag=True, help="Show the scan that would be deleted without deleting it.")
@with_appcontext
def delete_scan_command(scan_id: uuid.UUID, dry_run: bool):
    if dry_run:
        scan = ScanController.get(scan_id)
        if scan is None:
            raise click.ClickException(f"Scan not found: {scan_id}")
        echo(
            f"Would delete scan {scan.id} ({scan.variant.project.name}/{scan.variant.name}, "
            f"{scan.timestamp.isoformat()}): {scan.description or ''}", role="warning"
        )
        return
    ScanController.delete(scan_id)
    echo(f"Successfully deleted scan {scan_id}", role="success")


@click.command("delete-outdated", cls=Command)
@click.option("--dry-run", is_flag=True, help="List outdated data without deleting it.")
@with_appcontext
def delete_outdated_command(dry_run: bool):
    """Permanently remove all package evidence and assessments marked outdated."""
    from ..helpers import outdated_cleanup

    if dry_run:
        preview = outdated_cleanup.outdated_data_preview()
        packages = typing.cast("list[dict[str, typing.Any]]", preview["packages"])
        assessments = typing.cast("list[dict[str, typing.Any]]", preview["assessments"])
        echo(f"Would delete {len(packages)} outdated package links and {len(assessments)} assessments", role="warning")
        for package in packages:
            echo(
                f"  package {package['package']} in {package['project']}/{package['variant']}"
                f" ({len(package['vulnerabilities'])} vulnerabilities)", role="info"
            )
        for assessment in assessments:
            echo(
                f"  assessment {assessment['vulnerability']} on {assessment['package']}"
                f" in {assessment['project']}/{assessment['variant']}", role="info"
            )
        return

    summary = outdated_cleanup.delete_outdated_data()
    echo(
        "Deleted outdated data: "
        f"{summary['assessments_deleted']} assessments, "
        f"{summary['observations_deleted']} observations, "
        f"{summary['sbom_packages_deleted']} SBOM package links, "
        f"{summary['sbom_observations_deleted']} SBOM vulnerability records, "
        f"{summary['findings_deleted']} findings, "
        f"{summary['vulnerabilities_deleted']} vulnerabilities, "
        f"{summary['packages_deleted']} packages", role="success"
    )


@click.command("delete-empty-scans", cls=Command)
@click.option("--dry-run", is_flag=True, help="List empty scans without deleting them.")
@with_appcontext
def delete_empty_scans_command(dry_run: bool):
    """Permanently remove non-initial scans with no recorded changes."""
    from ..helpers import outdated_cleanup

    if dry_run:
        scans = outdated_cleanup.empty_scans_preview()
        echo(f"Would delete {len(scans)} empty scans", role="warning")
        for scan in scans:
            line = f"  {scan['id']} {scan['project']}/{scan['variant']} {scan['timestamp']} {scan['description']}"
            echo(line.rstrip(), role="info")
        return

    summary = outdated_cleanup.delete_empty_scans()
    echo(f"Deleted {summary['scans_deleted']} empty scans", role="success")


@click.command("delete-orphaned-vulns", cls=Command)
@click.option("--dry-run", is_flag=True, help="List orphaned vulnerabilities without deleting them.")
@with_appcontext
def delete_orphaned_vulnerabilities_command(dry_run: bool):
    """Permanently remove CVEs absent from every project and variant."""
    from ..helpers import outdated_cleanup

    if dry_run:
        vulnerabilities = outdated_cleanup.orphaned_vulnerabilities_preview()
        echo(f"Would delete {len(vulnerabilities)} orphaned vulnerabilities", role="warning")
        for vulnerability in vulnerabilities:
            echo(f"  {vulnerability['id']} ({vulnerability['assessments']} assessments)", role="info")
        return

    summary = outdated_cleanup.delete_orphaned_vulnerabilities()
    echo(
        f"Deleted {summary['vulnerabilities_deleted']} orphaned vulnerabilities, "
        f"{summary['assessments_deleted']} assessments, "
        f"{summary['findings_deleted']} findings", role="success"
    )

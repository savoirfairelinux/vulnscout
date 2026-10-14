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
@click.option("--dry-run", is_flag=True, help="Show the scan that would be deleted without deleting it.")
@with_appcontext
def delete_scan_command(scan_id: uuid.UUID, dry_run: bool):
    if dry_run:
        scan = ScanController.get(scan_id)
        if scan is None:
            raise click.ClickException(f"Scan not found: {scan_id}")
        click.echo(
            f"Would delete scan {scan.id} ({scan.variant.project.name}/{scan.variant.name}, "
            f"{scan.timestamp.isoformat()}): {scan.description or ''}"
        )
        return
    ScanController.delete(scan_id)
    click.echo(f"Successfully deleted scan {scan_id}")


@click.command("delete-outdated")
@click.option("--dry-run", is_flag=True, help="List outdated data without deleting it.")
@with_appcontext
def delete_outdated_command(dry_run: bool):
    """Permanently remove all package evidence and assessments marked outdated."""
    from ..helpers import outdated_cleanup

    if dry_run:
        preview = outdated_cleanup.outdated_data_preview()
        packages = typing.cast("list[dict[str, typing.Any]]", preview["packages"])
        assessments = typing.cast("list[dict[str, typing.Any]]", preview["assessments"])
        click.echo(f"Would delete {len(packages)} outdated package links and {len(assessments)} assessments")
        for package in packages:
            click.echo(
                f"  package {package['package']} in {package['project']}/{package['variant']}"
                f" ({len(package['vulnerabilities'])} vulnerabilities)"
            )
        for assessment in assessments:
            click.echo(
                f"  assessment {assessment['vulnerability']} on {assessment['package']}"
                f" in {assessment['project']}/{assessment['variant']}"
            )
        return

    summary = outdated_cleanup.delete_outdated_data()
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
@click.option("--dry-run", is_flag=True, help="List empty scans without deleting them.")
@with_appcontext
def delete_empty_scans_command(dry_run: bool):
    """Permanently remove non-initial scans with no recorded changes."""
    from ..helpers import outdated_cleanup

    if dry_run:
        scans = outdated_cleanup.empty_scans_preview()
        click.echo(f"Would delete {len(scans)} empty scans")
        for scan in scans:
            line = f"  {scan['id']} {scan['project']}/{scan['variant']} {scan['timestamp']} {scan['description']}"
            click.echo(line.rstrip())
        return

    summary = outdated_cleanup.delete_empty_scans()
    click.echo(f"Deleted {summary['scans_deleted']} empty scans")


@click.command("delete-orphaned-vulns")
@click.option("--dry-run", is_flag=True, help="List orphaned vulnerabilities without deleting them.")
@with_appcontext
def delete_orphaned_vulnerabilities_command(dry_run: bool):
    """Permanently remove CVEs absent from every project and variant."""
    from ..helpers import outdated_cleanup

    if dry_run:
        vulnerabilities = outdated_cleanup.orphaned_vulnerabilities_preview()
        click.echo(f"Would delete {len(vulnerabilities)} orphaned vulnerabilities")
        for vulnerability in vulnerabilities:
            click.echo(f"  {vulnerability['id']} ({vulnerability['assessments']} assessments)")
        return

    summary = outdated_cleanup.delete_orphaned_vulnerabilities()
    click.echo(
        f"Deleted {summary['vulnerabilities_deleted']} orphaned vulnerabilities, "
        f"{summary['assessments_deleted']} assessments, "
        f"{summary['findings_deleted']} findings"
    )

#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import os

import click
from flask.cli import with_appcontext

from ..controllers.projects import ProjectController
from ..controllers.variants import VariantController
from ..controllers.scans import ScanController
from ..controllers.sbom_documents import SBOMDocumentController

DEFAULT_VARIANT_NAME = "default"


@click.command("merge")
@click.option("--project", "-p", required=True, help="Project name.")
@click.option("--variant", "-v", default=None,
              help=f"Variant name (defaults to '{DEFAULT_VARIANT_NAME}').")
@click.argument("sbom_inputs", nargs=-1, type=click.Path(exists=True))
@with_appcontext
def create_project_context(project: str, variant: str | None, sbom_inputs: tuple) -> None:
    """Merge SBOM inputs into the database under a named project/variant scan.

    SBOM_INPUTS is one or more paths to SBOM files.
    When no variant is given, inputs go into a scan under the 'default' variant.
    """
    variant_name = variant or DEFAULT_VARIANT_NAME

    project_obj = ProjectController.get_or_create(project)
    variant_obj = VariantController.get_or_create(variant_name, project_obj.id)
    scan = ScanController.create("default", variant_obj.id)
    click.echo(f"project='{project}' variant='{variant_name}' scan={scan.id}")

    for sbom_file in sbom_inputs:
        abs_path = os.path.abspath(sbom_file)
        SBOMDocumentController.create(abs_path, os.path.basename(sbom_file), scan.id)
        click.echo(f"  + {sbom_file}")


def init_app(app) -> None:
    """Register the ``flask merge`` command with *app*."""
    app.cli.add_command(create_project_context)

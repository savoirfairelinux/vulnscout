# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Shared constants and helpers for CLI commands."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from ._console import echo

if TYPE_CHECKING:
    from ..models.project import Project
    from ..models.variant import Variant

DEFAULT_VARIANT_NAME = "default"


def get_default_author() -> str:
    """Return the author name, reading AUTHOR_NAME at call time."""
    return os.getenv("AUTHOR_NAME", "Savoir-faire Linux")


def resolve_project(project: str) -> Project:
    """Look up a project by name.

    Returns the project object or exits with an error.
    """
    from ..controllers.projects import ProjectController

    project_obj = ProjectController.get_by_name(project)
    if not project_obj:
        echo(f"Error: project not found: {project}", role="error")
        raise SystemExit(1)
    return project_obj


def resolve_project_variant(project: str, variant: str | None, *, create: bool = False) -> tuple[Project, Variant]:
    """Look up (or create) a project and variant by name.

    Parameters
    ----------
    project:
        Project name.
    variant:
        Variant name.  When *None*, ``DEFAULT_VARIANT_NAME`` is used.
    create:
        When *True*, missing projects/variants are created automatically
        (``get_or_create``).  When *False*, missing objects cause a
        ``SystemExit(1)`` with a user-friendly error message.

    Returns
    -------
    (project_obj, variant_obj)
    """
    from ..controllers.projects import ProjectController
    from ..controllers.variants import VariantController
    from ..models.variant import Variant as DBVariant

    variant_name = variant or DEFAULT_VARIANT_NAME

    if create:
        project_obj = ProjectController.get_or_create(project)
        variant_obj = VariantController.get_or_create(variant_name, project_obj.id)
    else:
        _proj = ProjectController.get_by_name(project)
        if not _proj:
            echo(f"Error: project not found: {project}", role="error")
            raise SystemExit(1)
        project_obj = _proj
        _var = DBVariant.get_by_name_and_project(variant_name, project_obj.id)
        if not _var:
            echo(f"Error: variant not found: {variant_name}", role="error")
            raise SystemExit(1)
        variant_obj = _var

    return project_obj, variant_obj

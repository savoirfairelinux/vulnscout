# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from typing import Optional

from ..models.project import Project


class ProjectController:
    """
    Service layer for Project CRUD operations.

    Handles input validation, delegates persistence to the :class:`Project`
    model and provides dictionary serialisation for API responses.
    """

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    @staticmethod
    def serialize(project: Project) -> dict:
        """Return a JSON-serialisable dict representation of *project*."""
        return {
            "id": str(project.id),
            "name": project.name,
        }

    @staticmethod
    def serialize_list(projects: list[Project]) -> list[dict]:
        """Return a list of serialised project dicts."""
        return [ProjectController.serialize(p) for p in projects]

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @staticmethod
    def get(project_id: uuid.UUID | str) -> Optional[Project]:
        """Return the project matching *project_id*, or ``None`` if not found."""
        if isinstance(project_id, str):
            project_id = uuid.UUID(project_id)
        return Project.get_by_id(project_id)

    @staticmethod
    def get_by_name(name: str) -> Project | None:
        """
        Return an existing project whose name matches *name* (case-sensitive),
        or None if no project with the name exists.

        :raises ValueError: if *name* is empty or blank.
        """
        name = name.strip()
        if not name:
            raise ValueError("Project name must not be empty.")
        return Project.get_by_name(name)

    @staticmethod
    def get_all() -> list[Project]:
        """Return all projects ordered by name."""
        return Project.get_all()

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    @staticmethod
    def create(name: str) -> Project:
        """
        Validate *name* and create a new project.

        :raises ValueError: if *name* is empty or blank.
        """
        name = name.strip()
        if not name:
            raise ValueError("Project name must not be empty.")
        return Project.create(name)

    @staticmethod
    def get_or_create(name: str) -> Project:
        """
        Return an existing project whose name matches *name* (case-sensitive),
        or create and persist a new one.

        :raises ValueError: if *name* is empty or blank.
        """
        name = name.strip()
        if not name:
            raise ValueError("Project name must not be empty.")
        return Project.get_or_create(name)

    @staticmethod
    def update(project: Project | uuid.UUID | str, name: str) -> Project:
        """
        Update *project*'s name.  *project* may be a :class:`Project` instance,
        a UUID object, or a UUID string.

        :raises ValueError: if *name* is empty or blank, or project is not found.
        """
        name = name.strip()
        if not name:
            raise ValueError("Project name must not be empty.")
        resolved: Project
        if isinstance(project, Project):
            resolved = project
        else:
            found = ProjectController.get(project)
            if found is None:
                raise ValueError("Project not found.")
            resolved = found
        return resolved.update(name)

    @staticmethod
    def delete(project: Project | uuid.UUID | str) -> None:
        """
        Delete *project*.  *project* may be a :class:`Project` instance,
        a UUID object, or a UUID string.

        :raises ValueError: if the project is not found.
        """
        resolved: Project
        if isinstance(project, Project):
            resolved = project
        else:
            found = ProjectController.get(project)
            if found is None:
                raise ValueError("Project not found.")
            resolved = found
        resolved.delete()

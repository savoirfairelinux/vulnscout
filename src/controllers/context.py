# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from typing import Optional

from ..models.project import Project
from ..models.variant import Variant
from ..models.project_context import ProjectContext
from ..models.variant_context import VariantContext
from ._base import ensure_uuid


class ProjectContextController:

    @staticmethod
    def _get_project(project_id: uuid.UUID | str) -> Project:
        pid = ensure_uuid(project_id)
        project = Project.get_by_id(pid)
        if project is None:
            raise ValueError(f"Project {project_id} not found.")
        return project

    @staticmethod
    def get_or_create(project_id: uuid.UUID | str) -> ProjectContext:
        pid = ensure_uuid(project_id)
        ProjectContextController._get_project(pid)
        existing = ProjectContext.get_by_project(pid)
        if existing is not None:
            return existing
        return ProjectContext.upsert(pid, description=None)

    @staticmethod
    def upsert(
        project_id: uuid.UUID | str,
        description: Optional[str] = None,
    ) -> ProjectContext:
        pid = ensure_uuid(project_id)
        ProjectContextController._get_project(pid)
        return ProjectContext.upsert(pid, description=description)

    @staticmethod
    def serialize(pc: ProjectContext) -> dict:
        return pc.to_dict()


class VariantContextController:

    @staticmethod
    def _get_variant(variant_id: uuid.UUID | str) -> Variant:
        vid = ensure_uuid(variant_id)
        variant = Variant.get_by_id(vid)
        if variant is None:
            raise ValueError(f"Variant {variant_id} not found.")
        return variant

    @staticmethod
    def get_or_create(variant_id: uuid.UUID | str) -> VariantContext:
        vid = ensure_uuid(variant_id)
        VariantContextController._get_variant(vid)
        existing = VariantContext.get_by_variant(vid)
        if existing is not None:
            return existing
        return VariantContext.upsert(vid)

    @staticmethod
    def upsert(
        variant_id: uuid.UUID | str,
        variant_description: Optional[str] = None,
        environment: Optional[str] = None,
        threat_model: Optional[str] = None,
        risks: Optional[str] = None,
        other_info: Optional[str] = None,
    ) -> VariantContext:
        vid = ensure_uuid(variant_id)
        VariantContextController._get_variant(vid)
        return VariantContext.upsert(
            vid,
            variant_description=variant_description,
            environment=environment,
            threat_model=threat_model,
            risks=risks,
            other_info=other_info,
        )

    @staticmethod
    def serialize(vc: VariantContext) -> dict:
        return vc.to_dict()

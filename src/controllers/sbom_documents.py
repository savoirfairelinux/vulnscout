# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid
from typing import Optional

from ..models.sbom_document import SBOMDocument


class SBOMDocumentController:
    """
    Service layer for SBOMDocument CRUD operations.

    Handles input validation, delegates persistence to the :class:`SBOMDocument`
    model and provides dictionary serialisation for API responses.
    """

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    @staticmethod
    def serialize(document: SBOMDocument) -> dict:
        """Return a JSON-serialisable dict representation of *document*."""
        return {
            "id": str(document.id),
            "path": document.path,
            "source_name": document.source_name,
            "scan_id": str(document.scan_id),
        }

    @staticmethod
    def serialize_list(documents: list[SBOMDocument]) -> list[dict]:
        """Return a list of serialised SBOM document dicts."""
        return [SBOMDocumentController.serialize(d) for d in documents]

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @staticmethod
    def get(document_id: uuid.UUID | str) -> Optional[SBOMDocument]:
        """Return the SBOM document matching *document_id*, or ``None`` if not found."""
        if isinstance(document_id, str):
            document_id = uuid.UUID(document_id)
        return SBOMDocument.get_by_id(document_id)

    @staticmethod
    def get_all() -> list[SBOMDocument]:
        """Return all SBOM documents ordered by path."""
        return SBOMDocument.get_all()

    @staticmethod
    def get_by_scan(scan_id: uuid.UUID | str) -> list[SBOMDocument]:
        """Return all SBOM documents belonging to *scan_id*, ordered by path."""
        if isinstance(scan_id, str):
            scan_id = uuid.UUID(scan_id)
        return SBOMDocument.get_by_scan(scan_id)

    @staticmethod
    def get_by_variant(variant_id: uuid.UUID | str) -> list[SBOMDocument]:
        """Return all SBOM documents belonging to *variant_id* (across all its scans), ordered by path."""
        if isinstance(variant_id, str):
            variant_id = uuid.UUID(variant_id)
        return SBOMDocument.get_by_variant(variant_id)

    @staticmethod
    def get_by_project(project_id: uuid.UUID | str) -> list[SBOMDocument]:
        """Return all SBOM documents belonging to *project_id* (across all variants and scans), ordered by path."""
        if isinstance(project_id, str):
            project_id = uuid.UUID(project_id)
        return SBOMDocument.get_by_project(project_id)

    # ------------------------------------------------------------------
    # Mutations
    # ------------------------------------------------------------------

    @staticmethod
    def create(path: str, source_name: str, scan_id: uuid.UUID | str) -> SBOMDocument:
        """
        Validate inputs and create a new SBOM document linked to *scan_id*.

        :raises ValueError: if *path* or *source_name* is empty or blank.
        """
        path = path.strip()
        source_name = source_name.strip()
        if not path:
            raise ValueError("SBOM document path must not be empty.")
        if not source_name:
            raise ValueError("SBOM document source_name must not be empty.")
        if isinstance(scan_id, str):
            scan_id = uuid.UUID(scan_id)
        return SBOMDocument.create(path, source_name, scan_id)

    @staticmethod
    def update(
        document: SBOMDocument | uuid.UUID | str,
        path: str,
        source_name: str,
    ) -> SBOMDocument:
        """
        Update *document*'s path and source_name.  *document* may be a
        :class:`SBOMDocument` instance, a UUID object, or a UUID string.

        :raises ValueError: if *path* or *source_name* is empty or blank,
                            or document is not found.
        """
        path = path.strip()
        source_name = source_name.strip()
        if not path:
            raise ValueError("SBOM document path must not be empty.")
        if not source_name:
            raise ValueError("SBOM document source_name must not be empty.")
        resolved: SBOMDocument
        if isinstance(document, SBOMDocument):
            resolved = document
        else:
            found = SBOMDocumentController.get(document)
            if found is None:
                raise ValueError("SBOM document not found.")
            resolved = found
        return resolved.update(path, source_name)

    @staticmethod
    def delete(document: SBOMDocument | uuid.UUID | str) -> None:
        """
        Delete *document*.  *document* may be a :class:`SBOMDocument` instance,
        a UUID object, or a UUID string.

        :raises ValueError: if the document is not found.
        """
        resolved: SBOMDocument
        if isinstance(document, SBOMDocument):
            resolved = document
        else:
            found = SBOMDocumentController.get(document)
            if found is None:
                raise ValueError("SBOM document not found.")
            resolved = found
        resolved.delete()

# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import uuid

from ..controllers import ControllersCache, PackagesController, VulnerabilitiesController, AssessmentsController
from ..helpers.active_scans import active_package_ids_for_scans, active_sbom_scan_ids_for_variant
from ..helpers.datetime_utils import normalize_timestamp_for_sort
from ..helpers.export_files import file_metadata, INVENTORY_UNKNOWN_COMMENT
from ..helpers.export_evidence import dependency_relationships, export_evidence, EVIDENCE_PREFIX
from ..helpers.verbose import warn
from ..models.assessment import Assessment
from .fast_spdx3 import FastSPDX3


def generate_spdx_namespace() -> str:
    """Generate SPDX namespace UUID-based for SPDX 3.0 specv3 documents."""
    ns_uuid = os.getenv("SPDX_DOCUMENT_UUID", str(uuid.uuid4()))
    return f"https://spdx.org/spdxdocs/{ns_uuid}.spdx.json-specv3"


class SPDX3:
    def __init__(self, controllers: ControllersCache):
        self.packagesCtrl: PackagesController = controllers.packages
        self.vulnerabilitiesCtrl: VulnerabilitiesController = controllers.vulnerabilities
        self.assessmentsCtrl: AssessmentsController = controllers.assessments
        self.pkg_to_ref: Dict[str, str] = {}
        self.vuln_to_ref: Dict[str, str] = {}
        self._active_package_ids_by_variant: Dict[str, set[uuid.UUID]] = {}
        self.namespace = generate_spdx_namespace()
        self._creation_info_ref: Optional[str] = None
        self._id_counter = 0  # sequential counter for gnrtdX IDs

    def _next_spdx_ref(self) -> str:
        """Return next sequential SPDXRef-gnrtdX string."""
        self._id_counter += 1
        return f"{self.namespace}/SPDXRef-gnrtd{self._id_counter}"

    def _get_spdx_id(self, obj_id: str, mapping: Dict[str, str]) -> str:
        if obj_id not in mapping:
            mapping[obj_id] = self._next_spdx_ref()
        return mapping[obj_id]

    # Map short names to SPDX 3.0.1 ExternalIdentifierType enum values
    _EXT_ID_TYPE_MAP = {
        "purl": "packageUrl",
        "securityAdvisory": "securityOther",
    }

    def _make_external_identifiers(self, pairs: List[tuple[str, Any]]) -> List[Dict[str, str]]:
        return [
            {
                "type": "ExternalIdentifier",
                "externalIdentifierType": self._EXT_ID_TYPE_MAP.get(t, t),
                "identifier": v,
            }
            for t, v in pairs if v
        ]

    def create_document_structure(self, author: str = "Savoir-faire Linux") -> Dict[str, Any]:
        """Create the base SPDX 3.0 document structure."""

        document_id = f"{self.namespace}#SPDXRef-Document"

        # Create creation info with blank node ID
        creation_info = {
            "@id": "_:creationInfo_0",
            "type": "CreationInfo",
            "specVersion": "3.0.1",
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "createdBy": [
                "https://vulnscout.io/spdx/Organization_SavoirFaireLinux",
                "https://vulnscout.io/spdx/Tool_VulnScout"
            ],
            "createdUsing": [
                "https://vulnscout.io/spdx/Tool_VulnScout"
            ]
        }

        # Cache creation info reference for reuse
        self._creation_info_ref = str(creation_info["@id"])

        # Create the SPDX document node
        spdx_document = {
            "type": "SpdxDocument",
            "spdxId": document_id,
            "name": "PRODUCT_NAME-1.0.0",
            "dataLicense": "http://spdx.org/licenses/CC0-1.0",
            "rootElement": [],
            "creationInfo": self._creation_info_ref
        }

        return {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [creation_info, spdx_document]
        }

    def generate_package_element(self, pkg) -> Dict[str, Any]:
        """Generate SPDX 3.0 package element from Package object."""

        spdx_id = self._get_spdx_id(pkg.string_id, self.pkg_to_ref)

        element = {
            "type": "software_Package",
            "spdxId": spdx_id,
            "name": pkg.name,
        }

        if pkg.version:
            element["software_packageVersion"] = pkg.version

        # Create external identifiers using helper method
        external_ids = self._make_external_identifiers(
            [("cpe23", cpe) for cpe in (pkg.cpe or [])] + [("purl", purl) for purl in (pkg.purl or [])]
        )
        if external_ids:
            element["externalIdentifier"] = external_ids

        element["software_primaryPurpose"] = "application"
        if pkg.source_file_count is None:
            element["comment"] = INVENTORY_UNKNOWN_COMMENT

        element["creationInfo"] = "_:creationInfo_0"

        return element

    def generate_vulnerability_element(self, vuln_id: str, vuln) -> Dict[str, Any]:
        """Generate SPDX 3.0 vulnerability element."""

        spdx_id = self._get_spdx_id(vuln_id, self.vuln_to_ref)

        # Create external identifiers using helper method
        external_identifiers = self._make_external_identifiers(
            [("cve", vuln_id)] + [("securityAdvisory", url) for url in (vuln.urls or [])]
        )

        element = {
            "type": "security_Vulnerability",
            "spdxId": spdx_id,
            "externalIdentifier": external_identifiers,
            "creationInfo": "_:creationInfo_0"
        }
        if vuln.description:
            element["description"] = vuln.description

        return element

    def generate_relationship(self, from_ref: str, to_refs: List[str], relationship_type: str) -> Dict[str, Any]:
        """Generate SPDX 3.0 relationship element."""

        # Generate deterministic ID based on relationship content
        relationship_id = self._next_spdx_ref()

        return {
            "type": "Relationship",
            "spdxId": relationship_id,
            "from": from_ref,
            "relationshipType": relationship_type,
            "to": to_refs,
            "creationInfo": "_:creationInfo_0"
        }

    def generate_assessment_relationships(self, vuln_id: str) -> List[Dict[str, Any]]:
        """Consolidate current target verdicts without hiding affected variants."""
        latest: Dict[tuple[Optional[str], str], Assessment] = {}
        scope = self.assessmentsCtrl.scope
        allowed_variants = {str(variant_id) for variant_id in scope.variant_ids} if scope is not None else None
        current_variant_id = self.assessmentsCtrl.current_variant_id
        dto_variant_id = str(current_variant_id) if current_variant_id is not None else None
        for assessment in self.assessmentsCtrl.gets_by_vuln(vuln_id):
            if assessment.origin == "ai":
                continue
            targets: List[tuple[Optional[str], str]] = [
                (target["variant_id"], target["package"]) for target in assessment.target_pairs
            ] or [(dto_variant_id, package_id) for package_id in assessment.packages]
            for variant_id, package_id in targets:
                if allowed_variants is not None and variant_id is not None and variant_id not in allowed_variants:
                    continue
                if package_id not in self.pkg_to_ref:
                    continue
                if variant_id is not None:
                    active_package_ids = self._active_package_ids_by_variant.get(variant_id)
                    if active_package_ids is None:
                        active_package_ids = active_package_ids_for_scans(
                            active_sbom_scan_ids_for_variant(uuid.UUID(variant_id)),
                            restrict_to_package_ids=scope.package_ids if scope is not None else None,
                        )
                        self._active_package_ids_by_variant[variant_id] = active_package_ids
                    if self.packagesCtrl.get_or_resolve_db_id(package_id) not in active_package_ids:
                        continue
                target_key = (variant_id, package_id)
                previous = latest.get(target_key)
                if previous is None or (
                    normalize_timestamp_for_sort(previous.timestamp)
                    < normalize_timestamp_for_sort(assessment.timestamp)
                ):
                    latest[target_key] = assessment

        by_package: Dict[str, List[Assessment]] = {}
        for (_, package_id), assessment in latest.items():
            by_package.setdefault(package_id, []).append(assessment)
        status_map = {
            "not_affected": ("NotAffected", "doesNotAffect"),
            "affected": ("Affected", "affects"),
            "fixed": ("Fixed", "fixedIn"),
            "under_investigation": ("UnderInvestigation", "underInvestigationFor"),
        }
        justification_map = {value: key for key, value in FastSPDX3.JUSTIFICATION_MAP.items()}
        relationships = []
        for package_id, current_assessments in by_package.items():
            statuses = {assessment.get_status_openvex() or "" for assessment in current_assessments}
            if not statuses <= status_map.keys():
                warn(f"[SPDX3 export {vuln_id!r}] unsupported assessment statuses {statuses!r}")
                continue
            conflicting = len(statuses) > 1
            status = next(iter(statuses))
            if conflicting:
                status = "affected" if "affected" in statuses else "under_investigation"
            matching_assessments = [
                assessment for assessment in current_assessments if assessment.get_status_openvex() == status
            ]
            assessment = max(
                matching_assessments or current_assessments,
                key=lambda assessment: normalize_timestamp_for_sort(assessment.timestamp),
            )
            vex_type, relationship_type = status_map[status]
            relationship = self.generate_relationship(
                self.vuln_to_ref[vuln_id], [self.pkg_to_ref[package_id]], relationship_type,
            )
            relationship["type"] = f"security_Vex{vex_type}VulnAssessmentRelationship"
            relationship["security_vexVersion"] = "1.0.0"
            if assessment.timestamp is not None:
                relationship["security_publishedTime"] = (
                    normalize_timestamp_for_sort(assessment.timestamp).astimezone(timezone.utc)
                    .strftime("%Y-%m-%dT%H:%M:%SZ")
                )
            notes = assessment.status_notes if matching_assessments else ""
            if conflicting:
                conflict_note = (
                    f"Consolidated export: conflicting current variant statuses ({', '.join(sorted(statuses))}); "
                    f"reported as {status}."
                )
                notes = f"{conflict_note}\n{notes}" if notes else conflict_note
            if notes:
                relationship["security_statusNotes"] = notes
            if matching_assessments:
                if status == "not_affected":
                    justification = assessment.get_justification_openvex()
                    if justification in justification_map:
                        relationship["security_justificationType"] = justification_map[justification]
                    if assessment.impact_statement:
                        relationship["security_impactStatement"] = assessment.impact_statement
                elif assessment.impact_statement:
                    relationship["description"] = assessment.impact_statement
                if status == "affected":
                    relationship["security_actionStatement"] = assessment.workaround or ""
            relationships.append(relationship)
        return relationships

    def output_as_json(self, author: str = "Savoir-faire Linux") -> str:
        self._active_package_ids_by_variant.clear()
        spdx_doc = self.create_document_structure(author)
        graph = spdx_doc["@graph"]

        elements_to_add = []
        relationships_to_add = []

        for pkg in self.packagesCtrl:
            pkg_element = self.generate_package_element(pkg)
            elements_to_add.append(pkg_element)
            if pkg.source_urls:
                build_ref = self._next_spdx_ref()
                elements_to_add.append({
                    "type": "build_Build", "spdxId": build_ref, "name": f"{pkg.name} source provenance",
                    "build_buildType": "https://vulnscout.io/build-types/source-provenance",
                    "creationInfo": self._creation_info_ref,
                })
                source_refs = []
                for url in pkg.source_urls:
                    source_ref = self._next_spdx_ref()
                    source_refs.append(source_ref)
                    elements_to_add.append({
                        "type": "software_Package", "spdxId": source_ref, "name": f"{pkg.name}-source",
                        "software_primaryPurpose": "source", "software_downloadLocation": url,
                        "creationInfo": self._creation_info_ref,
                    })
                relationships_to_add.append(self.generate_relationship(build_ref, source_refs, "hasInput"))
                relationships_to_add.append(self.generate_relationship(build_ref, [pkg_element["spdxId"]], "hasOutput"))

        for record in self.packagesCtrl.recorded_files():
            ref = self._next_spdx_ref()
            elements_to_add.append({
                "type": "software_File", "spdxId": ref, "name": record["path"],
                "creationInfo": self._creation_info_ref, **file_metadata(record, spdx3=True),
            })
            for owner in record["packages"]:
                if owner in self.pkg_to_ref:
                    relationships_to_add.append(self.generate_relationship(self.pkg_to_ref[owner], [ref], "contains"))

        for source, target, kind, scope in dependency_relationships(self.packagesCtrl, spdx3=True):
            relationship = self.generate_relationship(self.pkg_to_ref[source], [self.pkg_to_ref[target]], kind)
            if scope:
                relationship.update(type="LifecycleScopedRelationship", scope=scope)
            relationships_to_add.append(relationship)

        evidence = export_evidence(self.packagesCtrl, self.pkg_to_ref)
        graph[1]["comment"] = EVIDENCE_PREFIX + json.dumps(evidence, sort_keys=True)
        for build_target in evidence["build_targets"]:
            build_ref = self._next_spdx_ref()
            elements_to_add.append({
                "type": "build_Build", "spdxId": build_ref, "name": build_target["name"],
                "creationInfo": self._creation_info_ref,
                "build_buildType": "https://vulnscout.io/build-types/recorded-compiler-metadata",
                "comment": "Recorded compiler metadata only; not a reconstruction of the full build graph.",
                "build_parameter": [
                    {"type": "DictionaryEntry", "key": f"compile:{kind}:{language['language']}", "value": value}
                    for language in build_target["languages"] for kind in ("flags", "defines")
                    for value in language[kind]
                ],
            })
            relationships_to_add.append(self.generate_relationship(build_ref, build_target["package_ids"], "hasOutput"))

        for vuln_id, vuln in self.vulnerabilitiesCtrl.vulnerabilities.items():
            vuln_element = self.generate_vulnerability_element(vuln_id, vuln)
            elements_to_add.append(vuln_element)

        graph.extend(elements_to_add)

        document_node = next((item for item in graph if item.get("type") == "SpdxDocument"), None)
        if document_node and elements_to_add:
            root_elements = [element["spdxId"] for element in elements_to_add]
            # Create single relationship describing all elements
            rel = self.generate_relationship(document_node["spdxId"], root_elements, "describes")
            rel["creationInfo"] = self._creation_info_ref
            relationships_to_add.append(rel)
            document_node["rootElement"] = root_elements

        for vuln_id, vuln in self.vulnerabilitiesCtrl.vulnerabilities.items():
            vuln_ref = self.vuln_to_ref.get(vuln_id)
            if not vuln_ref:
                continue
            assessment_relationships = self.generate_assessment_relationships(vuln_id)
            assessed_refs = {ref for relationship in assessment_relationships for ref in relationship["to"]}
            if hasattr(vuln, "packages"):
                for pkg_id in vuln.packages:
                    pkg_ref = self.pkg_to_ref.get(pkg_id)
                    if pkg_ref and pkg_ref not in assessed_refs:
                        rel = self.generate_relationship(vuln_ref, [pkg_ref], "affects")
                        rel["creationInfo"] = self._creation_info_ref
                        relationships_to_add.append(rel)
            relationships_to_add.extend(assessment_relationships)

        graph.extend(relationships_to_add)
        return json.dumps(spdx_doc, indent=2)

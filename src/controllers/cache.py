from __future__ import annotations

import typing
from functools import cached_property

from . import (
    PackagesController,
    AssessmentsController,
    VulnerabilitiesController,
    ConditionParser,
    FindingController,
    MetricsController,
    ProjectController,
    SBOMDocumentController,
    ScanController,
    TimeEstimateController,
    VariantController,
)

if typing.TYPE_CHECKING:
    from ..helpers.export_scope import ExportScope


class ControllersCache:
    def __init__(self, scope: "ExportScope | None" = None):
        """Create a cache of controllers.

        When *scope* is provided the package/vulnerability/assessment
        controllers only expose the in-scope data, so every view built from
        this cache produces an export restricted to that project/variant.
        """
        self._scope = scope

    @cached_property
    def packages(self) -> PackagesController:
        return PackagesController(scope=self._scope)

    @cached_property
    def assessments(self) -> AssessmentsController:
        return AssessmentsController(self.packages, scope=self._scope)

    @cached_property
    def vulnerabilities(self) -> VulnerabilitiesController:
        return VulnerabilitiesController(self.packages, scope=self._scope)

    @cached_property
    def conditions_parser(self) -> ConditionParser:
        return ConditionParser()

    @cached_property
    def finding(self) -> FindingController:
        return FindingController()

    @cached_property
    def metrics(self) -> MetricsController:
        return MetricsController()

    @cached_property
    def project(self) -> ProjectController:
        return ProjectController()

    @cached_property
    def sbom_document(self) -> SBOMDocumentController:
        return SBOMDocumentController()

    @cached_property
    def scan(self) -> ScanController:
        return ScanController()

    @cached_property
    def time_estimate(self) -> TimeEstimateController:
        return TimeEstimateController()

    @cached_property
    def variant(self) -> VariantController:
        return VariantController()

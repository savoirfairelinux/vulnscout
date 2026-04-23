# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import json
import uuid
from datetime import datetime, timezone


def setup_demo_db(app):
    """Create all DB tables and insert demo data into the test in-memory DB."""
    from src.extensions import db
    from src.models.package import Package
    from src.models.vulnerability import Vulnerability
    from src.models.finding import Finding
    from src.models.assessment import Assessment
    from src.models.project import Project
    from src.models.variant import Variant
    from src.models.scan import Scan
    from src.models.sbom_document import SBOMDocument
    from src.models.sbom_package import SBOMPackage
    from src.models.observation import Observation

    with app.app_context():
        db.drop_all()
        db.create_all()

        # Demo package: cairo 1.16.0
        pkg = Package.find_or_create(
            "cairo",
            "1.16.0",
            [
                "cpe:2.3:a:*:cairo:1.16.0:*:*:*:*:*:*:*",
                "cpe:2.3:*:*:cairo:1.16.0:*:*:*:*:*:*:*",
                "cpe:2.3:a:cairographics:cairo:*:*:*:*:*:*:*:*",
                "cpe:2.3:a:cairographics:cairo:1.16.0:*:*:*:*:*:*:*",
            ],
            ["pkg:generic/cairo@1.16.0"],
            "",
        )
        db.session.commit()

        # Demo vulnerability: CVE-2020-35492
        vuln = Vulnerability.create_record(
            id="CVE-2020-35492",
            description="A flaw was found in cairo's image-compositor.c in all versions prior to 1.17.4 [...]",
            status="high",
            epss_score=0.311320,
            links=[
                "https://bugzilla.redhat.com/show_bug.cgi?id=1898396",
                "https://security.gentoo.org/glsa/202305-21",
                "https://nvd.nist.gov/vuln/detail/CVE-2020-35492",
            ],
        )

        db.session.commit()

        # Link package to vulnerability via Finding
        finding = Finding.get_or_create(pkg.id, "CVE-2020-35492")

        # Demo assessment with known UUID (tests check for this exact ID)
        assessment = Assessment(
            id=uuid.UUID("da4d18f0-d89e-4d54-819d-86fc884cc737"),
            status="fixed",
            timestamp=datetime(2024, 6, 7, 15, 10, 31, tzinfo=timezone.utc),
            status_notes="",
            justification="",
            impact_statement="Yocto reported vulnerability as Patched",
            responses=[],
            workaround="",
            finding_id=finding.id,
        )
        db.session.add(assessment)
        db.session.commit()

        # SBOM chain: project → variant → scan → sbom_document → sbom_package
        # Required so that _populate_found_by() can derive found_by at query time.
        project = Project(id=uuid.UUID("11111111-1111-1111-1111-111111111111"), name="demo")
        db.session.add(project)
        variant = Variant(
            id=uuid.UUID("22222222-2222-2222-2222-222222222222"),
            name="default",
            project_id=project.id,
        )
        db.session.add(variant)
        scan = Scan(
            id=uuid.UUID("33333333-3333-3333-3333-333333333333"),
            variant_id=variant.id,
        )
        db.session.add(scan)
        sbom_doc = SBOMDocument(
            id=uuid.UUID("44444444-4444-4444-4444-444444444444"),
            path="/demo/grype.json",
            source_name="grype.json",
            format="grype",
            scan_id=scan.id,
        )
        db.session.add(sbom_doc)
        db.session.add(SBOMPackage(sbom_document_id=sbom_doc.id, package_id=pkg.id))
        db.session.add(Observation(finding_id=finding.id, scan_id=scan.id))
        db.session.commit()


def write_demo_files(files):
    """Write files with an real-life example issued fron cairo vulnerability."""

    if "status" in files:
        files["status"].write_text("__END_OF_SCAN_SCRIPT__")

    if "packages" in files:
        files["packages"].write_text(json.dumps({
            "cairo@1.16.0": {
                "name": "cairo",
                "version": "1.16.0",
                "cpe": [
                    "cpe:2.3:a:*:cairo:1.16.0:*:*:*:*:*:*:*",
                    "cpe:2.3:*:*:cairo:1.16.0:*:*:*:*:*:*:*",
                    "cpe:2.3:a:cairographics:cairo:*:*:*:*:*:*:*:*",
                    "cpe:2.3:a:cairographics:cairo:1.16.0:*:*:*:*:*:*:*"
                ],
                "purl": [
                    "pkg:generic/cairo@1.16.0"
                ]
            }
        }))

    if "vulnerabilities" in files:
        files["vulnerabilities"].write_text(json.dumps({
            "CVE-2020-35492": {
                "id": "CVE-2020-35492",
                "found_by": ["grype"],
                "datasource": "https://nvd.nist.gov/vuln/detail/CVE-2020-35492",
                "namespace": "nvd:cpe",
                "aliases": [],
                "related_vulnerabilities": [],
                "urls": [
                    "https://bugzilla.redhat.com/show_bug.cgi?id=1898396",
                    "https://security.gentoo.org/glsa/202305-21",
                    "https://nvd.nist.gov/vuln/detail/CVE-2020-35492"
                ],
                "texts": {
                    "description": "A flaw was found in cairo's image-compositor.c in all versions prior to 1.17.4 [...]"
                },
                "fix": {
                    "versions_impacted": [],
                    "versions_fixing": [],
                    "state": "unknown"
                },
                "epss": {
                    "score": "0.311320000",
                    "percentile": "0.850420000"
                },
                "severity": {
                    "severity": "high",
                    "min_score": 6.8,
                    "max_score": 7.8,
                    "cvss": [
                        {
                            "version": "3.1",
                            "vector_string": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                            "author": "nvd@nist.gov",
                            "base_score": 7.8,
                            "exploitability_score": 1.8,
                            "impact_score": 5.9,
                            "severity": "High"
                        }
                    ]
                },
                "advisories": [],
                "packages": [
                    "cairo@1.16.0"
                ]
            }
        }))

    if "assessments" in files:
        files["assessments"].write_text(json.dumps({
            "da4d18f0-d89e-4d54-819d-86fc884cc737": {
                "id": "da4d18f0-d89e-4d54-819d-86fc884cc737",
                "vuln_id": "CVE-2020-35492",
                "packages": ["cairo@1.16.0"],
                "timestamp": "2024-06-07T15:10:31.107310",
                "last_update": "2024-06-07T15:10:31.107311",
                "status": "fixed",
                "status_notes": "",
                "justification": "",
                "impact_statement": "Yocto reported vulnerability as Patched",
                "responses": [],
                "workaround": "",
                "workaround_timestamp": ""
            }
        }))
    return files

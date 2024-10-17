# -*- coding: utf-8 -*-
import json


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

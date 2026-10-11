# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.views.spdx import SPDX
from src.models.package import Package
from src.controllers import ControllersCache
import json
from xml.etree import ElementTree


@pytest.fixture
def spdx_parser():
    return SPDX(ControllersCache())


def test_export_empty_json(spdx_parser):
    output = json.loads(spdx_parser.output_as_json(True, "MY_AUTHOR_NAME"))
    try:
        assert {
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
        }.items() <= output.items()
        assert output["documentNamespace"].startswith("https://")
        assert len(output["name"]) > 5
        assert len(output["creationInfo"]["creators"]) == 2
        assert any(map(lambda x: "MY_AUTHOR_NAME" in x, output["creationInfo"]["creators"]))
        assert "packages" not in output or len(output["packages"]) == 0
    except Exception as e:
        print(json.dumps(output, indent=2))
        raise e


def test_export_uses_generated_namespace_when_document_url_is_blank(monkeypatch, spdx_parser):
    monkeypatch.setenv("DOCUMENT_URL", "")

    json_output = json.loads(spdx_parser.output_as_json(True, "MY_AUTHOR_NAME"))
    assert json_output["documentNamespace"].startswith("https://spdx.org/spdxdocs/")

    xml_output = spdx_parser.output_as_xml(True, "MY_AUTHOR_NAME")
    assert ElementTree.fromstring(xml_output).tag == "Document"


def test_export_components_json(spdx_parser):
    pkg = Package("binutils", "2.38", [], [])
    pkg.add_purl("pkg:generic/gnu/binutils@2.38")
    pkg.add_cpe("cpe:2.3:a:gnu:binutils:2.38:*:*:*:*:*:*:*")
    spdx_parser.packagesCtrl.add(pkg)
    opsys = Package("linux", "6.8.0-40-generic", ["cpe:2.3:o:*:linux:6.8.0-40-generic:*:*:*:*:*:*:*"], [])
    spdx_parser.packagesCtrl.add(opsys)
    hw = Package("xyz", "rev2.3", ["cpe:2.3:h:*:xyz:rev2.3:*:*:*:*:*:*:*"], [])
    spdx_parser.packagesCtrl.add(hw)
    output = json.loads(spdx_parser.output_as_json())

    try:
        assert {
            "primaryPackagePurpose": "APPLICATION",
            "name": "binutils",
            "versionInfo": "2.38",
            "filesAnalyzed": False,
            "downloadLocation": "NOASSERTION"
        }.items() <= output["packages"][0].items()
        assert {
            "primaryPackagePurpose": "OPERATING-SYSTEM",
            "name": "linux",
            "versionInfo": "6.8.0-40-generic",
            "filesAnalyzed": False,
            "downloadLocation": "NOASSERTION"
        }.items() <= output["packages"][1].items()
        assert {
            "primaryPackagePurpose": "DEVICE",
            "name": "xyz",
            "versionInfo": "rev2.3",
            "filesAnalyzed": False,
            "downloadLocation": "NOASSERTION"
        }.items() <= output["packages"][2].items()

        assert len(output["packages"]) == 3
        assert output["packages"][0]["externalRefs"] == [{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": "pkg:generic/gnu/binutils@2.38",
        }]
    except Exception as e:
        print(json.dumps(output, indent=2))
        raise e


@pytest.mark.parametrize("fast", [False, True])
def test_spdx2_export_roundtrips_all_source_revisions(spdx_parser, fast):
    from src.views.fast_spdx import FastSPDX, SPDX2_SYNTHETIC_SOURCE_COMMENT

    urls = [f"git+https://example.org/source-{i}.git@{str(i) * 40}" for i in (1, 2)]
    spdx_parser.packagesCtrl.add(Package("libc6", "2.41", source_urls=urls))
    output = json.loads(spdx_parser.output_as_json())
    binary = next(pkg for pkg in output["packages"] if pkg["name"] == "libc6")
    assert binary["versionInfo"] == "2.41"
    assert sorted(pkg["downloadLocation"] for pkg in output["packages"]
                  if pkg.get("primaryPackagePurpose") == "SOURCE") == urls
    assert all(pkg["comment"] == SPDX2_SYNTHETIC_SOURCE_COMMENT for pkg in output["packages"]
               if pkg.get("primaryPackagePurpose") == "SOURCE")
    xml = ElementTree.fromstring(spdx_parser.output_as_xml())
    assert [pkg.findtext("comment") for pkg in xml.findall("packages")
            if pkg.findtext("primaryPackagePurpose") == "SOURCE"] == [SPDX2_SYNTHETIC_SOURCE_COMMENT] * 2
    for _ in range(3):
        controllers = ControllersCache()
        if fast:
            FastSPDX(controllers).parse_from_dict(output)
        else:
            parser = SPDX(controllers)
            parser.load_from_dict(output)
            parser.parse_and_merge()
        assert set(controllers.packages.packages) == {"libc6@2.41"}
        assert {pkg.string_id for pkg in Package.get_all()} == {"libc6@2.41"}
        restored = controllers.packages.get("libc6@2.41")
        assert sorted(restored.source_urls) == urls
        assert restored.version_info["revision_conflict"]
        output = json.loads(SPDX(controllers).output_as_json())
        assert len(output["packages"]) == 3


@pytest.mark.parametrize("fast", [False, True])
@pytest.mark.parametrize("marked", [False, True])
def test_spdx2_source_packages_with_independent_roles_are_not_dropped(spdx_parser, fast, marked):
    from src.views.fast_spdx import FastSPDX, SPDX2_SYNTHETIC_SOURCE_COMMENT

    spdx_parser.packagesCtrl.add(Package("app", "1.0"))
    output = json.loads(spdx_parser.output_as_json())
    binary_id = output["packages"][0]["SPDXID"]
    for role in ("versioned", "described", "dependency", "standalone", "generated-only"):
        source_id = f"SPDXRef-{role}"
        source = {"SPDXID": source_id, "name": role, "primaryPackagePurpose": "SOURCE",
                  "downloadLocation": f"git+https://example.org/{role}@{'a' * 40}", "filesAnalyzed": False}
        if role == "versioned":
            source["versionInfo"] = "1.0"
        if marked and role != "generated-only":
            source["comment"] = SPDX2_SYNTHETIC_SOURCE_COMMENT
        output["packages"].append(source)
        if role != "standalone":
            output["relationships"].append({
                "spdxElementId": binary_id, "relationshipType": "GENERATED_FROM", "relatedSpdxElement": source_id,
            })
        if role in {"described", "dependency"}:
            output["relationships"].append({
                "spdxElementId": "SPDXRef-DOCUMENT" if role == "described" else binary_id,
                "relationshipType": "DESCRIBES" if role == "described" else "DEPENDS_ON",
                "relatedSpdxElement": source_id,
            })
    controllers = ControllersCache()
    if fast:
        FastSPDX(controllers).parse_from_dict(output)
    else:
        parser = SPDX(controllers)
        parser.load_from_dict(output)
        parser.parse_and_merge()
    assert set(controllers.packages.packages) == {
        "app@1.0", "versioned@1.0", "described@", "dependency@", "standalone@", "generated-only@",
    }


def test_spdx2_xml_roundtrip_preserves_purls_and_skips_marked_sources(spdx_parser, tmp_path):
    url = f"git+https://example.org/lib@{'a' * 40}"
    purl = "pkg:generic/lib@1.0"
    spdx_parser.packagesCtrl.add(Package("lib", "1.0", purl=[purl], source_urls=[url]))
    path = tmp_path / "marked.spdx.xml"
    path.write_text(spdx_parser.output_as_xml())
    controllers = ControllersCache()
    parser = SPDX(controllers)
    parser.load_from_file(str(path))
    parser.parse_and_merge()
    assert set(controllers.packages.packages) == {"lib@1.0"}
    restored = controllers.packages.get("lib@1.0")
    assert restored.source_urls == [url]
    assert purl in restored.purl


@pytest.mark.parametrize("fast", [False, True])
def test_unmarked_old_exports_preserve_inventory_and_stop_further_growth(spdx_parser, fast):
    from src.views.fast_spdx import FastSPDX

    url = f"git+https://example.org/lib@{'a' * 40}"
    spdx_parser.packagesCtrl.add(Package("libc6", "2.41", source_urls=[url]))
    output = json.loads(spdx_parser.output_as_json())
    for package in output["packages"]:
        package.pop("comment", None)
    expected = {"libc6@2.41", "libc6-source@"}
    for _ in range(3):
        controllers = ControllersCache()
        if fast:
            FastSPDX(controllers).parse_from_dict(output)
        else:
            parser = SPDX(controllers)
            parser.load_from_dict(output)
            parser.parse_and_merge()
        assert set(controllers.packages.packages) == expected
        assert {pkg.string_id for pkg in Package.get_all()} == expected
        assert all(controllers.packages.get(sid).source_urls == [url] for sid in expected)
        output = json.loads(SPDX(controllers).output_as_json())
        assert len(output["packages"]) == 4


def test_export_normalizes_enum_values_without_modifying_package_text(spdx_parser):
    name = "PACKAGE_MANAGER-OPERATING_SYSTEM"
    purl = f"pkg:generic/{name}@1.0"
    spdx_parser.packagesCtrl.add(Package(
        name, "1.0", purl=[purl], cpe=[f"cpe:2.3:o:*:{name}:1.0:*:*:*:*:*:*:*"],
    ))
    output = json.loads(spdx_parser.output_as_json())
    package = output["packages"][0]
    assert package["name"] == name
    assert package["primaryPackagePurpose"] == "OPERATING-SYSTEM"
    assert package["externalRefs"][0] == {
        "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl,
    }
    xml = ElementTree.fromstring(spdx_parser.output_as_xml())
    assert xml.findtext("./packages/name") == name
    assert xml.findtext("./packages/primaryPackagePurpose") == "OPERATING-SYSTEM"
    assert xml.findtext("./packages/externalRefs/referenceCategory") == "PACKAGE-MANAGER"
    assert xml.findtext("./packages/externalRefs/referenceLocator") == purl


@pytest.mark.parametrize("format", ["json", "xml"])
def test_document_converter_normalizes_persistent_ids_and_preserves_security_references(spdx_parser, format):
    from io import StringIO
    from spdx_tools.spdx.model.package import ExternalPackageRef, ExternalPackageRefCategory
    from spdx_tools.spdx.writer.json.json_writer import write_document_to_stream as write_json
    from spdx_tools.spdx.writer.xml.xml_writer import write_document_to_stream as write_xml
    from src.views.spdx import _SPDXDocumentConverter

    spdx_parser.packagesCtrl.add(Package("PERSISTENT_ID", "1.0"))
    spdx_parser.output_as_json()
    locator = f"swh:1:cnt:{'a' * 40}"
    cpe = "cpe:2.3:a:vendor:lib:1.0:*:*:*:*:*:*:*"
    spdx_parser.sbom.packages[0].external_references = [
        ExternalPackageRef(ExternalPackageRefCategory.PERSISTENT_ID, "swh", locator),
        ExternalPackageRef(ExternalPackageRefCategory.SECURITY, "cpe23Type", cpe),
    ]
    stream = StringIO()
    writer = write_json if format == "json" else write_xml
    writer(spdx_parser.sbom, stream, validate=False, converter=_SPDXDocumentConverter())
    if format == "json":
        package = json.loads(stream.getvalue())["packages"][0]
        assert package["name"] == "PERSISTENT_ID"
        assert package["externalRefs"] == [
            {"referenceCategory": "PERSISTENT-ID", "referenceType": "swh", "referenceLocator": locator},
            {"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": cpe},
        ]
    else:
        package = ElementTree.fromstring(stream.getvalue()).find("packages")
        assert package.findtext("name") == "PERSISTENT_ID"
        assert [(ref.findtext("referenceCategory"), ref.findtext("referenceType"), ref.findtext("referenceLocator"))
                for ref in package.findall("externalRefs")] == [
            ("PERSISTENT-ID", "swh", locator), ("SECURITY", "cpe23Type", cpe),
        ]

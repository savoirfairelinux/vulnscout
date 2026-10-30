# SBOM and Scan Reference

Technical details of SBOM interpretation, provenance, and saved scan settings.
For everyday use, see [Interactive Mode](interactive-mode.md).

## Release Versions and Source Revisions

A trailing `+git` marker is ignored for release comparison, so `2.43+git` and
`2.43` agree; original identifier values remain in the evidence.

CPE update fields are included in the release: version `4.5.0` with update
`rc2` represents `4.5.0-rc2`, not the final `4.5.0` release. Hostap tags such as
`hostap_2_11` are displayed as `2.11` when the PURL explicitly identifies the
upstream Hostap Git repository. Similarly, Trusted Firmware-M tags such as
`TF-Mv2.3.1` are displayed as `2.3.1` only when the PURL identifies the upstream
Trusted Firmware-M repository. Original tag spellings and identifiers remain
visible in the evidence; unrelated tags and genuinely different releases still
produce a conflict.

Reimport older SBOMs to populate source revisions from the original files.

## Zephyr JSON-LD Provenance

For SPDX 3 JSON-LD produced by **West SPDX Generator**, VulnScout stores the
upstream dependency, source checkout and proven compiled target as **one package**
when explicit provenance connects them. For example, `mbedtls-deps`,
`mbedtls-sources` and `mbedtls` become `mbedtls@4.1.1` in the `packages` table.
The checkout revision is additional package metadata, not another package
identity. CPEs, PURLs and dependencies are combined and deduplicated; internal
dependency edges are omitted.
When several independently proven groups identify the same release in one
scan, their identifiers and checkout revisions are retained together. Multiple
checkout revisions remain visible as a revision conflict rather than being
replaced by the last group's evidence.

The package name carries a **Built component** badge when explicit provenance
connects it to a compiled target, or **Workspace component** when only its
upstream/source component is established. Ordinary packages use the default
`normal` type and have no badge. These types are stored on `sbom_packages`, not
globally on `packages`: the same package can be built in one variant and
workspace-only in another. Selecting several scopes can show both badges on
one package row. Upgrading backfills types from the preserved JSON-LD provenance
without adding packages or changing assessment identities.

Scanners, exports, findings and assessments use this ordinary persisted package
directly. Provenance facets are metadata, not separate assessment targets.
Upgrading the database consolidates previously recorded groups and moves their
findings and assessment targets to the parent. Conflicting duplicate reviews
or time estimates stop consolidation
with an explicit error rather than silently discarding analyst data.

Consolidation requires explicit upstream/source variant relationships, not just
matching name suffixes. Compiled targets join only through build input/output
ownership. West CMake `modules__<name>` targets can match the module name when
build provenance also connects them to that module's source component, even
if they include Zephyr adapter code. A matching target name alone is insufficient.
Other generated target names require exactly one candidate target whose inputs
belong exclusively to that source component.
Upstream/source records can still enrich a package without a proven
compiled target. This does not establish that a package is included in firmware.
Ambiguous compiled targets remain separate while the proven upstream/source
pair becomes a workspace component. Contradictory metadata within a group
prevents its consolidation. Yocto and other producers
and formats are unchanged, and revisions remain scoped to their source documents.
For imports predating recorded provenance, reimport all companion documents
together after upgrading.

## Dependency Import and Export

Settings' **Import SBOM** accepts Yocto and Zephyr SPDX 3 JSON-LD (`.json` or
`.jsonld`). Import all companion documents together so dependencies resolve.
SPDX archives (`.tar`, `.tar.gz`, `.tgz`, `.tar.zst`) containing `.spdx.json` or
`.jsonld` files are also supported.

Dependencies are read only from SBOM formats that describe them:

- **SPDX 3.0** (JSON-LD, including Yocto and Zephyr output) — `dependsOn`, `hasPrerequisite`, and reverse `dependencyOf` relationships.
- **SPDX 2.2 and 2.3** (JSON) — `DEPENDS_ON` relationships and their reverse forms `DEPENDENCY_OF`, `BUILD_DEPENDENCY_OF`, `RUNTIME_DEPENDENCY_OF`, `DEV_DEPENDENCY_OF`, `OPTIONAL_DEPENDENCY_OF`, `PROVIDED_DEPENDENCY_OF`, and `TEST_DEPENDENCY_OF`. Cross-document references (`DocumentRef-<name>:SPDXRef-<id>`) are resolved through `externalDocumentRefs` against the other SPDX documents of the same scan, which covers Yocto SPDX 2.2 archives (`*.spdx.tar.zst`, one document per recipe and package).
- **CycloneDX 1.4, 1.5, and 1.6** (JSON) — the `dependencies` array (`ref` → `dependsOn`). Nested applications, frameworks, libraries, operating systems, firmware, and device drivers (`components[].components[]`, e.g. bundled npm packages), including those under `metadata.component`, are imported as packages; other nested components such as containers, files, devices, or data are only searched for the packages they contain. The root `metadata.component` itself is imported as a package only when it is an `application`, `framework`, or `library` that appears in the `dependencies` array, so its direct dependencies are kept; container, file, and device roots are not. CycloneDX exports write the recorded dependencies back into the `dependencies` array, so re-importing an export restores the same graph.

Grype, Yocto `cve-check`, Yocto VEX, and OpenVEX files carry no dependency relationships, so packages known only from them show zero counts. Only relationships between two packages are kept; relationships to files, snippets, or elements missing from the scan are ignored. SBOMs imported before dependency support existed have no recorded relationships: their packages show **Not recorded** instead of zero counts (also in the graph's **Variants** list), and the SBOM must be imported again to record them.

SPDX 2.3 and SPDX 3.0 exports write the dependencies recorded by the exported active scans back as `DEPENDS_ON` and `dependsOn` relationships between packages respectively, so re-importing an export restores the same graph.

## CycloneDX VEX Reference Resolution

Local `bom-ref` affects retain path-order resolution when multiple BOMs reuse a
reference. Only BOM-Link references can resolve against a later inventory;
detached VEX documents mixing both forms preserve their original local mapping.
If a VEX also contains components, its inventory is imported at its original
path position before unresolved external affects are replayed.
BOM-Links use a separate UUID/version-qualified inventory index, so unrelated
local references cannot redirect a qualified target. If no qualified target
exists, an exact component `bom-ref` in the current document is retained as a
local fallback, including during deferred replay.

See the [bundled CycloneDX example](examples.md#yocto-spdx-2-and-cyclonedx-exports)
for import commands and expected findings.

## Scoped Scanner Evidence

For imported SPDX 3 Build-profile evidence, the local advisory engine receives
compiled-source paths from the selected variant's active SBOMs. When an advisory
identifies affected files and none were compiled, it can record a `not_affected`
assessment; the finding remains available for review. Incomplete evidence or
advisories without file information retain ordinary matching. This does not
evaluate Kconfig or infer release versions from Git revisions. Yocto recipe
inputs and SPDX 2 file inventories alone cannot enable refinement. Unknown,
packaging, generator-only tasks, unresolved containment, and unaccounted
artifact/package inputs cannot establish completeness. See
[Recorded files](web-sbom.md#recorded-files).

CLI and queued NVD API/local scans and sbom-cve-check receive package snapshots
with only the selected variant's active SBOM evidence. Sharing a canonical
package with another variant does not add that variant's identifiers to these
scans.

After upgrading a database that predates scoped identifier evidence, these scans
stop with a reimport-required error until the selected variant's original SBOMs
are reimported. Upload the original files for that project and variant, including
all companion documents for West JSON-LD, then run the scan again. Missing
evidence is never filled from globally merged package identifiers. A recorded
empty identifier list remains valid; an unpopulated (`NULL`) list requires
reimport.

## Native-Package Scan Preferences

Native package selections are saved when launching scans in a single `project-scan.json` file under `VULNSCOUT_CACHE_DIR` (default: `/cache/vulnscout`), keyed by the exact project name rather than its UUID. Each project's entry contains `exclude_native` and `native_package_exceptions`. They are restored the next time the wizard opens, including after browser or server restarts. Renaming a project uses the preferences for its new name, or the defaults if none have been saved for that name. **Select all** disables native exclusion, so even native packages added to the SBOM before launch are scanned. Changing an individual checkbox enables native exclusion and scans only the checked native packages.

Preferences are loaded only for selected projects, and package names are compared case-insensitively. All selected projects' preferences are saved atomically before scans are queued. If saving fails, no partial preferences are written and the wizard stays open with an error so you can retry. Native selections are not capped at 1000 package names; the normal HTTP request-size limit still applies.

The same JSON file now has two top-level nodes:

```json
{
  "global": {
    "exclude_native": true,
    "native_package_exceptions": ["cmake-native", "g++-native", "gcc-native"]
  },
  "projects": {
    "My Project": {
      "exclude_native": true,
      "native_package_exceptions": ["make-native"]
    }
  }
}
```

Existing flat project-name mappings remain readable and are upgraded to this shape on the next save. Project names, including `global` or `projects`, remain ordinary keys inside `projects`. The global settings API is `GET` / `PUT /api/config/native-packages`; project settings continue to use `GET` / `PUT /api/projects/<project-uuid>/scan-configuration`.

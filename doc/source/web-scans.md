# Scan History

The Scan History page provides a chronological record of every SBOM import and vulnerability scan that VulnScout has processed. Each time you load a new SBOM or run a scanner, VulnScout creates a scan entry that captures exactly what changed compared to the previous state. This makes it straightforward to track how your vulnerability landscape evolves over time, across builds, and across variants.

## Scanners

An SBOM lists the packages that make up your system, but a single vulnerability source rarely provides complete coverage. Different databases track different ecosystems, use different matching strategies, and update at different speeds. VulnScout cross-references your SBOM against several scanners to offer a wider set of information:

- **NVD** correlates packages with NIST's National Vulnerability Database using CPE identifiers. It uses the CPEs recorded in the selected variant's active SBOM associations.
- **Grype** leverages Anchore's vulnerability database, which combines multiple upstream feeds and applies its own matching heuristics. It is particularly effective at catching vulnerabilities in container and OS-level packages.
- **OSV** queries the open-source OSV database, which aggregates advisories from language-specific ecosystems (PyPI, npm, Go, Rust, etc.) and Linux distributions. It queries every PURL recorded in the selected variant's active SBOM associations, excluding identifiers found only in other variants or older SBOMs.
- **sbom-cve-check** uses local advisory databases to match recorded package identifiers and versions. See [Vulnerability Scanning](vulnerability-scanning.md) for scanner requirements and offline operation.

Scanners use the selected variant's active SBOM evidence. If a scan reports that
identifier evidence requires reimport, upload that variant's original SBOMs
together, including companion documents, then retry. See
[Scoped Scanner Evidence](sbom-scan-reference.md#scoped-scanner-evidence).

Combining sources broadens discovery coverage. Use the **Sources** column and
filter to trace each finding, but assess its applicability against product
evidence. Scanners can share upstream data, so agreement is not independent
proof of exploitability, and a finding reported by only one scanner can still
affect the product.

## Running Scans

The **Run Scans** button in the top-right corner of Scan History opens a five-step wizard:

1. **Scans** — select Grype, NVD CPE, OSV, and/or sbom-cve-check.
2. **Variants** — select variants in the current scope. A variant scope shows only that variant; a project scope offers its variants, with **Select all** and **Select none** controls.
3. **Filters** — choose whether to exclude kernel companion packages using the **Yes** / **No** controls (the main kernel package remains eligible). The **Native packages to scan** section is always visible: checked Yocto build-host packages ending in `-native` are scanned, and unchecked ones are skipped. Use **Select all** to scan every native package, or **Unselect all** to skip them all, then adjust individual checkboxes as needed. `gcc-native`, `g++-native`, and `cmake-native` are selected by default; other native packages from the project's current SBOMs are also available. Selections and bulk controls are separate for each project.
4. **Refresh** — optionally refresh newly discovered vulnerabilities from all applicable data sources or select a custom subset. With no refresh selected, the scans still run.
5. **Review** — check the selections and launch the batch.

### Saved Filters and Defaults

Native-package selections persist per project and are restored when the wizard
reopens. Projects with no saved selections use
[global native-package defaults](web-settings.md#native-package-scan-defaults).
See [Native-Package Scan Preferences](sbom-scan-reference.md#native-package-scan-preferences)
for storage, matching, and configuration migration details.

### Queue and Progress

The server queues Grype, NVD, OSV, and sbom-cve-check scans in that order, followed by selected vulnerability-data refreshes. Each source/variant pair has its own operation with live logs and progress in the Operation queue. While any scan is active, **Run Scans** is disabled; opening another tab does not create a second batch.

Every scan and vulnerability-data refresh is also tracked in the **Operation queue** in the navigation bar. A counter shows how many operations have finished out of the total tracked; clicking it opens the Operation queue window, where each running or finished operation has its own progress panel. The window can be closed at any time without interrupting the operations, which keep running in the background.

SBOM uploads and document exports appear in the same queue. Exports download automatically when ready; if the download was missed, the retained archive can be downloaded from the queue after reloading the page. An archive expires or is consumed on its first download. See [Operation Queue](web-operation-queue.md) for details.

## Source Visibility Toggles

Use **SBOM imports only** to hide every scanner scan/run while keeping SBOM imports visible. The individual source toggles (Grype, NVD, OSV, and sbom-cve-check) remain available when you want to show or hide particular scanners instead.

## Importing and Exporting Scan Data

The **Export** menu downloads scan history as VulnScout JSON. A single timeline entry can be exported either as its diff or as its full scan result. The toolbar export applies the same formats to every scan visible in the current project or variant scope.

Use **Import** to restore exported scan data. You can select one or more files, and each file may hold a single export or the array produced by the toolbar's Export All — every scan in the selection is imported together.

VulnScout matches the `project_name` and `variant_name` recorded in each export to an existing project and variant, then persists its packages, findings and assessments as a new scan entry. The destination project and variant must already exist; nothing is created implicitly.

A few properties are worth knowing:

- **Both export formats import.** A scan diff carries the scan's complete package and finding state at the top level, so a diff taken from any point in the timeline can be imported, not just the first one. The `diff` section itself describes the *source* instance's history and is ignored — the destination recomputes badges against its own timeline.
- **Imports are idempotent.** A scan is recognised by its variant, its kind (SBOM, or a tool plus that tool's name) and its timestamp, so importing the same scan into a variant that already has it is rejected as a duplicate instead of creating a second copy. This also catches an export whose scan the destination already holds natively — re-importing a file into the instance it came from changes nothing. Assessments that already exist on the destination are likewise left alone rather than duplicated.
- **Imports are all-or-nothing.** The entire selection is validated before anything is written and applied in one transaction. If any export is malformed, references a missing project or variant, or has already been imported, the request is rejected and the database is left untouched — the error names the offending entry so you can drop it and retry.
- **Existing data is reused.** Packages, vulnerabilities and findings already present in the destination are linked to rather than duplicated, so importing overlapping scans does not inflate the database. A supplier recorded in SPDX form is matched against the plain name the export carries, so no second copy of the package appears.
- **Assessments keep their finding.** An assessment applies to one package/vulnerability pair, and exports record that pair, so an imported assessment attaches to the same finding it had on the source rather than to every package sharing the vulnerability.

## Timeline Layout

Scans are displayed in a vertical timeline, most recent first. Each entry shows the timestamp of the import, the project and variant it belongs to, and a set of colour-coded badges summarising the delta. Scan-run badges use a different colour from SBOM-import badges. On a grouped scan run, select a scanner badge under **Tool scan diff details** to open that scanner's diff:

- **Green** badges indicate additions: new packages, new findings, or new vulnerabilities that appeared in this scan.
- **Red** badges indicate removals: packages, findings, or vulnerabilities that were present before but are no longer in the SBOM.
- **Yellow** badges indicate upgrades: packages whose version changed between scans, along with findings that shifted to a different package version.

For the very first scan of a variant, the badges simply show total counts (packages, findings, vulnerabilities) since there is no prior scan to compare against. A **Hide empty scans** toggle filters out entries where nothing changed.

## Scan Descriptions

Each scan entry has an editable description field. Hovering over the entry reveals a pencil icon that lets you add or modify a free-text note — for example, "nightly build 2026-04-21" or "after openssl bump". Descriptions are saved immediately and persist across sessions. This is especially useful when reviewing the history weeks later and needing context about why a particular scan looks the way it does.

## Diff Details Modal

Clicking the **Details** button on any scan entry opens a full diff modal. The modal is organised into tabbed sections:

- **Packages** — lists every package that was added, removed, or upgraded between this scan and the previous one. Each table shows the package name and version, and upgraded packages display both the old and new version side by side.
- **Findings** — shows the individual vulnerability-to-package associations that changed. Added findings are new detections; removed findings are associations that no longer apply (because the package was removed or the vulnerability was resolved upstream). Upgraded findings track cases where the same vulnerability now maps to a different package version.
- **Vulnerabilities** — a higher-level view listing just the CVE identifiers that appeared or disappeared. This is the quickest way to see which new CVEs were introduced by a build change.
- **Newly Detected** — lists findings and vulnerabilities that are net additions to the global scan result (i.e. not present in any previous scan). This section is especially relevant for tool scans where the distinction between "new to this tool" and "new overall" matters.

Each tab header carries its own badge counts, and every table inside supports a text filter so you can search for a specific package or CVE without scrolling through long lists.

### Dependency relationship changes

The **Import SBOM** details' Packages tab also shows dependency relationships
separately from added, removed, and upgraded packages. Expand **Added
relationships** or **Removed relationships** to see the dependent → dependency
package names and versions. Counts describe unique directed package pairs across
the import's documents; duplicate links are counted once. Dependency type and
scope metadata are not compared. A version upgrade can remove an old-version link
and add a new-version link, independently of the package upgrade classification.

The baseline is the same immediately preceding SBOM import used by the package
history, ordered by timestamp and scan ID, in the **same variant**. Tool scans do
not participate. Comparisons additionally require the same document inventory
(source filenames and formats, including duplicate filenames); upload paths are
not part of that scope. A different scope does not cause a search for an older
matching import.

Relationships are frozen at successful import completion after cross-document
resolution, not reconstructed from the editable current dependency graph.
Identical re-imports (including recorded empty graphs) show zero changes. First
imports, changed document scopes, and either import lacking a recorded snapshot
show **No comparable dependency baseline**, with a reason, instead of treating
unknown relationships as empty and reporting mass additions or removals. The
migration deliberately does not infer snapshots for older imports from live
edges; reimport the same document scope twice to establish a comparable baseline.
Upgrading a database that already has snapshot storage preserves its recorded
snapshots. Packages and other existing history details remain available.

## Scan Result Modal

Clicking the **Scan Result** button on a scan entry opens a modal showing the complete state of the global result at that point in time — the union of SBOM packages and all tool-scan findings. The modal displays packages, findings, and vulnerabilities tabs, each with their total counts. This is useful for understanding the full picture at a given snapshot rather than just the delta.

## Scan Export

VulnScout lets you export scan data as JSON files for archiving, reporting, or sharing with external tools.

**Per-scan export:** each scan entry has a download button that opens a small menu with two choices:

- **Export Diff** — downloads a JSON file containing changes compared to the previous scan (added, removed, upgraded, and unchanged packages, findings, and vulnerabilities). SBOM exports also carry the complete current package set, including upgraded versions, for reimport. For tool scans the export also includes newly-detected findings and assessments.
- **Export Scan Result** — downloads a JSON file with the complete global result at that point in time, including full package, finding, and vulnerability lists with source attribution.

Both files include scan metadata (timestamp, scan type, project, and variant) and strip internal identifiers so the output is portable.

Package entries also carry `sbom_evidence`: document-scoped CPEs, PURLs, source URLs,
source revisions, and component types. Importing these exports preserves the inputs
needed to run package advisory scans again, including for Zephyr SBOMs. Evidence
comes only from the SBOM contributing to the exported scan, not from other variants
or newer imports. Separate association records preserve component classifications;
`null` identifiers remain unknown, while empty arrays mean identifiers were recorded
but none were present. Older exports without this evidence can still be imported
for their scan history, but require reimporting the original SBOM before rescanning.
Tool-scan imports remain findings-only and do not replace the active SBOM.
Imports and exports accept at most 1,000 evidence records per package in each
scan and 10,000 across the entire archive, counting duplicates before
deduplication. Exceeding either limit rejects the whole request; imports write
no scans and exports produce no download. Bulk archives also allow at most
200 scans. For a history exceeding the evidence budget, narrow the project or
variant scope, or download individual scans instead. Each imported archive is
atomic. Multiple imported association records remain one logical SBOM source
in dependency graphs and scan-result source labels.

**Export All:** an **Export** button in the toolbar lets you download the entire visible scan history at once. A dropdown offers two modes — **Export All Diffs** and **Export All Scan Results** — which produce a single JSON array grouping all scans by variant. The export respects the current project/variant scope.

# Dependency Explorer

Click a package's **Dependency** cell in the **SBOM** tab to open the full-screen
**Package dependencies** popup. It starts at that package in **Graph** view at
depth 1 and uses the table's project, variant selection, and comparison
operation. Exploration stays in the popup; there is no separate Dependencies tab.

- **Graph** is a neighborhood diagram for the selected package, with one to
  three levels (one by default) and a clearly indicated 120-package limit. It
  displays the selected package's variant, without combining paths across
  variants. Select a node to center the diagram on it. Diagram arrows mean
  "depends on". Switch to **Tree** for complete paths; the active view is
  highlighted.
- **Tree** starts at the clicked package, with its direct dependencies expanded.
  **All packages** shows packages with no recorded parents in **Tree** view.
  Disconnected components, cyclic groups, and unlinked packages are included;
  these entry points are not necessarily application roots. Expand branches to
  follow complete transitive paths. Shared dependencies appear on each
  applicable path; a **Cycle** marker stops expansion when a package is already
  in that path. Select a row to see labeled **Depends on** and **Required by**
  counts in the package inspector; tree rows have no unlabeled numeric badges.
- **Find a package** searches the entire scope by name, version, or revision,
  including collapsed branches and packages beyond the current page. Choose a
  result to explore from that package. **All packages** returns to the overview.
- **Variants** shows per-variant direct **Deps** and **Req by** counts for the
  exploration root. Checkboxes show or hide each variant. **SBOM source**
  narrows relationships and version/revision evidence to one document; companion
  documents in the same variant can still resolve relationship endpoints.
  Variant and source controls share a compact row, wrapping on narrow screens.
- **Depends on** shows the packages the selected package needs, directly or
  transitively. **Required by** shows the packages that need it, directly or
  transitively, to explain what brings it in. Hover either button for a short
  reminder. Paths remain within one variant; relationships from different
  variants are never joined into a path.
- Select a row or node to inspect its path, direct and transitive-only unique
  package counts in each direction, release/revision evidence, and SBOM sources.
  Choose a package in the selected path to make it the exploration root.
  When refreshed SBOM data removes a package or relationship in the selected
  path, the inspector drops that stale path while keeping the selected package
  if it is still available.
- **Exclusive direct dependencies** in the package inspector lists direct
  dependencies whose only recorded incoming dependent is the selected package.
  For example, if CURL depends on A, B, C and D, but other packages also depend
  on A and D, only B and C are listed. Select a listed package to explore it.
  Candidates follow the current source/comparison selection, but incoming
  dependents are checked across **all active SBOM sources in that variant**,
  even when a source or comparison filter hides them. Variants are evaluated
  separately; duplicates do not create extra dependents.
  Only direct links are considered, not transitive dependencies or removal
  cascades. The selected package itself is excluded. Cycles are not traversed;
  a dependency's self edge counts as another incoming dependent.
- Arrow keys move between rows and expand/collapse branches; Enter or Space
  selects a package. Branches load 40 siblings at a time, and expanded trees
  initially render at most 500 rows. Explicit **Show more** controls expose all
  remaining rows without limiting the underlying dependency data or tree depth.

Packages whose SBOMs lack dependency data are labeled **not recorded**, not
assumed to have no dependencies. An unlinked package is not proof of unused
code. SBOM graphs may be incomplete: even exclusive recorded relationships are
not proof of actual build or runtime requirements, or evidence that removing a
package is safe.

The explorer uses the searchable tree and dependency-path patterns documented
by [Snyk](https://docs.snyk.io/scan-fix-and-prevent/scan-with-snyk/snyk-projects/view-project-issues-fixes-and-dependencies),
[GitHub](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/explore-dependencies),
and [GitLab](https://docs.gitlab.com/user/application_security/dependency_list/).

The **Dependency** column shows how many packages each package directly depends
on (**Deps**) and how many packages directly depend on it (**Req by**). Hover
the counts for definitions. Dependency data is loaded only when the popup opens
and reused across package openings until the scope or data revision changes.
Packages without relationships show zero counts. Outdated packages show
**Not in active scan** because dependency data covers active scans only.

## Available Relationship Data

Import SPDX or CycloneDX documents that declare dependency relationships.
Import companion SPDX documents together so cross-document references resolve.
Grype, Yocto CVE check, Yocto VEX, and OpenVEX inputs do not supply dependency
relationships.

**Not recorded** means the SBOM was imported before dependency recording was
available; reimport it to populate the graph. Zero counts mean no retained
package-to-package relationships were recorded in the selected active documents,
not proof that the software has no runtime dependencies.

The graph describes SBOM declarations, not runtime reachability or exploitability.
Click a graph link (or expand **Inspect dependency links** and choose a link) to
see every retained **Relationship**, **Lifecycle scope**, source SBOM document,
and variant. For example, the bundled Yocto Wrynose SPDX 3 image declares
`busybox-syslog` → `busybox` as `dependsOn`, **Runtime**. Explicit package
relationships scoped to `build` show **Build**; missing scopes and legacy
untyped relationships show **Unspecified**, never an inferred Runtime.
Multiple types/scopes or source documents can declare the same package pair:
each declaration remains visible, but **Deps** and **Req by** count the pair once.
The graph and its link details stay within the selected package's variant.
Hiding that variant switches to another visible variant rather than combining
their declarations. Link details close when their package or source scope changes.
Scope and relationship labels do not suppress vulnerabilities or establish that
a vulnerable function is reachable.
See [Dependency Import and Export](sbom-scan-reference.md#dependency-import-and-export)
for supported format versions, relationship types, and round-trip behavior.

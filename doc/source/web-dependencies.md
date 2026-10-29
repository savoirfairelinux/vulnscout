# Dependency Graph

The **Dependency** column of the SBOM table shows how many packages each package directly depends on (**Deps**) and how many packages directly depend on it (**Req by**). Hover the counts for definitions. Click the cell to open the graph and expandable trees for both directions. The graph shows every direct dependency (left, flowing in) and dependent (right, flowing out) of the package in a single diagram; zoom and pan to explore large ones. The **Variants** list beside the graph gives each variant a color, its own **Deps** / **Req by** counts, and a checkbox to show or hide its relationships (all variants are shown by default). Select an SBOM source to narrow the graph and its version/revision labels to one active document. Neighbouring packages in the graph use the colors of the variants where the relationship exists, split into stripes when it exists in several. Dependency graphs are loaded only when opened, and packages without relationships show zero counts. Outdated packages show **Not in active scan** because dependency data covers active scans only.

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
See [Dependency Import and Export](sbom-scan-reference.md#dependency-import-and-export)
for supported format versions, relationship types, and round-trip behavior.

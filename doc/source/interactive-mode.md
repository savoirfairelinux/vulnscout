# Interactive Mode

VulnScout's web interface lets you inspect packages, investigate vulnerabilities,
record triage decisions, and export results. See
[Starting the Web Interface](cli-web-interface.md) to open it, then select a
project and variant in the navigation bar.

## Getting Started with Vulnerability Analysis

### Starting a New Project

Importing an SBOM loads its package inventory and any vulnerability findings or
assessments supplied by the input documents. It does not run additional
vulnerability scanners.

Web uploads in **Settings** default to **Complete refresh**, which refreshes
provider metadata after parsing. This can make external provider requests and
lengthen the import. To disable this enrichment, choose **Custom refresh** and
deselect every source before uploading; see [SBOM Imports](web-settings.md#sbom-imports).
In contrast, CLI imports with `./vulnscout add` do not refresh provider metadata.

Use [Scan History](web-scans.md) to discover additional findings and
[refresh vulnerability data](web-vulnerabilities.md#refreshing-vulnerability-data)
to enrich findings already recorded.

Investigate findings that are **Pending Assessment** and record a supported
conclusion: **Exploitable**, **Not affected**, or **Fixed**. Keep unresolved
findings pending rather than guessing.

### Threat Model

A threat model describes the product's assets, trust boundaries, attack surfaces,
and deployment assumptions. Use it to investigate whether a vulnerability's
preconditions exist and to prioritise remediation.

The presence of a vulnerable package is not, by itself, proof that your product
is exploitable. Conversely, a low severity, low estimated likelihood, or accepted
business risk is not proof that the product is **Not affected**.

For example, evidence that the vulnerable code is excluded from the shipped
build may justify **Not affected**. A network-related finding requires checking
the actual vulnerable interfaces and attack preconditions, not merely assuming
that an offline deployment is safe.

If a reachable serial-port vulnerability can leak product data, it still affects
the product even when your team prioritises privilege escalation or code
execution. Record the impact and any risk-acceptance or prioritisation decision
in the assessment notes; do not use **Not affected** to mean "not a priority".

### Assessment Status in VulnScout

VulnScout groups all assessment statuses into four simplified categories:

- **Pending Assessment**: a conclusion has not been established or investigation is still in progress.
- **Exploitable**: the vulnerability is confirmed to affect the product in its current build, configuration, or deployment. Remediation priority is a separate decision.
- **Not affected**: technical evidence establishes that the vulnerability does not apply to the assessed product, for example because the vulnerable code is absent or its required execution path cannot be reached. A justification is required.
- **Fixed**: the vulnerability has been patched or resolved.

### Goal of the Interactive Mode

The interactive mode is where you investigate each CVE and record your triage decisions. The typical workflow is:

1. Find **Pending Assessment** findings in [Metrics](web-metrics.md) or the [Vulnerability Table](web-vulnerabilities.md).
2. Open [Vulnerability Details](web-vulnerability-details.md), read the advisory, inspect the affected packages, and check the build and deployment evidence.
3. Record a supported status, justification, impact, and notes; optionally document a workaround or estimate remediation effort. See [AI Assessments](ai-assessments.md) for assisted analysis and human approval.

(source-files)=
### Recorded files

**Recorded Files** counts the non-binary file records associated with a package
in the selected active SBOMs. These may include source code, patches, licenses,
and configuration files; they are not necessarily a complete source inventory.
The column's help tooltip explains this distinction. Click the count to inspect
paths, original SPDX file
properties (including recorded hashes and license information), source documents,
and build-input associations. The details view supports filtering by path or
document. Object files, libraries, and final build outputs are stored as file
records but are not included in this count. The details separately report
the number of files with compilation evidence.

SPDX 3 `software_File`, `contains`, and Build-profile `hasInput`/`hasOutput`
relationships are resolved across companion documents of the **same import
scan**, including West's `app.jsonld`, `zephyr.jsonld`, and `build.jsonld`.
Source/build package consolidation preserves those associations.
SPDX 2.2/2.3 `files`, package `hasFiles`, `CONTAINS`, and `CONTAINED_BY`
relationships also populate the inventory, including namespaced
`DocumentRef-*` references between companion documents.
When bare and epoch-prefixed package versions in one document are coalesced,
file containment through either SPDX package element is preserved.
Original SPDX 2 checksums, licenses, and file types remain visible in the details.
Explicit binary file types and installed package outputs are excluded from **Recorded Files**.

**Build input** means compilation evidence exists; **Listed only** does not
prove compilation, and neither proves inclusion in the final firmware.
Yocto SPDX 3 lifecycle-scoped build relationships are supported, but BitBake
recipe inputs are shown as **Build input (not proven compilation)**: patches,
licenses, configuration files, and source archives are not a list of compiled
translation units. SPDX 2 package provenance likewise does not prove compilation.
Compilation proof currently requires a West Zephyr CMake build with recorded
C, C++, or assembly compiler flags. Unknown build types, packaging/copy tasks,
and generator-only builds do not qualify.
Yocto's `SPDX_INCLUDE_COMPILED_SOURCES` does not provide this proof either: in
SPDX 3.0.1 output it lists original sources as well as compiled ones (the same
as `SPDX_INCLUDE_SOURCES`), and SPDX 2.2 output has no build relationships. Its
files are recorded and searchable, but compiled-source refinement stays disabled
for those packages.

**Not recorded** means file evidence is unavailable, not an empty recorded
inventory. Reimport the original companion SBOMs together to populate older
imports. Non-SPDX SBOM formats currently do not populate this inventory.
SPDX 2 packages with `filesAnalyzed: false` and no associated file records also
remain **Not recorded**, including package-only VulnScout exports.
Outdated packages show **Not in active scan**.

The local advisory engine uses resolved compiled-source paths for CVE refinement
only when the inventory is complete and the advisory supplies affected-file
information. Missing or malformed build/containment references disable this
refinement. Output-producing builds with no recorded inputs leave their owning
packages incomplete, even when another target for that package records its
compiled sources. Artifact or package inputs whose source contributions are not
accounted for also leave the affected inventory incomplete; VulnScout does not
trace sources through intermediate builds.
Unproven source files also disable refinement. These gaps do not justify
discarding a CVE. Kconfig expressions are not evaluated.
Reimport existing SBOMs to recompute compilation proof and completeness with
these checks.

## Web Interface Guides

Choose the guide for the screen or task you are using:

```{toctree}
:maxdepth: 1

web-metrics
web-sbom
web-dependencies
web-vulnerabilities
web-vulnerability-details
web-scans
web-refresh
web-review
web-export
web-settings
web-operation-queue
```

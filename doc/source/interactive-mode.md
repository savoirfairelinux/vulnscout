# Interactive Mode

VulnScout's web interface is the way most users interact with vulnerability data day-to-day. Once an SBOM has been imported and enriched, the interactive mode gives you everything needed to explore, filter, assess, and track vulnerabilities without leaving the application.

## How Assessments Works

### Starting a New Project

When you first import an SBOM into VulnScout, the application scans its contents and creates a finding for every vulnerability-to-package association it discovers.

If the SBOM source does not include any assessment data, those findings start with a **Pending assessment**, which means you will need to review the finding and make a decision about it (either it affects your system, or it doesn't or it was already fixed).

However, many SBOM sources carry assessments / triage decisions. Yocto CVE-check results, for example, mark vulnerabilities as Patched, Ignored, or Unpatched; CycloneDX and SPDX 3 documents often include full VEX analysis blocks; and OpenVEX files provide standalone assessment records. When VulnScout ingests these, it creates assessments automatically, so you may see some CVEs already labelled as **Fixed** or **Not affected** before you have done any manual triage.

### Scanners

An SBOM lists the packages that make up your system, but a single vulnerability source rarely provides complete coverage. Different databases track different ecosystems, use different matching strategies, and update at different speeds. VulnScout cross-references your SBOM against several scanners to offer a wider set of information:

- **NVD** correlates packages with NIST's National Vulnerability Database using CPE identifiers. It offers broad coverage across many ecosystems.
- **Grype** leverages Anchore's vulnerability database, which combines multiple upstream feeds and applies its own matching heuristics. It is particularly effective at catching vulnerabilities in container and OS-level packages.
- **OSV-Scanner** queries the open-source OSV database, which aggregates advisories from language-specific ecosystems (PyPI, npm, Go, Rust, etc.) and Linux distributions. Its PURL matching tends to be more precise than CPE-based lookup.

By combining these sources, VulnScout reduces the chance of missing a relevant CVE while giving you the **Sources** column and filter to trace exactly where each finding originated. If a vulnerability is reported by multiple scanners, you can have higher confidence that it genuinely applies; if only one scanner flags it, that context helps you prioritise your triage effort.

### Assessment Status in Vulnscout

VulnScout groups all assessment statuses into four simplified categories:

- **Pending Assessment**: the vulnerability has not been assessed yet. 
- **Exploitable**: the vulnerability is confirmed to affect your product in its current configuration and represents danger for it as defined in the threat model.
- **Not affected**: the vulnerability does not apply — even if the vulnerable package is present on the device, the CVE may not match your threat model (for example, the vulnerable code path is not reachable, or the attack vector does not exist in your environment). A justification is required when selecting this status.
- **Fixed**: the vulnerability has been patched or resolved.

### Threat Model

A vulnerability present in Vulnscout does not necessarily mean they represent a real danger to your device. A CVE describes a potential weakness whether it is actually exploitable depends on how the affected component is built, configured, and used in your specific environment.

For example, consider a CVE that can only be triggered when a particular compile-time flag is enabled. If your build does not use that flag, the vulnerable code path is never included, and the CVE cannot be exploited on your device. Similarly, a network-facing vulnerability has no impact on a system that is never connected to a network.

This is why triage matters: the goal is not to patch every CVE blindly, but to determine which ones are relevant given your threat model and mark the rest as **Not affected** with a clear justification.

### Goal of the Interactive Mode

The interactive mode is where you investigate each CVE and record your triage decisions. The typical workflow is:

0. Look for vulnerabilities that are **Pending assessment**: you can directly click on the orange part of the pie chart in the home page, or use the filters in the Vulnerabilities tab to see these CVEs.
1. Review the vulnerability details: read the description, check the CVSS score and EPSS probability, inspect which packages are affected, and follow the reference links for advisories and patches.
2. Assess: set a status, provide a justification when required, add notes explaining your reasoning, and optionally document a workaround or estimate remediation effort.

Assessments you create through the web dashboard are stored with a `custom` origin, which distinguishes them from the  assessments that were imported automatically. On subsequent SBOM re-imports, upstream assessments may be updated by newer VEX data, but your own assessments are always preserved as separate records.

---

## Vulnerability Table

Every vulnerability detected across imported SBOMs in your scope is listed here, and the toolbar across the top provides a rich set of controls to narrow down what you see and act on what matters.

### Search

The search bar accepts free-text queries that match against CVE identifiers, package names, and vulnerability descriptions. Typing at least two characters triggers a fuzzy search powered by Fuse.js. The search supports a small expression language:

- **`term`** — rows containing the term are shown.
- **`term1 term2`** — AND semantics: both terms must match.
- **`term1 | term2`** — OR semantics: either term matches.
- **`-term`** — NOT: rows containing the term are excluded.

A small **info icon** next to the search bar opens a quick-reference panel for this syntax, so you don't need to memorise it.

### Column Visibility

The **Columns** dropdown lets you toggle which columns are displayed. The default set includes ID, Severity, EPSS Score, SBOM Affected, Variants, Status, Last Updated, and Published Date, but you can also enable Attack Vector, Estimated Effort, First Scan Date, and Sources.

### Filters

VulnScout provides several filter categories, each accessible from a dedicated dropdown in the toolbar:

- **Source**: restrict the table to vulnerabilities found by a specific scanner or import source (Yocto, Grype, CycloneDX, SPDX3, OpenVEX, or Local User Data).
- **Severity**: select one or more severity levels (Critical, High, Medium, Low, None). You can also switch to a continuous **score-based** filter using a range slider, which filters by the underlying CVSS max score rather than the categorical label.
- **Status**: filter by triage status: Pending Assessment, Exploitable, Not affected, or Fixed.
- **Published Date**: filter vulnerabilities by their NVD publication date. The dropdown supports exact-date matching, before/after comparisons, date ranges, and a "within the last N days" shorthand. This filter becomes active once the NVD sync has completed.
- **More Filters**: groups less common filters together:
  - **EPSS Range**: a percentage-based range slider that narrows the list to vulnerabilities whose Exploit Prediction Scoring System score falls within the specified band.
  - **Attack Vector**: checkboxes for Network, Adjacent, Local, and Physical, reflecting the CVSS attack-vector metric.
  - **First Scan Date**: multi-select by scan timestamp, useful for identifying which vulnerabilities appeared in a particular import run.

When any filter is active, a small checkmark badge appears on its button so you can tell at a glance which filters are engaged. A **Reset Filters** button in the top-right corner clears everything back to defaults.

### Row Selection and Bulk Editing

Each row has a checkbox on the left. Selecting one or more rows reveals the **multi-edit bar**, which lets you apply a single assessment (status, justification, notes) to all selected vulnerabilities at once. This is particularly valuable when triaging a batch of related CVEs (for example, marking a group of low-severity findings as "Not affected" with a shared justification).

### Sorting

Every sortable column header is clickable. Severity sorts by the standard ordering (Critical -> None) or by numeric score when the score-based filter is active. Status sorts by triage progression. Published Date and Last Updated sort chronologically. EPSS and Estimated Effort sort numerically. Clicking the same header again reverses the direction.

### Opening a Vulnerability

Clicking a vulnerability's **ID cell** opens the detail modal in read-only mode. Clicking the **Edit** button in the actions column opens it directly in editing mode. Both actions capture a snapshot of the currently filtered and sorted list so that you can navigate between vulnerabilities within the modal without leaving the dialog box.

---

## Vulnerability Details

The Vulnerability Details is where individual vulnerability triage happens. It presents all the information VulnScout has gathered about a single CVE, and lets you modify assessments, CVSS vectors, and time estimates.

### Header and Metadata

The modal header shows the CVE identifier and a set of action buttons. Below it, a summary section displays:

- **Severity** with a colour-coded tag.
- **EPSS Score** as a percentage, when available.
- **Published date** from NVD.
- **Found by** — the list of scanners or sources that reported this vulnerability.
- **Status** — the current triage status.
- **Affects** — the list of packages in the SBOM that are impacted.
- **Aliases and Related vulnerabilities** — cross-references to other CVE identifiers.

### CVSS Vectors

Each CVSS vector associated with the vulnerability is rendered as a gauge card showing the version, base score, and a visual breakdown of the vector's metrics. When editing is enabled, a **plus** button appears next to the CVSS heading, allowing you to add a custom CVSS vector string. This is useful when the upstream score doesn't reflect your environment — for instance, if a network-based vulnerability only affects an air-gapped system.

### Descriptions and Links

The vulnerability's textual descriptions (from NVD, the SBOM source, or other feeds) are displayed in full, followed by a list of reference links. Each link opens in a new tab.

### Time Estimation

The time-estimate editor lets you record optimistic, likely, and pessimistic durations for remediation effort. These three-point estimates feed into the Estimated Effort column in the table and can be used for planning and prioritisation.

### Assessments

Assessments are the core triage artefact. Each assessment captures a status (pending assessment, exploitable, not affected, fixed), an optional justification, impact statement, status notes, and workaround. Assessments are displayed in a timeline, grouped by date and content, with the most recent at the top.

In editing mode, a form at the top of the timeline lets you create a new assessment. You can select which packages and which variants the assessment applies to, and VulnScout will create the appropriate records. Existing assessments can be edited inline or deleted.

When you have unsaved changes and attempt to close the modal or navigate away, VulnScout prompts you to confirm, preventing accidental data loss.

### Navigation

The modal footer contains **previous** and **next** buttons that move through the filtered vulnerability list without closing the modal. A counter ("Vulnerability x of y") shows your current position. This sequential navigation is the fastest way to triage a batch.

---

## Keyboard Shortcut Helper

Both the vulnerability table and the modal header feature a **question-mark** icon that opens a floating panel listing the keyboard shortcuts available in the current context.

### Table Shortcuts

- **`/`** — focus the search bar.
- **`↑` / `↓`** — move the row focus up or down.
- **`Home` / `End`** — jump to the first or last row.
- **`v`** — open the focused vulnerability in view mode.
- **`e`** — open the focused vulnerability in edit mode.

### Modal Shortcuts

- **`←` / `→`** — navigate to the previous or next vulnerability.
- **`Esc`** — close the modal (with confirmation if there are unsaved changes).

The panel dismisses automatically when you click outside it.

---

## Scan History

The scan history page provides a chronological record of every SBOM import that VulnScout has processed. Each time you load a new SBOM, VulnScout creates a scan entry that captures exactly what changed compared to the previous import. This makes it straightforward to track how your vulnerability landscape evolves over time, across builds, and across variants.

### Timeline Layout

Scans are displayed in a vertical timeline, most recent first. Each entry shows the timestamp of the import, the project and variant it belongs to, and a set of colour-coded badges summarising the delta:

- **Green** badges indicate additions: new packages, new findings, or new vulnerabilities that appeared in this scan.
- **Red** badges indicate removals: packages, findings, or vulnerabilities that were present before but are no longer in the SBOM.
- **Yellow** badges indicate upgrades: packages whose version changed between scans, along with findings that shifted to a different package version.

For the very first scan of a variant, the badges simply show total counts (packages, findings, vulnerabilities) since there is no prior scan to compare against.

### Scan Descriptions

Each scan entry has an editable description field. Hovering over the entry reveals a pencil icon that lets you add or modify a free-text note — for example, "nightly build 2026-04-21" or "after openssl bump". Descriptions are saved immediately and persist across sessions. This is especially useful when reviewing the history weeks later and needing context about why a particular scan looks the way it does.

### Diff Details Modal

Clicking the **Details** button on any scan entry opens a full diff modal. The modal is organised into three tabbed sections:

- **Packages** — lists every package that was added, removed, or upgraded between this scan and the previous one. Each table shows the package name and version, and upgraded packages display both the old and new version side by side.
- **Findings** — shows the individual vulnerability-to-package associations that changed. Added findings are new detections; removed findings are associations that no longer apply (because the package was removed or the vulnerability was resolved upstream). Upgraded findings track cases where the same vulnerability now maps to a different package version.
- **Vulnerabilities** — a higher-level view listing just the CVE identifiers that appeared or disappeared. This is the quickest way to see which new CVEs were introduced by a build change.

Each tab header carries its own badge counts, and every table inside supports a text filter so you can search for a specific package or CVE without scrolling through long lists.

### Documentation Link

A **book** icon sits next to the "Scan History" heading. It links to the [Scan History](https://vulnscout.readthedocs.io/en/latest/interactive-mode.html#scan-history) section of the VulnScout documentation on ReadTheDocs. The documentation site is not yet online — the link will become active once the docs are published.

---

## Review

The review page gives you a consolidated view of every assessment that was created directly within VulnScout (as opposed to assessments imported from upstream SBOM documents). It is designed for auditing and exporting the triage decisions your team has made.

### Assessment Table

The table presents one row per grouped assessment. Assessments that share the same vulnerability, status, justification, notes, workaround, and impact statement are automatically merged into a single row, with their packages and variants combined. This keeps the view compact even when a single triage decision was applied to many packages at once.

The columns include:

- **Vulnerability**: the CVE identifier. Clicking it opens the vulnerability detail modal in read-only mode, letting you inspect the full context without leaving the review page.
- **SBOM Affected**: the list of packages this assessment covers.
- **Variants**: the variant tags associated with the assessment.
- **Status**: the triage status (e.g. Not affected, Exploitable, Fixed).
- **Justification**: the VEX justification reason, if one was provided (e.g. "component not present", "vulnerable code not reachable").
- **Impact**: the impact statement describing how the vulnerability affects (or doesn't affect) the product.
- **Notes**: free-text status notes attached to the assessment.
- **Workaround**: any documented workaround.
- **Assessment Date**: the timestamp of the most recent assessment in the group.

### Search and Filters

The toolbar mirrors the vulnerability table's search bar. Filters are available for **Status** and **Justification**, and a **Reset Filters** button clears everything back to defaults.

### Import and Export

Two buttons in the toolbar handle review portability:

- **Import Review**: accepts an OpenVEX file (JSON or `.tar.gz`) and merges its assessments into the current project. This is useful for receiving triage decisions from another team or from a previous VulnScout instance.
- **Export Review**: downloads all review assessments as an OpenVEX `.tar.gz` archive. The export captures the full set of handmade assessments so they can be shared, archived, or loaded into another VulnScout deployment.
# Vulnerability Table

Every vulnerability detected across imported SBOMs in your scope is listed here, and the toolbar across the top provides a rich set of controls to narrow down what you see and act on what matters. The vulnerability pool is scoped to the **current scan result** — only vulnerabilities whose findings belong to packages present in the active SBOM are shown, ensuring that stale or cross-variant findings do not appear.

## Search

The search bar accepts free-text queries that match against CVE identifiers, package names, and vulnerability descriptions. Typing at least two characters triggers a fuzzy search powered by Fuse.js. The search supports a small expression language:

- **`term`** — rows containing the term are shown.
- **`term1 term2`** — AND semantics: both terms must match.
- **`term1 | term2`** — OR semantics: either term matches.
- **`-term`** — NOT: rows containing the term are excluded.

A small **info icon** next to the search bar opens a quick-reference panel for this syntax, so you don't need to memorise it.

## Column Visibility

The **Columns** dropdown lets you toggle which columns are displayed. The default set includes ID, Severity, EPSS Score, SBOM Affected, Variants, Status, Last Updated, and Published Date, but you can also enable Attack Vector, Estimated Effort, First Scan Date, and Sources.

## Filters

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

## Row Selection and Bulk Editing

Each row has a checkbox on the left. Selecting one or more rows reveals the
**multi-edit bar**, which applies a single assessment (status, justification,
notes) to all selected vulnerabilities. Use it only when the same conclusion
and supporting evidence apply to every selected target; low severity alone
does not justify **Not affected**.

## Refreshing Vulnerability Data

The vulnerabilities table also exposes a **Refresh Vulnerability Data** dropdown. Unlike the scanners on the Scan History page — which discover *which* CVEs affect your packages — these refreshers **enrich the vulnerabilities you already have** with up-to-date metadata pulled directly from upstream databases. The refresh operates on the vulnerabilities in the current scope.

The dropdown defaults to **Complete refresh**, which updates every available source for the current scope. Choose **Custom refresh** to select the sources to update. The selected sources are submitted together to the **Operation queue** and run in NVD, EPSS, GHSA, EUVD order on the server's pipeline lane. A progress banner below the toolbar shows the current source and count; each queued or running refresh can be cancelled individually. Closing the page does not stop the work, and another tab can see its progress in the same queue. See [Operation Queue](web-operation-queue.md) for recovery and cancellation behavior.

The available sources are:

- **NVD** — re-fetches the publication date and other metadata from NIST's National Vulnerability Database for CVEs in the current scope. This is what makes the **Published Date** column and filter usable.
- **EPSS** — updates the Exploit Prediction Scoring System probability for CVEs in the current scope, feeding the EPSS column and filter.
- **GHSA** — refreshes the publication date of GitHub Security Advisory (`GHSA-…`) identifiers in the current scope via the GitHub Advisory API.
- **ENISA EUVD** — annotates CVEs in the current scope from the European Union Vulnerability Database (see below). This option is only available when the scope contains at least one CVE identifier.

## ENISA EUVD Enrichment

The **ENISA EUVD** refresh annotates each selected CVE with information from the [European Union Vulnerability Database](https://euvd.enisa.europa.eu/), the vulnerability registry operated by ENISA. It is a **data enrichment, not a scanner**: it never discovers new vulnerabilities and performs no per-CVE network round-trips. Instead it loads two ENISA dumps once and maps them onto the CVEs you selected.

Two distinct pieces of information are added:

- **EUVD alias** — the ENISA EUVD identifier (for example `EUVD-2021-9696`) that corresponds to the CVE. This comes from ENISA's full *CVE → EUVD id* mapping dump, which covers every published CVE that ENISA tracks, regardless of exploitation status.
- **Known exploitable flag** — whether the CVE appears in the consolidated EU Known Exploited Vulnerabilities (KEV) list, which merges the CISA KEV and ENISA EU KEV catalogues. When present, the enrichment also records the KEV sources and the date the entry was added.

Both ENISA dumps are downloaded and cached on disk, refreshed at most once per day (ENISA itself publishes new dumps daily at 07:00 UTC). Network or parse failures degrade gracefully — a stale cache is reused, and enrichment never blocks your workflow.

Once an EUVD refresh completes, the banner reports how many of the selected CVEs were matched and how many are flagged as known exploitable. The annotations are then visible in the
[Vulnerability Details](web-vulnerability-details.md#header-and-metadata) modal.

## Sorting

Every sortable column header is clickable. Severity sorts by the standard ordering (Critical → None) or by numeric score when the score-based filter is active. Status sorts by triage progression. Published Date and Last Updated sort chronologically. EPSS and Estimated Effort sort numerically. Clicking the same header again reverses the direction.

## Opening a Vulnerability

Clicking a vulnerability's **ID cell** opens
[Vulnerability Details](web-vulnerability-details.md) in read-only mode.
Clicking **Edit** in the actions column opens it in editing mode. Both actions
capture the filtered and sorted list so you can navigate between vulnerabilities
without leaving the dialog.

# SBOM Table

The SBOM table lists every package present in the imported SBOMs within your current scope. It provides a package-centric view of your software bill of materials, complementing the vulnerability-centric Vulnerability Table.

## Search

The search bar accepts free-text queries that match against package name, reported version, release version, full source revision, CPE, and PURL identifiers. Typing at least two characters triggers a fuzzy search powered by Fuse.js. The search supports the same expression language as the vulnerability table:

- **`term`** — rows containing the term are shown.
- **`term1 term2`** — AND semantics: both terms must match.
- **`term1 | term2`** — OR semantics: either term matches.
- **`-term`** — NOT: rows containing the term are excluded.

A small **info icon** next to the search bar opens a quick-reference panel for this syntax. A **keyboard shortcut icon** on the right side of the toolbar shows available keyboard shortcuts (press `/` to focus the search bar, `↑`/`↓` to navigate rows, `Home`/`End` to jump to the first or last row).

## Column Visibility

The **Columns** dropdown lets you toggle which columns are displayed. The default set includes Name, Release version, Source revision, Dependency, Vulnerabilities, Variants, and Sources. The **Dependency** column shows each package's direct dependency (**Deps**) and dependent (**Req by**) counts and opens the [dependency graph](web-dependencies.md); sort it to list the packages with the highest **Deps** + **Req by** total first, or hide it to skip loading the counts. Additional columns available are:

- **CPE** — Common Platform Enumeration identifiers for the package. These are used by the NVD scanner to match vulnerabilities.
- **PURL** — Package URL identifiers. These are used by the OSV scanner for more precise ecosystem-level matching.
- **Remaining Pending Vulnerabilities** — the count of vulnerabilities still awaiting triage for this package.

**Release version** shows the release identified from the SBOM, PURL, or CPE.
**Source revision** shows the Git commit, shortened to 12 characters. Hover either
value to inspect its source information and the full revision. Missing values
are shown as **—**; contradictory values are flagged as **Conflicting metadata**.
A release version and a commit hash describe separate fields, not a conflict.

For version normalisation and source-evidence details, see the
[SBOM and Scan Reference](sbom-scan-reference.md#release-versions-and-source-revisions).

## Zephyr Component Badges

For Zephyr JSON-LD imports, **Built component** means recorded provenance connects
the package to a compiled target. **Workspace component** identifies a dependency
or source checkout without that proof; it does not establish inclusion in the
firmware. A package can carry different badges in different variants.
Ordinary packages have no badge.

Import companion documents together and reimport older inputs when source
revisions or provenance have not been recorded. See
[Zephyr Integration](zephyr-integration.md) for the import workflow and
[Zephyr JSON-LD Provenance](sbom-scan-reference.md#zephyr-json-ld-provenance)
for consolidation rules and upgrade behavior.
## Filters

- **Source**: restrict the table to packages originating from a specific SBOM source (e.g. a particular SPDX or CycloneDX document).
- **Outdated**: enable the toggle to show only historical package/variant combinations whose package version is no longer present in that variant's current SBOM. The toggle is off by default.

## Match Condition

The **Match condition** field in the toolbar filters packages using the same condition language as CI fail conditions (e.g. `cvss >= 7 and pending`). Press **Enter** or click **Apply** to evaluate the expression against every vulnerability in the current scope; the table is then reduced to packages that have at least one matching vulnerability. Clearing the field and applying again removes the filter. Whenever vulnerability data is refreshed the filter is cleared so it never shows stale results — apply the condition again to evaluate the fresh data.

While a match condition is active, the **Show Vulnerabilities** button carries the matching set along: the Vulnerability Table opens pre-filtered to that package *and* to the vulnerabilities that satisfied the condition.

See the [Match Conditions](ci_conditions.md) page for the full syntax and token reference.

## Actions

Each row has a **Show Vulnerabilities** button that opens the
[Vulnerability Table](web-vulnerabilities.md) filtered to that package.

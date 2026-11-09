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

The **Columns** dropdown lets you toggle which columns are displayed. The default set includes Name, Release version, Source revision, Recorded Files, Dependency, Vulnerabilities, Maintenance, Variants, and Sources. The **Dependency** column shows each package's direct dependency (**Deps**) and dependent (**Req by**) counts and opens the [dependency explorer](web-dependencies.md); sort it to list the packages with the highest **Deps** + **Req by** total first, or hide it to skip loading the counts. Additional columns available are:

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

## Recorded Files

Click anywhere in a **Recorded Files** count cell to open a fullscreen file browser, sized like
the dependency dialog. Search by path, document, or variant, and combine the
search with **Build evidence** and **SBOM document** filters. Select a file in
the list to read its provenance, hashes, properties, and build inputs/outputs.
On wide screens the list and details scroll independently; narrow screens stack
them vertically. **Clear filters** restores all records. Long build parameters
stay collapsed until expanded.
Technical identifiers and the original parsed data are available in a collapsed
section at the end of the details. An em dash (**—**) means file evidence has
not been recorded; reimport the original SPDX SBOMs to populate it. A zero count
means the imported SBOMs recorded no files for the package.

**Compilation recorded** means a compiler target records the file as an input.
**Other build input** includes recipe or packaging tasks and does not prove
compilation. **Listed only** means no associated build task was recorded.
**Binary / output** identifies explicitly contained SPDX 2 binaries and output
artifacts; use the corresponding filter to inspect them, including their original
file types, hashes, and licenses. These associations never count as compiled source
or enable CVE source exclusion. Reimport older SPDX 2 SBOMs to populate them.
None of these proves inclusion in the final firmware. The summary distinguishes
file records from unique compiled source paths. The browser presents the
recorded evidence without a CVE-matching policy banner; see
[Recorded files](interactive-mode.md#recorded-files) for how matching uses it.

See [Recorded files](interactive-mode.md#recorded-files) for supported formats,
scope, and reimport requirements.

## Maintenance

The **Maintenance** column shows the [OpenSSF Scorecard](https://scorecard.dev/)
score (0–10) of each package's upstream repository: green from 7, amber from 4,
red below. Chips summarise the Scorecard **Maintained** check (**Active**,
**Low activity**, **Inactive** or **Archived**, from commit and issue activity
over the last 90 days) and flag packages that deps.dev reports as
**Deprecated** in their registry. Sort the column to list the best-scored
packages first. Click a cell to open every Scorecard check with its reason, the
repository, and how that repository was found.

The score describes the maintainers' practices (code review, security policy,
fuzzing, signed releases, activity, …). It gives context while assessing a
package's vulnerabilities, for example how likely an upstream fix is, but it is
not a verdict and never changes assessments.

**Refresh maintenance** queues an **OpenSSF Scorecard** operation for the
current variants; scans started from the scan wizard queue it automatically.
The operation looks up the upstream repository of each package, in order, from:

1. SBOM metadata: `pkg:github`/`pkg:gitlab`/Go PURLs, Git source URLs, download
   locations, homepages, and CycloneDX `vcs`/`website`/`distribution`
   references (reimport older SBOMs to record download and homepage URLs);
2. [deps.dev](https://deps.dev/) for npm, PyPI, Cargo, Go, Maven, NuGet and
   RubyGems PURLs, which also provides the deprecation status;
3. the Git repository named by OSV for one of the package's CVEs, kept only when
   the CVE's CPE product matches the package.

Known mirror accounts are ignored, since their score says nothing about the
upstream maintainers. GitHub names from PURLs are case-insensitive while
Scorecard's are not, so a missing result is retried with GitHub's canonical
name; set `GITHUB_TOKEN` to lift GitHub's anonymous limit of 60 lookups per
hour. Repositories are re-resolved after 30 days and scores
after 7 days, matching Scorecard's weekly publication.

Cells read **Not covered** when the repository is not on GitHub or GitLab,
**Not scored** when it is outside the Scorecard public dataset, **No
repository** when none was found, and **Not fetched** until the refresh runs.
Set `VULNSCOUT_SCORECARD_ENABLED=0` to disable these lookups on offline
installations; the column then reads **Disabled**.

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

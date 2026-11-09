# Refresh Changes

Open **Refresh** in the navigation bar to inspect persisted vulnerability-data
refresh runs. Start a refresh with **Refresh Vulnerability Data** on the right
of the **Refresh History** bar. Choose
**Complete refresh** for every available provider or **Custom refresh** to choose
providers, then **Start**. The action uses vulnerabilities in the selected scope,
not table filters. Detailed progress is shown in the operation queue.
Per-provider cancellation remains available in the refresh menu, and success
or error banners appear above **Refresh History**.
Queued work continues after navigating away. Completed refreshes update the
loaded data and run results. This view does not run scanners or duplicate the
vulnerability's
[Data history](web-vulnerability-details.md#data-history).

## Scope and Run Selection

The project and variant selector controls visibility. A shared CVE can appear
in every captured project/variant scope where it is relevant; it is not limited
to the scope that initiated the refresh. Package links and coverage are scoped
by the server. The selector already identifies the viewing scope, so internal
project, variant, package and run IDs are not repeated in the page.

Use one project (all its variants) or a single variant. Variant comparisons are
not result scopes; the page asks you to select a project or variant rather than
silently broadening the results to the whole project. Refreshing from a
comparison still targets only its vulnerabilities.

Runs follow the Scan tab's timeline,
with provider markers, dated cards, status badges and highlighted change counts.
Use **View Refresh Result** to open a fullscreen popup like the Scan result popup.
Its **Changes**, **Coverage** and **Overview** sections present results in tables.
The timeline stays visible when no result is open. Use **Previous runs** and
**Next runs** to browse the history. Selected runs have a shareable
`/refresh?run=…` URL that opens their popup directly. Close it with **Close**,
Escape or the backdrop. An unavailable or out-of-scope run is explicitly reported.
The page never silently substitutes another run.

Run identifiers remain in shareable URLs; providers, start/end dates and status
are displayed without internal IDs.
**Reload results** retrieves those persisted records, including after a browser
reload or server restart. It does not refresh provider data, acknowledge changes,
or clear another user's indicators.

## Counts and Coverage

**Targeted**, **Checked**, **Changed**, **Skipped**, **Failed**, **Cancelled**
and **Pending** count distinct CVEs, not source/CVE pairs. One CVE checked by
several providers is counted once in each applicable category. Categories can
overlap: for example, NVD can succeed while EPSS fails for the same CVE.
Open **Overview** for the distinct counts or **Coverage** for per-source totals
and each CVE's outcome and error. Counts describe the whole selected run in the viewing scope,
not just the current page or change filter.

- **No refresh / no baseline** means no matching recorded run exists. Earlier
  values may predate run tracking; this does not establish that nothing changed.
  This is a normal empty state, not an API error.
- **First enrichment** means a field had no previous recorded value. It is an
  addition without a baseline, not a modification to a known prior value.
- **Zero changes** on a complete run is distinct from an absent run.
- **Running** shows committed changes so far; reload to retrieve progress.
- **Incomplete**, cancelled coverage and provider failures retain committed
  changes while exposing coverage gaps. They do not prove unchanged data.

## Inspecting Changes

Filter by source or change type (first enrichment, additions, modifications,
confirmed removals). Filtering is applied on the server before pagination.
The **Changes** table shows each field's before/after values, provider, timestamp
and relevant package links, with one row per field change.
CVSS entries identify the version, author and metric; scores and vectors remain
inspectable. Long descriptions, lists and vectors wrap and scroll.

Only recorded changes are shown. A missing provider response is never interpreted
as a removal. Collection changes show their additions/removals relative to the
recorded prior value.

**Open vulnerability** links to that CVE in the Vulnerabilities table. Relevant
package links filter that table to the package and CVE in the current scope.
Historical packages may no longer be present in the active SBOM table.

**Previous changes** and **Next changes** page through field changes. A CVE with
many field changes may continue on the next page; the **Changed** CVE count is
still distinct across the entire run.

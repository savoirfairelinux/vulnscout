# Refresh Changes

Open **Refresh** in the navigation bar to inspect persisted vulnerability-data
refresh runs. Start a refresh from **Vulnerabilities → Refresh Vulnerability
Data**. This view does not run scanners or duplicate the vulnerability's
[Data history](web-vulnerability-details.md#data-history).

## Scope and Run Selection

The project and variant selector controls visibility. A shared CVE can appear
in every captured project/variant scope where it is relevant; it is not limited
to the scope that initiated the refresh. Package links and coverage are scoped
by the server. The **Initiating scope** identifies where the run was requested,
which may differ from the scope you are viewing.

Use one project (all its variants) or a single variant. Variant comparisons are
not refresh scopes; the page asks you to select a project or variant rather than
silently broadening a comparison to the whole project.

The latest matching run opens by default. Select a recorded run to inspect it,
or use **Previous runs** and **Next runs**. Selected runs have a shareable
`/refresh?run=…` URL. An unavailable or out-of-scope run is explicitly reported;
the page never silently substitutes another run.

The run ID, sources, start/end timestamps and status are recorded server-side.
**Reload results** retrieves those persisted records, including after a browser
reload or server restart. It does not refresh provider data, acknowledge changes,
or clear another user's indicators.

## Counts and Coverage

**Targeted**, **Checked**, **Changed**, **Skipped**, **Failed**, **Cancelled**
and **Pending** count distinct CVEs, not source/CVE pairs. One CVE checked by
several providers is counted once in each applicable category. Categories can
overlap: for example, NVD can succeed while EPSS fails for the same CVE.
Expand **Per-source coverage and gaps**, then a source, to inspect each CVE's
outcome and error. Counts describe the whole selected run in the viewing scope,
not just the current page or change filter.

- **No refresh / no baseline** means no matching recorded run exists. Earlier
  values may predate run tracking; this does not establish that nothing changed.
- **First enrichment** means a field had no previous recorded value. It is an
  addition without a baseline, not a modification to a known prior value.
- **Zero changes** on a complete run is distinct from an absent run.
- **Running** shows committed changes so far; reload to retrieve progress.
- **Incomplete**, cancelled coverage and provider failures retain committed
  changes while exposing coverage gaps. They do not prove unchanged data.

## Inspecting Changes

Filter by source or change type (first enrichment, additions, modifications,
confirmed removals). Filtering is applied on the server before pagination.
Expand a CVE to see each field's before/after values, provider and timestamp.
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

# Metrics

The **Metrics** page is the home dashboard. Select a project and variant scope
in the navigation bar before interpreting its counts. It summarizes the
vulnerabilities in that scope by severity, assessment status, and discovery
source, and shows the five most critical unfixed vulnerabilities and the five
package names with the most vulnerability associations.

In **Current** mode, the default, the dashboard summarizes current exposure.
Select **Ever observed** below the variant controls in the **Project & Variant**
selector and click **Apply** to summarize both current and historical findings
in the selected project, variants, or comparison. Comparisons apply their set operation to
ever-observed evidence (for example, a pairwise difference shows what was
ever observed in the compared variant but never in the base).

Click a severity or status pie segment to open the Vulnerabilities table with
that filter and the same evidence mode. Use **Edit** to inspect a finding in
the critical list, or **See all** to open the corresponding full table.

**Assessment trend for current findings** shows how recorded assessments for
today's findings changed over the selected interval. It does not reconstruct
as-of scan membership or exposure and is hidden in **Ever observed** mode.
Status-chart counts are per vulnerability per status: when variants disagree,
one CVE can appear in more than one status segment, so the sum of segments is
not necessarily the number of distinct vulnerabilities.

The discovery-source chart attributes each vulnerability to exactly one primary
source, chosen using a fixed priority order when several sources are recorded.
Findings observed by multiple scanners count only once in this chart, not once
per source. Vulnerabilities without a recorded discovery source are omitted.

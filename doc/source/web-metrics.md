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
ever observed in the compared variant but never in the base). The help icon
beside **Evidence mode** describes both modes and the pages they affect.

Click a severity or status pie segment to open the Vulnerabilities table with
that filter and the same evidence mode. Use **Edit** to inspect a finding in
the critical list, or **See all** to open the corresponding full table.

**Assessment trend for current findings** shows the recorded assessment trend for
today's findings. **Assessment trend for ever-observed findings** instead looks
at the assessment history of the current and historical findings in the
selected evidence, matching the exact package and variant. A CVE counts once
per interval if any matching target had an active assessment status. Neither
chart reconstructs scan membership or exposure as of each date.
Status-chart counts are per vulnerability per status: when variants disagree,
one CVE can appear in more than one status segment, so the sum of segments is
not necessarily the number of distinct vulnerabilities.

The discovery-source chart attributes each vulnerability to exactly one primary
source, chosen using a fixed priority order when several sources are recorded.
Findings observed by multiple scanners count only once in this chart, not once
per source. Vulnerabilities without a recorded discovery source are omitted.

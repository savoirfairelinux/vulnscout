# Metrics

The **Metrics** page is the home dashboard. Select a project and variant scope
in the navigation bar before interpreting its counts. It summarizes the
vulnerabilities in that scope by severity, assessment status, and discovery
source, and shows the five most critical unfixed vulnerabilities and the five
package names with the most vulnerability associations.

Click a severity or status pie segment to open the Vulnerabilities table with
that filter. Click a vulnerability ID in the critical list to inspect it, or
use **See all** to open the corresponding full table.

The **Active vulnerabilities** chart tracks pending and exploitable
vulnerabilities over the selected time interval, from 24 hours to one year.
Status-chart counts are per vulnerability per status: when variants disagree,
one CVE can appear in more than one status segment, so the sum of segments is
not necessarily the number of distinct vulnerabilities.

The discovery-source chart attributes each vulnerability to exactly one primary
source, chosen using a fixed priority order when several sources are recorded.
Findings observed by multiple scanners count only once in this chart, not once
per source. Vulnerabilities without a recorded discovery source are omitted.

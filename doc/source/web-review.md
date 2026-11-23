# Review

The Review page gives you a consolidated view of every assessment that was created directly within VulnScout (as opposed to assessments imported from upstream SBOM documents). It is designed for auditing and exporting the triage decisions your team has made.

## Assessment Table

The table presents one row per assessment record. One record can cover several
exact `(variant, package)` targets; its row lists the combined package and
variant sets. Separate records remain separate even when their content is
identical. The displayed sets are summaries, not a guarantee that every listed
package is targeted in every listed variant.

The columns include:

- **Vulnerability**: the CVE identifier. Clicking it opens the vulnerability detail modal in read-only mode, letting you inspect the full context without leaving the review page.
- **SBOM Affected**: the list of packages this assessment covers.
- **Variants**: the variant tags associated with the assessment.
- **Modeled risk links**: references and descriptions from the saved STRIDE model for each exact variant/package target. An empty list means *no modeled risk linked*, not *no risk*. The same ID can mean something different in another variant.
- **Status**: the triage status (e.g. Not affected, Exploitable, Fixed).
- **Justification**: the VEX justification reason, if one was provided (e.g. "component not present", "vulnerable code not reachable").
- **Impact**: the impact statement describing how the vulnerability affects (or doesn't affect) the product.
- **Notes**: free-text status notes attached to the assessment.
- **Workaround**: any documented workaround.
- **Assessment Date**: the assessment record's timestamp.
- **AI review**: a second opinion on each target of a user-authored assessment. A single target shows ✓ when the review agrees, ⚠ when it differs, ⚠ stale when the assessment was edited since the review, or — when it has not been reviewed. Multi-target rows show counts for each state; hover for a breakdown. Open the vulnerability detail modal to read each target's review and rationale.

## Search and Filters

In **AI Assessments → Edit AI suggestion**, correct the risk IDs on the relevant target, or clear its field. `R1/T2` links a risk and one of its associated threats; `R1` links just the risk. **Confirm and approve** saves these changes without changing the verdict or target set. If a linked record or association disappears, or its description changes, Review retains the original description and labels the link stale. Correct or remove stale links before approval.

If the same IDs still apply, compare the saved and current descriptions and explicitly reconfirm the displayed revision. If the description changes again before approval, reload and review it again. Variant-filtered Review hides other variants' links; open the full project to review those targets. VulnScout JSON backups preserve the saved descriptions, even when the destination model uses the same ID differently.

The toolbar mirrors the vulnerability table's search bar. Filters include **Status**, **Justification**, and **AI review** (agreed, differed, stale, or no AI review). A multi-target row matches when any target has the selected review state.

On the **Assessments** and **AI Assessments** tabs, the **Outdated** selector defaults to **All**. Choose **Outdated** to show only rows with at least one target marked outdated or, for AI assessments, an outdated AI context. Choose **Not outdated** to exclude those rows. **Reset Filters** restores **All** and the other filter defaults.

See the "AI review of custom assessments" section in [AI Assessments](ai-assessments.md) for how to request an AI review.

Select rows in **Assessments**, then click **Review selected with AI** to queue
an independent review of each selected custom assessment, each in its own
conversation of the agent chat, which opens automatically. It uses the same
workflow as **Review with AI** in the vulnerability modal: it
retrieves each complete assessment and writes one review per target, including
targets outside the current project or variant view, without changing the
assessment. Scan-imported assessments and pending AI suggestions are not eligible.
Selection is preserved; already queued or running assessments are not queued
again; while queued, the button shows the request's state and opens it in the
chat. Closing the agent panel does not stop queued reviews. Its **AI queue**
button opens **Conversations**, listing requests from every page; select a
conversation to follow it, including reviews still waiting. Remove waiting
requests there, or retry a failed request to resume the queue.
Connection setup is available through the plug button, and the **Model**
selector is above the chat. Leaving the Review page or changing project/variant
does not cancel queued reviews; reviews already saved remain.

## Import and Export

Two buttons in the toolbar handle review portability:

- **Import Review**: choose either an OpenVEX JSON document or a VulnScout JSON file. OpenVEX imports assessments into one selected variant. VulnScout JSON restores all included assessments, custom CVSS scores, and time estimates using the variants recorded in the file.
- **Export Review**: choose **Normal export** to create a new file, or **Append/update existing file** to upload a previous export and preserve its stable ordering for smaller Git diffs. The existing file automatically selects VulnScout JSON or OpenVEX. VulnScout JSON exports assessments, custom CVSS scores, and time estimates for selected variants; OpenVEX exports assessments for one selected variant. Append/update replaces changed records, appends new records, and removes data for variants that are not currently selected.

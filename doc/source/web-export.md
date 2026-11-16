# Export

Use the **Export** page to generate rendered reports, standard SBOM/VEX
documents, and vulnerability field history. To transfer analyst decisions instead, use
[Review import and export](web-review.md#import-and-export).

SPDX exports include the selected active scans' recorded file metadata and
supported package/file associations, never file contents or invented hashes.
See [Recorded files in SPDX exports](exports.md#recorded-files-in-spdx-exports)
for roundtrip guarantees and build-evidence limitations.

1. **Scope** — choose a project in the navigation bar, then select its variants
   in the wizard. All project variants are initially selected, even when the
   navigation bar has a narrower variant selection; check this step explicitly.
2. **Export type** — choose **Reports**, **SBOM files**, or **Vulnerability history**. Reports offer one
   combined file per template/format across the selected variants, or a separate
   file per variant and template/format. SBOM files are always generated
   separately per variant; they cannot be combined with reports in one request.
3. For reports and SBOMs, **Documents** — enable the desired documents and choose their output
   formats. Reports can be filtered to built-in or custom templates.
   **Select visible** and **Clear visible** apply to the current category.
   Click **Download export** to queue the job.

For reports and SBOMs, the result is a ZIP archive. Generation and errors appear in the
[Operation queue](web-operation-queue.md), and the download starts when it is ready.
Closing the wizard or navigating away does not cancel the queued export.
After a missed download, reopen the queue to retrieve the retained archive;
it expires and can only be downloaded once.

Manage templates and images through **Settings → Custom reports & assets**.
Images are resources used by templates, not selectable export documents.
See [Writing Report Templates](templates.md) for custom template fields,
filters, and asset installation.

## Vulnerability history

After choosing **Vulnerability history**, the final step is **History options**.
Pick what to export:

- **Time window**: **Since** is required and inclusive; **Until** is optional
  and exclusive. Until must be later than Since. Leave it empty to include all
  recorded changes since the start. Enter times in your local timezone; the page
  converts them to UTC before requesting the export.
- **Latest refresh**: for each vulnerability, the changes made by the most
  recent refresh that updated it. No dates are needed, and the source filter
  only offers refresh providers (NVD, EPSS, GHSA, EUVD).

Then:

- Choose **JSON** or **CSV**, and optionally restrict to one **History source**.
- Click **Download history**. The file downloads directly, without a ZIP or
  queued operation. Download errors appear in the wizard and can be retried.

The export reuses the recorded field history introduced in the vulnerability
detail view. It contains old and resulting values, vulnerability identifiers,
sources, and timestamps. It only includes vulnerabilities in the selected
variants' **current active SBOM scope**, not historical variant membership.
Shared vulnerability data is exported once, without per-variant duplicates.
An empty result is a valid download, not proof that a refresh completed
successfully. Concurrent operations can contribute changes in the same window.
Latest-refresh exports group changes by the refresh run that recorded them;
refreshes started from the CLI or a single vulnerability before this option
existed carry no run identifier and are not considered.

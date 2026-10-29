# Export

Use the **Export** page to generate rendered reports and standard SBOM/VEX
documents. To transfer analyst decisions instead, use
[Review import and export](web-review.md#import-and-export).

1. **Scope** — choose a project in the navigation bar, then select its variants
   in the wizard. All project variants are initially selected, even when the
   navigation bar has a narrower variant selection; check this step explicitly.
2. **Export type** — choose **Reports** or **SBOM files**. Reports offer one
   combined file per template/format across the selected variants, or a separate
   file per variant and template/format. SBOM files are always generated
   separately per variant; they cannot be combined with reports in one request.
3. **Documents** — enable the desired documents and choose their output
   formats. Reports can be filtered to built-in or custom templates.
   **Select visible** and **Clear visible** apply to the current category.
   Click **Download export** to queue the job.

The result is a ZIP archive. Generation and errors appear in the
[Operation queue](web-operation-queue.md), and the download starts when it is ready.
Closing the wizard or navigating away does not cancel the queued export.
After a missed download, reopen the queue to retrieve the retained archive;
it expires and can only be downloaded once.

Manage templates and images through **Settings → Custom reports & assets**.
Images are resources used by templates, not selectable export documents.
See [Writing Report Templates](templates.md) for custom template fields,
filters, and asset installation.

# Settings

Settings has its own sidebar, independent of the main page selection:

- **General Settings** contains report metadata, the NVD API key, global
  native-package defaults, Grype memory settings, and data maintenance.
- **Project pages** list and create variants, rename the project, and provide
  project deletion. Expand a project in the sidebar to open a variant page.
- **Variant pages** import SBOM files into that variant and allow renaming it.
  Delete a variant from its project's variant list.
  Select all companion SPDX documents in one import. Uploads and
  their progress are tracked in the operation queue.
  Input formats can be auto-detected or chosen explicitly; see
  [Input Sources](cli-inputs.md) for supported formats.
- **Transfer Assessments** copies existing custom assessments to matching
  findings; see [Copying assessments](#copying-assessments).
- **Custom reports & assets** lists installed custom templates/images and
  accepts uploads through the drop zone or file picker. Supported image uploads
  are PNG, JPEG, GIF, and WebP. See [Adding Assets](templates.md#adding-assets).

Project names must be unique across the instance; variant names must be unique
within their project.

Deleting a project or variant permanently removes its associated data and
requires confirmation. Export important review data before deleting it.

## Native-Package Scan Defaults

In **Settings → General → Global native-package exclusions**, choose whether to exclude native packages by default and edit the exceptions under **Native packages to scan by default** (one name per line or comma-separated). Saving applies these defaults to projects without saved selections the next time the wizard opens. Existing project selections take precedence and are not overwritten. Disabling global exclusion scans all native packages by default while retaining the exception list.

See [Running Scans](web-scans.md#running-scans) to override these defaults for
a project and [Native-Package Scan Preferences](sbom-scan-reference.md#native-package-scan-preferences)
for the persisted configuration format.

## Data maintenance

Under **General Settings → Data Maintenance**, choose **Analyze outdated data**,
**Analyze empty scans**, or **Analyze orphaned CVEs** to inspect a deletion plan
before confirming. These operations are global: the current project/variant
selector does not restrict their scope. Outdated-data cleanup removes redundant
historical records, empty-scan cleanup removes scans with no retained data, and
orphan cleanup removes vulnerabilities no longer referenced by projects or
variants, including their assessments.

Review the listed records before confirming permanent deletion. If data changes
after the preview and the server rejects the stale plan, analyze again rather
than retrying the old selection. Keep a backup when history must be retained.

## Copying assessments

Open **Settings → Transfer Assessments** and select a project in the navigation
bar. Only user-authored custom assessments are copied, not scanner assessments
or pending AI suggestions.

1. Choose **Within the same variant** to carry decisions from previous package
   versions, or **Between two variants** to choose distinct source and
   destination variants.
2. Select a copy condition: only targets without a custom assessment, targets
   with a different status, or targets differing in any assessment value.
3. Choose package matching: **Same Versions**, **Same Major and Minor
   Versions**, **Same Major Versions**, or **Any Versions**. Exact-version
   matching is not offered within a single variant. Broader matching is a
   convenience, not evidence that a decision remains valid after an upgrade.
4. Click **Preview & Copy**. Inspect each source decision and its candidate
   target packages, adjust the selected targets, and confirm the copy.

Copying creates new custom assessment records on existing target findings;
it does not move or modify the source assessment. Source timestamps and AI
reviews are not carried over. Recheck the applicability of a decision before
copying it across versions or environments, especially with **Any Versions**.

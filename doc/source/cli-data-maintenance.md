# Data Maintenance

## Removing Outdated Data

VulnScout retains historical package evidence after an SBOM changes so it can identify
outdated findings and assessments. After the replacement SBOM and scans have been
reviewed, remove this obsolete data from **Settings → General Settings → Data Maintenance**.

The confirmation dialog previews every package/variant and custom assessment selected
for deletion. The cleanup applies to every project and variant in the database.

The same global cleanup is available to automation and CI:

```bash
./vulnscout delete outdated
./vulnscout delete empty-scans
./vulnscout delete orphaned-vulns
```

When run from a terminal, each command previews what it will remove and asks for
confirmation. Add `--yes` to skip the prompt, or `--dry-run` to print the preview
without deleting. Non-interactive runs, such as CI jobs, do not prompt.

The cleanup removes outdated package observations, SBOM links, and custom assessments.
It then removes a finding, package, or vulnerability only when nothing else references it.
When an orphaned vulnerability is removed, its exclusive metrics and refresh metadata are
removed as well. Vulnerabilities and package records that are still referenced by current
or other-variant data are preserved.

Empty-scan cleanup preserves each variant's initial scan and removes later scans only when
the scan-history diff contains no package, finding, CVE, or assessment changes. Orphaned-CVE
cleanup removes vulnerabilities with no scan evidence in any variant, together with their
findings, assessments, metrics, and refresh metadata.

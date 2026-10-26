# Enrich

Use two distinct operations to improve the evidence available for assessment:

- **Scan** the selected variant's packages to discover additional vulnerability
  findings using Grype, NVD, OSV, or sbom-cve-check.
- **Refresh** vulnerabilities already recorded to update NVD, EPSS, ENISA EUVD,
  and GitHub Advisory metadata. Refreshing does not discover new findings.

**Result:** scanner observations and updated vulnerability intelligence for the
chosen scope, not proof that a finding is exploitable in the product.

```{toctree}
:maxdepth: 1

vulnerability-scanning
vulnerability-data
```

When both operations are needed, scan first so the subsequent refresh includes
newly discovered vulnerabilities. Scanner choice, network requirements, local
advisory downloads, and offline behavior are described in the scanning guide.

The web interface exposes the same operations through
[Scan History](web-scans.md#running-scans) and the
[Vulnerability Table](web-vulnerabilities.md#refreshing-vulnerability-data).
Follow queued work in the [Operation Queue](web-operation-queue.md).

Continue with [Assess](workflow-assess.md). Repeat enrichment periodically,
even for an unchanged SBOM, when current vulnerability intelligence is needed.

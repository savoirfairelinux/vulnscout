# Interactive Mode

VulnScout's web interface lets you inspect packages, investigate vulnerabilities,
record triage decisions, and export results. See
[Starting the Web Interface](cli-web-interface.md) to open it, then select a
project and variant in the navigation bar.

## Getting Started with Vulnerability Analysis

### Starting a New Project

Importing an SBOM loads its package inventory and any vulnerability findings or
assessments supplied by the input documents. It does not run additional
vulnerability scanners.

Web uploads in **Settings** default to **Complete refresh**, which refreshes
provider metadata after parsing. This can make external provider requests and
lengthen the import. To disable this enrichment, choose **Custom refresh** and
deselect every source before uploading; see [SBOM Imports](web-settings.md#sbom-imports).
In contrast, CLI imports with `./vulnscout add` do not refresh provider metadata.

Use [Scan History](web-scans.md) to discover additional findings and
[refresh vulnerability data](web-vulnerabilities.md#refreshing-vulnerability-data)
to enrich findings already recorded.

Investigate findings that are **Pending Assessment** and record a supported
conclusion: **Exploitable**, **Not affected**, or **Fixed**. Keep unresolved
findings pending rather than guessing.

### Threat Model

A threat model describes the product's assets, trust boundaries, attack surfaces,
and deployment assumptions. Use it to investigate whether a vulnerability's
preconditions exist and to prioritise remediation.

The presence of a vulnerable package is not, by itself, proof that your product
is exploitable. Conversely, a low severity, low estimated likelihood, or accepted
business risk is not proof that the product is **Not affected**.

For example, evidence that the vulnerable code is excluded from the shipped
build may justify **Not affected**. A network-related finding requires checking
the actual vulnerable interfaces and attack preconditions, not merely assuming
that an offline deployment is safe.

If a reachable serial-port vulnerability can leak product data, it still affects
the product even when your team prioritises privilege escalation or code
execution. Record the impact and any risk-acceptance or prioritisation decision
in the assessment notes; do not use **Not affected** to mean "not a priority".

### Assessment Status in VulnScout

VulnScout groups all assessment statuses into four simplified categories:

- **Pending Assessment**: a conclusion has not been established or investigation is still in progress.
- **Exploitable**: the vulnerability is confirmed to affect the product in its current build, configuration, or deployment. Remediation priority is a separate decision.
- **Not affected**: technical evidence establishes that the vulnerability does not apply to the assessed product, for example because the vulnerable code is absent or its required execution path cannot be reached. A justification is required.
- **Fixed**: the vulnerability has been patched or resolved.

### Goal of the Interactive Mode

The interactive mode is where you investigate each CVE and record your triage decisions. The typical workflow is:

1. Find **Pending Assessment** findings in [Metrics](web-metrics.md) or the [Vulnerability Table](web-vulnerabilities.md).
2. Open [Vulnerability Details](web-vulnerability-details.md), read the advisory, inspect the affected packages, and check the build and deployment evidence.
3. Record a supported status, justification, impact, and notes; optionally document a workaround or estimate remediation effort. See [AI Assessments](ai-assessments.md) for assisted analysis and human approval.

## Web Interface Guides

Choose the guide for the screen or task you are using:

```{toctree}
:maxdepth: 1

web-metrics
web-sbom
web-dependencies
web-vulnerabilities
web-vulnerability-details
web-scans
web-review
web-export
web-settings
web-operation-queue
```

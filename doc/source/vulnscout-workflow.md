# VulnScout Workflow

The **VulnScout full pipeline** turns an existing SBOM into scoped vulnerability
findings, product assessments, executable policy, and shareable evidence.
It starts after SBOM generation and follows the same operating model as the
[VulnScout website](https://vulnscout.io/) and training:

![VulnScout full pipeline: Import, Enrich, Assess, Enforce, and Share, with optional AI assistance during assessment.](_static/vulnscout-pipeline.svg)

| Stage | Purpose | Result |
| --- | --- | --- |
| [Import](workflow-import.md) | Load SBOMs and any existing findings into a project and variant. | A scoped inventory and initial evidence. |
| [Enrich](workflow-enrich.md) | Scan for additional findings and refresh existing vulnerability metadata. | Broader discovery coverage and updated intelligence. |
| [Assess](workflow-assess.md) | Investigate product impact and record evidence-backed decisions, optionally assisted by AI. | Human-owned assessments and rationale. |
| [Enforce](workflow-enforce.md) | Evaluate a versioned vulnerability policy in CI. | A policy result distinguishable from an execution error. |
| [Share](workflow-share.md) | Generate reports, enriched SBOMs, VEX, or assessment-exchange files. | Artifacts for reviewers, customers, and downstream tools. |

This is a repeatable lifecycle, not a mandatory command sequence. Revisit
enrichment and assessments when advisories, builds, or deployment context change.
Scanning discovers findings; refreshing enriches findings already recorded.
AI assistance is optional, and proposed AI assessments require human approval
before becoming official.

In CI, generate required reports and exports **before the final
`match-condition`** so a policy failure does not prevent their creation. See
[Enforce](workflow-enforce.md) for execution order and exit codes.

For startup, configuration, and cleanup, see
[Supporting Tasks](workflow-supporting-tasks.md). For command syntax and
project/variant options, see [VulnScout CLI](vulnscout-script.md).

```{toctree}
:hidden:
:maxdepth: 2

workflow-import
workflow-enrich
workflow-assess
workflow-enforce
workflow-share
workflow-supporting-tasks
```

# VulnScout Workflow

These guides cover individual tasks, from importing an SBOM to scanning,
reviewing findings, and generating outputs. For command syntax and scope
options, see [VulnScout CLI](vulnscout-script.md).

Start by importing your inputs. Run vulnerability scanners if you need additional
findings, and refresh vulnerability metadata when current provider data is
needed. You can then review results in the web interface, generate reports and
exports, or evaluate match conditions in CI.

Choose the guide for the task you want to perform:

```{toctree}
:maxdepth: 2

cli-inputs
vulnerability-scanning
monitor-vulnerabilities
vulnerability-data
cli-web-interface
cli-data-maintenance
reports
exports
cli-assessments
cli-configuration
```

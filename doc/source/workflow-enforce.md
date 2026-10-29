# Enforce

Turn your vulnerability policy into a match condition evaluated against the
selected project's or variant's stored findings, intelligence, and assessments.
Keep the condition in version control alongside the CI job that applies it.

**Result:** a CI decision with separate exit codes for a policy match and an
execution failure.

```{toctree}
:maxdepth: 1

monitor-vulnerabilities
```

Use [Writing Match Conditions](ci_conditions.md) for the condition language,
scope rules, and examples. Exit **0** means no vulnerability matched, exit
**2** means the condition matched, and exit **1** means execution failed.
Handle policy failure and operational failure separately.

Match conditions use stored data; they do not scan packages, refresh metadata,
schedule recurring jobs, or send alerts by themselves. Configure your CI
scheduler and notifications, and run the relevant [Enrich](workflow-enrich.md)
operations before checking policy when current intelligence is required.

The pipeline diagram describes the logical stages, not a strict shell ordering.
In a CI shell that stops on errors, generate [Share](workflow-share.md) artifacts
before the final policy check:

```bash
set -e
./vulnscout report -p demo -v x86 summary.adoc
./vulnscout export -p demo -v x86 spdx cdx openvex
./vulnscout match-condition -p demo -v x86 \
  "cvss >= 7.0 and (pending or affected)"
```

This example assumes the same scope has already been imported, enriched, and
assessed as appropriate. Configure CI to retain the generated artifacts even
when the final policy check fails.

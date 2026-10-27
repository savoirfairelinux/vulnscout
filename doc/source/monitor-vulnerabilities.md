# Monitor Vulnerabilities

For CI pipelines or automated scans, import the inputs and then use `match-condition` instead of the web UI:

```bash
./vulnscout add -p demo --spdx /path/to/sbom.spdx.json --cve-check /path/to/cve-check.json
./vulnscout match-condition -p demo "((cvss >= 9.0 or (cvss >= 7.0 and epss >= 30%)) and (pending or affected))"
```

If vulnerabilities match the condition, `match-condition` exits with **code 2**, allowing CI systems to fail the pipeline. Run `match-condition` last: a shell running with `set -e` stops at the first non-zero exit, so commands after `match-condition` would not run.

Match conditions evaluate vulnerability data already stored by VulnScout. They do not automatically refresh EPSS or other provider data. Run `vulnscout refresh` before `match-condition` when the condition must use current enrichment data.

When `-p demo` is supplied without `-v`, the condition is evaluated across all variants in `demo`. Supplying both options limits evaluation to one variant. Omitting both options evaluates `default/default`. Supplying only `-v` is rejected; use `-p default -v <name>` to select a variant in the default project. Unknown names exit with **code 1**.

See the [Match Conditions](ci_conditions.md) page for the full syntax and token reference.

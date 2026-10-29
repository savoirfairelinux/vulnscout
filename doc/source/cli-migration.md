# Migrating from Legacy CLI Flags

For current command syntax and project/variant scope, see
[VulnScout CLI](vulnscout-script.md).

Releases before v0.24 used flags for every action, and one call could chain several of them. The flag syntax still works until **v0.25**. Each legacy flag prints one warning on stderr naming its replacement:

```
deprecated: --add-spdx (removed in v0.25); use 'vulnscout add --spdx <path>'
```

Set `VULNSCOUT_NO_DEPRECATION_WARNING=1` to silence the warnings, for example in CI logs. A call uses one syntax or the other: flags and commands cannot be mixed in the same call.

| Flag syntax | Command |
|---|---|
| `--add-spdx <path>` (also `--add-cdx`, `--add-cve-check`, `--add-yocto-vex`, `--add-openvex`, `--add-grype`) | `add --spdx <path>` (also `--cdx`, `--cve-check`, `--yocto-vex`, `--openvex`, `--grype`) |
| `--perform-scans <types>` | `scan <types>` |
| `--perform-grype-scan`, `--perform-nvd-scan`, `--perform-osv-scan`, `--perform-sbom-cve-check-scan` | `scan grype`, `scan nvd`, `scan osv`, `scan sbom-cve-check` |
| `--refresh-vulnerability-data` | `refresh` |
| `--match-condition <expr>` | `match-condition <expr>` |
| `--report <template>` | `report <template>` |
| `--match-condition <expr> --report <template>` | `report <template> --condition <expr>`, then `match-condition <expr>` |
| `--export-spdx`, `--export-cdx`, `--export-openvex` | `export spdx`, `export cdx`, `export openvex` |
| `--export-custom-vulnscout-data` | `export custom-data` |
| `--export-custom-openvex-assessments` | `export custom-openvex` |
| `--export-context` | `export context` |
| `--amend` | `export custom-data --amend`, `export custom-openvex --amend` |
| `--import-custom-vulnscout-data <path>` | `import custom-data <path>` |
| `--import-custom-openvex-assessments <path>` | `import custom-openvex <path>` |
| `--import-context <path>` | `import context <path>` |
| `--use-original-timestamps`, `--use-current-timestamps` | `--timestamps original`, `--timestamps current` |
| `--delete-scan <id>` | `delete scan <id>` |
| `--delete-outdated`, `--delete-empty-scans`, `--delete-orphaned-vulns` | `delete outdated`, `delete empty-scans`, `delete orphaned-vulns` |
| `--list-projects`, `--list-scans` | `list projects`, `list scans` |
| `config <key> <value>`, `--config <key> <value>` | `config set <key> <value>` |
| `config-list`, `--config-list` | `config list` |
| `config-clear <key>`, `--config-clear <key>` | `config unset <key>` |
| `--serve` | `serve` |
| `--start`, `--stop`, `--restart`, `--update` | `start`, `stop`, `restart`, `update` |
| `--add-asset <path>` | `asset add <path>` |
| `--project`, `--variant`, `--json`, `--dev`, `--version` | unchanged; `-p` and `-v` are new short forms |

## Behaviour changes

- **One command per call.** Split a chained call into one call per command, in this order: `add`, `scan`, `refresh`, `import`, `export`, `report`, `match-condition`.
- **Put `match-condition` last.** A chained legacy call still wrote its reports and exports when the condition matched. With separate calls, a script running with `set -e` stops at the first non-zero exit, so run `match-condition` last or handle its exit code explicitly.
- **`refresh` uses its own scope.** It refreshes the selected project or variant (every vulnerability without `-p`), not only the vulnerabilities imported by the previous `add`.
- **Custom OpenVEX without `-v`.** `export custom-openvex` writes every project variant, and `import custom-openvex` targets the project's only variant. The legacy flags still default to the `default` variant.
- **Scope is command-specific.** Put `-p` and `-v` after the command. A command that does not use them exits with code 1 instead of ignoring them.
- **`delete` confirms on a terminal.** Use `--yes` to skip the prompt and `--dry-run` to preview. Non-interactive runs do not prompt.
- **Removed spellings.** The undocumented `perform-grype-scan`, `perform-nvd-scan`, `perform-osv-scan`, `perform-sbom-cve-check-scan`, `sbom-cve-check-scan` and `--sbom-cve-check-scan` forms now fail as unknown commands. Use `scan <type>`.

## CI example

```bash
# Flag syntax (one call)
./vulnscout --project demo --variant x86 \
  --add-spdx sbom.spdx.json --add-cve-check cve.json \
  --perform-scans nvd,osv --refresh-vulnerability-data \
  --match-condition "cvss >= 9.0" --report summary.adoc --export-cdx

# Commands (one per call)
./vulnscout add -p demo -v x86 --spdx sbom.spdx.json --cve-check cve.json
./vulnscout scan -p demo -v x86 nvd,osv
./vulnscout refresh -p demo -v x86
./vulnscout report -p demo -v x86 summary.adoc --condition "cvss >= 9.0"
./vulnscout export -p demo -v x86 cdx
./vulnscout match-condition -p demo -v x86 "cvss >= 9.0"   # last: exit 2 fails the job
```

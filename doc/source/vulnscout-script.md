# VulnScout CLI

The `./vulnscout` script is the main host-side entry point for running VulnScout.
It manages the container lifecycle (Docker or Podman) and forwards commands to the container's entrypoint.

```
./vulnscout [global options] <command> [arguments] [options]
./vulnscout <command> --help
```

Releases before v0.24 used flags instead of commands. They still work until v0.25 and print a deprecation warning; see [Migrating from the flag syntax](#migrating-from-the-flag-syntax).

## Commands

| Command | Purpose | `-p` | `-v` |
|---|---|---|---|
| `add --spdx\|--cdx\|--cve-check\|--yocto-vex\|--openvex\|--grype <path>` | Import input files. Options repeat and mix; one call is processed as one import. | default `default` | default `default` |
| `scan [--grype] [--nvd] [--osv] [--sbom-cve-check] [--all]` | Run the selected scanners together on the current data. Positional types (`scan nvd,osv`) also work; no selection means `all`. | default `default` | default `default` |
| `refresh` | Refresh EPSS, NVD, ENISA EUVD and GitHub Advisory data. | optional; all data when omitted | optional; needs `-p` |
| `match-condition <condition>` | Exit 2 when a vulnerability matches the condition. | optional; all variants of the project | optional; needs `-p` |
| `report <template\|path>... [--format pdf\|html] [--condition <expr>]` | Generate reports. | default `default` | optional; all variants when omitted |
| `export <kind>... [--amend]` | Write `spdx`, `cdx`, `openvex`, `custom-data`, `custom-openvex` or `context` to the outputs directory. `--amend` applies to `custom-*` only. | default `default` | optional; all variants when omitted |
| `import custom-data <path> [--timestamps original\|current]` | Import custom VulnScout JSON data. | default `default` | rejected (the file names its variants) |
| `import custom-openvex <path> [--timestamps original\|current]` | Import custom OpenVEX assessments. | default `default` | optional; the project's only variant when omitted |
| `import context <path>` | Import project and variant context. | optional; retargets the file | optional; needs `-p` |
| `delete scan <id>\|outdated\|empty-scans\|orphaned-vulns [--dry-run] [--yes]` | Remove data from every project. | rejected | rejected |
| `list projects\|scans [--json]` | List projects and variants, or past scans. | rejected | rejected |
| `config get <key>\|set <key> <value>\|unset <key>\|list` | Read and write `.vulnscout/cache/config.env`. | rejected | rejected |
| `serve` | Start the web UI on port 7275. | rejected | rejected |
| `start`, `stop`, `restart`, `update`, `version` | Manage the container. | rejected | rejected |
| `asset add <path>...` | Stage report images (`png`, `jpg`, `jpeg`, `gif`, `svg`, `webp`). | rejected | rejected |

Global options can appear before or after the command:

| Option | Meaning |
|---|---|
| `--dev` | Mount the local `src/` and `vulnscout_mcp/` (commands that start the container). |
| `-h, --help` | Help for the command, or the overview. |
| `--version` | Same as `version`. |

`-p, --project <name>` and `-v, --variant <name>` are options of the commands marked in the `-p` and `-v` columns above; see `<command> --help`. A command that does not use a scope exits with code 1 when given `-p` or `-v`.

## Projects and Variants

VulnScout organises data into **projects** and **variants**. A project typically maps to a product, and variants represent different builds or architectures (e.g. `x86_64`, `aarch64`).

Select them with `-p, --project` and `-v, --variant`. Each command documents how it uses them (see [Commands](#commands)); commands that do not use a scope reject these options.

```text
./vulnscout -p <name> -v <name> <command>
```

Example:

```bash
./vulnscout -p demo -v x86 add \
  --spdx "$(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json" \
  --cve-check "$(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.json"
```

## Workflow Guides

Choose a guide for the task you want to perform:

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

## Migrating from the flag syntax

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

### Behaviour changes

- **One command per call.** Split a chained call into one call per command, in this order: `add`, `scan`, `refresh`, `import`, `export`, `report`, `match-condition`.
- **Put `match-condition` last.** A chained legacy call still wrote its reports and exports when the condition matched. With separate calls, a script running with `set -e` stops at the first non-zero exit, so run `match-condition` last or handle its exit code explicitly.
- **`refresh` uses its own scope.** It refreshes the selected project or variant (every vulnerability without `-p`), not only the vulnerabilities imported by the previous `add`.
- **Custom OpenVEX without `-v`.** `export custom-openvex` writes every project variant, and `import custom-openvex` targets the project's only variant. The legacy flags still default to the `default` variant.
- **Scope is validated.** `-p` or `-v` on a command that does not use them exits with code 1 instead of being ignored.
- **`delete` confirms on a terminal.** Use `--yes` to skip the prompt and `--dry-run` to preview. Non-interactive runs do not prompt.
- **Removed spellings.** The undocumented `perform-grype-scan`, `perform-nvd-scan`, `perform-osv-scan`, `perform-sbom-cve-check-scan`, `sbom-cve-check-scan` and `--sbom-cve-check-scan` forms now fail as unknown commands. Use `scan <type>`.

### CI example

```bash
# Flag syntax (one call)
./vulnscout --project demo --variant x86 \
  --add-spdx sbom.spdx.json --add-cve-check cve.json \
  --perform-scans nvd,osv --refresh-vulnerability-data \
  --match-condition "cvss >= 9.0" --report summary.adoc --export-cdx

# Commands (one per call)
./vulnscout -p demo -v x86 add --spdx sbom.spdx.json --cve-check cve.json
./vulnscout -p demo -v x86 scan nvd,osv
./vulnscout -p demo -v x86 refresh
./vulnscout -p demo -v x86 report summary.adoc --condition "cvss >= 9.0"
./vulnscout -p demo -v x86 export cdx
./vulnscout -p demo -v x86 match-condition "cvss >= 9.0"   # last: exit 2 fails the job
```

## Shell completion

Bash completion for commands, options and fixed values (scan types, export and import kinds, `--format`, `--timestamps`):

```bash
source <(vulnscout completion bash)
```

It is registered for `vulnscout` (on `PATH`) and `./vulnscout`. For any other invocation path, register it too, for example `complete -F _vulnscout_complete /opt/tools/vulnscout`. Add the line to `~/.bashrc` to make it permanent. Project and variant names are not completed.

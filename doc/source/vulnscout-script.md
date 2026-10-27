# VulnScout CLI

The `./vulnscout` script is the main host-side entry point for running VulnScout.
It manages the container lifecycle (Docker or Podman) and forwards commands to the container's entrypoint.

This page introduces command syntax, options, and project/variant selection.
For task-specific instructions, see [VulnScout Workflow](vulnscout-workflow.md).

```
./vulnscout [global options] <command> [arguments] [options]
./vulnscout <command> --help
```

Releases before v0.24 used flags instead of commands. They still work until
v0.25 and print a deprecation warning; see
[Migrating from Legacy CLI Flags](cli-migration.md).

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

`-p, --project <name>` and `-v, --variant <name>` are command options, not global options. Place them after the command; see `<command> --help` and the `-p` and `-v` columns above. A command that does not use a scope exits with code 1 when given `-p` or `-v`.

## Projects and Variants

VulnScout organises data into **projects** and **variants**. A project typically maps to a product, and variants represent different builds or architectures (e.g. `x86_64`, `aarch64`).

Select them with `-p, --project` and `-v, --variant`. Each command documents how it uses them (see [Commands](#commands)); commands that do not use a scope reject these options.

```text
./vulnscout <command> -p <name> -v <name>
```

Example:

```bash
./vulnscout add -p demo -v x86 \
  --spdx "$(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json" \
  --cve-check "$(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.json"
```

## Shell completion

Bash completion for commands, options and fixed values (scan types, export and import kinds, `--format`, `--timestamps`):

```bash
source <(vulnscout completion bash)
```

It is registered for `vulnscout` (on `PATH`) and `./vulnscout`. For any other invocation path, register it too, for example `complete -F _vulnscout_complete /opt/tools/vulnscout`. Add the line to `~/.bashrc` to make it permanent. Project and variant names are not completed.

```{toctree}
:hidden:
:maxdepth: 1

cli-migration
```

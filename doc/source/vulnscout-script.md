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
| `assess --cve <id>...\|--filter <expr> [--model <id>] [--timeout <s>] [--dry-run] [--json]` | Create pending AI assessments with the configured AI provider. Use `--cve` or `--filter`, not both; see [Assess from the CLI or CI](ai-assessments.md#assess-from-the-cli-or-ci). | optional; all variants of the project | optional, repeatable; needs `-p` |
| `report <template\|path>... [--format pdf\|html] [--condition <expr>]` | Generate reports. | default `default` | optional; all variants when omitted |
| `export <kind>... [--amend]` | Write `spdx`, `cdx`, `openvex`, `custom-data`, `custom-openvex` or `context` to the outputs directory. `--amend` applies to `custom-*` only. | default `default` | optional; all variants when omitted |
| `export vulnerability-history --since <timestamp> [--until <timestamp>] [--format json\|csv]` | Export recorded field changes to stdout. | optional; all data when omitted | optional; needs `-p` |
| `export vulnerability-history --last-refresh [--format json\|csv]` | Export each vulnerability's latest refresh changes to stdout. | optional; all data when omitted | optional; needs `-p` |
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

## Export Vulnerability Changes

Export the field history already recorded by VulnScout, either within a time
window or from each vulnerability's latest refresh:

```bash
./vulnscout export vulnerability-history \
  --since 2026-10-01T00:00:00Z --until 2026-10-02T00:00:00Z \
  --format json > changes.json

./vulnscout export vulnerability-history -p demo -v x86 \
  --since 2026-10-01T00:00:00Z --source nvd,epss \
  --format csv > changes.csv

./vulnscout export vulnerability-history -p demo --last-refresh \
  --format csv > last-refresh.csv
```

`--since` is inclusive; optional `--until` is exclusive and must be later.
Timestamps without a timezone mean UTC. `--last-refresh` replaces the time
window and cannot be combined with `--since` or `--until`: for each
vulnerability, it exports the changes made by the most recent refresh run
(`./vulnscout refresh`, a scan with refresh, or a refresh started from the web
interface) that updated it. Refreshes recorded by the CLI or a single-vulnerability
refresh before this option existed carry no run identifier and are not
considered. Optional `--source` (repeatable or
comma-separated), `--field`, and `--vuln-id` filters narrow the selection.
Without `-p`, all vulnerabilities are eligible. With `-p`/`-v`, the selection
uses the vulnerabilities in the **current active scope**, not historical
project membership. Unknown projects or variants fail instead of exporting
unscoped data. Explicitly empty or whitespace-only `-p`/`-v` names are rejected;
omit the option to leave that scope unrestricted.

JSON includes the time bounds, the `last_refresh` mode, total and history
entries. CSV contains one row
per field change, with JSON-encoded old/resulting values. Successful exports
write only the document to stdout; errors exit nonzero. No changes produces an
empty JSON history or a CSV header, not an error.

For CI, `--last-refresh` reports what the last refresh changed for each
vulnerability. To bound the export to one exact invocation instead, record
timestamps around a refresh and preserve its exit status:

```bash
since="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
status=0
./vulnscout refresh -p demo -v x86 || status=$?
until="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
./vulnscout export vulnerability-history -p demo -v x86 \
  --since "$since" --until "$until" --format json > changes.json || exit $?
exit "$status"
```

This exports changes within a time window, not the outcome of an exact
invocation: concurrent operations can contribute changes, and an empty export
does not establish that providers completed successfully. Exports depend on
retained vulnerability history; archive the files externally if needed.

Direct Python deployments can use
`flask --app src.bin.webapp export-vulnerability-history --since <timestamp> --format csv --output changes.csv`
(or `--last-refresh` instead of `--since`).
See [Vulnerability History](api.md#vulnerability-history) for the corresponding
HTTP export.

## Source evidence and CVE refinement

For imported SPDX 3 Build-profile evidence, the local engine also receives
compiled-source paths from the selected variant's active SBOMs. When an advisory
identifies affected files, the engine can record a `not_affected` VEX assessment
if none were compiled. The finding remains available for review; it is not
deleted. Missing or incomplete build evidence retains ordinary matching, and
advisories without affected-file information cannot use this refinement.
This does not evaluate Kconfig expressions or infer release versions from Git
revisions. Yocto BitBake recipe inputs and SPDX 2 package/file inventories
remain available for inspection but cannot by themselves enable compiled-source
refinement. See [Source files](interactive-mode.md#source-files).

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

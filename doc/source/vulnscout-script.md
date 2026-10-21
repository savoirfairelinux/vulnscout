# VulnScout CLI

The `./vulnscout` script is the main host-side entry point for running VulnScout.
It manages the container lifecycle (Docker or Podman) and forwards commands to the container's entrypoint.

```
./vulnscout [global options] <command> [arguments] [options]
./vulnscout <command> --help
```

Releases before v0.24 used flags instead of commands. They still work until v0.26 and print a deprecation warning; see [Migrating from the flag syntax](#migrating-from-the-flag-syntax).

---

## Commands

| Command | Purpose | `-p` | `-v` |
|---|---|---|---|
| `add --spdx\|--cdx\|--cve-check\|--yocto-vex\|--openvex\|--grype <path>` | Import input files. Options repeat and mix; one call is processed as one import. | default `default` | default `default` |
| `scan [grype\|nvd\|osv\|sbom-cve-check\|all]` | Run scanners on the current data. No type means `all`. | default `default` | default `default` |
| `refresh` | Refresh EPSS, NVD, ENISA EUVD and GitHub Advisory data. | optional; all data when omitted | optional; needs `-p` |
| `match-condition <condition>` | Exit 2 when a vulnerability matches the condition. | optional; all variants of the project | optional |
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

---

## Container Lifecycle

The `vulnscout` script manages the container automatically (using Docker or Podman, whichever is available). You can also control it explicitly:

```bash
# Start the container (done automatically by most commands)
./vulnscout start

# Stop and remove the container
./vulnscout stop

# Restart the container (useful after changing config)
./vulnscout restart
```

---

## Updating VulnScout

To update VulnScout to the latest version, pull the latest container image and restart:

```bash
./vulnscout update
```

Then verify the new version is correctly running:

```bash
./vulnscout version
```

---

## Interactive Mode (Web UI)

By default VulnScout runs in **interactive mode**, starting a web dashboard.

```bash
./vulnscout add \
  --spdx $(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
  --cve-check $(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.json
./vulnscout serve
```

Then open:

```
http://localhost:7275
```

If data has already been imported, run `serve` alone:

```bash
./vulnscout serve
```

### Web Interface Settings

The web interface includes a **Settings** tab that provides:

- **Rename Project** — Select a project and give it a new name (must be unique across all projects).
- **Rename Variant** — Select a variant within a project and rename it (must be unique within the project).
- **Import SBOM** — Upload an SBOM file directly from the browser instead of `vulnscout add`.
  When importing, you must select (or create) the target project and variant.
  Supported formats are auto-detected or can be specified explicitly: SPDX (2/3), CycloneDX, OpenVEX, Yocto CVE check, and Grype.
- **Data Maintenance** — In **Scan Settings**, remove outdated data, empty scans, or CVEs no longer included in any project or variant.
  This action is not limited to the project or variant currently selected in the web interface.

### Removing Outdated Data

VulnScout retains historical package evidence after an SBOM changes so it can identify
outdated findings and assessments. After the replacement SBOM and scans have been
reviewed, remove this obsolete data from **Settings → Scan Settings → Data Maintenance**.

The confirmation dialog previews every package/variant and custom assessment selected
for deletion. The cleanup applies to every project and variant in the database.

The same global cleanup is available to automation and CI:

```bash
./vulnscout delete outdated
./vulnscout delete empty-scans
./vulnscout delete orphaned-vulns
```

When run from a terminal, each command previews what it will remove and asks for
confirmation. Add `--yes` to skip the prompt, or `--dry-run` to print the preview
without deleting. Non-interactive runs, such as CI jobs, do not prompt.

The cleanup removes outdated package observations, SBOM links, and custom assessments.
It then removes a finding, package, or vulnerability only when nothing else references it.
When an orphaned vulnerability is removed, its exclusive metrics and refresh metadata are
removed as well. Vulnerabilities and package records that are still referenced by current
or other-variant data are preserved.

Empty-scan cleanup preserves each variant's initial scan and removes later scans only when
the scan-history diff contains no package, finding, CVE, or assessment changes. Orphaned-CVE
cleanup removes vulnerabilities with no scan evidence in any variant, together with their
findings, assessments, metrics, and refresh metadata.

---

## Projects and Variants

VulnScout organises data into **projects** and **variants**. A project typically maps to a product, and variants represent different builds or architectures (e.g. `x86_64`, `aarch64`).

Select them with `-p, --project` and `-v, --variant`. Each command documents how it uses them (see [Commands](#commands)); commands that do not use a scope reject these options.

```bash
./vulnscout -p <name> -v <name> <command>
```

Example:

```bash
./vulnscout -p demo -v x86 add \
  --spdx $(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
  --cve-check $(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.json
```

## Input Sources

VulnScout accepts multiple input file types through `add`. Repeat an option or mix types in one call; the inputs are processed together.

### Refresh Vulnerability Data

Use `refresh` to enrich vulnerabilities with current EPSS, NVD, ENISA EUVD, and
GitHub Advisory data. After importing new inputs, refresh the same project:

```bash
./vulnscout -p demo add --spdx $(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json
./vulnscout -p demo refresh
```

Inside the container, the equivalent Flask command is:

```bash
flask --app src.bin.webapp process --refresh-vulnerability-data
```

Omit `-p` to refresh every vulnerability, or supply it to restrict the refresh to
that project's active vulnerabilities:

```bash
./vulnscout refresh
./vulnscout -p demo refresh
./vulnscout -p demo -v x86 refresh
```

Inside the container, use `flask --app src.bin.webapp refresh-vulnerability-data`
with optional `--project` and `--variant` arguments. A variant requires its project
because variant names are project-local.

The refresh enriches existing imported CVE and GHSA records; it does not discover new
findings. Providers with no applicable vulnerability identifiers are skipped. If any
applicable provider fails, processing continues through the remaining providers and the
command exits with an error listing the failed sources.

### SPDX SBOM

```
add --spdx <path>
```

Path to an SPDX 2 or SPDX 3 SBOM file. SPDX 3 JSON-LD files (`.jsonld`), including Zephyr-generated SBOMs, are supported. Also supports SPDX JSON, tag-value (`.spdx`), and archive formats (`.tar`, `.tar.gz`, `.tar.zst`).

For Zephyr's West SPDX generator, import the companion documents together into the
same project and variant:

```bash
./vulnscout -p zephyr_demo -v mbedtls_native_sim add \
  --spdx "$(pwd)/example/zephyr/app.jsonld" \
  --spdx "$(pwd)/example/zephyr/build.jsonld" \
  --spdx "$(pwd)/example/zephyr/modules-deps.jsonld" \
  --spdx "$(pwd)/example/zephyr/zephyr.jsonld"
```

These files are bundled under `example/zephyr/`. See
[Bundled Examples](examples.md) for the full dataset list and interactive
import commands.

Release versions and Git revisions are displayed separately in the SBOM table;
see [Interactive mode](interactive-mode.md#column-visibility).

---

### CycloneDX SBOM

```
add --cdx <path>
```

Path to a CycloneDX file.

---

### Yocto CVE Check Output

```
add --cve-check <path>
```

JSON output from the Yocto `cve-check` task.

---

### Yocto VEX Output

```
add --yocto-vex <path>
```

JSON output from the Yocto `vex.bbclass` task.  Carries richer CPE and
patch-file information than the plain cve-check output.

---

### OpenVEX

```
add --openvex <path>
```

Include vulnerability assessments provided as OpenVEX.

---

### Grype

```
add --grype <path>
```

Import a Grype native JSON file. Files should end with `.grype.json`.

---

### Combining Inputs

Repeat or mix input options in one `add` call:

```bash
./vulnscout -p demo -v x86 add \
  --spdx /path/to/sbom.spdx.json \
  --cve-check /path/to/cve-check.json \
  --openvex /path/to/assessments.openvex.json
```

```{tip}
The input format is determined by the CLI flag used (`--spdx`, `--cdx`, etc.), not by the file extension.
The only exception is SPDX archive inputs (`.tar`, `.tar.gz`, `.tar.zst`), which are automatically extracted and their `.spdx.json` contents imported.
To ignore parsing errors for malformed SBOMs, set: `IGNORE_PARSING_ERRORS=true`
```

---

## Performing a Grype Scan

VulnScout can run Grype on the current database contents:

```bash
./vulnscout -p demo -v x86 scan grype
```

`scan` accepts `grype`, `nvd` (CPE-based), `osv` (PURL-based), and `sbom-cve-check` (local advisory databases). Select several with commas (`scan nvd,osv`) or spaces (`scan nvd osv`). With no type, or with `all`, every available scanner runs. Scans always run in the order Grype, NVD, OSV, sbom-cve-check. Vulnerability-data refresh is a separate command (`refresh`).

To scan newly added files, run `add` and then `scan` with the same scope:

```bash
./vulnscout -p demo add --spdx example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json
./vulnscout -p demo scan grype
```

`scan grype` can consume significant RAM on large SBOMs.
VulnScout automatically caps Grype's memory at ~80 % of the container/cgroup limit.
Use `GRYPE_MEMLIMIT` to override:

```bash
# Set a persistent limit
./vulnscout config set GRYPE_MEMLIMIT 6GiB

# Or export it on the host before running (forwarded into the container)
export GRYPE_MEMLIMIT=24GiB
./vulnscout -p demo scan grype

# Disable the limit entirely
./vulnscout config set GRYPE_MEMLIMIT off
```

Accepts any value valid for Go's `GOMEMLIMIT` (`4GiB`, `8192MiB`, plain bytes).
Set to `off`, `0`, or `disabled` to remove the cap.

---

## Performing an sbom-cve-check Scan

`scan sbom-cve-check` runs a CVE scan powered by [sbom-cve-check](https://github.com/savoirfairelinux/sbom-cve-check). Unlike the NVD and OSV scanners, and once the databases are synced, this scan never makes network calls during analysis; it queries locally-cloned advisory databases (NVD-FKIE JSON feeds and CVEList V5).

```bash
./vulnscout -p demo -v x86 scan sbom-cve-check
```

To scan newly added files, run `add` first:

```bash
./vulnscout -p demo add --spdx example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json
./vulnscout -p demo scan sbom-cve-check
```

---

## Non-Interactive Mode (CI / Automation)

For CI pipelines or automated scans, import the inputs and then use `match-condition` instead of the web UI:

```bash
./vulnscout -p demo add --spdx /path/to/sbom.spdx.json --cve-check /path/to/cve-check.json
./vulnscout -p demo match-condition "((cvss >= 9.0 or (cvss >= 7.0 and epss >= 30%)) and (pending or affected))"
```

If vulnerabilities match the condition, `match-condition` exits with **code 2**, allowing CI systems to fail the pipeline. Run `match-condition` last: a shell running with `set -e` stops at the first non-zero exit, so commands after `match-condition` would not run.

Match conditions evaluate vulnerability data already stored by VulnScout. They do not automatically refresh EPSS or other provider data. Run `vulnscout refresh` before `match-condition` when the condition must use current enrichment data.

When `-p demo` is supplied without `-v`, the condition is evaluated across all variants in `demo`. Supplying both options limits evaluation to one variant. Omitting both options evaluates `default/default`; supplying only `-v` selects that variant from the `default` project. Unknown names exit with **code 1**.

See the [Match Conditions](ci_conditions.md) page for the full syntax and token reference.

---

## Report Generation

Reports are generated from templates. VulnScout ships with built-in templates and also supports custom ones.
Use `-p` to select the report scope; when omitted, the `default` project is used. A project report includes all its variants. Add `-v` to restrict the report to one variant in that project. Unknown project or variant names exit with **code 1** instead of broadening the report scope.

```bash
# Generate a report from a built-in template
./vulnscout -p demo report summary.adoc

# Generate a report for one variant only
./vulnscout -p demo -v x86 report summary.adoc

# Generate a match-condition report
./vulnscout -p demo report match_condition.adoc --condition "cvss >= 9.0"

# Pass a local template file path — stages and runs it in one step
./vulnscout -p demo report /path/to/my-custom-report.adoc

# Convert the output
./vulnscout -p demo report summary.adoc --format pdf
```

`--condition` fills the report's list of matching vulnerabilities. A match does not fail `report`; use `match-condition` to fail a CI job. `--format pdf` or `--format html` overrides the format implied by the template extension.

Multiple reports can be generated in one command:

```bash
./vulnscout -p demo report summary.adoc all_assessments.adoc
```

Reports are written to the outputs directory (default: `.vulnscout/outputs/`).

See the [Templates](templates.md) page for documentation on writing custom report templates.

---

## Exporting SBOM Files

VulnScout can export the enriched project data as standard SBOM formats. Exported files are written to the outputs directory (default: `.vulnscout/outputs/`).

```bash
# Export as SPDX 3.0 SBOM
./vulnscout -p demo export spdx

# Export as CycloneDX 1.6 SBOM
./vulnscout -p demo export cdx

# Export as OpenVEX document (vulnerabilities + assessments)
./vulnscout -p demo export openvex
```

One `export` call can write several formats:

```bash
./vulnscout -p demo export spdx cdx openvex
```

---

## Exporting and Importing Custom Assessments

VulnScout lets you export and re-import the assessments you have manually created through the web interface (review / triage decisions). This is useful for:

- Backing up your review work before re-importing SBOMs.
- Sharing assessment decisions across different VulnScout instances.
- Restoring triage state in CI pipelines after a database reset.

### VulnScout JSON

`export custom-data` exports custom assessments, pending AI
assessments, CVSS scores, and time estimates as one VulnScout JSON file. It
includes every variant in the selected project unless `-v` is provided.
After import, pending AI assessments are available from the Review page's **AI
Assessments** tab for approval or rejection.

```bash
./vulnscout -p demo export custom-data
```

Export one variant:

```bash
./vulnscout -p demo -v x86 export custom-data
```

Add `--amend` to reconcile current review data with the existing file in the
output directory:

```bash
./vulnscout -p demo export custom-data --amend
```

`import custom-data` restores entries according to the variant metadata stored in the file, so it rejects `-v`. Imported assessments use the current system time by default. Add `--timestamps original` to preserve assessment timestamps from the file; `--timestamps current` selects the default explicitly.

Current version 2 exports identify targets with variant names and packages,
not instance-local variant UUIDs. Legacy version 1 files remain importable;
unsupported future versions are rejected explicitly.

```bash
./vulnscout -p demo import custom-data /path/to/custom_vulnscout_data_all.json

./vulnscout -p demo import custom-data /path/to/custom_vulnscout_data_all.json --timestamps original
```

### OpenVEX

OpenVEX products carry no variant identity, so each document belongs to one
variant. With `-v`, `export custom-openvex` writes `custom_openvex_<variant>.json`;
without it, it writes one such file per project variant that has custom
assessments. `import
custom-openvex` imports into `-v`, or into the project's only variant when `-v`
is omitted. If the project has several variants, it exits with code 1 and lists
them.

```bash
# Export a variant
./vulnscout -p demo -v x86 export custom-openvex

# Export every variant of the project
./vulnscout -p demo export custom-openvex

# Import into a variant
./vulnscout -p demo -v x86 import custom-openvex /path/to/custom_openvex_x86.json

# Ignore OpenVEX statement timestamps and use the current system time
./vulnscout -p demo -v x86 import custom-openvex /path/to/custom_openvex_x86.json --timestamps current
```

OpenVEX imports preserve statement timestamps by default. Add
`--timestamps current` to use the current system time, or
`--timestamps original` to select the default explicitly.

### Project and Variant Context

`export context` writes the AI context of the selected scope to
`context-export.json`. `import context` restores it:

```bash
./vulnscout -p demo export context

# Import into the projects and variants named in the file
./vulnscout import context /path/to/context-export.json

# Import every entry into project "staging", keeping variant names
./vulnscout -p staging import context /path/to/context-export.json

# Import a single-entry file into one variant
./vulnscout -p staging -v x86 import context /path/to/context-export.json
```

With `-p`, the file must name a single project. With `-p` and `-v`, it must
hold exactly one entry. `-v` without `-p` is rejected.

---

## Configuration

### Configuration Commands

Persistent configuration is stored in `.vulnscout/cache/config.env` and is automatically loaded on each run.

```bash
# Set a config value
./vulnscout config set <key> <value>

# Print one value
./vulnscout config get <key>

# List current configuration (sensitive values masked)
./vulnscout config list

# Remove a config key
./vulnscout config unset <key>
```

Example — set an NVD API key for higher rate limits:

```bash
./vulnscout config set NVD_API_KEY abc123
```

### Environment Variables

The following environment variables can be set via `vulnscout config set` or exported before running.

Example:

```bash
./vulnscout config set NVD_API_KEY abc123
```

#### Container & Runtime

| Variable | Description | Default |
|----------|-------------|---------|
| `VULNSCOUT_CONTAINER` | Name of the container | `vulnscout` |
| `VULNSCOUT_IMAGE` | Container image to use | `docker.io/sflinux/vulnscout:v0.23` |
| `VULNSCOUT_BUILD_DIR` | Root build directory on the host | `./.vulnscout` |
| `VULNSCOUT_OUTPUTS_DIR` | Directory for output files on the host | `$VULNSCOUT_BUILD_DIR/outputs` |
| `VULNSCOUT_CACHE_DIR` | Cache directory (SQLite database and config) | `$VULNSCOUT_BUILD_DIR/cache` |
| `FLASK_RUN_PORT` | Port the web UI listens on | `7275` |
| `FLASK_RUN_HOST` | Host address for the web UI | `0.0.0.0` |
| `VITE_API_URL` | Optional backend API URL for the dev frontend (empty uses Vite's same-origin `/api` proxy) | empty |
| `USER_UID` | UID used to write output files | current user |
| `USER_GID` | GID used to write output files | current group |
| `REFRESH_REMOTE_DELAY` | How often EPSS/NVD data is re-fetched (`never`, `always`, `48h`, `7d`, etc.) | `48h` |

#### Scan & Enrichment

| Variable | Description | Default |
|----------|-------------|---------|
| `NVD_API_KEY` | NVD API key for higher rate limits | _(none)_ |
| `IGNORE_PARSING_ERRORS` | Continue scanning even if input files contain errors | `false` |
| `VERBOSE_MODE` | Enable verbose logging in the container | `false` |

#### Report Metadata

| Variable | Description | Default |
|----------|-------------|---------|
| `PRODUCT_NAME` | Product name embedded in reports and SBOMs | _(none)_ |
| `PRODUCT_VERSION` | Product version embedded in reports | _(none)_ |
| `AUTHOR_NAME` | Author/company name embedded in reports | _(none)_ |
| `CLIENT_NAME` | Customer company name (optional, may be empty) | _(none)_ |
| `CONTACT_EMAIL` | Contact email embedded in reports | _(none)_ |
| `DOCUMENT_URL` | URL embedded in exported SBOM documents | _(none)_ |

---

## HTTP Proxy Configuration

VulnScout supports HTTP proxies. Set them via the config command:

```bash
./vulnscout config set HTTP_PROXY http://proxy.example.com:8080
./vulnscout config set HTTPS_PROXY http://proxy.example.com:8080
./vulnscout config set NO_PROXY localhost,127.0.0.1
```

Or set them as environment variables in the shell before running `vulnscout`:

```bash
export HTTP_PROXY=http://proxy.example.com:8080
./vulnscout serve
```

---

## Migrating from the flag syntax

Releases before v0.24 used flags for every action, and one call could chain several of them. The flag syntax still works until **v0.26**. Each legacy flag prints one warning on stderr naming its replacement:

```
deprecated: --add-spdx (removed in v0.26); use 'vulnscout add --spdx <path>'
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

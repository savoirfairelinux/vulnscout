# Using Container Entrypoint

The VulnScout container ships with an entrypoint script at `/scan/src/entrypoint.sh`.
This is what the `./vulnscout` host wrapper calls under the hood. You can also invoke it directly via `docker exec` (or `podman exec`) for advanced workflows or CI pipeline integration where you manage the container yourself.

```bash
docker exec <container> /scan/src/entrypoint.sh [OPTIONS]
# or
podman exec <container> /scan/src/entrypoint.sh [OPTIONS]
```

> **Note:** VulnScout supports Docker and Podman. For rootless Podman, also apply
> the user-namespace settings described below; substituting the command name alone
> does not provide the wrapper's ownership mapping.

---

## Output colors

First-party help and human-readable messages use cyan for headings/information,
green for success, yellow for warnings, and red for errors, with bold labels.
Colors are automatic and stdout/stderr are detected separately. Pipes and
redirected files stay plain; non-empty `NO_COLOR` or `TERM=dumb` disables colors.
For example, run `NO_COLOR=1 ./vulnscout scan nvd` for plain output.

The host wrapper forwards its stream eligibility on each container exec, without
allocating a TTY or changing the container's persistent configuration. Direct
entrypoint or Flask invocations detect their own terminals. Plain `docker exec`
without a TTY therefore produces plain output. To disable colors inside a
direct container invocation, pass `--env NO_COLOR=1` to `docker exec` or
`podman exec`.

JSON listings, generated completion scripts, captured run IDs, configuration
values, status files, and exported SBOMs/reports are never colorized. Third-party
tools retain their own output behavior.

Flask application and Werkzeug server logs use the same terminal detection and
opt-outs. Debug messages are dim gray, information is cyan, warnings are yellow,
errors are red, and critical messages are bold red. Werkzeug's existing
HTTP-status highlighting is retained in terminals and stripped from plain
output. Log levels, message text, and tracebacks are unchanged. Explicit logging
handlers configured by a deployment take precedence over these defaults.

## Container Lifecycle

When the container starts with no arguments, it enters **daemon mode** — it stays alive and waits for commands sent via `docker exec` (or `podman exec`). This is the mode used by the `./vulnscout` host wrapper.

### Standalone Docker setup

Run this from the repository root. Use a different container name if the host
wrapper already manages a container named `vulnscout`. The separate
`.vulnscout-container/` directory avoids sharing its database with the wrapper.

```bash
umask 077
mkdir -p .vulnscout-container/{cache,outputs,config}
# Create once; retain this file and the cache when recreating the container.
if [ ! -f .vulnscout-container/config/config.env ]; then
  cat > .vulnscout-container/config/config.env <<EOF
FLASK_RUN_HOST=0.0.0.0
FLASK_RUN_PORT=7275
USER_UID=$(id -u)
USER_GID=$(id -g)
EOF
fi
chmod 600 .vulnscout-container/config/config.env

docker run -d --name vulnscout \
  -p 127.0.0.1:7275:7275 \
  --env-file "$(pwd)/.vulnscout-container/config/config.env" \
  -v "$(pwd)/.vulnscout-container/cache:/cache/vulnscout:Z" \
  -v "$(pwd)/.vulnscout-container/outputs:/scan/outputs:Z" \
  -v "$(pwd)/.vulnscout-container/config:/etc/vulnscout:Z" \
  -v "$(pwd)/example:/imports:ro,Z" \
  docker.io/sflinux/vulnscout:v0.23 daemon

docker exec vulnscout /scan/src/entrypoint.sh \
  --project demo --variant x86 \
  --add-spdx /imports/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
  --add-cve-check /imports/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.json

docker exec -it vulnscout /scan/src/entrypoint.sh --serve
```

Open <http://localhost:7275/> and select `demo/x86`. Omit `-it` for non-interactive
CI commands. Add proxy values or API keys to the configuration before creating
the container if needed. Mounting the **configuration directory** allows config
commands to replace `config.env` while retaining persistence.

The image alone does not configure Flask's bind address or port; both environment
settings above are required for this published-port recipe. To use another host
port, change only the host side, for example `-p 127.0.0.1:8080:7275`.
The host wrapper instead publishes a fixed `7275:7275` mapping.

For rootless Podman, replace `docker` with `podman` and add
`--userns=keep-id:uid=0,gid=0 --user=0:0 -e VULNSCOUT_ROOTLESS_PODMAN=true`
to `podman run`. This maps container root to the host owner so it can read the
private config and keep persisted files host-owned.

The `/imports` mount is read-only; files are copied to the writable staging area
before processing. To use other inputs, mount their parent directory read-only
at `/imports`, or copy files into the container before referencing them:

```bash
docker cp /path/to/sbom.spdx.json vulnscout:/scan/sbom.spdx.json
docker exec vulnscout /scan/src/entrypoint.sh \
  --project demo --variant x86 --add-spdx /scan/sbom.spdx.json
```

Stop and remove this standalone container with `docker rm -f vulnscout`. Its
database, config, and exports remain under `.vulnscout-container/`; recreate it
with the same mounts to reuse them. Recreate after changing environment or port
settings, and start `--serve` again. Do not run two containers against the same
SQLite cache.

---

## Command Reference

### Settings

| Flag | Description |
|------|-------------|
| `--project <name>` | Project name (default: `default` for imports, scans, reports and exports; omitted refresh scope means all data) |
| `--variant <name>` | Variant name; imports/scanners and legacy custom OpenVEX operations default to `default`. Reports and ordinary exports include all project variants when omitted |

### Input Commands

| Flag | Description |
|------|-------------|
| `--add-spdx <path>` | Add SPDX 2/3 JSON (`*.spdx.json`), SPDX 3 JSON-LD (`*.jsonld`), or a `.tar`, `.tar.gz`, `.tar.zst` archive containing those files |
| `--add-cve-check <path>` | Add a Yocto CVE check file (`*.json`) |
| `--add-yocto-vex <path>` | Add a Yocto VEX file from `vex.bbclass` (`*.json`) |
| `--add-openvex <path>` | Add an OpenVEX file; name must match `*openvex*.json` |
| `--add-cdx <path>` | Add a CycloneDX file (`*.json`) |
| `--add-grype <path>` | Add a Grype results file (`.grype.json`) |
| `--perform-scans <types|all>` | Run one or more scanners: `grype`, `nvd`, `osv`, `sbom-cve-check`, or `all`. Separate types with commas or repeat the option. Grype exports the current DB as CycloneDX, runs Grype and merges results; memory is capped by `GRYPE_MEMLIMIT` (default: auto ~80 % of cgroup limit). |

`all` runs every available scanner in the order Grype, NVD, OSV, sbom-cve-check. `--refresh-vulnerability-data` is separate: it enriches existing vulnerability records rather than discovering new findings.

The input flag selects a format, but filenames must also match the patterns above.
Other names may be ignored without failing the command. Rename generic SPDX
`bom.json` to `bom.spdx.json`; tag-value `.spdx` files are not supported by this
pipeline.

The previous `--perform-grype-scan`, `--perform-nvd-scan`, `--perform-osv-scan`, and `--perform-sbom-cve-check-scan` flags remain supported as aliases.

### Scan & Output Commands

| Flag | Description |
|------|-------------|
| `--serve` | Start the web UI and process requested inputs/scans. Uses Flask environment settings (7275 in the setup above). Incompatible with `--match-condition` |
| `--refresh-vulnerability-data` | Refresh stored EPSS, NVD, EUVD, and GHSA data on demand. Without new inputs, `--project` and `--variant` can limit the refresh scope |
| `--report <template>` | Generate a report from a template (name or path). `--project` includes every project variant; adding `--variant` restricts the report to that variant. The `default` project is used when `--project` is omitted. Unknown scopes fail rather than broadening the report. If a path is given, the template is staged automatically |
| `--export-spdx` | Export project as SPDX 3.0 SBOM to `/scan/outputs/` |
| `--export-cdx` | Export project as CycloneDX 1.6 SBOM to `/scan/outputs/` |
| `--export-openvex` | Export project as OpenVEX document to `/scan/outputs/` |
| `--export-custom-vulnscout-data` | Export custom VulnScout JSON data for all project variants, or the selected `--variant`, to `/scan/outputs/` |
| `--import-custom-vulnscout-data <path>` | Import custom VulnScout JSON data using the variant metadata in the file |
| `--use-original-timestamps` | With either custom import, preserve file timestamps |
| `--export-custom-openvex-assessments` | Export custom assessments for the selected `--variant` as an OpenVEX `.json` file |
| `--import-custom-openvex-assessments <path>` | Import an OpenVEX `.json` file into the selected `--variant` |
| `--use-current-timestamps` | With either custom import, use the current system time |
| `--match-condition <expr>` | Exit with code 2 if expression matches stored data for any in-scope vulnerability; it does not refresh EPSS. A project without a variant includes all its variants. Incompatible with `--serve` |
| `--export-context` | Export selected project/variant AI context to `/scan/outputs/context-export.json` |
| `--import-context <path>` | Import context into existing scopes named in the file; use `--retarget-context` to override the destination |
| `--add-asset <path>` | Stage a report image (`png`, `jpg`, `jpeg`, `gif`, `svg`, `webp`) in `/cache/vulnscout/templates/assets/` |

Custom VulnScout JSON imports use current timestamps by default; custom OpenVEX
imports preserve original statement timestamps by default. Context imports
overwrite existing matching context, ignore unknown scopes, and do not create
projects or variants. Retargeted imports require existing destinations.

### Data Maintenance Commands

| Flag | Description |
|------|-------------|
| `--delete-scan <id>` | Delete a past scan by its UUID |
| `--delete-outdated` | Remove outdated package evidence and assessments across all projects and variants |
| `--delete-empty-scans` | Remove non-initial scans with no recorded history changes |
| `--delete-orphaned-vulns` | Remove vulnerabilities without scan evidence anywhere, including their associated data |

Deletion runs immediately as arguments are parsed, without a confirmation prompt,
and is not restricted by `--project` or `--variant`. Preview with `--dry-run`
**before** the deletion flag. The host `delete` subcommands add terminal
confirmation; direct entrypoint calls do not.

### Data Retrieval Commands

| Flag | Description |
|------|-------------|
| `--list-projects` | List all projects and their variants |
| `--list-scans` | List all past scans |
| `--json` | Output objects in JSON format |

### Configuration Commands

| Flag | Description |
|------|-------------|
| `--config <key> <value>` | Set a persistent config value in `/etc/vulnscout/config.env` |
| `--config-list` | Show current configuration (sensitive values masked) |
| `--config-clear <key>` | Remove a config key |

The entrypoint sources the config on each invocation; scans also export its
application settings. Already-running web processes retain their old environment.
With the standalone setup, recreate the container after config changes so
`--env-file` is reloaded, then restart the web UI. Merely exporting variables on
the host does not change a running container; use `docker run -e`/`--env-file` or
the mounted config. Config values override same-named inherited environment
values.

### Other Commands

| Flag | Description |
|------|-------------|
| `--help`, `-h` | Show help message |
| `--version` | Print the VulnScout version |
| `daemon` | Enter daemon mode (default when no arguments are given) |

### Modifier Flags

These flags change the behaviour of other commands in the same invocation. The host `./vulnscout` wrapper sends them; they are also usable directly.

| Flag | Applies to | Effect |
|------|------------|--------|
| `--dry-run` | `--delete-scan`, `--delete-outdated`, `--delete-empty-scans`, `--delete-orphaned-vulns` | Print what would be removed without deleting. Must come before the delete flag. |
| `--all-variants` | `--export-custom-openvex-assessments`, `--import-custom-openvex-assessments` | Do not default the variant to `default`: export each project variant to its own file, or import into the project's only variant. |
| `--retarget-context` | `--import-context` | Forward `--project` (and `--variant`, if set) so entries are imported into that scope instead of the scope named in the file. |
| `--report-format <pdf\|html>` | `--report` | Override the output format implied by the template extension. |
| `--amend` | Custom VulnScout JSON and custom OpenVEX exports | Reconcile with an existing output file while preserving review order; the file must already exist. |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Execution error (invalid arguments, scan failure, configuration error) |
| `2` | Match condition triggered — at least one vulnerability matched the expression |

---

## Execution Order

Some flags execute during argument parsing: input/asset staging, configuration
changes, and deletion. Put modifiers such as `--dry-run` before these immediate
actions. Remaining work is deferred until parsing has finished:

1. **Scan** — If inputs, a match condition, scanners, refresh, or `--serve` were requested:
   - Web server started in background (if `--serve`)
   - Database migration (`flask db upgrade`)
   - Input files merged into the database
   - Grype, NVD/local, OSV, then sbom-cve-check scans, when selected
   - Vulnerability processing; stored NVD, EPSS, EUVD, and GHSA data is refreshed only when `--refresh-vulnerability-data` is requested
   - Input files cleaned up after processing
2. **Reports** — Templates specified with `--report` are generated for every variant in the selected project, or only the selected `--variant`
3. **Exports** — SBOM formats specified with `--export-*` are written
4. **Custom assessments and context** — Export/import of review data, then AI context
5. **Listings** — Requested project or scan listing

With `--serve`, the scan phase waits for the web process before returning;
issue reports and exports in separate invocations rather than queueing them
behind a running web server. A match exits with code 2 only after deferred
reports and exports complete; other scan errors stop subsequent work.

---

## Internal Paths

The following paths inside the container are relevant:

| Path | Purpose |
|------|---------|
| `/scan/` | Base directory for the VulnScout application |
| `/scan/src/` | Python/Flask backend source code |
| `/scan/inputs/` | Staging area for input files (cleaned after each scan) |
| `/scan/outputs/` | Default output directory for reports and exports |
| `/cache/vulnscout/templates/` | Custom report templates (user-installed, persisted via cache volume) |
| `/scan/src/views/templates/` | Built-in report templates |
| `/cache/vulnscout/vulnscout.db` | SQLite database |
| `/etc/vulnscout/config.env` | Persistent configuration file |
| `/cache/vulnscout/local_databases/` | Shared NVD/local and sbom-cve-check advisory clones (`nvd-fkie` + `cvelist`), persisted in the cache. Set `SBOM_CVE_CHECK_DATABASES_DIR` and mount another directory to override |
| `/scan/status.txt` | Scan progress status (used by the web UI) |

For local execution outside the container, `VULNSCOUT_BASE_DIR` and `VULNSCOUT_INPUTS_DIR` can override `/scan` and `/scan/inputs`; container defaults are unchanged.

---

## Examples

These examples assume the standalone recipe's `/imports` mount. Do not start a
second web process if one is already running: omit `--serve` in that case.

**Add inputs and start the web UI:**
```bash
docker exec vulnscout /scan/src/entrypoint.sh \
  --project demo --variant x86 \
  --add-spdx /imports/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
  --add-cve-check /imports/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.json \
  --serve
```

**Run a CI scan with a match condition:**
```bash
docker exec vulnscout /scan/src/entrypoint.sh \
  --project demo \
  --add-spdx /imports/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
  --add-cve-check /imports/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.json \
  --match-condition "cvss >= 9.0 or (cvss >= 7.0 and epss >= 50%)"
```

This evaluates all variants in `demo`. Add `--variant x86` to evaluate only that variant. With neither option, matching uses `default/default`.
The condition uses stored metadata; run `--refresh-vulnerability-data` separately
first if current EPSS is required. Import and/or scan first, refresh second,
then run a condition-only invocation for that workflow.

**Generate reports and export SBOMs without a new scan:**
```bash
docker exec vulnscout /scan/src/entrypoint.sh \
  --project demo --variant x86 \
  --report summary.adoc \
  --report all_assessments.adoc \
  --export-spdx --export-cdx
```

Omit `--variant x86` to include every variant in `demo`.

**Run a sbom-cve-check scan:**
```bash
docker exec vulnscout /scan/src/entrypoint.sh \
  --project demo --variant x86 \
  --add-spdx /imports/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
  --perform-scans sbom-cve-check
```

Both `--perform-scans nvd` and `--perform-scans sbom-cve-check` use the shared
local engine, powered by [sbom-cve-check](https://pypi.org/project/sbom-cve-check/).
Its `nvd-fkie` and `cvelist` clones live in
`/cache/vulnscout/local_databases` by default. `SBOM_CVE_CHECK_AUTO_UPDATE=1`
is the default: first use clones the databases and each local scan fetches
updates. For offline matching, populate both clones first, then set
`SBOM_CVE_CHECK_AUTO_UPDATE=0` in the persistent config and recreate the container.
This does not make OSV, Grype, or remote enrichment offline.

To use another host database directory in a standalone container, add
`-v /absolute/host/databases:/local_databases:Z` and set
`SBOM_CVE_CHECK_DATABASES_DIR=/local_databases`. The host wrapper's
`VULNSCOUT_SBOM_CVE_CHECK_DB_DIR` shortcut does **not** create mounts for
standalone `docker run`.

NVD API mode is available only through the lower-level Flask CLI, not
`--perform-scans nvd`:

```bash
docker exec vulnscout flask --app src.bin.webapp nvd-scan \
  --project demo --variant x86 --mode api
```

It needs network access; an `NVD_API_KEY` increases its API rate limit.

**Set persistent configuration:**
```bash
docker exec vulnscout /scan/src/entrypoint.sh --config NVD_API_KEY abc123
docker exec vulnscout /scan/src/entrypoint.sh --config-list
```

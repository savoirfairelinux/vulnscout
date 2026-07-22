# Using Container Entrypoint

The VulnScout container ships with an entrypoint script at `/scan/src/entrypoint.sh`.
This is what the `./vulnscout` host wrapper calls under the hood. You can also invoke it directly via `docker exec` (or `podman exec`) for advanced workflows or CI pipeline integration where you manage the container yourself.

```bash
docker exec <container> /scan/src/entrypoint.sh [OPTIONS]
# or
podman exec <container> /scan/src/entrypoint.sh [OPTIONS]
```

> **Note:** VulnScout is compatible with both **Docker** and **Podman**. All `docker` commands shown in this page can be replaced with `podman`.

---

## Container Lifecycle

When the container starts with no arguments, it enters **daemon mode** — it stays alive and waits for commands sent via `docker exec` (or `podman exec`). This is the mode used by the `./vulnscout` host wrapper.

```bash
# The container starts in daemon mode by default
docker run -d --name vulnscout sflinux/vulnscout:v0.18

# Then send commands to it
docker exec vulnscout /scan/src/entrypoint.sh --serve
```

---

## Command Reference

### Settings

| Flag | Description |
|------|-------------|
| `--project <name>` | Project name for subsequent commands (default: `default`) |
| `--variant <name>` | Variant name for subsequent commands (default: `default`) |

### Input Commands

| Flag | Description |
|------|-------------|
| `--add-spdx <path>` | Add an SPDX 2/3 SBOM file or archive (`.json`, `.spdx`, `.tar`, `.tar.gz`, `.tar.zst`) |
| `--add-cve-check <path>` | Add a Yocto CVE check JSON file |
| `--add-yocto-vex <path>` | Add a Yocto VEX JSON file (from `vex.bbclass`) |
| `--add-openvex <path>` | Add an OpenVEX JSON file |
| `--add-cdx <path>` | Add a CycloneDX file |
| `--add-grype <path>` | Add a Grype results file (`.grype.json`) |
| `--perform-grype-scan` | Export current DB as CycloneDX, run Grype on it, and merge results back. Memory capped by `GRYPE_MEMLIMIT` (default: auto ~80 % of cgroup limit) |
| `--perform-nvd-scan` | Run an NVD CPE-based vulnerability scan |
| `--perform-osv-scan` | Run an OSV PURL-based vulnerability scan |
| `--perform-sbom-cve-check-scan` | Run a CVE scan using local sbom-cve-check databases |

### Scan & Output Commands

| Flag | Description |
|------|-------------|
| `--serve` | Run scan then start the interactive web UI (port 7275). Incompatible with `--match-condition` |
| `--report <template>` | Generate a report from a template (name or path). If a path is given, the template is staged automatically |
| `--export-spdx` | Export project as SPDX 3.0 SBOM to `/scan/outputs/` |
| `--export-cdx` | Export project as CycloneDX 1.6 SBOM to `/scan/outputs/` |
| `--export-openvex` | Export project as OpenVEX document to `/scan/outputs/` |
| `--export-custom-assessments` | Export custom (review) assessments of the project as OpenVEX `.json` files to `/scan/outputs/` |
| `--import-custom-assessments <path>` | Import custom assessments from `.json` files or a directory of JSON files |
| `--match-condition <expr>` | Exit with code 2 if expression matches any vulnerability. Incompatible with `--serve` |
| `--delete-scan <id>` | Delete a past scan by its ID |

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

### Other Commands

| Flag | Description |
|------|-------------|
| `--help`, `-h` | Show help message |
| `--version` | Print the VulnScout version |
| `daemon` | Enter daemon mode (default when no arguments are given) |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Execution error (invalid arguments, scan failure, configuration error) |
| `2` | Match condition triggered — at least one vulnerability matched the expression |

---

## Execution Order

When multiple flags are provided in a single invocation, the entrypoint processes them in this order:

1. **Input staging** — Files specified with `--add-*` are copied into `/scan/inputs/<type>/`
2. **Scan** — If new inputs, a match condition, or a Grype scan was requested, the scan pipeline runs:
   - Database migration (`flask db upgrade`)
   - Web server started in background (if `--serve`)
   - Input files merged into the database
   - Grype scan (if `--perform-grype-scan`)
   - NVD CPE scan (if `--perform-nvd-scan`)
   - OSV PURL scan (if `--perform-osv-scan`)
   - sbom-cve-check scan (if `--perform-sbom-cve-check-scan`)
   - Vulnerability processing (NVD enrichment, EPSS scoring)
   - Input files cleaned up after processing
3. **Reports** — Templates specified with `--report` are generated
4. **Exports** — SBOM formats specified with `--export-*` are written
5. **Custom assessments** — Export/import of review assessments

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
| `/cache/vulnscout/local_databases/` | Local sbom-cve-check advisory database clones (NVD-FKIE + CVEList), stored inside the cache volume next to `vulnscout.db`. Override the host path with `$VULNSCOUT_SBOM_CVE_CHECK_DB_DIR` (then mounted at `/local_databases`) |
| `/scan/status.txt` | Scan progress status (used by the web UI) |

---

## Examples

**Add inputs and start the web UI:**
```bash
docker exec vulnscout /scan/src/entrypoint.sh \
  --project demo --variant x86 \
  --add-spdx /scan/inputs/sbom.spdx.json \
  --add-cve-check /scan/inputs/cve-check.json \
  --add-yocto-vex /scan/inputs/vex.json \
  --serve
```

**Run a CI scan with a match condition:**
```bash
docker exec vulnscout /scan/src/entrypoint.sh \
  --project demo --variant x86 \
  --add-spdx /scan/inputs/sbom.spdx.json \
  --match-condition "cvss >= 9.0 or (cvss >= 7.0 and epss >= 50%)"
```

**Generate reports and export SBOMs without a new scan:**
```bash
docker exec vulnscout /scan/src/entrypoint.sh \
  --project demo \
  --report summary.adoc \
  --report all_assessments.adoc \
  --export-spdx --export-cdx
```

**Run a sbom-cve-check scan:**
```bash
docker exec vulnscout /scan/src/entrypoint.sh \
  --project demo --variant x86 \
  --add-spdx /scan/inputs/sbom.spdx.json \
  --perform-sbom-cve-check-scan
```

> By default the sbom-cve-check databases live in `/cache/vulnscout/local_databases` (inside the cache volume, next to `vulnscout.db`); set `$VULNSCOUT_SBOM_CVE_CHECK_DB_DIR` to use a shared host clone mounted at `/local_databases` instead. With `SBOM_CVE_CHECK_AUTO_UPDATE=1` the databases are cloned automatically on first use and refreshed before every scan.

**Set persistent configuration:**
```bash
docker exec vulnscout /scan/src/entrypoint.sh --config NVD_API_KEY abc123
docker exec vulnscout /scan/src/entrypoint.sh --config-list
```

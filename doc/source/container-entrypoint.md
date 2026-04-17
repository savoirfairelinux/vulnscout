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
docker run -d --name vulnscout sflinux/vulnscout:latest

# Then send commands to it
docker exec vulnscout /scan/src/entrypoint.sh --serve
```

---

## Command Reference

### Settings

| Flag | Description |
|------|-------------|
| `--project <name>` | Project name for subsequent input commands (default: `default`) |
| `--variant <name>` | Variant name for subsequent input commands (default: `default`) |

### Input Commands

| Flag | Description |
|------|-------------|
| `--add-spdx <path>` | Add an SPDX 2/3 SBOM file or archive (`.json`, `.spdx`, `.tar`, `.tar.gz`, `.tar.zst`) |
| `--add-cve-check <path>` | Add a Yocto CVE check JSON file |
| `--add-openvex <path>` | Add an OpenVEX JSON file |
| `--add-cdx <path>` | Add a CycloneDX file |
| `--add-grype <path>` | Add a Grype results file (`.grype.json`) |
| `--perform-grype-scan` | Export current DB as CycloneDX, run Grype on it, and merge results back |
| `--clear-inputs` | Remove all staged input files |

### Scan & Output Commands

| Flag | Description |
|------|-------------|
| `--serve` | Run scan then start the interactive web UI (port 7275). Incompatible with `--match-condition` |
| `--report <template>` | Generate a report from a template (name or path). If a path is given, the template is staged automatically |
| `--export-spdx` | Export project as SPDX 3.0 SBOM to `/scan/outputs/` |
| `--export-cdx` | Export project as CycloneDX 1.6 SBOM to `/scan/outputs/` |
| `--export-openvex` | Export project as OpenVEX document to `/scan/outputs/` |
| `--export-custom-assessments` | Export custom (review) assessments as `.tar.gz` to `/scan/outputs/` |
| `--import-custom-assessments <path>` | Import custom assessments from `.json` or `.tar.gz` |
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
| `/scan/status.txt` | Scan progress status (used by the web UI) |

---

## Examples

**Add inputs and start the web UI:**
```bash
docker exec vulnscout /scan/src/entrypoint.sh \
  --project demo --variant x86 \
  --add-spdx /scan/inputs/sbom.spdx.json \
  --add-cve-check /scan/inputs/cve-check.json \
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

**Set persistent configuration:**
```bash
docker exec vulnscout /scan/src/entrypoint.sh --config NVD_API_KEY abc123
docker exec vulnscout /scan/src/entrypoint.sh --config-list
```

---

## Legacy Setup Detection

If the container detects a legacy docker-compose setup (an `openvex.json` output exists but no SQLite database), it will:

- In interactive mode: display a warning notification in the web UI
- In non-interactive mode: exit with code 2 and print migration instructions

Use the `migration.sh` script on the host to import legacy data into the new database format. See the [VulnScout CLI](vulnscout-script.md) page for details.

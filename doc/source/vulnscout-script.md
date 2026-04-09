# VulnScout CLI

The `./vulnscout` script is the main host-side entry point for running VulnScout.
It manages the container lifecycle (Docker or Podman) and forwards commands to the container's entrypoint.

```
./vulnscout [options] [command]
```

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
./vulnscout --update
```

Then verify the new version is correctly running:

```bash
./vulnscout --version
```

---

## Interactive Mode (Web UI)

By default VulnScout runs in **interactive mode**, starting a web dashboard.

```bash
./vulnscout --serve \
  --add-spdx $(pwd)/example/spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
  --add-cve-check $(pwd)/example/spdx3/core-image-minimal-qemux86-64.rootfs.json
```

After starting the scan, open:

```
http://localhost:7275
```

If data has already been imported, the web UI can be started without any additional arguments:

```bash
./vulnscout --serve
```

### Web Interface Settings

The web interface includes a **Settings** tab that provides:

- **Rename Project** — Select a project and give it a new name (must be unique across all projects).
- **Rename Variant** — Select a variant within a project and rename it (must be unique within the project).
- **Import SBOM** — Upload an SBOM file directly from the browser instead of using CLI flags.
  When importing, you must select (or create) the target project and variant.
  Supported formats are auto-detected or can be specified explicitly: SPDX (2/3), CycloneDX, OpenVEX, Yocto CVE check, and Grype.

---

## Projects and Variants

VulnScout organises data into **projects** and **variants**. A project typically maps to a product, and variants represent different builds or architectures (e.g. `x86_64`, `aarch64`).

Both flags are optional and default to `default` if not provided.

```bash
./vulnscout --project <name> --variant <name> <command>
```

Example:

```bash
./vulnscout --project demo --variant x86 \
  --add-spdx $(pwd)/example/spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
  --add-cve-check $(pwd)/example/spdx3/core-image-minimal-qemux86-64.rootfs.json
```

## Input Sources

VulnScout accepts multiple input file types. Commands can be chained and will automatically trigger a scan.

### SPDX SBOM

```
--add-spdx <path>
```

Path to an SPDX 2 or SPDX 3 SBOM file. Supports JSON, tag-value (`.spdx`), and archive formats (`.tar`, `.tar.gz`, `.tar.zst`).

---

### CycloneDX SBOM

```
--add-cdx <path>
```

Path to a CycloneDX file.

---

### Yocto CVE Check Output

```
--add-cve-check <path>
```

JSON output from the Yocto `cve-check` task.

---

### OpenVEX

```
--add-openvex <path>
```

Include vulnerability assessments provided as OpenVEX.

---

### Grype

```
--add-grype <path>
```

Import a Grype native JSON file. Files should end with `.grype.json`.

---

### Combining Inputs

Multiple inputs can be chained in a single command:

```bash
./vulnscout --project demo --variant x86 \
  --add-spdx /path/to/sbom.spdx.json \
  --add-cve-check /path/to/cve-check.json \
  --add-openvex /path/to/assessments.openvex.json
```

```{tip}
The input format is determined by the CLI flag used (`--add-spdx`, `--add-cdx`, etc.), not by the file extension.
The only exception is SPDX archive inputs (`.tar`, `.tar.gz`, `.tar.zst`), which are automatically extracted and their `.spdx.json` contents imported.
To ignore parsing errors for malformed SBOMs, set: `IGNORE_PARSING_ERRORS=true`
```

---

## Performing a Grype Scan

VulnScout can run Grype on the current database contents:

```bash
./vulnscout --project demo --variant x86 --perform-grype-scan
```

This can be chained with other inputs to scan newly added files immediately:

```bash
./vulnscout --project demo \
  --add-spdx example/spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
  --perform-grype-scan
```

---

## Non-Interactive Mode (CI / Automation)

For CI pipelines or automated scans, use the `--match-condition` argument instead of the web UI:

```bash
./vulnscout --project demo \
  --add-spdx /path/to/sbom.spdx.json \
  --add-cve-check /path/to/cve-check.json \
  --match-condition "((cvss >= 9.0 or (cvss >= 7.0 and epss >= 30%)) and (pending == true or affected == true))"
```

If vulnerabilities match the condition, the script exits with **code 2**, allowing CI systems to fail the pipeline.

See the [Match Conditions](ci_conditions.md) page for the full syntax and token reference.

---

## Report Generation

Reports are generated from templates. VulnScout ships with built-in templates and also supports custom ones.

```bash
# Generate a report from a built-in template
./vulnscout --project demo --report summary.adoc

# Generate a match-condition report
./vulnscout --project demo --match-condition "cvss >= 9.0" --report match_condition.adoc

# Pass a local template file path — stages and runs it in one step
./vulnscout --project demo --report /path/to/my-custom-report.adoc
```

Multiple reports can be generated in one command:

```bash
./vulnscout --project demo --report summary.adoc --report all_assessments.adoc
```

Reports are written to the outputs directory (default: `.vulnscout/outputs/`).

See the [Templates](templates.md) page for documentation on writing custom report templates.

---

## Exporting SBOM Files

VulnScout can export the enriched project data as standard SBOM formats. Exported files are written to the outputs directory (default: `.vulnscout/outputs/`).

```bash
# Export as SPDX 3.0 SBOM
./vulnscout --project demo --export-spdx

# Export as CycloneDX 1.6 SBOM
./vulnscout --project demo --export-cdx

# Export as OpenVEX document (vulnerabilities + assessments)
./vulnscout --project demo --export-openvex
```

Export commands can be chained with inputs and reports in a single invocation:

```bash
./vulnscout --project demo \
  --add-spdx /path/to/sbom.spdx.json \
  --add-cve-check /path/to/cve-check.json \
  --export-spdx --export-cdx --export-openvex \
  --report summary.adoc
```

---

## Exporting and Importing Custom Assessments

VulnScout lets you export and re-import the assessments you have manually created through the web interface (review / triage decisions). This is useful for:

- Backing up your review work before re-importing SBOMs.
- Sharing assessment decisions across different VulnScout instances.
- Restoring triage state in CI pipelines after a database reset.

### Exporting Custom Assessments

The `--export-custom-assessments` flag produces a `.tar.gz` archive containing one OpenVEX JSON file per variant:

```bash
./vulnscout --project demo --export-custom-assessments
```

### Importing Custom Assessments

The `--import-custom-assessments` flag reads a `.json` or `.tar.gz` file and replays the assessment statements into the database:

```bash
# Import from a single OpenVEX JSON file
./vulnscout --project demo --import-custom-assessments /path/to/assessments.json

# Import from a tar.gz archive previously exported
./vulnscout --project demo --import-custom-assessments /path/to/custom_assessments.tar.gz
```

---

## Configuration

### Configuration Commands

Persistent configuration is stored in `.vulnscout/cache/config.env` and is automatically loaded on each run.

```bash
# Set a config value
./vulnscout config <key> <value>

# List current configuration (sensitive values masked)
./vulnscout config-list

# Remove a config key
./vulnscout config-clear <key>
```

Example — set an NVD API key for higher rate limits:

```bash
./vulnscout config NVD_API_KEY abc123
```

### Environment Variables

The following environment variables can be set via `vulnscout config` or exported before running.

Example:

```bash
./vulnscout config NVD_API_KEY abc123
```

#### Container & Runtime

| Variable | Description | Default |
|----------|-------------|---------|
| `VULNSCOUT_CONTAINER` | Name of the container | `vulnscout` |
| `VULNSCOUT_IMAGE` | Container image to use | `docker.io/sflinux/vulnscout:latest` |
| `VULNSCOUT_BUILD_DIR` | Root build directory on the host | `./.vulnscout` |
| `VULNSCOUT_OUTPUTS_DIR` | Directory for output files on the host | `$VULNSCOUT_BUILD_DIR/outputs` |
| `VULNSCOUT_CACHE_DIR` | Cache directory (SQLite database and config) | `$VULNSCOUT_BUILD_DIR/cache` |
| `FLASK_RUN_PORT` | Port the web UI listens on | `7275` |
| `FLASK_RUN_HOST` | Host address for the web UI | `0.0.0.0` |
| `VITE_API_URL` | Backend API URL used by the dev frontend | `http://localhost:7275` |
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
./vulnscout config HTTP_PROXY http://proxy.example.com:8080
./vulnscout config HTTPS_PROXY http://proxy.example.com:8080
./vulnscout config NO_PROXY localhost,127.0.0.1
```

Or set them as environment variables in the shell before running `vulnscout`:

```bash
export HTTP_PROXY=http://proxy.example.com:8080
./vulnscout --serve
```

---

## Migrating from the Legacy docker-compose Workflow

If you were previously running VulnScout with a `docker-compose.yml` file per variant or with `vulnscout.sh`, use `migration.sh` to import all your existing data into the new SQLite database.

```bash
# Migrate specifying the directory explicitly
./migration.sh /path/to/.vulnscout --project myproject

# Remove legacy YAML files and output dirs without prompting
./migration.sh /path/to/.vulnscout --project myproject --remove-old

# Keep legacy files (skip cleanup prompt)
./migration.sh /path/to/.vulnscout --project myproject --keep-old
```

The script will:

1. Scan the build directory for sub-directories containing `docker-compose.yml` files.
2. Use each sub-directory name as the `--variant` for that import batch.
3. Extract host-side input paths from the compose volume mounts and import them.
4. Re-import legacy assessments from any `output/openvex.json` found alongside the compose file.
5. After all imports succeed, prompt whether to delete the old YAML files and output directories (overridden by `--keep-old` / `--remove-old`).

Once migration is complete, start VulnScout normally:

```bash
./vulnscout --serve
```


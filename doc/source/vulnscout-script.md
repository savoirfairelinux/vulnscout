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
./vulnscout --delete-outdated
./vulnscout --delete-empty-scans
./vulnscout --delete-orphaned-vulnerabilities
```

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

### Yocto VEX Output

```
--add-yocto-vex <path>
```

JSON output from the Yocto `vex.bbclass` task.  Carries richer CPE and
patch-file information than the plain cve-check output.

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

`--perform-grype-scan` can consume significant RAM on large SBOMs.
VulnScout automatically caps Grype's memory at ~80 % of the container/cgroup limit.
Use `GRYPE_MEMLIMIT` to override:

```bash
# Set a persistent limit
./vulnscout --config GRYPE_MEMLIMIT 6GiB

# Or export it on the host before running (forwarded into the container)
export GRYPE_MEMLIMIT=24GiB
./vulnscout --project demo --perform-grype-scan

# Disable the limit entirely
./vulnscout --config GRYPE_MEMLIMIT off
```

Accepts any value valid for Go's `GOMEMLIMIT` (`4GiB`, `8192MiB`, plain bytes).
Set to `off`, `0`, or `disabled` to remove the cap.

---

## Performing an sbom-cve-check Scan

The `--perform-sbom-cve-check-scan` flag runs a CVE scan powered by [sbom-cve-check](https://github.com/savoirfairelinux/sbom-cve-check). Unlike the NVD and OSV scanners, and once the databases are synced, this scan never makes network calls during analysis,it queries locally-cloned advisory databases (NVD-FKIE JSON feeds and CVEList V5).

```bash
./vulnscout --project demo --variant x86 --perform-sbom-cve-check-scan
```

The scan can be chained with other inputs:

```bash
./vulnscout --project demo \
  --add-spdx example/spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
  --perform-sbom-cve-check-scan
```

---

## Non-Interactive Mode (CI / Automation)

For CI pipelines or automated scans, use the `--match-condition` argument instead of the web UI:

```bash
./vulnscout --project demo \
  --add-spdx /path/to/sbom.spdx.json \
  --add-cve-check /path/to/cve-check.json \
  --match-condition "((cvss >= 9.0 or (cvss >= 7.0 and epss >= 30%)) and (pending or affected))"
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

### VulnScout JSON

The `--export-custom-vulnscout-data` flag exports custom assessments, pending AI
assessments, CVSS scores, and time estimates as one VulnScout JSON file. It
includes every variant in the selected project unless `--variant` is provided.
After import, pending AI assessments are available from the Review page's **AI
Assessments** tab for approval or rejection.

```bash
./vulnscout --project demo --export-custom-vulnscout-data
```

Export one variant:

```bash
./vulnscout --project demo --variant x86 --export-custom-vulnscout-data
```

The `--import-custom-vulnscout-data` command restores entries according to the
variant metadata stored in the file. Imported assessments use the current
system time by default. Add `--use-original-timestamps` to preserve assessment
timestamps from the file. `--use-current-timestamps` is also accepted to select
the default explicitly.

```bash
./vulnscout --project demo --import-custom-vulnscout-data /path/to/custom_vulnscout_data_all.json

./vulnscout --project demo --import-custom-vulnscout-data /path/to/custom_vulnscout_data_all.json --use-original-timestamps
```

### OpenVEX

OpenVEX custom-assessment transfers operate on one JSON document and require `--variant` for both import and export.

```bash
# Export a variant
./vulnscout --project demo --variant x86 --export-custom-openvex-assessments

# Import into a variant
./vulnscout --project demo --variant x86 --import-custom-openvex-assessments /path/to/custom_openvex_x86.json

# Ignore OpenVEX statement timestamps and use the current system time
./vulnscout --project demo --variant x86 --import-custom-openvex-assessments /path/to/custom_openvex_x86.json --use-current-timestamps
```

OpenVEX imports preserve statement timestamps by default. Add
`--use-current-timestamps` to use the current system time, or use
`--use-original-timestamps` to select the default explicitly.

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
| `VULNSCOUT_IMAGE` | Container image to use | `docker.io/sflinux/vulnscout:v0.20` |
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

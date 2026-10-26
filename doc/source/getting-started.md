# Getting Started

VulnScout helps you identify, review, and track vulnerabilities in software
components using an **SBOM (Software Bill of Materials)**. Import your SBOM and
existing vulnerability findings, then run scanners to discover additional
vulnerabilities and refresh their metadata to support prioritisation.

Organise your software into **projects and variants**, use the web interface to
assess findings and record triage decisions, and export enriched SBOMs or reports.
The command-line interface also supports automated workflows and CI pipelines.

This guide walks you through importing example data and opening the web interface.

## Requirements

VulnScout runs locally inside a container. On the host, you need:

- **Git** to clone the repository.
- **Bash** to run the `vulnscout` launcher.
- **Docker** or **Podman**, installed and configured so your user can run
  containers. If your setup uses a container service, ensure it is running.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/savoirfairelinux/vulnscout.git
cd vulnscout
```

---

## First Run

### Import the Example Data

Use `./vulnscout add` to parse and import the provided SBOM and vulnerability findings:

```bash
./vulnscout add \
  --spdx "$(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json" \
  --cve-check "$(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.json"
```

The script automatically manages the container lifecycle (Docker or Podman):
it pulls the image if needed, starts the container, and imports the input files.
This command does not start the web interface.

A **project** groups a software product's data; a **variant** represents a
specific build or target within that project.
The import uses project `default` and variant `default`. It loads the supplied
findings but does not run additional scanners or refresh provider metadata.
See [Vulnerability Scanning](vulnerability-scanning.md) for `scan` and
[Refresh Vulnerability Data](vulnerability-data.md) for `refresh`.

For other sample inputs and their import commands, see [Bundled Examples](examples.md).

### Starting the Web Interface

**API keys are not required to view the imported example data.** If you need
proxy settings or API keys for external services, configure them before starting
the web interface with `./vulnscout config set <key> <value>`, then run
`./vulnscout restart`. See [Configuration](cli-configuration.md#configuration).

The preceding `add` command has already initialised VulnScout. If you skipped it,
run `./vulnscout start` before using `config set` so the default configuration
exists.

After the import finishes, start the web interface:

```bash
./vulnscout serve
```

Then open <http://localhost:7275> in your browser. On subsequent runs, use
`./vulnscout serve` again; you do not need to re-import the same data.

In the navigation bar, select project **default** and variant **default**.
Open **Vulnerabilities** to inspect the imported findings and select a
vulnerability to view its details. See [Interactive Mode](interactive-mode.md)
for filtering findings, recording assessments, and exporting results.

Press `Ctrl+C` to stop the web server and return to your shell. The container keeps running in the background.

---

## Stopping VulnScout

To stop and remove the container entirely:

```bash
./vulnscout stop
```

The database, configuration, and exports remain in `.vulnscout/cache/` and
`.vulnscout/outputs/` beside the launcher unless you configured other paths.
Stopping the container does not reset your data.

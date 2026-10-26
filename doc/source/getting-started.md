# Getting Started

## Requirements

VulnScout runs locally inside a container. It requires **Docker** or **Podman** installed on the host.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/savoirfairelinux/vulnscout.git
cd vulnscout
```

---

## First Run

Start VulnScout and import the provided example data:

```bash
./vulnscout add \
  --spdx "$(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json" \
  --cve-check "$(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.json"
./vulnscout serve
```

Then open the web interface:

```
http://localhost:7275
```

The script automatically manages the container lifecycle (Docker or Podman) — it pulls the image (if needed), starts the container, imports the input files, and removes the container once the command finishes; `serve` then starts the web interface and keeps the container running.

The import uses project `default` and variant `default`. It loads the supplied
findings but does not run additional scanners or refresh provider metadata.
See [VulnScout CLI](vulnscout-script.md) for `scan` and `refresh`.

If you need proxy settings or API keys **before** this import, run
`./vulnscout start` first to generate the default configuration, then use
`./vulnscout config set <key> <value>` and `./vulnscout restart`.
Do not create a partial configuration with `config set` before initialization;
see [Configuration](vulnscout-script.md#configuration).

Once the initial import finishes, background scans, vulnerability-data refreshes, SBOM uploads, and document exports appear in the web interface's **Operation queue**. See {ref}`Operation Queue <operation-queue>` for progress, cancellation, and recovery after a reload.

For the Zephyr SPDX 3 JSON-LD example, Yocto SPDX 2 archives, and CycloneDX
exports, see [Bundled Examples](examples.md). Import the four Zephyr companion
documents together into the same project and variant.

---

## Starting the Web Interface

If you have already loaded your data and just want to start the web interface:

```bash
./vulnscout serve
```

Press `Ctrl+C` to stop the web server and return to your shell. The container keeps running in the background
until another command, such as `add` or `scan`, finishes, or until you stop it.

---

## Stopping VulnScout

To stop and remove the container entirely:

```bash
./vulnscout stop
```

The database, configuration, and exports remain in `.vulnscout/cache/` and
`.vulnscout/outputs/` beside the launcher unless you configured other paths.
Stopping the container does not reset your data.

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
  --spdx $(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
  --cve-check $(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.json
./vulnscout serve
```

Then open the web interface:

```
http://localhost:7275
```

The script automatically manages the container lifecycle (Docker or Podman) — it pulls the image (if needed), starts the container, and imports the input files; `serve` then starts the web interface.

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

Press `Ctrl+C` to stop the web server and return to your shell. The container keeps running in the background.

---

## Stopping VulnScout

To stop and remove the container entirely:

```bash
./vulnscout stop
```

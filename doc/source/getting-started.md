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
./vulnscout start \
  --add-spdx $(pwd)/example/spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
  --add-cve-check $(pwd)/example/spdx3/core-image-minimal-qemux86-64.rootfs.json
```

Then open the web interface:

```
http://localhost:7275
```

The script automatically manages the container lifecycle (Docker or Podman) — it pulls the image (if needed), starts the container, imports the input files, and runs a scan.

---

## Starting the Web Interface

If you have already loaded your data and just want to start the web interface:

```bash
./vulnscout --serve
```

Press `Ctrl+C` to stop the web server and return to your shell. The container keeps running in the background.

---

## Stopping VulnScout

To stop and remove the container entirely:

```bash
./vulnscout stop
```

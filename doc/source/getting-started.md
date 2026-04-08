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

Run VulnScout using the provided example:

```bash
./vulnscout --serve \
  --add-spdx $(pwd)/example/spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json \
  --add-cve-check $(pwd)/example/spdx3/core-image-minimal-qemux86-64.rootfs.json
```

Then open the web interface:

```
http://localhost:7275
```

The script automatically manages the container lifecycle (Docker or Podman) — it pulls the image (if needed), starts the container, imports the input files, runs a scan, and serves the web UI.

---

## Restarting Without New Input

If you have already loaded your data and just want to start the web interface again:

```bash
./vulnscout --serve
```

---

## Stopping VulnScout

```bash
./vulnscout stop
```

# Interactive Mode (Web UI)

Start the web dashboard explicitly with `serve`; importing data does not start it.

```bash
./vulnscout add \
  --spdx "$(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json" \
  --cve-check "$(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.json"
./vulnscout serve
```

Then open:

```
http://localhost:7275
```

If data has already been imported, run `serve` alone:

```bash
./vulnscout serve
```

## Web Interface Settings

The web interface includes a **Settings** tab that provides:

- **Rename Project** — Select a project and give it a new name (must be unique across all projects).
- **Rename Variant** — Select a variant within a project and rename it (must be unique within the project).
- **Import SBOM** — Upload an SBOM file directly from the browser instead of `vulnscout add`.
  When importing, you must select (or create) the target project and variant.
  Supported formats are auto-detected or can be specified explicitly: SPDX (2/3), CycloneDX, OpenVEX, Yocto CVE check, and Grype.
- **Data Maintenance** — In **General Settings**, remove outdated data, empty scans, or CVEs no longer included in any project or variant.
  This action is not limited to the project or variant currently selected in the web interface.
- **Custom reports & assets** — Manage installed report templates and images from
  this Settings page; see [Templates](templates.md).

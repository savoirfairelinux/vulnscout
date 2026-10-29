# Starting the Web Interface

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

## Using the Interface

Select your project and variant in the navigation bar. See
[Interactive Mode](interactive-mode.md) for the web workflow,
[Vulnerability Table](web-vulnerabilities.md) to investigate findings, and
[Settings](web-settings.md) to manage projects, variants, imports, and custom
reports.

# Bundled Examples

The repository includes example datasets under `example/` for both Yocto and
Zephyr. Run the commands below from the repository root.

| Directory | Contents |
| --- | --- |
| `example/zephyr/` | Four Zephyr West-generated SPDX 3 JSON-LD companion documents. |
| `example/yocto-wrynose-spdx3/` | Yocto Wrynose SPDX 3 JSON-LD and CVE-check JSON. |
| `example/yocto-scarthgap-spdx2/` | Yocto Scarthgap SPDX 2 archive and CVE-check JSON. |
| `example/yocto-scarthgap-cdx/` | Yocto CycloneDX SBOM/VEX |

The examples use separate project/variant selections to keep different builds
and input formats apart. Keep the same selection when continuing a workflow.
After starting an interactive import, open <http://localhost:7275/> and select
the corresponding project and variant.

## Zephyr SPDX 3 JSON-LD

Import all four companion documents in a single invocation:

```bash
./vulnscout --serve --project zephyr_demo --variant mbedtls_native_sim \
  --add-spdx "$(pwd)/example/zephyr/app.jsonld" \
  --add-spdx "$(pwd)/example/zephyr/build.jsonld" \
  --add-spdx "$(pwd)/example/zephyr/modules-deps.jsonld" \
  --add-spdx "$(pwd)/example/zephyr/zephyr.jsonld"
```

The documents describe the application, build targets, module dependencies, and
Zephyr/module sources. They contain cross-document references, so import them
together into the same project and variant rather than as separate scans.

These SBOMs provide a component inventory, not precomputed vulnerability
findings. Add `--perform-scans all` to the import command to request vulnerability
discovery, or run scanners afterward:

```bash
./vulnscout --project zephyr_demo --variant mbedtls_native_sim \
  --perform-scans all
```

Scanners may require network access and credentials. If the web server is
already running, omit `--serve` from subsequent commands.

## Yocto Wrynose SPDX 3

Import the SPDX 3 SBOM together with its CVE-check results:

```bash
./vulnscout --serve --project yocto_demo --variant wrynose \
  --add-spdx "$(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json" \
  --add-cve-check "$(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.json"
```

## Yocto Scarthgap SPDX 2

Pass the SPDX archive directly; VulnScout extracts its documents:

```bash
./vulnscout --serve --project yocto_demo --variant scarthgap \
  --add-spdx "$(pwd)/example/yocto-scarthgap-spdx2/core-image-minimal-stm32mp25-eval.spdx.tar.zst" \
  --add-cve-check "$(pwd)/example/yocto-scarthgap-spdx2/core-image-minimal-stm32mp25-eval.scouted.json"
```

The `.scouted.json` file in this dataset uses the Yocto CVE-check format; import
it with `--add-cve-check`.

## Yocto SPDX 2 and CycloneDX exports

Import the original SPDX 2 archive and CVE-check results:

```bash
./vulnscout --serve --project yocto_demo --variant spdx2 \
  --add-spdx "$(pwd)/example/yocto-scarthgap-spdx2/core-image-minimal-stm32mp25-eval.spdx.tar.zst" \
  --add-cve-check "$(pwd)/example/yocto-scarthgap-spdx2/core-image-minimal-stm32mp25-eval.scouted.json"
```

Alternatively, use the CycloneDX exports in a separate variant:

```bash
./vulnscout --project yocto_demo --variant cyclonedx add \
  --cdx "$(pwd)/example/yocto-scarthgap-cdx/bom.json" \
  --cdx "$(pwd)/example/yocto-scarthgap-cdx/vex.json"
./vulnscout serve
```

Both files use CycloneDX, including `vex.json`; do not pass that file to
`add --openvex`, which expects the different OpenVEX format. Import the BOM
and the VEX in the same `add` command, in either order: the VEX uses BOM-Link URNs
(`urn:cdx:<BOM UUID>/<version>#<component reference>`) to refer to the BOM's
components.

Local `bom-ref` affects retain path-order resolution when multiple BOMs reuse a
reference. Only BOM-Link references can resolve against a later inventory;
detached VEX documents mixing both forms preserve their original local mapping.

The bundled files contain 97 components (93 distinct name/version packages) and
3,133 distinct CVE IDs, forming 7,063 distinct package/CVE findings. These findings
should appear under the `yocto_demo` project and `cyclonedx` variant without
running additional scanners. All bundled VEX entries are assessed as `resolved`
or `not_affected`, so a view filtered to exploitable or unassessed vulnerabilities
can legitimately be empty. Clear status filters to inspect the imported findings
and assessments. The BOM alone provides inventory, not vulnerability findings.

See [VulnScout CLI](vulnscout-script.md) for input flags, scanner selection,
metadata refresh, and container lifecycle commands.

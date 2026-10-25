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
After importing, start the web interface with `./vulnscout serve`, open
<http://localhost:7275/>, and select the corresponding project and variant.
If it is already running, leave it running while issuing imports or scans
from another terminal.

## Zephyr SPDX 3 JSON-LD

Import all four companion documents in a single invocation:

```bash
./vulnscout -p zephyr_demo -v mbedtls_native_sim add \
  --spdx "$(pwd)/example/zephyr/app.jsonld" \
  --spdx "$(pwd)/example/zephyr/build.jsonld" \
  --spdx "$(pwd)/example/zephyr/modules-deps.jsonld" \
  --spdx "$(pwd)/example/zephyr/zephyr.jsonld"
```

The documents describe the application, build targets, module dependencies, and
Zephyr/module sources. They contain cross-document references, so import them
together into the same project and variant rather than as separate scans.

These SBOMs provide a component inventory, not precomputed vulnerability
findings. Request vulnerability discovery after the import:

```bash
./vulnscout -p zephyr_demo -v mbedtls_native_sim scan all
```

Scanners may require network access and credentials. `all` includes NVD and
sbom-cve-check local database setup: first use downloads the advisory databases,
and updates run before each local scan by default. See
[scanner setup and offline mode](vulnscout-script.md#performing-an-sbom-cve-check-scan).
Discovery does not automatically refresh all provider metadata; run
`./vulnscout -p zephyr_demo -v mbedtls_native_sim refresh` when enrichment is needed.

## Yocto Wrynose SPDX 3

Import the SPDX 3 SBOM together with its CVE-check results:

```bash
./vulnscout -p yocto_demo -v wrynose add \
  --spdx "$(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json" \
  --cve-check "$(pwd)/example/yocto-wrynose-spdx3/core-image-minimal-qemux86-64.rootfs.json"
```

## Yocto Scarthgap SPDX 2

Pass the SPDX archive directly; VulnScout extracts its documents:

```bash
./vulnscout -p yocto_demo -v scarthgap add \
  --spdx "$(pwd)/example/yocto-scarthgap-spdx2/core-image-minimal-stm32mp25-eval.spdx.tar.zst" \
  --cve-check "$(pwd)/example/yocto-scarthgap-spdx2/core-image-minimal-stm32mp25-eval.scouted.json"
```

The `.scouted.json` file in this dataset uses the Yocto CVE-check format; import
it with `add --cve-check`.

## Yocto SPDX 2 and CycloneDX exports

Import the original SPDX 2 archive and CVE-check results:

```bash
./vulnscout -p yocto_demo -v spdx2 add \
  --spdx "$(pwd)/example/yocto-scarthgap-spdx2/core-image-minimal-stm32mp25-eval.spdx.tar.zst" \
  --cve-check "$(pwd)/example/yocto-scarthgap-spdx2/core-image-minimal-stm32mp25-eval.scouted.json"
```

Alternatively, use the CycloneDX exports in a separate variant:

```bash
./vulnscout -p yocto_demo -v cyclonedx add \
  --cdx "$(pwd)/example/yocto-scarthgap-cdx/bom.json" \
  --cdx "$(pwd)/example/yocto-scarthgap-cdx/vex.json"
```

Both files use CycloneDX, including `vex.json`; do not pass that file to
`add --openvex`, which expects the different OpenVEX format and a filename
containing `openvex` and ending in `.json`. Import the BOM
and the VEX in the same `add` command, in either order: the VEX uses BOM-Link URNs
(`urn:cdx:<BOM UUID>/<version>#<component reference>`) to refer to the BOM's
components.

Local `bom-ref` affects retain path-order resolution when multiple BOMs reuse a
reference. Only BOM-Link references can resolve against a later inventory;
detached VEX documents mixing both forms preserve their original local mapping.
If a VEX also contains components, its inventory is imported at its original
path position before unresolved external affects are replayed.
BOM-Links use a separate UUID/version-qualified inventory index, so unrelated
local references cannot redirect a qualified target. If no qualified target
exists, an exact component `bom-ref` in the current document is retained as a
local fallback, including during deferred replay.

The bundled files contain 97 components (93 distinct name/version packages) and
3,133 distinct CVE IDs, forming 7,063 distinct package/CVE findings. These findings
should appear under the `yocto_demo` project and `cyclonedx` variant without
running additional scanners. All bundled VEX entries are assessed as `resolved`
or `not_affected`, so a view filtered to exploitable or unassessed vulnerabilities
can legitimately be empty. Clear status filters to inspect the imported findings
and assessments. The BOM alone provides inventory, not vulnerability findings.

See [VulnScout CLI](vulnscout-script.md) for input flags, scanner selection,
metadata refresh, and container lifecycle commands.

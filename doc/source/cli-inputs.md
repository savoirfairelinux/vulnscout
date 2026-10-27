# Input Sources

VulnScout accepts multiple input file types through `add`. Repeat an option or mix types in one call; the inputs are processed together.

## SPDX SBOM

```
add --spdx <path>
```

Path to an SPDX 2 or SPDX 3 JSON SBOM named `*.spdx.json`, an SPDX 3 JSON-LD
file named `*.jsonld`, or an archive (`.tar`, `.tar.gz`, `.tar.zst`) containing
files with those names. Zephyr-generated JSON-LD is supported. Rename a generic
SPDX JSON file such as `bom.json` to `bom.spdx.json` before importing.
SPDX tag-value (`.spdx`) files are not supported by this import pipeline.

For Zephyr's West SPDX generator, import the companion documents together into the
same project and variant:

```bash
./vulnscout add -p zephyr_demo -v mbedtls_native_sim \
  --spdx "$(pwd)/example/zephyr/app.jsonld" \
  --spdx "$(pwd)/example/zephyr/build.jsonld" \
  --spdx "$(pwd)/example/zephyr/modules-deps.jsonld" \
  --spdx "$(pwd)/example/zephyr/zephyr.jsonld"
```

These files are bundled under `example/zephyr/`. See
[Bundled Examples](examples.md) for the full dataset list and interactive
import commands.

Release versions and Git revisions are displayed separately in the SBOM table;
see [SBOM Table](web-sbom.md#column-visibility).

---

## CycloneDX SBOM

```
add --cdx <path>
```

Path to a CycloneDX JSON file named `*.json`.

---

## Yocto CVE Check Output

```
add --cve-check <path>
```

JSON output from the Yocto `cve-check` task, named `*.json`.

---

## Yocto VEX Output

```
add --yocto-vex <path>
```

JSON output from the Yocto `vex.bbclass` task, named `*.json`. Carries richer CPE and
patch-file information than the plain cve-check output.

---

## OpenVEX

```
add --openvex <path>
```

Include vulnerability assessments provided as OpenVEX. The filename must contain
`openvex` and end in `.json`, for example `assessments.openvex.json`; rename
`assessments.json` before importing it.

---

## Grype

```
add --grype <path>
```

Import a Grype native JSON file. Files should end with `.grype.json`.

---

## Combining Inputs

Repeat or mix input options in one `add` call:

```bash
./vulnscout add -p demo -v x86 \
  --spdx /path/to/sbom.spdx.json \
  --cve-check /path/to/cve-check.json \
  --openvex /path/to/assessments.openvex.json
```

```{tip}
The CLI flag selects the parser, but staging also filters filenames: SPDX needs
`*.spdx.json` or `*.jsonld`, OpenVEX needs `*openvex*.json`, Grype needs
`*.grype.json`, and the other inputs need `*.json`. Files that do not match
can be ignored without failing the command. SPDX archives (`.tar`, `.tar.gz`,
`.tar.zst`) are extracted and their `.spdx.json` and `.jsonld` files imported.
To ignore parsing errors for malformed SBOMs, set: `IGNORE_PARSING_ERRORS=true`
```

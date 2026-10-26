# Zephyr Integration

VulnScout can be integrated into a Zephyr build workflow using
**zephyr-west-vulnscout**, a West extension that generates SPDX 3 SBOMs and
imports them into VulnScout for vulnerability analysis.

## zephyr-west-vulnscout

The extension provides `west vulnscout` for SBOM generation and import,
vulnerability scanning, metadata refresh, and policy checks. It also provides
`west vulnscout report` and `west vulnscout export` to generate outputs from
stored results without importing or rescanning.

It uses Docker or Podman directly by default, with an optional mode that invokes
the VulnScout host launcher. The extension is maintained separately from this
repository; consult its
[documentation](https://github.com/ValentinBoudevinSFL/zephyr-west-vulnscout/tree/main/doc)
for installation, supported Zephyr versions, and configuration.

### Getting Started

Add the extension to your West manifest's project list:

```yaml
manifest:
  projects:
    - name: zephyr-west-vulnscout
      url: https://github.com/ValentinBoudevinSFL/zephyr-west-vulnscout
      revision: main
      path: zephyr-west-vulnscout
      west-commands: west-commands.yml
```

Update the project and check command availability:

```bash
west update zephyr-west-vulnscout
west help vulnscout
```

Build your application with `CONFIG_BUILD_OUTPUT_META=y`. From the Zephyr
workspace root, generate and import its SPDX 3.0 SBOMs, replacing the build path
with your application's build directory:

```bash
ZEPHYR_BASE="$PWD/zephyr" west vulnscout \
  -d /path/to/build \
  --project zephyr_demo --variant my_board
```

Use the same project and variant for subsequent operations. Import alone does
not request a full vulnerability scan; add `--perform-scan` to run the scanners.
Scanners can require network access and local advisory database downloads.

### Web Interface

Add `--serve` to the generation/import command to start the web interface after
initial processing completes, then open <http://localhost:7275/> and select your
project and variant. Follow the initial import or scan in the terminal.

Unlike the host launcher's `./vulnscout serve`, `west vulnscout --serve` also
generates and imports an SBOM. `--no-generate --serve` imports existing SPDX
files before serving; it is not a view-only command. If the interface is already
running in the container, omit `--serve` from later imports and scans.

In direct container mode, pressing `Ctrl+C` while serving stops the container,
including its other services. Coordinate with other users before stopping a
shared container. Cache locations, port settings, and wrapper-mode behavior are
described in the extension's documentation.

### Importing Existing Zephyr SBOMs

You can also import generated SBOMs with the VulnScout host launcher, without
installing the West extension. Import the companion SPDX 3 JSON-LD documents
together into the same project and variant to preserve cross-document
relationships. See [Bundled Examples](examples.md#zephyr-spdx-3-json-ld) for a
complete example using the four files in `example/zephyr/`.

See [Input Sources](cli-inputs.md) for supported filenames,
[Vulnerability Scanning](vulnerability-scanning.md) for scanner setup, and
[Interactive Mode](interactive-mode.md) for reviewing imported packages and
findings.
For component badges and consolidation rules, see
[Zephyr JSON-LD Provenance](sbom-scan-reference.md#zephyr-json-ld-provenance).

# Yocto Integration

VulnScout can be integrated into your Yocto/OpenEmbedded build workflow using the
**meta-vulnscout** integration layer.

## meta-vulnscout

The `meta-vulnscout` layer provides recipes and classes to automatically run
VulnScout vulnerability analysis as part of your Yocto build process. It handles
SBOM generation, vulnerability scanning, and report collection.

### Features

- Automatic SBOM extraction from Yocto builds
- Integration with the VulnScout scanning pipeline
- Support for SPDX 2 and SPDX 3 SBOM formats
- CI/CD-ready with configurable fail conditions

### Getting Started

Full documentation, installation instructions, and configuration options are
available on the meta-vulnscout documentation site:

> **[meta-vulnscout documentation](https://meta-vulnscout.readthedocs.io/en/latest/)**

The layer is maintained separately from this repository; consult its documentation
for supported Yocto releases and its build-specific configuration.

### Importing existing Yocto build outputs

You can also import build artifacts without installing the layer. See
[Bundled Examples](examples.md) for SPDX 2 archives, SPDX 3 JSON-LD, and Yocto
CVE-check inputs. Import matching artifacts together into the same project and
variant. SPDX JSON filenames must end in `.spdx.json` (or `.jsonld` for JSON-LD);
tag-value `.spdx` files are not supported by the current import pipeline.

Importing findings, running additional scanners, refreshing vulnerability metadata,
and enforcing CI conditions are separate host commands. See
[VulnScout CLI](vulnscout-script.md) for command scope,
[Vulnerability Scanning](vulnerability-scanning.md) for local advisory database
setup, and [Configuration](cli-configuration.md#configuration) for initialization
requirements.

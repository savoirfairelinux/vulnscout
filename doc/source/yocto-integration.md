# Yocto Integration

VulnScout can be integrated into your Yocto/OpenEmbedded build workflow using the
**meta-vulnscout** BSP layer.

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

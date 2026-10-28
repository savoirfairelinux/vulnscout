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

The layer requires a working Yocto/OpenEmbedded build environment, the
**Docker** command available to your build user, and the host
**python3-packaging** package. Unlike the standalone VulnScout launcher, the
layer invokes Docker directly.

1. Clone the layer alongside your other layers:

   ```bash
   git clone https://github.com/savoirfairelinux/meta-vulnscout.git
   ```

2. Add its absolute path to `build/conf/bblayers.conf`:

   ```bitbake
   BBLAYERS += "/path/to/meta-vulnscout"
   ```

3. Keep your existing distro and add these fragments to `local.conf` or your
   distro configuration to enable the integration for all images:

   ```bitbake
   require conf/distro/include/sbom-cve-check.inc
   require conf/distro/include/vulnscout-core.inc
   ```

   These fragments enable sbom-cve-check with its recommended settings,
   VulnScout image tasks, and SPDX generation. Alternatively, the layer's
   `defaultsetup-vulnscout` distro enables these features; do not combine that
   distro with the manual fragment configuration above.

4. From your initialized build environment, build the image and launch
   VulnScout, replacing `core-image-minimal` with your image recipe:

   ```bash
   bitbake core-image-minimal
   bitbake core-image-minimal -c vulnscout
   ```

   Open <http://localhost:7275/> to inspect the imported build and findings.
   To reopen the interface using existing data without rescanning:

   ```bash
   bitbake core-image-minimal -c vulnscout_no_scan
   ```

The default project is `default`; the variant name is
`${DISTRO}_${MACHINE}_${IMAGE_BASENAME}`. Override them in `local.conf` when
needed:

```bitbake
VULNSCOUT_PROJECT = "my-product"
VULNSCOUT_VARIANT = "production"
```

Select the corresponding project and variant in the web interface. The layer
stores its data and outputs under `${TOPDIR}/../.vulnscout` by default; change
`VULNSCOUT_ROOT_DIR` to relocate that directory.

For non-interactive analysis and report generation, use the CI task:

```bash
bitbake core-image-minimal -c vulnscout_ci
```

The layer is maintained separately from this repository. Consult its documentation
for supported Yocto releases, per-image enablement, CI match conditions, and
report configuration:

**[meta-vulnscout documentation](https://meta-vulnscout.readthedocs.io/en/latest/)**

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

VulnScout Documentation
=======================

.. image:: _static/vulnscout_logo.png
   :alt: VulnScout logo
   :width: 220

VulnScout is an open-source, SBOM-first platform for identifying, assessing,
and managing vulnerabilities in software components and dependencies.
Import a **Software Bill of Materials (SBOM)**, investigate findings in the web
interface, record product-specific assessments, and automate policy checks in CI.

It runs locally inside a Docker or Podman container, with a web interface,
command-line tools, and a REST API sharing the same project and variant data.
A **project** groups a software product's data; a **variant** represents a
build, target, or deployment within it.

`Website <https://vulnscout.io/>`_ |
`Source code <https://github.com/savoirfairelinux/vulnscout>`_

From SBOM to Assessment
-----------------------

VulnScout starts after SBOM generation and supports a repeatable lifecycle:
**Import → Enrich → Assess → Enforce → Share**.

.. image:: _static/vulnscout-pipeline.svg
   :alt: Import, Enrich, Assess, Enforce, and Share, with optional AI assistance during assessment

* **Import** SBOMs and existing findings into a project and variant.
* **Enrich** the inventory with vulnerability scans and refreshed intelligence.
* **Assess** product impact using build, source, and deployment evidence.
* **Enforce** vulnerability policies through executable CI match conditions.
* **Share** reports, enriched SBOMs, VEX, and custom assessment data.

Scanning discovers findings; refreshing updates metadata for findings already
recorded. Assessments connect those findings to product evidence. The stages
describe a logical lifecycle, not a mandatory shell sequence: in CI, generate
required reports and exports before the final policy check.

What You Can Do
---------------

* Import SPDX 2/3 JSON, SPDX 3 JSON-LD, and CycloneDX JSON, together with
  Yocto CVE-check/VEX, OpenVEX, and Grype JSON findings.
* Discover vulnerability candidates with Grype, NVD, OSV, and sbom-cve-check;
  enrich recorded vulnerabilities with NVD, EPSS, ENISA EUVD, and GitHub
  Advisory metadata.
* Inspect package dependencies, compare scan history, and investigate
  vulnerabilities in their project and variant scope.
* Record VEX assessments, customize CVSS scores, and estimate remediation effort.
* Use the optional built-in Agent for AI-assisted assessments and independent
  reviews of custom assessments. Proposed AI assessments require human approval
  before becoming official.
* Generate customizable reports and export enriched SPDX, CycloneDX, OpenVEX,
  or VulnScout assessment-exchange data.

Where to Start
--------------

Follow :doc:`getting-started` to import bundled example data and open the web
interface. Normal container use does not require Python or Node.js on the host.

Use :doc:`vulnscout-workflow` for the full lifecycle, :doc:`interactive-mode`
for web-interface tasks, or :doc:`vulnscout-script` for CLI syntax and automation.
See :doc:`ai-assessments` for optional provider setup, source evidence, and
human review. The embedded Agent is intended for localhost-only, single-user
use; assessment context and source evidence may be sent to the selected AI
provider.

Architecture
------------

.. image:: _static/vulnscout-architecture.svg
   :alt: CLI and web access, core services, scanners, storage, and the Copilot SDK and MCP tool loop

See :doc:`getting-started` for instructions on launching VulnScout, importing
an SBOM, and inspecting vulnerability findings in the web interface.

.. toctree::
   :maxdepth: 3
   :caption: Contents:

   getting-started
   vulnscout-script
   vulnscout-workflow
   interactive-mode
   ai-assessments
   custom-data-format
   templates
   ci_conditions
   api
   dev_guide
   container-entrypoint
   yocto-integration
   zephyr-integration
   license

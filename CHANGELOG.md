# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [0.13.0] - 2026-04-28

### Added
- Scan: multi-source support (Grype, OSV, NVD), scan routes, diff engine, delete, queue system, and scan history with variant display.
- Scan: CPE generation, Grype artifact builder, and `--perform-nvd-scan` / `--perform-osv-scan` CLI commands.
- Scan: scan history diffs with tool-scan findings on removed packages.
- SBOM: add CPE/PURL columns to packages table.
- Review: implement assessment edit / delete features.
- Templates: add missing controllers, new data models graph, and new fields after DB migration.

### Changed
- Scan: redesigned start button, log windows per variant, and active vulnerability pool.
- Refactor: split `scans.py` into modules; refactor template kwargs; remove unused popup component.

### Fixed
- Scan diffs: unified diff logic for list & detail views, SBOM baseline at scan time, stable historical counts after new SBOM import, active view includes latest tool scan per source.
- Scan execution: Grype performs only on active SBOM elements, OSV queries all PURLs correctly, NVD queries all package CPEs, queue system for Grype scans.
- Active-scan logic: unified active-scan logic, scoped `found_by` attribution to active scans, linked each CVE to introducing scan, variant enrichment uses correct scan IDs.
- Packages: route uses only SBOM scan for package list, resolved active packages, removed SBOM-package filtering system, avoid code duplication for pkg init, empty packages block creation.
- Assessments: scope variant tags to assessment group date, pre-check only active packages on new assessment.
- Frontend: uncheck CPE & PURL by default, remove "+" sign for detected elements, fix array column size, remove unknown URL.
- Templates: filters handle dict input; remove unnecessary conversion explanation.
- Timestamps: include UTC offset in serialized timestamps.
- SPDX3/Yocto: CVSS persistence and description parsing.

### Documentation
- Add details on threat model, impact, assessment workflow, and terminology.
- Update interactive mode documentation.

---

## [0.12.1] - 2026-04-17

### Added
- Read the Docs configuration.

### Changed
- Code quality: added shellcheck, fixed flake8 configuration, fixed pre-commits.
- Upgrade cyclonedx-python-lib to 11.7.0.
- Redirect users to the official documentation in the README.

### Fixed
- Persist custom report templates.
- Remove API GET request per CVE on Review.
- Multiedit correct vulnerability count.
- Frontend data clear when navigating.
- DB lock after few assessments due to NVD taking control of the DB.
- UI bug fixes.
- Strip staging prefix from filename.
- Error 500 when setting a custom assessment.
- Update initialization message to get URL.
- Raise a warning when providing an invalid SPDX file
- PURL as OpenVEX product @id, not name@version

---

## [0.12.0] - 2026-04-09

### Added
- Migration to a database persistance.
- Variant support: variant-specific assessments, variant columns in Vulnerabilities & Packages tables, project/variant picker.
- Review tab: import/export custom user assessments as `.tar.gz`, grouped by variants and packages.
- Scans tab: scan history with upgrade feature, diff UI, per-scan vulnerability metrics, and timezone support.
- Settings tab: create/delete projects & variants, import multiple SBOMs per scan, custom loading messages.
- New Vulnscout CLI entrypoint.
- Podman container support; container runs as daemon.
- Database migration tooling with notification UI.

### Changed
- Migrated from in-memory DTOs to SQLAlchemy models.
- Replaced NVD/EPSS local SQLite cache with direct API clients.
- New Sphinx documentation; removed `README_DEV`.
- Reorganized `/example` and `/templates` folders.

### Fixed
- Data integrity and duplicate assessment issues.
- Long "Loading Data" at serve time.
- UI fixes: tooltips, table overflow, gauge overflow, hover effects, variant tags.
- Match condition exit codes; `merger_ci` early exit on DB commit.
- Deprecated SBOM parsing in Packages & Vulnerabilities tabs.

### Removed
- Patch-Finder feature (temporarily).

---

## [0.11.1] - 2026-03-11

### Added
- SPDX3: Extract vulnerability description and CVSS scores.

### Fixed
- Fix comma in vulnerabilities.csv template fields breaking CSV output.
- Ensure no file is created when a fail condition occurs in templates.
- Fix CycloneDX export: score field was exported as a string instead of a number.
- VulnModal: Prevent keyboard navigation shortcuts from triggering when editing text.

---

## [0.11.0] - 2026-03-03

### Added
- Keyboard shortcuts: navigation and row focus in Packages/Vulnerabilities tables, shortcut helper with tooltip in NavigationBar, and enhanced keyboard navigation in VulnModal.
- Severity filtering: custom CVSS score range slider; scores displayed in severity column when custom filter is active.
- Filter vulnerabilities by Published Date in dashboard and templates.
- `vulnscout.sh`: new arguments to ignore parsing errors and bypass grype scan.
- `vulnscout.sh`: argument to exclude fixed vulnerabilities in `cve_check`.
- Enable debug mode in Flask server when using `--dev`.
- Displaying Yocto vulnerability description
- Support for environment variables in report templates
- Adding a report template for match conditions.
- Check for existing YAML file before building a new one, if arguments remain unchanged.
- Docker entrypoint to manage permissions.
- Backend tests and improved test coverage.

### Changed
- Search: use FuseJS query syntax with `-` as negation prefix, handle exclude patterns, remove unwanted fuse keys.
- `cve_check`: transition from existing status to fixed.
- `vulnscout.sh`: use functions instead of env variables; arguments validity check & cleanup;
- Change variable names for containers.
- Capitalize description title text in modal; reorganize example files.
- Updated `.gitignore` to include VulnScout files and exclude specific directories.

### Fixed
- Fetch published date for GHSA vulnerabilities; fix timezone handling.
- `.tar.zst` files no longer cause errors in `vulnscout.sh`
- Renamed `--sbom` parameter to `--spdx` to match documentation.
- Fix correct return code with Podman
- Fix permission in entrypoint tree; chown also the cache folder.
- VulnModal: scroll to top on vulnerability change; clear unsaved input fields on close.

### Removed
- Remove `start-example.sh`.

---

## [0.10.0] - 2026-02-06

### Added
- Patch-Finder: Add loading bar.
- SPDX3: fix parsing and read CVEs contained in the SBOM file.
- OpenVEX: Support OpenVEX input files.
- Packages table: Add CPE ID column.
- Networking: Add support for HTTP proxy.
- Container runtime: Add support for Podman.
- UI: Display version string in the app.
- Templates: Support templates in non-interactive mode.
- `vulnscout.sh`: Add support for SELinux.

### Changed
- Documentation: Update architecture schema.
- Reports: Add filter based on assessment dates.

### Fixed
- Metrics: Fix version string overflow.

---

## [0.9.1] - 2025-12-01
### Added
- Batch multi-edit requests: When selecting multiple vulnerabilities, changes are now sent in a single batch request instead of individually.

### Changed
- Clear impact statement when status is different from not_affected / false positive.
- Remove justification when status is not not_affected / false_positive.
- Remove licenses from frontend UI.
- Vulnerabilities by Source chart: Title changed to "Vulnerabilities by Database", "User Data" to "Local User Data", and fixed typos ("yocto" to "Yocto", "grype" to "Grype").
- Community Pending Analysis renamed to "Pending Assessment".
- Remove openvex(scanner) and change openvex to User Data.
- Fix vulnerability index: Improved stack count consistency when assessing vulnerabilities within a filtered set.
- Resolve sorting issue with tables.
- Change Active Vulnerabilities dot colors.
- Change time empty estimate error message.
- Hide message banner when moving to another CVE.
- Updated and added tests.

### Fixed
- Spelling and formatting: Fixed spelling of VulnScout and added missing inline code formatting.
- vulnscout_CI_test.sh: Fixed CI test to account for new sbom.spdx3.json output.

---

## [0.9.0] - 2025-11-12

### Added
- Add ability to see vulnerabilities for specific packages
- Generate and export SPDX3 outputs
- Add last assessment and priority to vulnerabilities template
- Adding buttons to move between vulnerabilities
- Add silent execution mode to start-example.sh
- Add Package indicator to the Vulns table
- Add support for tag-value SPDX files
- Add a Columns selector in Table Vulnerabilities
- Add last updated and change labels in Vulnerabilities
- Add newline to VEX assessments

### Changed
- Move "new assessment" above history in VulnModal
- Add animation for newly added assessment
- Status string capitalization
- Changed source graph to display dinamic sources
- Change All Assessments template
- Change exploitability label in frontend
- "Status" field in New Assessment picks last status
- Change Vulnerability workflow to View and Edit modes
- Modify vulnerabilities Report
- Change vulnerabilities report fields
- Update frontend data in real-time after edition
- Update edit mode syncing
- Change button from Vulns to Show Vulnerabilities
- Only show unfixed vulns in Most critical vulns

### Fixed
- Fix cve_check CVE version issue
- Fix missing field in OpenVEX False Positive
- Fix Vulns workflow UI issues

### Removed
- Remove NVD sync from CI mode

---

## [0.8.1] - 2025-10-10

### Added
- vulnscout.sh: Add script for manual VS usage (CI Mode)
- vulnscout_CI_test.sh: Add automatic test for CI mode

### Changed
- Set WebUI print only in interactive mode
- Change frontend loading title and icons
- README.adoc: Update of the README
- Replace browser-native alerts with custom banners
- Frontend: improve nav bar and metrics

---

## [v0.8.0] - 2025-09-24

### Added
- Custom CVSS scoring support
- “Reset filters” button in Packages view
- New dashboard elements
- Filtering criteria propagation from pie charts
- Persistence & instant display in vulnerability popup
- Severity sorting + “Hide fixed” toggle in Vulnerabilities tab
- ESC-close + confirmation on vuln modal
- Grouping multiple packages under one assessment
- Added README section about custom CVSS scoring

### Changed
- Refactored dark mode feature
- Export page redesign
- Removed excess scroll in Vulnerabilities view
- Absolute API URLs used across the app
- Changed OpenVEX “author” field name

### Removed
- `status` column from Packages table

### Fixed
- Fixed Version line rendering in Patch-Finder
- Prevent duplicate SPDX3 assessments on re-runs
- Removed duplicate assessments in frontend

### Infrastructure, Tests & CI

- Improved error reporting in NVD DB builder
- Frontend + backend testing & coverage display enhancements
- Enforced minimum test coverage threshold
- Added frontend linting, config updates, updated Vite version
- CI workflow extended to ARM architecture
- Dockerfile updated to latest Node.js version

---
## [v0.7.1] - 2025-08-20

### Added
- Licenses support.
- HTML report generation for AsciiDoc documents.
- docker-compose: example for NVD_API_KEY.
- CI: publish Docker image on tag.

### Changed
- Frontend enhancements and UI/UX improvements.

### Fixed
- Removed unused dependency faChartLine in frontend.
- Improved project examples.
- Added notification when vulnscout is ready to use.
- Resolved NPM issue on default Ubuntu with pip install; NPM no longer mandatory for testing.
- Corrected docker-compose mount path (mount src instead of npm).
- Ensured docker pull step is included.

---
## [v0.7.0] - 2025-08-07

### Added
- SPDX 3.0 support.
- Contribution guide.
- Changelog file.
- Code of conduct.
- Caching support.
- Pagination in vulnerability dashboard.
- PR request template.
- SELinux support.
- Clickable pie charts in frontend.
- Toggle switch component.
- Architecture diagram and improved documentation.
- Background highlight when hovering rows.
- Start-example script enhancements.
- CQFD testing improvements.
- New test procedure in CI for CQFD.
- Filtering options for vulnerabilities.
- Sync with meta-vulnscout.
- Time estimate editor and related tests.

### Changed
- Updated configuration file name in documentation.
- Modified label for Exploitability/EPSS for clarity.
- UI/UX improvements in search results.
- Improved search code and fixed related bugs.
- Updated template paths and fixed related tests.

### Fixed
- EPSS builder issue.
- CQFD testing fixes.
- Search code bug.
- Template path and test fixes.

---

## [v0.6.0] - 2025-02-28

### Added
- `vulnscout.sh`: added verbose flag, refactored interpreter.
- Frontend: status fetching before scanning, page for computed upgrades.
- SPDX improvements: 2.3 support, fast parsing class.
- OpenVEX: added full parsing, editing, and encoding support.

### Changed
- Multiple refactors and dependency cleanups.
- UI/UX enhancements and bulk edit features in vulnerability dashboard.

### Fixed
- Multiple bugs in SPDX handling and frontend state management.

---

## [v0.5.0] - 2024-09-13

### Added
- New export formats: XML, PDF, CSV, CycloneDX JSON.
- CI expression parsing and `ci` command.
- Time estimation features for vulnerabilities.
- EPSS integration and filtering.

### Changed
- Improved frontend performance and UX.
- Added dashboards and scan status indicators.

### Fixed
- Bug fixes in package handling and SPDX merge.

---

## [v0.4.1] - 2024-09-09

### Added
- Bugfix release with improvements in SPDX merging and assessment display.

---

## [v0.4.0] - 2024-08-14

### Added
- Duration estimation for vulnerabilities (ISO 8601 format).
- New controller and model classes for CVSS, packages, vulnerabilities.
- Frontend input improvements and escape handling.

---

## [v0.3.0] - 2024-07-15

### Added
- CycloneDX parsing/export.
- EPSS scoring display and filtering.
- Dashboard UX improvements and legend linking.

---

## [v0.2.1] - 2024-06-27

### Fixed
- Deduplication issues in vulnerabilities and assessments.

---

## [v0.1.0] - 2024-06-10

### Added
- Initial release with Flask API, Docker support, React frontend.
- Vulnerability scanning and SPDX handling.
- Metrics dashboard, reporting templates, and assessment logic.

---

## [Initial commit] - 2024-05-17

### Added
- Initial repo setup with Python, frontend, and basic documentation.

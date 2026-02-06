# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased]
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


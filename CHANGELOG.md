# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

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


# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- CHANGELOG.md created (commit `df50b24`).
- HTTPS update in `vulnscout.sh`.
- General cleanup, typo fixes, and documentation improvements.

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


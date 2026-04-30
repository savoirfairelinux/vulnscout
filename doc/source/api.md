# REST API

VulnScout exposes a REST API served by the Flask backend, available at `http://localhost:7275/api/` by default.
All endpoints return JSON unless otherwise noted. Routes are registered directly on the Flask application without URL prefixes or blueprints.

---

## Version & Status

### Get Server Version

```
GET /api/version
```

Returns the running VulnScout version.

**Response:**
```json
{ "version": "1.2.3" }
```

The value comes from the `VULNSCOUT_VERSION` environment variable (`"unknown"` when unset).

### Get Initial Scan Status

```
GET /api/scan/status
```

Returns the progress of the container entrypoint import script. This endpoint is available even while the import is still running (all other `/api/*` routes return `503` until the script finishes).

**Response:**
```json
{
  "status": "running",
  "maxsteps": 8,
  "step": 3,
  "message": "Merging SBOMs"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | `"running"` or `"done"` |
| `maxsteps` | int | Total number of import steps |
| `step` | int | Current step number |
| `message` | string | Human-readable progress label |

---

## Config

### Get Current Config

```
GET /api/config
```

Returns the active project and variant based on the `PROJECT_NAME` / `VARIANT_NAME` environment variables, or the first project in the database.

**Response:**
```json
{
  "project": { "id": "...", "name": "..." },
  "variant": { "id": "...", "name": "...", "project_id": "..." }
}
```

Fields may be `null` if no project or variant exists.

---

## Projects

### List Projects

```
GET /api/projects
```

Returns all projects.

**Response:** JSON array of project objects.

### Create Project

```
POST /api/projects
```

**Request body:**
```json
{ "name": "my-project" }
```

**Response:** `201 Created` — serialized project. `409 Conflict` if the name is already taken.

### Rename Project

```
PATCH /api/projects/<project_id>/rename
```

**Request body:**
```json
{ "name": "new-name" }
```

**Response:** Serialized project. `409 Conflict` if the name is already taken.

### Delete Project

```
DELETE /api/projects/<project_id>
```

Deletes the project and all its associated data (variants, scans, findings).

**Response:**
```json
{ "message": "Project deleted." }
```

---

## Variants

### List All Variants

```
GET /api/variants
```

Returns all variants across all projects.

### List Variants for a Project

```
GET /api/projects/<project_id>/variants
```

**Response:** JSON array of variant objects. `404` if project not found.

### Create Variant

```
POST /api/projects/<project_id>/variants
```

**Request body:**
```json
{ "name": "x86_64" }
```

**Response:** `201 Created`. `409 Conflict` if the name already exists within the project.

### Rename Variant

```
PATCH /api/variants/<variant_id>/rename
```

**Request body:**
```json
{ "name": "aarch64" }
```

**Response:** Serialized variant. `409 Conflict` if the name is already taken within the project.

### Delete Variant

```
DELETE /api/variants/<variant_id>
```

**Response:**
```json
{ "message": "Variant deleted." }
```

---

## Packages

### List Packages

```
GET /api/packages
```

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `variant_id` | UUID | Filter by variant |
| `project_id` | UUID | Filter by project |
| `compare_variant_id` | UUID | Second variant for comparison (requires `variant_id`) |
| `operation` | string | `"difference"` (default) or `"intersection"` — comparison mode |
| `format` | string | `"list"` (default) or `"dict"` (keyed by `name@version`) |

**Response:** JSON array of package objects enriched with `variants` and `sources` fields.

When `compare_variant_id` is provided together with `variant_id`, the endpoint computes a diff or intersection of packages between the two variants.

---

## Vulnerabilities

### List Vulnerabilities

```
GET /api/vulnerabilities
```

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `variant_id` | UUID | Filter by variant |
| `project_id` | UUID | Filter by project |
| `compare_variant_id` | UUID | Second variant for comparison |
| `operation` | string | `"difference"` or `"intersection"` |
| `format` | string | `"list"` (default) or `"dict"` |

**Response:** JSON array of vulnerability objects enriched with `packages_current`, `variants`, `first_scan_date` and `found_by`.

> **Note:** When `variant_id` or `project_id` is provided, findings from tool scans (Grype, NVD, OSV) are automatically filtered to only include packages present in the variant's active SBOM. This prevents stale or cross-variant vulnerabilities from appearing. SBOM-scan findings are always included unconditionally.

### Get Single Vulnerability

```
GET /api/vulnerabilities/<id>
```

**Response:** Vulnerability object. `404` if not found.

### Update Vulnerability

```
PATCH /api/vulnerabilities/<id>
```

Update effort estimates and/or CVSS scoring for a vulnerability.

**Request body:**
```json
{
  "effort": {
    "optimistic": 3600,
    "likely": 7200,
    "pessimistic": 14400
  },
  "cvss": {
    "base_score": 7.5,
    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "version": "3.1"
  },
  "variant_id": "optional-uuid"
}
```

Effort values can be integers (seconds) or ISO 8601 duration strings.

**Response:** Updated vulnerability object.

### Batch Update Vulnerabilities

```
PATCH /api/vulnerabilities/batch
```

**Request body:**
```json
{
  "vulnerabilities": [
    { "id": "CVE-2024-1234", "effort": { "likely": 3600 } },
    { "id": "CVE-2024-5678", "cvss": { "base_score": 9.0 } }
  ]
}
```

**Response:**
```
{
  "status": "success",
  "vulnerabilities": [...],
  "count": 2,
  "errors": [],
  "error_count": 0
}
```

---

## Assessments

### List Assessments

```
GET /api/assessments
```

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `variant_id` | UUID | Filter by variant |
| `project_id` | UUID | Filter by project |
| `format` | string | `"list"` (default) or `"dict"` |

### Get Single Assessment

```
GET /api/assessments/<assessment_id>
```

**Response:** Assessment object. `404` if not found.

### List Assessments for a Vulnerability

```
GET /api/vulnerabilities/<vuln_id>/assessments
```

**Query parameters:** `format` (`"list"` or `"dict"`).

### List Variants for a Vulnerability

```
GET /api/vulnerabilities/<vuln_id>/variants
```

Returns all distinct variants that have a finding for this vulnerability.

**Response:**
```json
[
  { "id": "...", "name": "x86_64", "project_id": "..." }
]
```

### Create Assessment

```
POST /api/vulnerabilities/<vuln_id>/assessments
```

**Request body:**
```json
{
  "packages": ["package-name@1.0.0"],
  "status": "affected",
  "variant_id": "optional-uuid",
  "status_notes": "Confirmed by manual review",
  "justification": "",
  "impact_statement": "",
  "workaround": "",
  "responses": ["update"]
}
```

**Response:**
```
{
  "status": "success",
  "assessments": [...],
  "assessment": { ... }
}
```

### Batch Create Assessments

```
POST /api/assessments/batch
```

**Request body:**
```json
{
  "assessments": [
    { "vuln_id": "CVE-2024-1234", "packages": ["pkg@1.0"], "status": "affected" },
    { "vuln_id": "CVE-2024-5678", "packages": ["pkg@2.0"], "status": "not_affected", "justification": "code_not_reachable" }
  ]
}
```

**Response:**
```
{
  "status": "success",
  "assessments": [...],
  "count": 2,
  "errors": [],
  "error_count": 0
}
```

### Update Assessment

```
PUT /api/assessments/<assessment_id>
PATCH /api/assessments/<assessment_id>
```

**Request body:**
```json
{
  "status": "not_affected",
  "status_notes": "False positive",
  "justification": "vulnerable_code_not_present",
  "impact_statement": "Component is not included in our build",
  "workaround": ""
}
```

All fields are optional.

**Response:**
```
{
  "status": "success",
  "assessment": { ... }
}
```

### Delete Assessment

```
DELETE /api/assessments/<assessment_id>
```

**Response:**
```json
{
  "status": "success",
  "message": "Assessment deleted successfully"
}
```

### Review Assessments (User-Created)

#### List Review Assessments

```
GET /api/assessments/review
```

Returns only user-created assessments (not scan-imported).

**Query parameters:** `variant_id`, `project_id`.

#### Export Review Assessments

```
GET /api/assessments/review/export
```

Downloads a `.tar.gz` archive containing one OpenVEX JSON file per variant.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `author` | string | Author name in the export (default: `"Savoir-faire Linux"`) |

**Response:** Binary `.tar.gz` file (`Content-Type: application/gzip`).

#### Import Review Assessments

```
POST /api/assessments/review/import
```

Upload an OpenVEX `.json` or `.tar.gz` file. For `.tar.gz` archives, filenames inside must match variant names.

**Request:** Multipart form-data with a `file` field.

**Response:**
```json
{
  "status": "success",
  "imported": 15,
  "skipped": 2,
  "errors": []
}
```

---

## Documents

### List Available Documents

```
GET /api/documents
```

Returns all available report templates and SBOM export formats.

**Response:**
```json
[
  { "id": "summary.adoc", "extension": "adoc", "is_template": true, "category": "report" },
  { "id": "CycloneDX 1.6", "extension": "json", "is_template": false, "category": "sbom" }
]
```

### Generate / Download Document

```
GET /api/documents/<doc_name>
```

Generate a report from a template or export an SBOM in the requested format.

**Path parameter:** `doc_name` — template name (e.g. `summary.adoc`) or SBOM format (e.g. `CycloneDX 1.6`, `SPDX 2.3`, `SPDX 3.0`, `OpenVex`).

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `ext` | string | Target output format / extension |
| `author` | string | Author name for the document |
| `client_name` | string | Client name for the document |
| `export_date` | string | Export date override |
| `ignore_before` | ISO datetime | Ignore vulnerabilities assessed before this date |
| `only_epss_greater` | float | Only include vulns with EPSS score above this value |

**Response:** File download with appropriate `Content-Type` and `Content-Disposition` headers. Supports JSON, XML, PDF, and HTML outputs depending on the template.

---

## Scans

### List Scans

```
GET /api/scans
```

Returns all scans with diff statistics compared to the previous scan of the same variant.

**Response:** JSON array of scan objects including:
- `finding_count`, `package_count`, `vuln_count`
- `findings_added`, `findings_removed`, `findings_upgraded`
- `packages_added`, `packages_removed`, `packages_upgraded`
- `vulns_added`, `vulns_removed`
- `variant_name`, `project_name`, `is_first`

### List Scans for a Project

```
GET /api/projects/<project_id>/scans
```

### List Scans for a Variant

```
GET /api/variants/<variant_id>/scans
```

### Update Scan Description

```
PATCH /api/scans/<scan_id>
```

**Request body:**
```json
{ "description": "Weekly CI scan" }
```

**Response:** Updated scan object.

### Delete Scan

```
DELETE /api/scans/<scan_id>
```

Deletes the scan and its observations. Findings that are no longer referenced by any observation are also removed.

**Response:**
```json
{
  "deleted": true,
  "scan_id": "...",
  "orphaned_findings_removed": 3
}
```

### Get Scan Diff

```
GET /api/scans/<scan_id>/diff
```

Returns a detailed diff between this scan and the previous scan of the same type (and source) for the same variant.

For **SBOM scans**, the diff is computed against the *scan result* — that is, the merged union of the SBOM and active tool-scan findings filtered by SBOM packages. This means the numbers are consistent with the Scan Result badges shown in the list view.

For **tool scans**, the diff reflects the change in the *global result* (SBOM ∪ tool scans) caused by this scan. Additionally, `newly_detected_*` and `all_*` fields provide the raw tool-scan contents.

**Response:**
```
{
  "scan_id": "...",
  "scan_type": "sbom",
  "previous_scan_id": "...",
  "is_first": false,
  "finding_count": 120,
  "package_count": 45,
  "vuln_count": 80,
  "findings_added": [...],
  "findings_removed": [...],
  "findings_upgraded": [...],
  "findings_unchanged": [...],
  "packages_added": [...],
  "packages_removed": [...],
  "packages_upgraded": [...],
  "packages_unchanged": [...],
  "vulns_added": [...],
  "vulns_removed": [...],
  "vulns_unchanged": [...],
  "newly_detected_findings": null,
  "newly_detected_vulns": null,
  "newly_detected_findings_list": null,
  "newly_detected_vulns_list": null,
  "all_findings": null,
  "all_vulns": null
}
```

| Field | Type | Scope | Description |
|-------|------|-------|-------------|
| `scan_type` | string | all | `"sbom"` or `"tool"` |
| `findings_unchanged` | array | all | Findings present in both the current and previous scan result |
| `packages_unchanged` | array | SBOM | Packages present in both scans |
| `vulns_unchanged` | array | all | Vulnerability IDs present in both scan results |
| `newly_detected_findings` | int\|null | tool | Count of findings new in the global result |
| `newly_detected_vulns` | int\|null | tool | Count of vulnerabilities new in the global result |
| `newly_detected_findings_list` | array\|null | tool | Finding objects newly detected in the global result |
| `newly_detected_vulns_list` | array\|null | tool | Vulnerability IDs newly detected |
| `all_findings` | array\|null | tool | All raw findings from this tool scan |
| `all_vulns` | array\|null | tool | All vulnerability IDs from this tool scan |

### Get Scan Global Result

```
GET /api/scans/<scan_id>/global-result
```

Returns every active finding, vulnerability, and package at the time of the given scan, combining SBOM and tool-scan data with source attribution. Tool-scan findings are filtered to packages present in the SBOM.

**Response:** JSON object with `findings`, `vulnerabilities`, and `packages` arrays, each entry enriched with an `origin` field indicating the source (SBOM document name/format or tool scan source).

---

## Scan Triggers

These endpoints trigger asynchronous vulnerability scans for a specific variant. Each returns `202 Accepted` immediately; use the corresponding `/status` endpoint to poll progress.

All trigger endpoints return `409 Conflict` if a scan of the same type is already running for the variant, `404` if the variant is not found, and `503` if the required tool is unavailable (Grype only).

### Trigger Grype Scan

```
POST /api/variants/<variant_id>/grype-scan
```

Runs Grype on the export, filters the results to only the variant's SBOM packages, and merges findings back as a tool scan.

**Response:** `202 Accepted`
```json
{ "status": "started", "variant_id": "..." }
```

Progress steps: `1/4 Exporting CycloneDX` → `2/4 Running Grype` → `3/4 Merging results` → `4/4 Processing`.

### Check Grype Scan Status

```
GET /api/variants/<variant_id>/grype-scan/status
```

**Response:**
```json
{
  "status": "running",
  "error": null,
  "progress": "2/4 Running Grype",
  "logs": ["[1/4] CycloneDX export complete", "..."],
  "total": 4,
  "done_count": 1
}
```

Status values: `"idle"` (no scan started), `"running"`, `"done"`, `"error"`.

### Trigger NVD Scan

```
POST /api/variants/<variant_id>/nvd-scan
```

For every active package with CPE identifiers, queries the NVD CVE API and creates findings for any matched CVEs. Respects the `NVD_API_KEY` environment variable for higher rate limits.

**Response:** `202 Accepted`
```json
{ "status": "started", "variant_id": "..." }
```

### Check NVD Scan Status

```
GET /api/variants/<variant_id>/nvd-scan/status
```

Same response shape as Grype status. `total` is the number of unique CPEs to query, `done_count` tracks progress.

### Trigger OSV Scan

```
POST /api/variants/<variant_id>/osv-scan
```

For every active package with PURL identifiers, queries the OSV API. All PURLs per package are queried (e.g. generic + ecosystem-specific) so no vulnerabilities are missed.

**Response:** `202 Accepted`
```json
{ "status": "started", "variant_id": "..." }
```

### Check OSV Scan Status

```
GET /api/variants/<variant_id>/osv-scan/status
```

Same response shape as Grype status. `total` is the number of unique PURLs to query.

---

## SBOM Upload

### Upload SBOM Files

```
POST /api/sbom/upload
```

Upload one or more SBOM files for asynchronous processing.

**Request:** Multipart form-data.

| Field | Type | Description |
|-------|------|-------------|
| `files` | file(s) | One or more SBOM files |
| `project_id` | UUID | Target project |
| `variant_id` | UUID | Target variant |
| `format` | string | Optional: `spdx`, `cdx`, `openvex`, `yocto_cve_check`, `grype` — auto-detected if omitted |

**Response:** `202 Accepted`
```json
{
  "upload_id": "...",
  "scan_id": "...",
  "message": "Upload accepted, processing started"
}
```

### Check Upload Status

```
GET /api/sbom/upload/<upload_id>/status
```

**Response:**
```json
{
  "status": "processing",
  "message": "Merging inputs..."
}
```

Status values: `"processing"`, `"done"`, `"error"`.

---

## Progress

### NVD Progress

```
GET /api/nvd/progress
```

Get the current progress of NVD database updates.

**Response:**
```json
{
  "in_progress": true,
  "phase": "Fetching CVE data",
  "current": 42,
  "total": 100,
  "message": "Processing page 42/100",
  "last_update": "2026-04-07T10:30:00Z",
  "started_at": "2026-04-07T10:25:00Z"
}
```

### EPSS Progress

```
GET /api/epss/progress
```

Get the current progress of EPSS score enrichment.

**Response:**
```json
{
  "in_progress": false,
  "phase": "Complete",
  "current": 100,
  "total": 100,
  "message": "EPSS enrichment complete",
  "last_update": "2026-04-07T10:35:00Z",
  "started_at": "2026-04-07T10:30:00Z"
}
```

---

## Notifications

### Get Notifications

```
GET /api/notifications
```

Returns pending system notifications (e.g. legacy setup warnings).

**Response:** JSON array — empty when no notifications are pending.
```json
[
  {
    "level": "warning",
    "title": "Legacy setup detected",
    "message": "This container was started using the old docker-compose workflow.",
    "action": "Run migration.sh to import your data."
  }
]
```

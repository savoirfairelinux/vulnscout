# API

VulnScout exposes an API served by the Flask backend, available at `http://localhost:7275/api/` by default.
All endpoints return JSON unless otherwise noted. Routes are registered directly on the Flask application without URL prefixes or blueprints.

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

### Get Scan Diff

```
GET /api/scans/<scan_id>/diff
```

Returns a detailed diff between this scan and the previous scan of the same variant.

**Response:**
```
{
  "scan_id": "...",
  "previous_scan_id": "...",
  "is_first": false,
  "finding_count": 120,
  "package_count": 45,
  "vuln_count": 80,
  "findings_added": [...],
  "findings_removed": [...],
  "findings_upgraded": [...],
  "packages_added": [...],
  "packages_removed": [...],
  "packages_upgraded": [...],
  "vulns_added": [...],
  "vulns_removed": [...]
}
```

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

## Patch Finder

### Check Status

```
GET /api/patch-finder/status
```

**Response:**
```json
{
  "db_ready": true,
  "vulns_count": 1234
}
```

### Scan for Patches

```
POST /api/patch-finder/scan
```

Query fix/affected versions for a list of CVEs.

**Request body:**
```json
["CVE-2024-1234", "CVE-2024-5678"]
```

**Response:** Dictionary keyed by package name:
```json
{
  "package-name": {
    "CVE-2024-1234 grype": {
      "fix": ["1.2.4", "1.3.0"],
      "affected": ["1.2.0", "1.2.1", "1.2.3"]
    }
  }
}
```

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

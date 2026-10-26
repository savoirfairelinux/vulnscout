# REST API

VulnScout exposes a REST API served by the Flask backend, available at `http://localhost:7275/api/` by default.
Successful responses return JSON unless a download, stream, HTML page, or empty response is noted below.
Most routes are registered directly on the Flask application; the agent routes use a blueprint without an additional URL prefix.
Project, variant, scan, assessment, finding, and file IDs are UUIDs.
Vulnerability IDs are strings such as `CVE-2024-1234` or `GHSA-xxxx-xxxx-xxxx`; operation and queue IDs are opaque strings, not UUIDs.

The backend also exposes a machine-readable OpenAPI document at `GET /api/openapi`.
For compatibility, the same document is also available at `GET /api` and `GET /api/openapi.json`.
An interactive Swagger UI is available at `GET /api/openapi/ui` and is preconfigured to load the canonical spec from `/api/openapi`.
The navigation bar's **API documentation** link opens it in a new tab.
Swagger UI assets are bundled with the backend using a pinned dependency; viewing the API documentation needs no CDN or external validator.
This JSON document is generated from the registered Flask routes. Every registered `GET`, `POST`, `PUT`, `PATCH`, and `DELETE` operation under `/api` is included; descriptions and explicitly annotated metadata come from route docstrings.
The specification includes reusable domain schemas, required request fields,
multipart file controls, collection shapes, explicit success statuses, and
stream/download media types. Bodyless responses have no content schema.
Vulnerability, operation, and queue identifiers remain strings rather than being
inferred as UUIDs from their names. Agent operations describe their localhost
restrictions, session cookie, optional conversation header, and JSON/NDJSON replies.
Schemas remain extensible where responses carry computed enrichment or external
SBOM/VEX fields. These are documentation contracts, not additional runtime validation.
Swagger UI loads the canonical *spec URL*, not a separately curated specification;
the UI's spec and asset URLs also respect a WSGI deployment prefix.

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

Returns the progress of the container entrypoint import script. Most API routes return `503` with `{"error":"Scan not finished"}` until import finishes.
Exceptions are this endpoint, `/api/version`, the four OpenAPI URLs above, `/api/events/stream`, and the independently registered agent blueprint. Agent routes still apply their own access and availability checks.

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
  "variant": { "id": "...", "name": "...", "project_id": "..." },
  "product_name": "",
  "author_name": "vulnscout",
  "client_name": "",
  "contact_email": "",
  "grype_memlimit": ""
}
```

Fields may be `null` if no project or variant exists.

### Update Mutable Config

```
PATCH /api/config
```

Accepts a JSON object containing any of `product_name`, `author_name`, `client_name`, `contact_email`, and `grype_memlimit`.
Values must be strings or `null` (clears the value); whitespace is trimmed. Unknown keys return `400`.
Nonempty email values must have email syntax. `grype_memlimit` accepts a Go memory value such as `4GiB`, `512MiB`, or `1073741824`, or `off`/`disabled`.

```json
{ "author_name": "Example team", "grype_memlimit": "4GiB" }
```

**Response:** `200` with the same complete configuration shape as GET; `400` for invalid input; `500` if persistence to `config.env` fails.
Validated settings also update the process environment.

### Read or Set the NVD API Key

```
GET /api/config/nvd-api-key
PUT /api/config/nvd-api-key
```

GET returns `200` with `{"has_key":false,"masked_key":""}` or a masked configured key.
PUT accepts `{"api_key":"your-key"}`; an empty string removes the key.
A nonempty key is checked using an NVD API probe. Explicit credential rejection returns `400`; network failure returns `503`.
Other non-200 probe responses may still save the key with a `warning`.

**PUT response:** `200` with `{"status":"ok","has_key":true,"masked_key":"masked-value"}` and optional `warning`.
Invalid/missing key input returns `400`; persistence failure returns `500`. The key is saved to `config.env` and the process environment.

### Global Native-Package Scan Defaults

```
GET /api/config/native-packages
PUT /api/config/native-packages
```

GET returns the global native-package scan defaults. PUT replaces them with:

```json
{
  "exclude_native": true,
  "native_package_exceptions": ["cmake-native", "g++-native", "gcc-native"]
}
```

`exclude_native` must be a boolean. The exception list must contain strings, each at most 255 characters and ending in `-native`. Names are trimmed, lowercased, deduplicated, and sorted. An empty list excludes all native packages when `exclude_native` is true; false scans all native packages while retaining the exception list.

These defaults apply to projects without saved scan preferences; saved project preferences override them. Values persist in the top-level `global` node of `project-scan.json` under `VULNSCOUT_CACHE_DIR`, alongside a `projects` node keyed by exact project names. Existing flat mappings are upgraded on save without dropping project entries.

**Response:** `200 OK` with the saved preferences; `400` for invalid input; `500` if the configuration cannot be read or saved.

---

## Projects

### Read or Save Project Scan Preferences

```
GET /api/projects/<project_id>/scan-configuration
PUT /api/projects/<project_id>/scan-configuration
PUT /api/projects/scan-configurations
```

Single-project PUT replaces native-package preferences using the same `exclude_native` boolean and
`native_package_exceptions` list, normalization, and limits as the global defaults above.
GET returns saved preferences or the global defaults when none are saved.
Both single-project methods return `200` with these fields plus `native_packages`, the available `-native` package names from the project's latest SBOMs.

The batch PUT accepts a nonempty JSON object keyed by project UUID and saves all selected preferences atomically:

```json
{
  "11111111-1111-1111-1111-111111111111": {
    "exclude_native": true,
    "native_package_exceptions": ["cmake-native"]
  }
}
```

Its `200` response is the normalized preferences keyed by the same UUIDs, without `native_packages`.
All three operations return `400` for invalid identifiers/preferences, `404` for missing projects, and `500` for configuration read/write failures.

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

### Preview or Copy Custom Assessments

```
POST /api/variants/copy-assessments/preview
POST /api/variants/copy-assessments
```

Both accept:

```json
{
  "source_variant_id": "11111111-1111-1111-1111-111111111111",
  "target_variant_id": "22222222-2222-2222-2222-222222222222",
  "match_mode": "exact",
  "version_precision": 1,
  "copy_condition": "no_custom"
}
```

Source and target variants must belong to the same project. Only custom assessments are copied,
using active SBOM packages and findings actually observed in the target's active scans.
`match_mode` is `exact` (name/version, default),
`ignore_minor_version` (name plus leading version components), or `ignore_version` (name only).
`version_precision` defaults to 1, must be integer-convertible, and is clamped to at least 1.
`copy_condition` is `no_custom` (default), `different_status`, or `different_value`; the latter two also allow a copy when the newest target custom assessment differs in simplified status or copied content, respectively.
Copies create new custom rows; they do not overwrite existing rows.

**Preview response:** `200` with `count`, `skipped`, `message`, `mode`, and either:

- `entries` for exact matching, with `source_assessment_id`, `source_finding_id`, `target_finding_id`, `vulnerability_id`, `source_package`, `target_package`, `already_has_custom`, `selected`, and `assessment_details`.
- `groups` for other modes, with source assessment/finding/package details and a `candidates` array containing target finding/package IDs, `already_has_custom`, and `selected`.

The copy request optionally includes `selections`, an array of
`{"source_assessment_id":"uuid","target_finding_id":"uuid"}` pairs from the preview.
Without it, eligible candidates are recomputed and copied automatically.
**Copy response:** `200` with `{"copied":2,"skipped":0,"message":"Copied 2 assessments to target."}`.
Invalid payloads, IDs, modes, or selections return `400`; missing variants return `404`.

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

## Context

### Get Merged Context

```
GET /api/context?project_id=<project_id>&variant_id=<variant_id>
```

Returns the merged project and variant context, including uploaded codebase reference metadata
(`files`: `id`, `original_name`, `description`; no server filesystem paths). Both UUID parameters are required,
and the variant must belong to the selected project.

The agent-facing keys are plain text: `threat_model` and `risks` are rendered from the variant's STRIDE model.
`codebase_path` is `null` when the codebase source is references, and `files` is `[]` when it is paths. An additive
`editor` object carries the raw editor data (system and STRIDE data, and both stored codebase values).

### Get or Update Project Context

```
GET /api/projects/<project_id>/context
PUT /api/projects/<project_id>/context
```

The `PUT` request accepts a JSON object with a `description` field.

### Update Variant Context

```
PUT /api/variants/<variant_id>/context
```

Two body shapes are accepted.

**Editor shape** (body contains `stride`) is the full draft saved by the AI Context page:
`variant_description`, `environment`, `other_info`,
`codebase_source` (`"paths"` or `"references"`), `codebase_path`,
`system` (`scope`, `actors`, `entry_points`, `trust_boundaries`) and
`stride` (`components`, `interactions`, `threats`, `notes`, `risks`, `risk_notes`).
Validation failures return `400` with `{"error": ..., "fields": {"<path>": "<message>"}}`
(for example `"threat_model": "A threat model is required."`).

**Legacy shape** (no `stride`) accepts the four text fields `variant_description`, `codebase_path`, `environment`
and `other_info`. Each is replaced by the sent value (omitted means null). It never changes `codebase_source` or the
system and STRIDE data; on a variant whose codebase source is references, a null `codebase_path` keeps the stored
paths. The threat model and risks are read-only here: a non-null `threat_model` or `risks` returns `400` with a
`fields` entry for each.

### Import or Export Context

```
GET /api/context/export
POST /api/context/import
```

Export accepts either a `project_id` and `variant_id` pair, a comma-separated `variant_ids` filter, or no filter to
export all context. Import accepts an exported context JSON document and applies all valid entries atomically.

Export format `2.0` carries `codebase_source`, `system` and `stride_model` per variant, alongside the text fields.
Every entry is imported through the editor path, so it needs a valid `codebase_source` and a non-empty threat model;
`1.0` files, which only carry `threat_model` and `risks` text, are reported under `failed`.

### Manage Codebase References

```
POST /api/variants/<variant_id>/context/files
DELETE /api/variants/<variant_id>/context/files/<file_id>
```

Upload uses `multipart/form-data` with a required `file` and an optional `description`.
The AI Context page exposes drag-and-drop and a file picker in a variant's **Context** tab when its codebase source is
references. Files belong to one variant and are saved immediately.
ZIP, TAR and TAR.GZ/TGZ archives are validated before storage and limited to 5,000 entries.
Each archive member is capped at 10 MiB, and total expanded archive content is capped at 100 MiB.
Unsafe paths, duplicate file paths, encrypted ZIP members, links,
sparse files and special entries are rejected. Archives are never extracted or executed.
Upload/delete updates the variant context timestamp, marking older pending AI assessments outdated.
Context JSON import/export includes context data only, not uploaded references; text imports leave existing uploads intact.
Upload returns `201` with the file's `id`, `original_name`, and `description`; delete returns an empty `204` response.
Invalid uploads/UUIDs return `400`, missing variants/references `404`, and upload storage failures `500`.

### Browse Uploaded Source

```
GET /api/variants/<variant_id>/context/files/<file_id>/source
```

The file must belong to that variant. `operation` selects `list` (default), `read` or `search`.

| Operation | Parameters | Result |
|-----------|------------|--------|
| `list` | `pattern` (case-sensitive path glob, default `*`), `offset` (default 0), `limit` (1-200, default 200) | `files` with `path`/`size`, `total`, `next_offset` |
| `read` | `path` (exact listed member path), `start_line` (1-based, default 1), `max_lines` (1-200, default 200) | UTF-8 `content`, `start_line`, `end_line`, `total_lines`, `next_line`; at most 64 KB of content |
| `search` | `query` (1-200 characters, literal case-sensitive text), `pattern` (glob, default `*`), `max_results` (1-100, default 100) | `matches` with `path`/`line`/`text` (500-character snippets), `truncated`, `searched_files`, `skipped_binary_files` |

Every response includes `file_id` and `original_name`. Follow pagination for complete evidence and narrow
truncated searches. Binary/non-UTF-8 files return 400 for reads and are counted as skipped in searches.
Missing references/members return 404; unavailable stored files return 500 with an explicit error.
Individual files use their original name as the listed path. No arbitrary host path is accepted.

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
| `variant_ids` | string | Comma-separated variant IDs; union (default) or intersection |
| `include_outdated` | boolean-like string | `1`, `true`, or `yes` includes historical packages alongside active packages |
| `outdated_only` | boolean-like string | Same true values; returns historical packages only |

**Response:** JSON array of package objects enriched with `variants` and `sources` fields.

When `compare_variant_id` is provided together with `variant_id`, difference means packages in the **compare** variant but not the base `variant_id`; intersection includes both.
Pairwise comparison takes precedence over `variant_ids`, then single `variant_id`, then `project_id`.
Outdated queries require a variant/project scope (`400` otherwise). Outdated entries have `outdated: true`, `variant_id`, `finding_ids`, and `vulnerability_ids`; their dict keys append `@<variant_id>` to `name@version`.

### Package Dependencies

```
GET /api/package-dependencies
```

**Query parameters:** at least one of `variant_id`, `project_id` or `variant_ids` is required.

| Parameter | Type | Description |
|-----------|------|-------------|
| `variant_id` | UUID | Filter by variant |
| `project_id` | UUID | Filter by project |
| `variant_ids` | string | Comma-separated variant IDs |
| `compare_variant_id` | UUID | Second variant for comparison (requires `variant_id`) |
| `operation` | string | `"difference"` (default for comparison), `"intersection"` or `"union"` (default for `variant_ids`) |
| `counts` | string | `"1"` to return only per-package `in`/`out` totals |

**Response:** `{"documents": [...]}` where each active SBOM document lists its `variant_id`, `variant_name`, `dependencies_recorded`, `packages` and directed `edges` (`package_id` depends on `dependency_id`), or `{"counts": {"name@version": {"in": n, "out": n}}, "unrecorded": ["name@version", ...]}` when `counts=1` (`in`: packages it depends on, `out`: packages that depend on it). `dependencies_recorded` is `false` for documents imported before dependency support, and `unrecorded` lists packages found only in such documents, whose relationships are unknown rather than zero. An edge is listed under the dependent package's document; its dependency may appear in another document of the same scan (SPDX 2 `DocumentRef-` links). Package selection follows the same comparison rules as `GET /api/packages`.

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
| `variant_ids` | string | Comma-separated variant IDs; union (default) or intersection |
| `operation` | string | Pairwise `"difference"` (compare minus base, default) or `"intersection"`; multi-variant `"union"` (default) or `"intersection"` |
| `format` | string | `"list"` (default), `"dict"` (keyed by vulnerability ID), or `"compact"` |

**Response:** JSON array of vulnerability objects enriched with `packages_current`, `variants`, `first_scan_date` and `found_by`.

`dict` returns an object instead. `compact` returns a reduced array without texts, URLs, or CPEs, sets `details_loaded: false`, and reduces CVSS entries to version, score, and attack vector.
Pairwise comparison takes precedence over `variant_ids`, then single variant, then project.

> **Note:** When `variant_id` or `project_id` is provided, findings from tool scans (Grype, NVD, OSV) are automatically filtered to only include packages present in the variant's active SBOM. This prevents stale or cross-variant vulnerabilities from appearing. SBOM-scan findings are always included unconditionally.

### Get Single Vulnerability

```
GET /api/vulnerabilities/<id>
```

**Response:** Vulnerability object. `404` if not found.

Optional `variant_id` applies variant-scoped effort/CVSS and observation text selection; `project_id` scopes texts to a project when no variant is supplied.
With `variant_id` and `agent_scoped=1`, the vulnerability must be in that variant's active scope (`404` otherwise), and packages are scoped accordingly. Malformed UUID filters return `400`. Missing vulnerabilities currently return plain-text `Not found`.

### Get Variant-Specific Vulnerability Data

```
GET /api/vulnerabilities/<id>/variant-snapshots
GET /api/vulnerabilities/<vuln_id>/variant-active-packages
```

Both accept an optional `project_id` UUID to restrict variants (`400` for a malformed UUID).

Snapshots return `200` with an array of `{"variant_id":"uuid","effort":{"optimistic":"PT1H","likely":"PT2H","pessimistic":"PT4H"},"custom_cvss":[]}`.
Each entry contains the scoped effort and custom CVSS metric objects for an observing variant with available scoped data.
A missing vulnerability returns plain-text `Not found` with `404`.

Active-packages returns `200` with an array of:

```json
[
  {
    "variant_id": "11111111-1111-1111-1111-111111111111",
    "active_packages": ["pkg@1.0::supplier"],
    "findings": [
      { "finding_id": "22222222-2222-2222-2222-222222222222", "package": "pkg@1.0::supplier", "outdated": false }
    ]
  }
]
```

`active_packages` contains the vulnerability's packages still present in each variant's active SBOM.
`findings` describes actually observed variant/finding pairs; `outdated` compares package name/version with the active SBOM.
No findings (including an unknown vulnerability) returns an empty array.

### Update Vulnerability

```
PATCH /api/vulnerabilities/<id>
```

Update effort estimates and/or CVSS scoring for a vulnerability.

**Request body:**
```json
{
  "effort": {
    "optimistic": 1,
    "likely": 2,
    "pessimistic": 4
  },
  "cvss": {
    "base_score": 7.5,
    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "version": "3.1"
  },
  "variant_id": "11111111-1111-1111-1111-111111111111"
}
```

Effort values are integer **hours** or ISO 8601 duration strings (converted to whole hours, discarding sub-hour precision).
All three effort fields are required and must satisfy `optimistic <= likely <= pessimistic`.
CVSS updates require all of `base_score`, `vector_string`, and `version`; `author` and `origin` are optional.
With `variant_id`, writes affect that variant. Without it, updates apply to every variant observing the vulnerability, falling back to unscoped data if none does.

**Response:** Updated vulnerability object.

Success returns `200`; invalid effort/CVSS/UUID input returns `400`, and a missing vulnerability returns plain-text `Not found` with `404`.

### Batch Update Vulnerabilities

```
PATCH /api/vulnerabilities/batch
```

**Request body:**
```json
{
  "vulnerabilities": [
    { "id": "CVE-2024-1234", "effort": { "optimistic": 1, "likely": 2, "pessimistic": 4 } },
    { "id": "CVE-2024-5678", "cvss": { "base_score": 9.8, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "version": "3.1" } }
  ]
}
```

**Response:**
```
{
  "status": "success",
  "vulnerabilities": [...],
  "count": 2
}
```

Batch update items support `variant_id` and the same complete effort/CVSS objects as the single update.
Items are processed independently: `200` if any succeed, `400` if none succeed. Failures add `errors` and `error_count`; these keys are absent when there are no failures.

### Evaluate a Match Condition

```
POST /api/vulnerabilities/match-condition
```

Evaluates a condition expression against supplied objects and returns the matching IDs.

**Request body:**
```json
{
  "condition": "severity.cvss.base_score >= 7",
  "items": [{ "id": "CVE-2026-0001", "data": { "severity": { "cvss": { "base_score": 8.1 } } } }]
}
```

### Search Vulnerability Descriptions

```
POST /api/vulnerabilities/search-descriptions
```

Searches the supplied vulnerability IDs for each term. Optional `variant_id` or `project_id` query parameters scope
observation descriptions to active scans.

**Request body:**
```json
{
  "vulnerability_ids": ["CVE-2026-0001"],
  "terms": ["buffer overflow"]
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

`format=compact` also returns a reduced positional-array representation for the Explorer, rather than full assessment objects.
Single-variant filtering takes precedence over project filtering.

### Get Single Assessment

```
GET /api/assessments/<assessment_id>
```

**Response:** Assessment object, `404` if not found. Its `targets` array holds
every `(variant_id, package)` pair the assessment covers, each annotated with
`outdated`:

```json
{
  "id": "uuid",
  "vuln_id": "CVE-2024-1234",
  "status": "not_affected",
  "status_notes": "",
  "justification": "vulnerable_code_not_present",
  "impact_statement": "",
  "workaround": "",
  "origin": "custom",
  "responses": [],
  "timestamp": "2024-01-01T00:00:00+00:00",
  "targets": [
    { "variant_id": "uuid", "package": "pkg@1.0::supplier", "outdated": false }
  ]
}
```

Single-assessment responses also include flattened `packages`, `variant_id` (null for multi-variant scope), `variant_ids`, `source`, `last_update`, `project_id`, `assessment_fingerprint`, and `reviews`.
Targets include `project_id`. `simplified_status` is not part of this serializer. Use the fingerprint when writing an independent review below.

### List Assessments for a Vulnerability

```
GET /api/vulnerabilities/<vuln_id>/assessments
```

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `format` | string | `"list"` (default) or `"dict"` |
| `project_id` | UUID | Restrict results to variants of one project |

**Response:** array of assessment objects in the shape above, newest first.

### List Assessments for Review

```
GET /api/reviews/assessments
```

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `variant_id` | UUID | Restrict results to one variant |
| `project_id` | UUID | Restrict results to variants of one project |
| `origin` | string | Restrict results to one origin (e.g. `custom`, `ai`) |

**Response:** array of assessment objects, each enriched with a `vuln_texts`
array holding the vulnerability texts of its CVE for front-end tooltips.

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

### Reconcile an Assessment

Brings an assessment to the requested state in a single transaction: its
targets are added or removed so it ends up covering exactly the given
packages and variants, and its content is updated at the same time.

```
POST /api/assessments/<assessment_id>/reconcile
```

**Request body:**
```json
{
  "vuln_id": "CVE-2024-1234",
  "packages": ["pkg@1.0::supplier"],
  "variant_ids": ["uuid"],
  "targets": [
    { "package": "pkg@1.0::supplier", "variant_id": "uuid" }
  ],
  "status": "not_affected",
  "status_notes": "",
  "justification": "vulnerable_code_not_present",
  "impact_statement": "",
  "workaround": "",
  "responses": [],
  "update_timestamp": true,
  "timestamp": "2024-01-01T00:00:00+00:00"
}
```

When present, `targets` is the authoritative exact list of package/variant
pairs. This preserves sparse scopes without implicitly creating the
cross-product of the flattened fields. An explicitly empty `targets` list
removes every target and deletes the now-empty assessment. Legacy clients may
omit `targets` and provide non-empty `packages` and `variant_ids`; those fields
retain their cross-product behavior. `vuln_id` must match the assessment's
vulnerability. `responses` is only applied when the key is present, so
omitting it preserves the stored VEX responses. `update_timestamp` defaults to
`true`.

**Response:**
```json
{
  "status": "success",
  "updated": [],
  "created": [],
  "deleted": []
}
```

`400` on an invalid payload, a `vuln_id` that does not match the assessment, or
a request that would delete a target from a pending AI assessment. `404` if
the assessment does not exist.

### Approve an AI Assessment

Converts a pending AI assessment to `custom` origin.

```
POST /api/assessments/<assessment_id>/approve
```

**Response:**
```json
{
  "status": "success",
  "assessments": [ { } ]
}
```

`400` if the assessment is not a pending AI assessment. `404` if it does not
exist.

### Reject an AI Assessment

Deletes a pending AI assessment.

```
POST /api/assessments/<assessment_id>/reject
```

**Response:**
```json
{
  "status": "success",
  "deleted": ["uuid"]
}
```

`400` if the assessment is not a pending AI assessment. `404` if it does not
exist.

### Create Assessment

```
POST /api/vulnerabilities/<vuln_id>/assessments
```

**Request body:**
```json
{
  "packages": ["package-name@1.0.0"],
  "status": "affected",
  "variant_id": "11111111-1111-1111-1111-111111111111",
  "status_notes": "Confirmed by manual review",
  "impact_statement": "",
  "workaround": "",
  "responses": ["update"]
}
```

`variant_ids` (a list) may be given instead of `variant_id` to scope one
assessment to several variants. Set `"ai_generated": true` to create a pending
AI assessment (`origin` `"ai"`) instead of a `custom` one.

One variant scope is required. Alternatively, supply a non-empty `targets` array of exact
`{"variant_id":"uuid","package":"name@version::supplier"}` pairs; it overrides flattened scope fields.
Packages must already exist and have an observed finding for this vulnerability in at least one selected variant; no package or finding is invented.
Selected variants must belong to one project. Unobserved cross-product pairs are omitted.
For `not_affected`, provide an accepted OpenVEX/CycloneDX justification; omit `justification` rather than sending an empty string for other statuses.
An optional ISO 8601 `timestamp` overrides creation time. Success returns `200`, invalid input `400`, database errors `500`.

**Response:**
```
{
  "status": "success",
  "assessments": [...],
  "assessment": { ... },
  "replaced": [ { "id": "...", "action": "trimmed", "variant_ids": ["..."] } ]
}
```

`replaced` is present only when an AI-generated write replaced a pending AI
assessment. Such a write replaces pending AI assessments on the same
vulnerability only on the (variant, package) targets it writes, in the same
transaction as the create, so a failed write leaves the old assessment
untouched. `action` is `"deleted"` when the old assessment had no other targets
left and `"trimmed"` when it also covered other targets (other variants or
packages) and keeps those; `variant_ids` lists the variants whose targets were
removed. Approved (`custom`) and
scan-imported assessments are never replaced.

### Batch Create Assessments

```
POST /api/assessments/batch
```

**Request body:**
```json
{
  "assessments": [
    { "vuln_id": "CVE-2024-1234", "packages": ["pkg@1.0"], "variant_ids": ["11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"], "status": "affected" },
    { "vuln_id": "CVE-2024-5678", "packages": ["pkg@2.0"], "variant_id": "11111111-1111-1111-1111-111111111111", "status": "not_affected", "justification": "code_not_reachable" }
  ]
}
```

Each item requires either `variant_id` or a non-empty `variant_ids` array. The
plural form takes precedence when both are present. One item creates one
assessment row covering every observed package/variant target; separate items
remain separate rows. If any item is invalid, nothing in the batch is written.

**Response:**
```json
{
  "status": "success",
  "assessments": [],
  "count": 2,
  "vuln_count": 2
}
```

On failure (`400` for an invalid payload, `500` for a database error) the same
shape is returned with `status` `"error"`, empty `assessments`, and the failures
listed:

```json
{
  "status": "error",
  "assessments": [],
  "count": 0,
  "vuln_count": 0,
  "errors": [ { "vuln_id": "CVE-2024-1234", "error": "variant_id is required" } ],
  "error_count": 1
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

Individual content fields are optional, but the JSON object must not be empty.
An existing `not_affected` assessment still requires a `justification` key when edited.
`update_timestamp` defaults to `true`; `false` preserves the timestamp, while an optional ISO 8601 `timestamp` selects it explicitly when updating.
`allowed_variant_ids` may restrict the edit to assessments whose complete current target set is within that non-empty UUID array (`409` on scope changes).
Targets must still reference observed package/vulnerability/variant combinations (`400` otherwise).
Editing a scan-imported assessment converts it to `custom`; editing pending AI keeps origin `ai` until explicit approval/rejection.
Changing status away from `not_affected`/`false_positive` clears justification and impact before other supplied fields are applied.

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

Deletes the whole assessment and its targets. Pending AI assessments return `400`; use the reject endpoint instead. Missing assessments return `404`.

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

#### List Pending AI Assessments

```
GET /api/assessments/review/ai
```

Optional `variant_id` or `project_id` filters use UUIDs; a single variant takes precedence.
Returns `200` with an array of pending `origin: "ai"` assessments, their target/outdated metadata,
and `context_outdated` when project or variant context changed after assessment creation.
Malformed UUIDs return `400`. This endpoint does not approve suggestions.

#### List Custom CVSS and Time Estimates

```
GET /api/assessments/review/time-estimates
GET /api/assessments/review/custom-cvss
DELETE /api/assessments/review/time-estimates
DELETE /api/assessments/review/custom-cvss
```

GET accepts optional `variant_id` or `project_id` (variant takes precedence; malformed UUIDs return `400`).
Time estimates include nonzero records with `id`, `vuln_id`, nullable `variant_id`, integer-hour
`optimistic`/`likely`/`pessimistic`, corresponding `optimistic_iso`/`likely_iso`/`pessimistic_iso` duration strings,
and `vuln_texts`. Variant-scoped entries take precedence over an unscoped estimate for the same vulnerability.
Custom CVSS entries contain `id`, `vuln_id`, nullable `variant_id`, `version`, `vector_string`,
`base_score`, `author`, `origin`, and `vuln_texts`; scanner-authored records are excluded.
Scoped queries can include legacy unscoped data. Both return `200` arrays, including `[]`.

DELETE takes a nonempty JSON `ids` array of record UUIDs:

```json
{ "ids": ["11111111-1111-1111-1111-111111111111"] }
```

It deletes exactly those records atomically, not every record in a query scope.
Returns `200` with `{"status":"success","deleted":["11111111-1111-1111-1111-111111111111"]}`,
`400` for invalid IDs/body, or `404` if any record is absent (or is not custom CVSS for that endpoint).

#### Export Review Assessments

```
GET /api/assessments/review/export
```

Downloads one OpenVEX JSON document for a selected variant.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `author` | string | Author name in the export (default: `"Savoir-faire Linux"`) |
| `variant_id` | UUID | Required. The single variant to export. |

**Response:** OpenVEX JSON file (`Content-Type: application/json`).

#### Import Review Assessments

```
POST /api/assessments/review/import
```

Upload an OpenVEX `.json` file into a selected variant. The uploaded filename is not used to select the target.

**Request:** Multipart form-data with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `file` | file | OpenVEX `.json` document (required) |
| `variant_id` | UUID | Required target variant. |
| `timestamp_policy` | string | `"original"` (default) preserves statement timestamps; `"current"` uses import time |

**Response:**
```json
{
  "status": "success",
  "imported": 15,
  "skipped": 2,
  "errors": []
}
```

### Custom Data Import / Export

#### Export Custom Data

```
GET /api/assessments/review/export-custom-data
```

Exports handmade review assessments, pending AI assessments, custom CVSS scores,
and time estimates as a single JSON file. Pending AI assessments can be reviewed
from the **AI Assessments** tab after import.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `variant_id` | UUID | Restrict to selected variants; may be repeated. |
| `project_id` | UUID | Restrict to all variants in a project. |

**Response:** JSON file download (`Content-Disposition: attachment`) named `custom_data_<project-name>.json` when a project name is resolved, otherwise `custom_data.json`, containing:

```text
{
  "version": 2,
  "assessments": [...],
  "ai_assessments": [...],
  "cvss": [...],
  "time_estimates": [...]
}
```

Version 2 assessment records store their scope exclusively as exact target
pairs such as `{"variant": "x86", "package": "openssl@3.0"}`. Exported
records do not contain database variant UUIDs, so files can be transferred to
another VulnScout instance. CVSS and time-estimate records likewise identify
their variant by name. Legacy version 1 files remain importable; unsupported
future versions are rejected explicitly.

Returns `404` if there is no custom data to export.

#### Import Custom Data

```
POST /api/assessments/review/import-custom-data
```

Imports assessments, pending AI assessments, custom CVSS scores, and time
estimates from a custom-data JSON file. Imported AI assessments retain their
pending state and appear in the **AI Assessments** tab.

Accepts either:

- `multipart/form-data` with a `file` field containing a `.json` file and a required `project_id` form field.
- `application/json` body with the custom-data payload directly.

The JSON body must include the destination `project_id` UUID. Version 2 variant
names are resolved only within that project. Version 1 retains its legacy
variant ID/name resolution for existing backups.
The payload's optional `timestamp_policy` is `"current"` (default) or `"original"`; for multipart, it belongs inside the uploaded JSON, not a separate form field.
Do not supply `variant_id` query parameters: variants are selected from the file. Missing destination projects return `404`.

**Response:**
```json
{
  "status": "success",
  "assessments_imported": 12,
  "ai_assessments_imported": 4,
  "cvss_imported": 5,
  "time_estimates_imported": 3
}
```

Returns `400` for invalid format or unsupported content type.

#### Update an Existing Review Export

```
POST /api/assessments/review/export-update
```

Accepts multipart form-data: required `file` (a `.json` VulnScout custom-data or OpenVEX export),
required `project_id`, and one or more repeated `variant_id` fields belonging to that project.
OpenVEX requires exactly one variant; optional `author` defaults to the uploaded author or `Savoir-faire Linux`.
The uploaded format determines the output format. Current database records replace matching records,
records outside the selected variants are removed, and new records are appended while retaining matching order.
This updates the downloaded file, not the database.

**Response:** `200` JSON attachment using a sanitized uploaded filename; `400` for invalid format/body/scope,
`404` for a missing selected variant.

### Independent Reviews of Custom Assessments

These reviews are separate from the assessment itself, one per `(assessment, variant, finding)` target.
They never change the assessment's VEX verdict.

#### Read or Delete Reviews

```
GET /api/assessments/<assessment_id>/review
GET /api/assessments/<assessment_id>/reviews
DELETE /api/assessments/<assessment_id>/review
```

Singular GET and DELETE require query `variant_id` and either `finding_id` (UUID, takes precedence)
or `package` (exact package string ID). The resolved pair must be a target of that assessment.
Plural GET needs no query and returns every target's review.

**Responses:** singular GET returns `200` with `{"review":{...}}`; plural GET returns `{"reviews":[...]}`.
DELETE returns `200` with `{"status":"success","deleted":"<assessment_id>"}`.
Invalid IDs/targets return `400`; missing assessments or singular reviews return `404`.
Review objects have `id`, `assessment_id`, `variant_id`, `package`, VEX fields (`status`, `status_notes`,
`justification`, `impact_statement`, `workaround`, `responses`), `rationale`, `timestamp`,
`verdict` (`agrees` or `differs`, comparing VEX content), and `is_stale` (assessment changed since review).

#### Write a Target Review

```
PUT /api/assessments/<assessment_id>/review
```

Read the assessment first, then submit its current `assessment_fingerprint` as
`expected_assessment_fingerprint`, with a target and independently derived verdict:

```json
{
  "variant_id": "11111111-1111-1111-1111-111111111111",
  "package": "pkg@1.0::supplier",
  "expected_assessment_fingerprint": "fingerprint-from-assessment-response",
  "status": "not_affected",
  "justification": "vulnerable_code_not_present",
  "rationale": "The vulnerable implementation is absent from this target.",
  "responses": []
}
```

`finding_id` may replace `package`. `status` must be an OpenVEX status
(`under_investigation`, `not_affected`, `affected`, `fixed`); nonblank `rationale` is required.
`not_affected` requires an OpenVEX justification. Optional `status_notes`, `impact_statement`,
`workaround`, and `responses` are stored with the review; `responses` must be an array.
PUT creates or replaces the review for that target.

**Response:** `200` with `{"status":"success","review":{...}}`; `400` for invalid data/targets;
`404` for missing assessment; `409` if origin is not `custom` or the fingerprint no longer matches.
Fingerprint conflicts include `code: "assessment_changed"` and the current `assessment_fingerprint`; reread and reassess before retrying.

#### List Custom Assessments and Reviews

```
GET /api/custom-assessments
GET /api/assessment-reviews
```

Both accept repeated `variant_id` UUIDs or `project_id`; if both are supplied, variants must belong to that project.
Without a filter, results span all variants. Invalid identifiers/scope return `400`, and a missing explicitly
selected variant checked against a project returns `404`.

Custom-assessments accepts `has_review=true` (any reviewed scoped target) or `false`
(any unreviewed or stale scoped target), `order=timestamp_desc` (default) or `timestamp_asc`,
`limit` (integer >=1, default 50), and `offset` (integer >=0, default 0).
It returns a `200` array of custom assessment objects with scoped `packages`, `variant_ids`, `targets`,
`project_id`, `assessment_fingerprint`, `has_review`, and `target_reviews`
(`variant_id`, `package`, `has_review`, `is_stale`). Invalid pagination returns `400`.

Assessment-reviews additionally accepts `vulnerability_id` and returns `200` with an object keyed by
assessment ID, whose values are arrays of review objects (one per target). An empty scope returns `{}`.

---

## Documents

### Upload a Custom Template or Image Asset

```
POST /api/documents/templates
POST /api/documents/assets
```

Both require `multipart/form-data` with a single `file` field and save into the first writable template directory
(assets use its `assets/` subdirectory). Filenames are sanitized; uploading the same sanitized name replaces that file.

Templates allow `adoc`, `asciidoc`, `html`, `htm`, `md`, `markdown`, `csv`, `txt`, `json`, `xml`, `tex`, `j2`, `jinja`, and `jinja2`, up to 10 MiB.
**Template response:** `201` with `{"id":"custom.adoc","category":["custom"],"message":"Template imported."}`.

Assets allow genuine raster images matching `png`, `jpg`, `jpeg`, `gif`, or `webp`, up to 5 MiB.
SVG is not accepted by this upload endpoint.
**Asset response:** `201` with `{"name":"logo.png","message":"Asset uploaded."}`.

Both return `400` for missing/invalid upload or unsupported content, `413` when the applicable upload/request size limit is exceeded,
and `500` if no writable storage exists or saving fails. Discover saved resources through `GET /api/documents`.

### List Available Documents

```
GET /api/documents
```

Returns all available report templates and SBOM export formats.

**Response:**
```json
[
  { "id": "summary.adoc", "extension": "adoc | pdf | html", "is_template": true, "category": ["built-in"] },
  { "id": "CycloneDX 1.6", "extension": "json", "is_template": false, "category": ["sbom"] }
]
```

### Generate / Download Document

The list also includes image assets (`is_template: false`, `category: ["assets"]`).
`category` is always an array; `extension` may contain pipe-separated alternatives.

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
| `variant_id` | UUID | Restrict to one variant; takes precedence over `project_id` |
| `project_id` | UUID | Restrict to all variants of one project |

**Response:** File download with appropriate `Content-Type` and `Content-Disposition` headers. Supports JSON, XML, PDF, and HTML outputs depending on the template.

Without a scope filter, exports include global data. The same URL can download an asset by its name.

### Export Multiple Documents

```
POST /api/documents/export
```

Renders selected document formats for every variant in one project. `consolidated` creates one project-wide file per selection; `per_variant` creates one file per selection and variant. Both modes return a ZIP archive.

**Request body:**

```json
{
  "project_id": "11111111-1111-1111-1111-111111111111",
  "variant_ids": [
    "22222222-2222-2222-2222-222222222222"
  ],
  "mode": "per_variant",
  "documents": [
    { "name": "summary.adoc", "extension": "pdf" },
    { "name": "CycloneDX 1.6", "extension": "json" }
  ],
  "async": true
}
```

`variant_ids` selects one or more variants belonging to the project. When omitted, all project variants are exported. Reports support either output mode. SBOM selections require `per_variant` mode and cannot be mixed with reports in the same request. Document and extension pairs must match non-asset entries returned by `GET /api/documents`. Custom assets are resources used by report templates and cannot be exported directly.

With `"async": true`, returns `202 Accepted` with `{ "op_id": "export:<uuid>" }`. Watch `GET /api/events/stream` for a `done` operation, then download the retained ZIP from `GET /api/documents/export/<op_id>/download`. The archive is consumed on the first download and retained for up to one hour, subject to server limits. A repeat request or one after expiry normally returns `404` because the operation has been removed; request a new export rather than relying on `410` to identify those cases. An archive missing while its operation still exists can return `410`, and an unfinished export returns `409`. Without `async`, the response is a ZIP file (`Content-Type: application/zip`).

---

## Scans

### Import Scan Exports

```
POST /api/scans/import
```

Accepts an `application/json` scan export object, or a nonempty array of up to 200 exports from
`GET /api/scans/export`. Use exports from `/export-diff` or `/export-result`, not raw scanner/SBOM files.
Supported markers are `export_version: 1` and `export_format: "scan-diff"` or `"full-result"`.
Legacy full-result objects with neither marker remain accepted if they carry the required full-result fields.

Required metadata is `scan_id` (source UUID), `scan_type` (`import_sbom` or `vulnerability_scan`),
ISO 8601 `timestamp`, `project_name`, and `variant_name`. Names must resolve to an existing destination
project/variant; no destination UUID override is accepted.
`findings` is required; `packages` is required for SBOM imports.
Package entries use `package_name`, optional `package_version`, and optional `supplier`; findings add `vulnerability_id`.
Optional `scan_source`, `assessments`, and `newly_detected_assessments` preserve supported scan evidence.
The exported `diff` is ignored: the destination recomputes history against its own timeline.

Minimal empty-SBOM example (the named destination must already exist):

```json
{
  "export_version": 1,
  "export_format": "full-result",
  "scan_id": "11111111-1111-1111-1111-111111111111",
  "scan_type": "import_sbom",
  "timestamp": "2026-01-01T00:00:00Z",
  "project_name": "my-project",
  "variant_name": "default",
  "packages": [],
  "findings": []
}
```

The whole request is validated and written atomically. Imported scans receive new destination IDs.
Previously imported/existing duplicate scans are skipped; duplicate scan entries within one request return `409`.

**Response:** `201` with `imported_count`, `skipped_count`, and `scans` (one entry per imported scan:
`scan_id`, `source_scan_id`, `format` (`diff` or `full`), `project_name`, `variant_name`,
`package_count`, `finding_count`, `vulnerability_count`, `assessment_count`, `is_first`).
Top-level `scan_id`, `format`, and `is_first` describe the last imported scan (null when all are skipped);
top-level counts aggregate imported entries.
Errors: `400` malformed/unsupported payload, `404` missing destination, `409` conflicting entries,
`413` request-size limit, `500` persistence failure. No partial import is kept on failure.

### List Scans

```
GET /api/scans
```

Returns all scans with diff statistics compared to the previous scan of the same variant.

Optional `variant_ids` is a comma-separated UUID list. With it, `project_id` validates that all selected variants belong to that project; `project_id` alone does not filter this endpoint (use the project-scans URL).
Invalid filters return `400`, missing selected variants `404`.

**Response:** JSON array of scan objects including:
- `finding_count`, `package_count`, `vuln_count`
- `findings_added`, `findings_removed`, `findings_upgraded`
- `packages_added`, `packages_removed`, `packages_upgraded`
- `vulns_added`, `vulns_removed`
- `variant_name`, `project_name`, `is_first`
- `run_id`: operation queue id shared by the tool scans launched together, or `null`
- `run`: for a tool scan that shares its `run_id` with other tool scans of the same variant, the combined
  summary of that scan run (`id`, `scan_ids`, `sources`, `vuln_count`, `finding_count`, `assessment_count`,
  `newly_detected_vulns`, `newly_detected_findings`, `newly_detected_assessments`); `null` otherwise

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

**Response:** JSON object with `scan_id`, `scan_type`, `findings`, `vulnerabilities`, `packages`, and `assessments`, plus `finding_count`, `vuln_count`, `package_count`, and `assessment_count`.
Packages, findings, and vulnerabilities carry `sources` arrays (SBOM document name/format or tool scan source), not an `origin` field.

### Export Scan Diff

```
GET /api/scans/<scan_id>/export-diff
```

Exports a single scan's diff as a cleaned JSON download. The response strips internal fields and normalises supplier names for a portable, human-readable report.

For **SBOM scans** the export includes `vulnerabilities`, `findings`, `packages`, `assessments`, and (when the scan is not the first) a `diff` object with `*_added`, `*_removed`, `*_upgraded`, and `*_unchanged` arrays.

For **tool scans** the export includes `vulnerabilities`, `findings`, `newly_detected_vulns`, `newly_detected_findings`, and `newly_detected_assessments`.

**Response:** JSON file download (`Content-Disposition: attachment`).

### Export Scan Global Result

```
GET /api/scans/<scan_id>/export-result
```

Exports a single scan's global result (SBOM + tool data merged) as a cleaned JSON download. The response includes `packages`, `findings`, and `vulnerabilities` arrays with source attribution.

**Response:** JSON file download (`Content-Disposition: attachment`).

### Export All Scans

```
GET /api/scans/export
```

Exports all visible scans, optionally filtered by variant or project.

**Query parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `variant_id` | UUID | Restrict to a single variant |
| `project_id` | UUID | Restrict to all variants of a project |
| `type` | string | `"diff"` (default) or `"total"` — selects the diff or global-result export format |

**Response:** JSON array of export objects grouped per variant, served as a file download (`Content-Disposition: attachment`).
No matching scans returns `200` with `[]`, without download headers. More than 200 matching scans returns `400`; reduce the scope. A missing requested project returns `404`.

### Preview and Delete Obsolete Data

```
GET /api/outdated-data
DELETE /api/outdated-data
GET /api/empty-scans
DELETE /api/empty-scans
GET /api/orphaned-vulnerabilities
DELETE /api/orphaned-vulnerabilities
```

These operations are global, not scoped by project/variant query parameters. Always fetch a fresh GET preview,
then send its **complete** candidate set in the DELETE JSON body. They are not arbitrary subset-deletion APIs.

| Endpoint | GET response (`200`) | DELETE body |
|----------|----------------------|-------------|
| `/api/outdated-data` | `candidate_ids` (`observations`, `assessments`, `package_pairs`), `packages`, `assessments` | `{"candidate_ids": <unchanged candidate_ids object>}` |
| `/api/empty-scans` | `{"scans":[...]}`; entries have `id`, `description`, `timestamp`, `project`, `variant` | `{"scan_ids":["<every preview scan id>"]}` |
| `/api/orphaned-vulnerabilities` | `{"vulnerabilities":[{"id":"CVE-2024-1234","assessments":0}]}` | `{"vulnerability_ids":["<every preview vulnerability id>"]}` |

Outdated cleanup removes stale observations, package/variant evidence, and assessment targets,
pruning shared rows only when no references remain. Its `package_pairs` are `{"package_id":"uuid","variant_id":"uuid"}` objects.
The DELETE `200` response contains counts: `assessments_deleted`, `assessment_targets_removed`,
`observations_deleted`, `sbom_packages_deleted`, `sbom_observations_deleted`, `findings_deleted`,
`vulnerabilities_deleted`, and `packages_deleted`.

Empty scans are non-initial **tool** scans whose complete change statistics are zero;
DELETE returns `{"scans_deleted":0}` with the actual count.
Orphaned vulnerabilities lack scan/SBOM evidence, time estimates, and variant-scoped metrics;
DELETE returns `vulnerabilities_deleted`, `assessments_deleted`, and `findings_deleted` counts.

All DELETEs return `400` for an invalid/missing candidate body, `409` if the preview no longer matches current candidates
(fetch a new preview and review it), and `500` on cleanup failure. Empty complete candidate sets are allowed.

---

## NVD Refresh

These endpoints update cached NVD data (description, CVSS scores, references) for vulnerabilities already present in the database. Unlike the NVD scan, refresh does not create new findings — it only enriches existing `Vulnerability` records.

The NVD refresh endpoint accepts a `mode` field to select the NVD data source:

- **`local`** (default) — reads from the local NVD-FKIE advisory database; no network calls, no API key needed.
- **`api`** — queries the NVD REST API v2; requires network access and honours the `NVD_API_KEY` environment variable.

### Refresh a Single CVE

```
POST /api/vulnerabilities/<cve_id>/nvd-refresh
```

Fetches NVD data for the given CVE and updates the stored description, CVSS scores, and references.

**Request body:**
```json
{ "mode": "local" }
```

| Field | Type | Description |
|-------|------|-------------|
| `mode` | string | `"local"` (default) or `"api"`. |

**Response:** `200` with `{"vulnerabilities": [<updated vulnerability>]}`.

**Error responses:**

| Code | `error_code` | Condition |
|------|--------------|-----------|
| `503` | `unavailable` | Local mode: CVE not found in the local database. API mode: NVD API unreachable or returned no data. |
| `429` | `rate_limited` | API mode only: NVD rate limit exceeded. |
| `401`/`403` | `unauthorized` | API mode only: API key rejected by NVD. |

### Refresh EPSS or GitHub Advisory Metadata

```
POST /api/vulnerabilities/<cve_id>/epss-refresh
POST /api/vulnerabilities/<ghsa_id>/ghsa-refresh
```

Neither endpoint needs a request body or accepts NVD's `mode` selector.
EPSS queries the EPSS API for an existing CVE and updates its score/fetched timestamps; percentile is returned transiently.
GHSA refresh accepts a `GHSA-xxxx-xxxx-xxxx` identifier and updates the advisory's published date/fetched timestamps from GitHub.
Identifiers are normalized to uppercase. Neither endpoint creates findings.

**Response:** `200` with `{"vulnerabilities":[<updated vulnerability>]}`.
EPSS returns `404` for an unknown CVE and `503` for unavailable data.
GHSA returns `400` for invalid identifiers, `404` for missing local/upstream advisories,
`502` for other upstream HTTP errors, and `503` for network/unusable published-date data.

### Operation Queue and Event Stream

```
POST /api/operations
GET /api/operations
GET /api/events/stream
POST /api/operations/<op_id>/cancel
POST /api/operations/queue/<queue_id>/cancel
DELETE /api/operations/<op_id>
```

Submit scans and vulnerability-data refreshes as one ordered batch. Scans run in Grype, NVD, OSV, sbom-cve-check order on the pipeline lane, followed by NVD, EPSS, GHSA, and EUVD refreshes. A batch may expand to at most 100 operations.

**Request body:**
```json
{
  "jobs": [
    { "kind": "scan", "source": "grype", "variant_ids": ["<variant-uuid>"], "options": { "exclude_kernel": true, "exclude_native": false } },
    { "kind": "refresh", "source": "nvd", "variant_ids": ["<variant-uuid>"], "exclude_ids": ["CVE-2024-1234"] }
  ]
}
```

For a standalone refresh, supply `ids` (CVE IDs for NVD/EPSS/EUVD, GHSA IDs for GHSA) instead of `variant_ids`. Deferred refresh jobs resolve the variant's newly discovered IDs after preceding scans; `exclude_ids` omits the pre-scan baseline. Scan options `exclude_kernel` and `exclude_native` default to `true` and `false`, respectively. `options.mode` accepts `"local"` (default) or `"api"` where supported. Duplicate or invalid operations are rejected before any job is queued; active conflicts return `409` with the conflicting operation IDs.

**Response:** `202 Accepted` with `{ "queue_id": "q-...", "operations": [ ... ] }`. Each operation contains `op_id`, `kind`, `source`, `queue_id`, `position`, `status`, `progress` (`current`, `total`, `message`), `logs`, `error`, `result`, `scope`, and `cancellable`. `GET /api/operations` returns `{ "operations": [ ... ] }` with the current snapshot. Status values are `queued`, `running`, `done`, `error`, and `cancelled`; do not infer completion from the HTTP 202 response.

`GET /api/events/stream` returns `text/event-stream`. A fresh connection starts with a `snapshot` containing `seq` and `operations`. Each `operation` event replaces the full state for one `op_id`; `operation_removed` contains only the removed `op_id`. Idle clients receive `heartbeat` events every 15 seconds. Server shutdown sends `bye` and the client reconnects. For example, a fresh empty stream begins with:

```text
id: <epoch>:0
event: snapshot
data: {"seq": 0, "operations": []}
```

The cursor is instance-specific and changes on server restart. Reconnect with the **complete** `<epoch>:<seq>` `Last-Event-ID` header (or a URL-encoded `last_event_id` query parameter) to replay buffered updates. An invalid or too-old cursor yields a new snapshot. The SSE stream has a default limit of 32 concurrent clients (`VULNSCOUT_SSE_MAX_STREAMS`); requests above the limit return `503`. `GET /api/operations` is a diagnostic snapshot endpoint, not an automatic fallback in the web UI.

To stop one queued/running operation, `POST /api/operations/<op_id>/cancel` returns `200` with `{"status":"cancelling","op_id":"..."}` if accepted, `404` when no active operation has that ID, or `409` for a known non-cancellable operation. Cancellation of running work is cooperative, so wait for a `cancelled` event. `POST /api/operations/queue/<queue_id>/cancel` returns `{"cancelled": <count>}`. For terminal work, `DELETE /api/operations/<op_id>` returns `200` on dismissal or `409` if the operation is unknown or still active; dismissal does not remove its scan results. Upload, export, and boot-enrichment operations also appear in the stream, but not every kind supports cancellation.

Invalid job bodies or batches above 100 expanded operations return `400`; unknown variants return `404`, and active operation conflicts return `409`. The server may return `503` if the SSE stream or document export queue is full.

The registry and replay buffer are process-local, so a restart clears queued and retained operations. Terminal items remain for up to one hour unless dismissed sooner. For queue behavior and user-facing recovery, see {ref}`Operation Queue <operation-queue>`.

---

## Scan Sources

`POST /api/operations` accepts `scan` jobs for `grype`, `nvd`, `osv`, and `scc` (sbom-cve-check). Each scan takes one or more `variant_ids`. The Grype job exports CycloneDX, runs Grype, merges the results and processes findings. NVD scans use the local advisory database by default; set `options.mode` to `"api"` to query NVD by CPE. OSV scans query every package PURL. SCC scans match packages against the local NVD-FKIE and CVEList databases. Progress and errors arrive as operation events, not separate per-scanner status responses.

The SCC databases live at `SBOM_CVE_CHECK_DATABASES_DIR` inside the container (default: `/cache/vulnscout/local_databases`). Set `$VULNSCOUT_SBOM_CVE_CHECK_DB_DIR` on the host to mount a shared clone, or `SBOM_CVE_CHECK_AUTO_UPDATE=1` to update before scans.

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
| `refresh_sources` | repeated string | NVD, EPSS, GHSA, EUVD; use `none` to disable post-import refreshes |

**Response:** `202 Accepted`
```json
{
  "op_id": "upload:<uuid>",
  "scan_id": "...",
  "message": "Upload accepted. Processing started."
}
```

Follow the returned `op_id` in `GET /api/events/stream` (or `GET /api/operations`) for progress, completion, and errors. There is no separate upload-status endpoint.

The required project/variant must exist and the variant must belong to the project (`404` for missing entities, `400` for mismatches).
Optional `format` overrides SBOM format detection. Multiple files/companion SPDX archive members form one scan.
Omitting `refresh_sources` defaults to EPSS; send `none` alone for no refresh. Unknown refresh sources return `400`.

---

## Agent Chat

Agent routes use the `vulnscout_agent` cookie to retain a browser conversation; preserve cookies between calls.
An optional `X-Agent-Thread` UUID selects an independent thread sharing root credentials and the response lock
(at most 20 child threads). Conversations expire after one hour of inactivity.
Responses use `Cache-Control: no-store`; credentials are never included in status responses.

All agent operations require a localhost host name and a trusted local client connection;
non-GET browser requests with an `Origin` must match the server origin (`403` otherwise).
Malformed thread IDs return `400`. The bootstrap import gate does not apply, but individual operations can still
fail when the provider, Copilot SDK, MCP server, or database scope is unavailable.
Agent POSTs return `200` on success, not `201`.

### Read Agent Status

```
GET /api/agent
```

Returns `200` with `authenticated`, nullable `login`, `configured` (bundled MCP server file exists),
`device_login`, `token_connected`, nullable `provider`, nullable `config_error`, `messages` (role/content objects),
`model`, and `usage` (`cost`, `input_tokens`, `output_tokens`, each nullable).
Provider authentication/configuration and conversation history are scoped to the cookie/root thread.

### Connect or Disconnect a Provider

```
POST /api/agent/provider
DELETE /api/agent/provider
```

POST accepts:

```json
{
  "provider": "local",
  "base_url": "http://localhost:11434/v1",
  "model": "my-local-model",
  "api_key": ""
}
```

`provider` is `openai`, `azure`, `anthropic`, or `local`.
Hosted providers require a nonblank `api_key`; local providers do not.
`model` is optional (at most 100 characters); when omitted/empty, the server discovers available models.
`api_key` is at most 4096 characters; control characters are rejected in these fields and URLs.
`base_url` is optional for OpenAI/Anthropic (their standard API defaults), required for Azure/local, and at most 2048 characters.
Hosted URLs require HTTPS; local URLs require HTTP and an allowed loopback/container host. URLs cannot include credentials, query strings, or fragments.

POST uses the supplied model or discovers the provider's model list; supplying a model does not itself probe the provider.
DELETE clears the provider. Both clear prior conversation threads and persist configuration to `config.env`.
**Response:** `200` with `{"provider":"local","model":"my-local-model"}` (DELETE uses null provider and resets the model).
Errors: `400` invalid configuration or model discovery failure, `409` agent already responding,
`500` persistence failure, `503` failure clearing the previous stored conversation.

### GitHub Device Sign-In and Sign-Out

```
POST /api/agent/auth
POST /api/agent/auth/poll
DELETE /api/agent/auth
```

No request bodies are needed. POST auth starts GitHub device sign-in and returns `200` with
`user_code`, HTTPS `verification_uri`, and polling `interval` in seconds. Complete sign-in at that URI.
POST poll uses the cookie's stored device code; wait at least the returned interval between calls.

**Poll responses:** `200` with `{"status":"pending","interval":5}` while waiting (the interval can increase),
or `{"status":"connected","authenticated":true,"login":"account-name"}` on verified Copilot access.
`410` means the device code is missing/expired; start again.
`401` means sign-in was denied/failed or the account has no Copilot access;
`503` means GitHub/Copilot verification is unavailable; `500` means credentials could not be persisted.
Starting sign-in can also return `503`.

DELETE signs out, clears provider/device credentials and all threads, and returns
`200` with `{"authenticated":false,"cleanup_error":null}`.
A remote-session cleanup error may be reported in `cleanup_error` despite successful local sign-out;
persistence failure returns `500`. Successful sign-in persists credentials and resets prior threads.

### List or Select Models

```
GET /api/agent/models
POST /api/agent/model
```

GET returns `200` with `{"models":[{"id":"model-id","name":"Model name"}]}` for the current provider/Copilot account.
POST accepts `{"model":"model-id"}`; the string must be at most 100 characters, contain no control characters,
and identify an available model. It persists `AI_MODEL` and returns `200` with `{"model":"model-id"}`.
Errors: `400` invalid configuration/model, `503` unavailable Copilot model lookup;
POST additionally returns `409` while the agent is responding or `500` if persistence fails.

### Reset a Conversation

```
DELETE /api/agent/conversation
```

Deletes the selected thread's stored session, messages, and usage without signing out.
With `X-Agent-Thread`, only that child thread is removed.
Returns `200` with `{"messages":[],"usage":{"cost":null,"input_tokens":null,"output_tokens":null}}`,
or `503` if deleting the stored session fails.

### Send a Message

```
POST /api/agent/messages
```

```json
{
  "message": "Summarize the selected variant's pending assessments.",
  "context": {
    "page": "review",
    "projectId": "11111111-1111-1111-1111-111111111111",
    "variantId": "22222222-2222-2222-2222-222222222222"
  }
}
```

`message` is required, nonblank, and at most 8000 characters. Optional `model` defaults to the conversation model
(nonempty string, at most 100 characters). Optional `context` describes browser selection, not trusted project facts.
Its `page` must be `metrics`, `packages`, `vulnerabilities`, `scans`, `review`, `exports`, `settings`, `ai`, or `unknown`.
Optional scope strings `projectId`, `variantId`, `baseVariantId`, `compareOperation`, `multiOperation` are at most 100 characters;
`variantIds` permits at most 1000 strings of that length. Selected variant UUIDs must belong to the selected project.
With no context/project on non-AI pages, the agent scope spans all projects.
AI-page scope instead uses `view.selectedProjectId` and `view.selectedVariantId`, with no project selection yielding no project scope.

Optional `context.view` accepts UI selection metadata:

- Strings up to 200 characters: `openVulnerabilityId`, `search`, `section`, `selectedProjectId`, `selectedProjectName`,
  `selectedVariantId`, `selectedVariantName`, `openScanId`, `exportType`, `exportMode`, `exportCategory`, `refreshMode`.
- Arrays of up to 100 strings (each up to 200 characters): `visibleVulnerabilityIds`, `selectedVulnerabilityIds`,
  `visiblePackageIds`, `visibleScanIds`, `matchingVariantIds`, `selectedVariantIds`, `selectedExportKeys`,
  `enabledExportDocuments`, `selectedScanTypes`, `selectedRefreshTypes`.
- Integers from 0 to 1,000,000: `visibleCount`, `selectionCount`.
- Booleans: `hideEmptyScans`, `excludeKernel`, `excludeNative`.

**Default response:** `200` JSON with `reply`, `model`, and accumulated `usage`.
Set the exact header `Accept: application/x-ndjson` for a `200` newline-delimited JSON stream instead.
Stream event `type` values include `status`, `heartbeat`, `delta`, `tool_start`, `tool_end`, and terminal
`done` (with `reply`, `model`, `usage`) or `error` (with `error` message).
Once streaming starts, failures are events rather than changed HTTP statuses.

Before streaming/JSON processing, invalid messages/configuration/context return `400`,
concurrent responses return `409`, and a missing bundled MCP server returns `503`.
For nonstreaming requests, unavailable model selection returns `400` and provider/agent execution failures return `503`.

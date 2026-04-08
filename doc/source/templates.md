# Writing Report Templates

## Templating System

VulnScout uses [Jinja2](https://jinja.palletsprojects.com/) as its templating engine, which has great community support, documentation, and supports any text-based format (AsciiDoc, HTML, Markdown, CSV, plain text, etc.).

### Template Locations

| Path | Purpose |
|------|---------|
| `src/views/templates/` | Built-in templates shipped with VulnScout. |
| `.vulnscout/templates/` | Per-project host-side templates (mounted automatically if the directory exists). |

### Adding a Custom Template

Pass the file path directly to `--report` — it stages and runs the template in one step:

```bash
./vulnscout --project demo --report /path/to/my-report.adoc
```

### Automatic Generation

Set the `GENERATE_DOCUMENTS` environment variable to automatically build templates at the end of every scan. Multiple templates are comma-separated (values are trimmed):

```bash
./vulnscout config GENERATE_DOCUMENTS "summary.adoc, all_assessments.adoc"
```

Generated files are written to the outputs directory (default: `.vulnscout/outputs/`).
All templates can also be run on-demand from the web interface using the export button in the toolbar.

---

### Global Variables Available in Templates

| Variable | Type | Description |
|----------|------|-------------|
| `vulnerabilities` | dict | All vulnerabilities found in the project, keyed by ID. Use `vulnerabilities \| as_list` to get a list. |
| `packages` | dict | All packages found in the project, keyed by ID. Use `packages \| as_list` to get a list. |
| `assessments` | dict | All assessments found in the project, keyed by ID. Use `assessments \| as_list` to get a list. |
| `author` | string | Company name producing this document (from `AUTHOR_NAME` config). |
| `export_date` | string | Date of export as `YYYY-MM-DD`. |
| `scan_date` | string | Date and time of the last scan, or `unknown date` if unavailable. |
| `client_name` | string | Customer company name. Set via `CLIENT_NAME` config or overridden per-export from the web UI. May be empty. |
| `unfiltered_vulnerabilities` | dict | All vulnerabilities, bypassing any active export filter. Use `\| as_list` to get a list. Always the full dataset. |
| `unfiltered_assessments` | dict | All assessments, bypassing any active export filter. Keyed by assessment ID. |
| `failed_vulns` | list[string] | List of vulnerability IDs that triggered the `--match-condition` expression. Empty when no condition was set or no vulnerability matched. Use `unfiltered_vulnerabilities[vuln_id]` to get the full object. |

---

### Environment Variables Available in Templates

Use `env(name, default="")` to access host environment variables in your templates.

For example, to fetch the value of the `DISTRO` environment variable:

```
{{ env("DISTRO") }}
{{ env("DISTRO", "unknown") }}
```

VulnScout will automatically scan your templates for `env("...")` patterns and pass the corresponding environment variable values from the host system.

When exporting, users can add filters to export only some vulnerabilities. To bypass these filters and access all vulnerabilities, use `unfiltered_vulnerabilities` instead of `vulnerabilities` and `unfiltered_assessments` instead of `assessments`. This is useful when producing a summary or showing the number of filtered-out vulnerabilities.

---

### Vulnerability Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | CVE / vulnerability ID. |
| `found_by` | list[string] | Tools that found the vulnerability (e.g. `grype`, `yocto`, `spdx3`). |
| `datasource` | string | Primary URL for the vulnerability. |
| `namespace` | string | Database name (e.g. `nvd`). |
| `aliases` | list[string] | Alternative IDs for this vulnerability. |
| `related_vulnerabilities` | list[string] | IDs of related vulnerabilities. |
| `urls` | list[string] | Additional reference URLs. |
| `texts` | dict[str, str] | Descriptions and notes. Key is the title, value is the content. |
| `severity.severity` | string | Severity level: `low`, `medium`, `high`, `critical`, `unknown`. |
| `severity.min_score` | float | Minimum CVSS score (0–10). |
| `severity.max_score` | float | Maximum CVSS score (0–10). |
| `severity.cvss` | list[CVSS] | List of CVSS scoring objects (version, score, vector, author). |
| `epss.score` | float | EPSS probability score (0–1). |
| `epss.percentile` | float | EPSS rank relative to all CVEs (0–1). |
| `effort.optimistic` | string | Optimistic fix time estimate in ISO 8601 duration (e.g. `PT5H`). |
| `effort.likely` | string | Likely fix time estimate in ISO 8601 duration (e.g. `P1D`). |
| `effort.pessimistic` | string | Pessimistic fix time estimate in ISO 8601 duration (e.g. `P2DT4H`). |
| `packages` | list[string] | Packages affected by the vulnerability, in form `name@version`. |
| `published` | string | CVE publish date as ISO 8601, or empty if unknown. |
| `status` | string | Current status string (see Assessment object for possible values). |
| `simplified_status` | string | Simplified status: `pending`, `affected`, `fixed`, or `ignored`. |
| `last_assessment` | Assessment | Most recent assessment object (shorthand for `assessments[0]`). |
| `assessments` | list[Assessment] | All assessments, sorted most recent first. |

---

### Package Object

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Name of the package. |
| `version` | string | Version of the package. |
| `cpe` | list[string] | List of CPE identifiers. |
| `purl` | list[string] | List of PURL identifiers. |

---

### Assessment Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Assessment ID (UUID). |
| `vuln_id` | string | ID of the vulnerability this assessment affects. |
| `packages` | list[string] | List of packages concerned. |
| `timestamp` | string | Creation datetime in ISO 8601 format. |
| `last_update` | string | Last update datetime in ISO 8601 format. |
| `status` | string | Status of the assessment (see possible values below). |
| `simplified_status` | string | Simplified status: `pending`, `affected`, `fixed`, or `ignored`. |
| `status_notes` | string | Free-text note about the status. |
| `justification` | string | Justification for the status (see possible values below). |
| `impact_statement` | string | Text explaining why the vulnerability does not apply. |
| `responses` | list[string] | List of remediation responses (see possible values below). |
| `workaround` | string | Workaround description. |
| `workaround_timestamp` | string | Datetime of this workaround in ISO 8601 format. |
| `variant_id` | string | UUID of the variant this assessment belongs to, or empty. |

#### Possible values for `status`

| Value | Description | Filter |
|-------|-------------|--------|
| `in_triage`, `under_investigation` | Vulnerability found but presence not confirmed. Default status. | `status_pending`, `status_active` |
| `affected`, `exploitable` | Vulnerability confirmed and affecting the product. | `status_affected`, `status_active` |
| `fixed`, `resolved`, `resolved_with_pedigree` | Vulnerability is fixed and no longer exploitable. | `status_fixed`, `status_inactive` |
| `not_affected`, `false_positive` | Vulnerability is a false positive or not affecting us. | `status_ignored`, `status_inactive` |

#### Possible values for `justification`

- `component_not_present`
- `vulnerable_code_not_present`
- `vulnerable_code_not_in_execute_path`
- `vulnerable_code_cannot_be_controlled_by_adversary`
- `inline_mitigations_already_exist`
- `code_not_present`
- `code_not_reachable`
- `requires_configuration`
- `requires_dependency`
- `requires_environment`
- `protected_by_compiler`
- `protected_at_runtime`
- `protected_at_perimeter`
- `protected_by_mitigating_control`

#### Possible values for `responses`

- `can_not_fix`
- `will_not_fix`
- `update`
- `rollback`
- `workaround_available`

---

## Filters and Helpers

In addition to [Jinja built-in filters](https://jinja.palletsprojects.com/en/3.1.x/templates/#list-of-builtin-filters), the following custom filters are available.

### Conversion

| Filter | Description |
|--------|-------------|
| `as_list` | Convert a dict to a list using `.values()`. |
| `limit(n)` | Limit the number of results to `n` (int). |
| `print_iso8601` | Transform an ISO 8601 duration string into a human-readable format (e.g. `P2DT4H` → `2d 4h`) or format a datetime string. |

### Status Filtering

| Filter | Description |
|--------|-------------|
| `status(x)` | Keep only vulnerabilities with status in `x` (str or list of str). |
| `status_pending` | Shorthand for `in_triage` + `under_investigation`. |
| `status_affected` | Shorthand for `affected` + `exploitable`. |
| `status_fixed` | Shorthand for `fixed` + `resolved` + `resolved_with_pedigree`. |
| `status_ignored` | Shorthand for `not_affected` + `false_positive`. |
| `status_active` | `status_pending` + `status_affected`. |
| `status_inactive` | `status_fixed` + `status_ignored`. |

### Score Filtering

| Filter | Description |
|--------|-------------|
| `severity(x)` | Keep only vulnerabilities with severity in `x` (str or list of str). |
| `epss_score(x)` | Keep only vulnerabilities with EPSS score ≥ `x`. `x` is a percentage in [0, 100]. |

### Date Filtering

Both `last_assessment_date` and `filter_by_publish_date` accept date expressions in the following formats:

| Format | Meaning |
|--------|---------|
| `'>2026-01-01'` | After this date (exclusive) |
| `'>=2026-01-01'` | After or on this date (inclusive) |
| `'<2026-01-01'` | Before this date (exclusive) |
| `'<=2026-01-01'` | Before or on this date (inclusive) |
| `'2026-01-01..2026-01-31'` | Between two dates (inclusive) |
| `'2026-01-01'` | Exact date match |

| Filter | Description |
|--------|-------------|
| `last_assessment_date(x)` | Filter vulnerabilities by their last assessment date. |
| `filter_by_publish_date(x, include_unknown=False)` | Filter by CVE publish date. Pass `include_unknown=True` to also include vulnerabilities with no known publish date. |

> **Note for `filter_by_publish_date`:** Exact date match ignores time (hours, minutes, seconds). When `include_unknown=True`, also includes vulnerabilities without a published date.

### Sorting

| Filter | Description |
|--------|-------------|
| `sort_by_epss` | Sort vulnerabilities by EPSS score, highest first. |
| `sort_by_effort` | Sort vulnerabilities by effort (`effort.likely`), most effort first. |
| `sort_by_last_modified` | Sort vulnerabilities by latest assessment date, most recent first. |

---

## Common Examples and Tips

**Get total count of active/open vulnerabilities:**
```
{{ vulnerabilities | as_list | status_active | length }}
```

**Get active vulnerability with highest EPSS score:**
```
{{ vulnerabilities | as_list | status_active | sort_by_epss | first }}
```

**Get vulnerabilities assessed after a specific date:**
```
{{ vulnerabilities | as_list | last_assessment_date('>2026-01-01') | length }}
```

**Get vulnerabilities assessed in January 2026:**
```
{{ vulnerabilities | as_list | last_assessment_date('2026-01-01..2026-01-31') }}
```

**Get critical vulnerabilities assessed recently (after or on 2026-01-15):**
```
{{ vulnerabilities | as_list | severity('critical') | last_assessment_date('>=2026-01-15') | sort_by_last_modified }}
```

**List all critical unresolved vulnerabilities, sorted by most recent assessment:**
```
{% for vuln in vulnerabilities | as_list | severity('critical') | status_active | sort_by_last_modified %}
- {{ vuln.id }} (CVSS: {{ vuln.severity.max_score }})
{% endfor %}
```

**Use an environment variable in a template:**
```
Product: {{ env("PRODUCT_NAME", "unknown") }}
Version: {{ env("PRODUCT_VERSION", "unknown") }}
```


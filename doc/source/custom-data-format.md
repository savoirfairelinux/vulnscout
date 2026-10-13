# VulnScout JSON format

VulnScout JSON transfers Review-page assessments, pending AI assessments,
custom CVSS values, and remediation time estimates between VulnScout
instances. The current export version is **2**. Version **1** remains supported
for importing existing backups.

The JSON Schemas are the machine-readable interchange contract:

- `tests/schemas/vulnscout/vulnscout-1.schema.json`
- `tests/schemas/vulnscout/vulnscout-2.schema.json`

Both schemas use JSON Schema draft 2020-12.

## Document structure

Every document is a JSON object with these fields:

| Field | Required | Description |
| --- | --- | --- |
| `version` | Yes | Format version. Use `1` or `2`. The legacy strings `"1"` and `"1.0"` are also accepted for version 1. |
| `exported_at` | No | RFC 3339 date-time at which the document was generated. |
| `assessments` | Yes | Human-approved custom assessment records. May be empty. |
| `ai_assessments` | No | AI assessment records awaiting human review. May be empty. |
| `cvss` | No | Custom CVSS records. May be empty. |
| `time_estimates` | No | Remediation time-estimate records. May be empty. |

Unknown fields are rejected. Extension fields whose names begin with `x-` are
allowed on the document and its records. VulnScout preserves record-level
`x-` fields when amending an existing Review export.

## Assessments

Assessment records in `assessments` and `ai_assessments` share the same shape.
They require:

| Field | Description |
| --- | --- |
| `vuln_id` | Non-empty vulnerability identifier, such as `CVE-2026-0001`. |
| `status` | A supported OpenVEX or CycloneDX VEX status. |
| `packages` | Non-empty array of package identifiers. |

Supported statuses are `under_investigation`, `not_affected`, `affected`,
`fixed`, `in_triage`, `false_positive`, `exploitable`, `resolved`, and
`resolved_with_pedigree`.

Package identifiers use `name@version` or `name@version::supplier`. A missing
version or supplier is represented by omitting that part.

The following fields are optional: `simplified_status`, `justification`,
`impact_statement`, `status_notes`, `workaround`, and `timestamp`. The four
free-text assessment fields may be strings or `null`. `timestamp`, when
present, is an RFC 3339 date-time.

### Version 1 targeting

Version 1 assigns the complete `packages` array to one variant. Each assessment
must contain at least one non-empty variant identifier:

- `variant_id`: the source instance's variant UUID or a resolvable variant
  token.
- `variant`: the human-readable variant name.

When several packages are listed, importing the record creates one independent
assessment per package. Version 1 has no `targets` field.

```json
{
  "version": 1,
  "assessments": [
    {
      "vuln_id": "CVE-2026-0001",
      "status": "not_affected",
      "justification": "component_not_present",
      "packages": ["openssl@3.0.0"],
      "variant": "default"
    }
  ]
}
```

### Version 2 targeting

Version 2 uses portable target pairs and does not permit `variant_id`.
Assessment-level `variant` is also forbidden. Each assessment requires a
non-empty `targets` array whose entries contain:

| Field | Description |
| --- | --- |
| `variant` | Non-empty destination variant name. |
| `package` | Non-empty package identifier observed for the vulnerability in that variant. |

`packages` remains a required summary of the packages covered by the record;
`targets` is authoritative for variant-to-package relationships. One version 2
record imports as one assessment containing all successfully resolved targets.

```json
{
  "version": 2,
  "exported_at": "2026-09-22T12:00:00+00:00",
  "assessments": [
    {
      "vuln_id": "CVE-2026-0002",
      "status": "affected",
      "packages": ["openssl@3.0.0", "zlib@1.3.1"],
      "targets": [
        {"variant": "default", "package": "openssl@3.0.0"},
        {"variant": "production", "package": "zlib@1.3.1"}
      ]
    }
  ],
  "ai_assessments": [],
  "cvss": [],
  "time_estimates": []
}
```

On import, every version 2 target must resolve to an existing variant, package,
and observed vulnerability finding. VulnScout reports unresolved targets
instead of creating packages or findings implicitly.

## CVSS records

Each `cvss` record requires `vuln_id`, `version`, `vector_string`, and
`base_score`. Scores range from 0 through 10. Optional fields are
`exploitability_score`, `impact_score`, `author`, and `origin`.

Version 1 records may identify scope with `variant_id` and/or `variant`.
Version 2 records may use only `variant`, containing a non-empty variant name
or `null`. A missing or `null` variant applies the value to variants where the
vulnerability is observed.

## Time-estimate records

Each `time_estimates` record requires `vuln_id`, `optimistic`, `likely`, and
`pessimistic`. Estimate values are ISO 8601 durations such as `PT4H`.

Variant scope follows the same version rules as CVSS records: version 1 permits
`variant_id` and `variant`, while version 2 permits only a variant name or
`null` in `variant`.

## Validation

The repository validation target checks both valid and intentionally invalid
examples against each schema, alongside CycloneDX, SPDX, and OpenVEX exports:

```console
cqfd -b validate_sbom
```

To validate one document directly, select the schema matching its `version`:

```console
tests/schemas/.npm/node_modules/.bin/ajv validate \
  -c ajv-formats --strict=false --spec=draft2020 \
  -s tests/schemas/vulnscout/vulnscout-2.schema.json \
  -d custom_vulnscout_data_all.json
```

The Review page and CLI reject unsupported future versions rather than
silently interpreting them as the current format.
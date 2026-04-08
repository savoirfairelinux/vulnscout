# Writing Match Conditions

Evaluate and enforce conditions on vulnerabilities within a project.

## Synopsis

```
./vulnscout --match-condition [CONDITION]
```

## Description

The `vulnscout` command can optionally accept a `--match-condition CONDITION` argument that causes the command to exit with code **2** if the specified condition is met by any vulnerability found in the project.

The `CONDITION` is a boolean expression that is evaluated against each vulnerability identified. If the condition is met, the IDs of the matching vulnerabilities are displayed in the output. The command returns an exit code of **2** if at least one vulnerability meets the condition.

Match conditions can be combined with input files in a single invocation:

```bash
./vulnscout --project demo \
  --add-spdx /path/to/sbom.spdx.json \
  --add-cve-check /path/to/cve-check.json \
    --match-condition "((cvss >= 9.0 or (cvss >= 7.0 and epss >= 30%)) and (pending == true or affected == true))"
```

If the `CONDITION` is invalid, the configuration is not found, or an error occurs during the process, the command returns an exit code of **1**. This allows users to differentiate between a configuration error and a condition match.

## Exit Status

| Code | Meaning |
|------|---------|
| `0` | Success — no vulnerability matched the condition. |
| `1` | Execution error — invalid condition syntax, configuration error, or scan failure. |
| `2` | Condition triggered — at least one vulnerability matched the condition. |

## Examples

```sh
./vulnscout --project demo --match-condition "cvss >= 7.0"
```

This example will cause the command to exit with code **2** if any vulnerability with a CVSS score of 7.0 or higher is found.

---

## Global Syntax and Language Definition

The full language definition can be found in `src/controllers/conditions_parser.py`. The following keywords are recognized:

- `true`, `false`
- `and`, `or`, `not`
- `>`, `>=`, `<`, `<=`, `==`, `!=`
- `0`, `5`, `2.3`, `-1`, `.42`, `25%` are recognized as numbers. Percentages are divided by 100 internally.
- `(` ... `)` are used to group expressions.

Any condition is always expressed as `<left token> <operator> <right token>`.

**Example:** `cvss >= 5 or ignored == true`

> **Note:** `true` alone is not a valid expression, but `true == true` is.

Any unrecognised token is treated as a string identifier. String tokens can start with `[a-zA-Z_]` and contain `[a-zA-Z0-9_-:]`.

---

## Tokens

The following tokens are evaluated per vulnerability:

| Token | Type | Description |
|-------|------|-------------|
| `id` | string | The CVE / vulnerability ID (e.g. `CVE-2021-44228`). |
| `cvss` | number | The maximum CVSS score of the vulnerability. Generally between 0 and 10. |
| `cvss_min` | number | The minimum CVSS score of the vulnerability. Generally between 0 and 10. |
| `epss` | number | The EPSS score of the vulnerability (0–1). Use `%` notation for percentages, e.g. `epss >= 50%`. |
| `effort` | number / boolean | The "most likely" estimation of time needed to fix the vulnerability. Expressed in seconds. Evaluates to `false` when no estimate is set. |
| `effort_min` | number | The "optimistic" estimation of time needed to fix the vulnerability. Expressed in seconds. |
| `effort_max` | number | The "pessimistic" estimation of time needed to fix the vulnerability. Expressed in seconds. |
| `fixed` | boolean | Whether the vulnerability status is fixed. |
| `ignored` | boolean | Whether the vulnerability status is ignored / not_affected. |
| `affected` | boolean | Whether the vulnerability is affecting the project. |
| `pending` | boolean | Whether the vulnerability has not yet been reviewed (status is pending). |
| `new` | boolean | Whether the vulnerability was not present in the previous scan. |

Any other token will be treated as a string. Strings are not quoted, can start with `[a-zA-Z]` or an underscore `_`, and can contain `[a-zA-Z0-9_-:]`.

---

## Common Examples and Tips

**Fail if any vulnerability is critical:**
```
cvss >= 9.0
```

**Fail if any vulnerability is critical or has both high CVSS and EPSS scores:**
```
cvss >= 9.0 or (cvss >= 7.0 and epss >= 50%)
```

**Fail if any vulnerability was not reviewed by a human yet:**
```
pending == true
```

**Fail if there are important vulnerabilities not fixed or ignored:**
```
cvss >= 7.0 and (not fixed == true and not ignored == true)
```

Or more concisely:
```
cvss >= 7 and fixed == false and ignored == false
```

**Fail if a vulnerability with affected status doesn't have an effort set already:**
```
affected == true and effort == false
```

**Fail if a high vulnerability is affecting the product and needs less than an hour to fix:**
```
cvss >= 7.0 and affected == true and effort < 3600
```

**Fail if Log4j is found:**
```
id == CVE-2021-44228
```

**Fail if any new (previously unseen) vulnerability is critical:**
```
new == true and cvss >= 9.0
```

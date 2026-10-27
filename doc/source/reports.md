# Report Generation

Reports are generated from templates. VulnScout ships with built-in templates and also supports custom ones.
Use `-p` to select the report scope; when omitted, the `default` project is used. A project report includes all its variants. Add `-v` to restrict the report to one variant in that project. Unknown project or variant names exit with **code 1** instead of broadening the report scope.

```bash
# Generate a report from a built-in template
./vulnscout report -p demo summary.adoc

# Generate a report for one variant only
./vulnscout report -p demo -v x86 summary.adoc

# Generate a match-condition report
./vulnscout report -p demo match_condition.adoc --condition "cvss >= 9.0"

# Pass a local template file path — stages and runs it in one step
./vulnscout report -p demo /path/to/my-custom-report.adoc

# Convert the output
./vulnscout report -p demo summary.adoc --format pdf
```

`--condition` fills the report's list of matching vulnerabilities. A match does not fail `report`; use `match-condition` to fail a CI job. `--format pdf` or `--format html` overrides the format implied by the template extension.

Multiple reports can be generated in one command:

```bash
./vulnscout report -p demo summary.adoc all_assessments.adoc
```

Reports are written to the outputs directory (default: `.vulnscout/outputs/`).

See the [Templates](templates.md) page for documentation on writing custom report templates.

# Share

Choose an output for its consumer: reports communicate analysis to people,
SBOMs exchange software composition and associated vulnerability data, and VEX
communicates vulnerability assessment status.

**Result:** scoped artifacts for review, product delivery, or downstream tools.
Check the selected variants and format before generating them.

```{toctree}
:maxdepth: 1

reports
exports
cli-assessments
```

Use [Writing Report Templates](templates.md) to customize reports. In the web
interface, use [Export](web-export.md) for reports and SBOM/VEX documents, or
[Review import and export](web-review.md#import-and-export) to transfer analyst
data.

Pending AI suggestions are excluded from exported VEX until approved. VulnScout
JSON assessment-exchange files can carry pending suggestions for review; that
does not make them official assessments.

For CI, create required artifacts before the final policy check as described in
[Enforce](workflow-enforce.md). Return to [Import](workflow-import.md) for a new
build, or [Enrich](workflow-enrich.md) when advisory data changes without a
new SBOM.

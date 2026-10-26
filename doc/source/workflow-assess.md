# Assess

Investigate whether each finding affects the actual product build, configuration,
and deployment. Record a supported status, justification, impact, and rationale
for the exact variant/package targets.

**Result:** auditable product assessments. Keep unresolved findings under
investigation; accepting risk or assigning a low remediation priority does not
justify **Not affected**.

1. Find candidates in [Metrics](web-metrics.md) and the
   [Vulnerability Table](web-vulnerabilities.md), then inspect advisories,
   affected packages, and product evidence.
2. Use [Vulnerability Details](web-vulnerability-details.md#assessments) to
   create or edit an assessment. Follow the
   [assessment status guidance](interactive-mode.md#assessment-status-in-vulnscout).
3. Optionally use [AI Assessments](ai-assessments.md) to propose assessments or
   request independent reviews of custom assessments. Proposed AI assessments
   remain pending until a human approves them; an independent review does not
   change the underlying assessment.
4. Audit recorded decisions in [Review](web-review.md). Reassess when product
   context or source evidence changes rather than blindly carrying an old
   conclusion forward.

Continue with [Enforce](workflow-enforce.md) to evaluate CI policy or
[Share](workflow-share.md) to communicate the results.

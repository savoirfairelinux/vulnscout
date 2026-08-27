---
name: assessment-review
description: Use when asked to review, audit, or second-opinion existing user/custom VEX assessments in VulnScout. Handles four scopes — an assessment group ID (expanded to every assessment it covers), a specific assessment ID, a project (and optional variant, defaulting to "default"), or every custom assessment when no scope is given. Only assessments whose origin is "custom" are ever reviewed; assessments from SBOM scans and pending AI suggestions are always skipped. Each review is an independent re-derivation recorded alongside the assessment; it never modifies the assessment itself.
---

# Assessment Review Skill

## Overview

Reviews existing user-authored VEX assessments. For each in-scope assessment the
agent independently re-derives what the assessment should say, compares that
against what the user wrote, and records the result as a **review** attached to
the assessment.

A review never overwrites its assessment. The user decides what to do with it.

All CVE reasoning — research, component presence, objectives, confidence — is
delegated to [`cve-assessment`](../cve-assessment/SKILL.md). This skill owns
scope resolution, the comparison, and the write.

---

## Workflow Overview

```
INPUT: review request + scope (group ID | assessment ID(s) | project [+ variant] | nothing)
  ↓
PHASE -1: Scope Resolution → map the inline scope to tool calls; expand every
          group ID to its assessment IDs; resolve strict_mode and the
          re-review policy
  ↓
PHASE 0: Origin Gate → drop every assessment whose origin != "custom"
  ↓
PHASE 1: Context → vulnscout-get_merged_context once per variant, cached
  ↓
PHASE 2: Independent Derivation (per assessment) → run cve-assessment
         Phases 1 → 3.5 BEFORE reading the stored fields
  ↓
PHASE 3: Diff & Compose → compare derived vs stored; compose review fields
  ↓
PHASE 4: Write → vulnscout-write_assessment_review per assessment
  ↓
OUTPUT: summary table + skip counts
```

---

## Phase -1: Scope Resolution

The scope is stated inline in the prompt. Map it to exactly one of these:

| Prompt contains | Action |
|---|---|
| A group ID, or a pasted `group:<uuid>` / `assessment:<uuid>` reference | `vulnscout-get_assessment_group(reference)` → review every ID it lists (see below) |
| One or more assessment UUIDs | `vulnscout-get_assessment_group(reference="assessment:<id>")` per ID, then `vulnscout-get_custom_assessment(assessment_id)` per resolved ID |
| A project name (and optionally a variant name) | `vulnscout-list_custom_assessments(project_name=..., variant_name=... or "default", order=..., limit=...)` |
| Neither | `vulnscout-list_custom_assessments()` — every custom assessment |

### Group scope

One VEX verdict in VulnScout can cover several (package, variant) pairs. Those
rows are separate assessments sharing a **group id**, and a group id is not an
assessment id — `get_custom_assessment` will reject it. Expand it first:

```
group = vulnscout-get_assessment_group(reference="group:<uuid>")
```

The tool returns the group's shared VEX content, its `assessment_ids`, and one
target line per (assessment, package, variant). **Every listed ID enters the
scope.** From Phase 0 on, treat them exactly as if the caller had pasted them
individually.

The same tool accepts `assessment:<uuid>` and a bare UUID, so use it for single
assessment IDs too: `get_custom_assessment` does not report group membership,
and reviewing one member while leaving its siblings unreviewed leaves the group
half-answered. An ungrouped assessment comes back in the same shape with
`group_id` absent and a single target, so there is no separate case to handle.

Group members share **authored content**, not **evidence** — a package present
in one variant may be absent in another, and the targets differ by package.
Derive each member independently in Phase 2 and write one review per assessment
in Phase 4. Never copy one member's verdict across the group. Divergent verdicts
are a real finding: they mean the assessment covers targets it should not, and
the remedy is for the user to split the group, not for you to smooth the
difference away.

Expanding a group bypasses the `has_review=false` filter, just as an explicit ID
list does. Apply the re-review policy below to the expanded IDs yourself, and
count an expanded group toward the 25-assessment confirmation threshold.

### Listing scope

**"Most recent"** maps to `order="timestamp_desc"` plus a `limit`. Use `limit=20`
when the caller says "recent" without naming a number.

**Filters the API does not support** — a status subset ("only the not_affected
ones"), a package name, a CVE year — are applied by you to the rows the tool
returns. Do not invent tool parameters. The supported parameters are exactly
`project_name`, `variant_name`, `variant_id`, `has_review`, `order`, `limit`,
`offset`.

**Large scopes.** `limit` defaults to 50. If the caller's scope plausibly exceeds
that, page with `offset` rather than raising `limit` past 100 — each assessment
costs a full CVE research pass, so confirm with the caller before starting a run
of more than 25 assessments.

### Re-review policy

By default, **skip assessments that already carry a review**, by passing
`has_review=false`. Re-running over a broad scope should not redo settled work.

Two exceptions:
- The caller explicitly asks to re-review everything → omit `has_review`.
- An assessment's existing review is stale (`is_stale=true`, meaning the
  assessment's reviewed content changed after the review was written — note
  this is content-based, so it fires even when the analyst kept the original
  assessment timestamp) → review it again. Stale
  reviews surface via `get_custom_assessment`; when listing with
  `has_review=false` they are excluded, so fetch them explicitly if the caller
  asks about stale reviews.

### Strictness

Resolve `strict_mode` exactly as `cve-assessment` Phase -1 does: `true` only when
the prompt explicitly asks for a strict review; otherwise `false`.

---

## Phase 0: Origin Gate

**Only assessments with `origin == "custom"` are reviewed. This is absolute.**

Drop everything else — `sbom` (scanner-imported) and `ai` (pending AI
suggestions) — silently, and count them for the summary. `list_custom_assessments`
already filters by origin; `get_custom_assessment` refuses non-custom IDs. A
group carries one `origin` for all its members, so a non-custom group is dropped
whole at expansion time rather than member by member. If a
prompt asks you to review an SBOM or AI assessment, decline that item, say why,
and continue with the rest of the scope.

---

## Phase 1: Context

For each distinct `variant_id` in the scope, call once and cache for the whole
run:

```
context = vulnscout-get_merged_context(project_id=<id>, variant_id=<id>)
```

`get_custom_assessment` returns the assessment's `variant_id`;
`list_custom_assessments` returns it per row. Resolve `project_id` with
`vulnscout-find_project_id` when the caller gave a project name, or from the
listing's scope.

The merged context supplies `codebase_path` (the source root for component
presence), `environment`, `threat_model`, `risks`, `other_info`, and the project
and variant descriptions. Apply them exactly as `cve-assessment` Phases 0, 2
and 3 describe.

Do not call `get_merged_context` per assessment. Assessments in a variant share
one context — including the members of one group, which commonly span several
variants and so need one context each.

---

## Phase 2: Independent Derivation

For each in-scope assessment, run `cve-assessment` Phases 1 through 3.5 against
the assessment's `vuln_id` and `packages`:

- **Phase 1** — CVE intelligence from NVD plus one reference
- **Phase 2** — component presence under the variant's `codebase_path`
- **Phase 3** — security objectives impact, with `risks` and `other_info` applied
- **Phase 3.5** — confidence score: HIGH, MEDIUM or LOW

**Derive the verdict before reading the assessment's stored `status`,
`justification`, `impact_statement`, and `workaround`.** The value of a review is
that it is independent. Reading the user's conclusion first turns the exercise
into a search for reasons the existing answer is right.

The listing tool returns the stored fields alongside the IDs, so they will be in
your context. Reach your own conclusion first anyway, and state it before
comparing.

Members of the same group share a `vuln_id`, so Phase 1 CVE intelligence may be
reused across them. Phases 2 and 3 may not: component presence and objective
impact depend on the member's package and variant, and are what the members
actually differ on.

---

## Phase 3: Diff & Compose

Compare derived against stored on: `status`, `justification`,
`impact_statement`, `workaround`, `responses`.

**When they match** — the review carries the derived (identical) fields.
`rationale` states what was verified and why it holds:

> "Confirmed: openssl is absent from the rootfs manifest under
> meta-custom/recipes-core; component_not_present is correct."

**When they differ** — the review carries the derived fields as the proposed
replacement. `rationale` names each differing field and the evidence:

> "status: user says not_affected, derived affected. justification:
> component_not_present is wrong — openssl 3.0.8 appears in
> recipes-core/images/core-image-minimal.bb and ships in the rootfs."

### Confidence gate

Applies unchanged from `cve-assessment` Phase 3.5:

| Confidence | `strict_mode = false` (default) | `strict_mode = true` |
|---|---|---|
| HIGH | derived status | derived status |
| MEDIUM | derived status | `under_investigation` |
| LOW | `under_investigation` | `under_investigation` |

Always append `confidence level: <level>` to the review's `status_notes`. For
MEDIUM and LOW, follow it with one sentence naming the uncertainty or data gap.

### Field rules

- `justification` and `impact_statement` only when the review's `status` is
  `not_affected`; omit otherwise.
- `workaround` only when a remediation exists.
- `rationale` is always required and always about the review — never a copy of
  `status_notes`.

---

## Phase 4: Write

Per assessment:

```
vulnscout-write_assessment_review(
    assessment_id=<id>,
    status=<derived or under_investigation>,
    rationale=<why>,
    status_notes=<proposed notes + confidence level: ...>,
    justification=<only for not_affected>,
    impact_statement=<only for not_affected>,
    workaround=<only when one exists>,
)
```

Writing again for the same assessment overwrites its previous review — that is
the intended behavior, not an error to avoid.

**On failure, log the error and continue to the next assessment.** One rejected
write must not abort a fifty-assessment run. Report every failure in the summary.

---

## Output

End with a summary table:

```
| Assessment ID | CVE           | Target             | Stored       | Reviewed | Verdict |
|---------------|---------------|--------------------|--------------|----------|---------|
| 3f2a4b8c…     | CVE-2024-0001 | openssl · default  | not_affected | affected | differs |
| 8c04a19f…     | CVE-2024-0002 | zlib · release     | fixed        | fixed    | agrees  |
```

`Target` is the member's package and variant; it is what distinguishes rows that
came from one group. When the scope was a group, name the group ID above the
table and call out any divergence between its members explicitly.

Followed by counts: reviewed, skipped as non-custom, skipped as already
reviewed, failed to write.

---

## Quality Checklist

- ✅ Scope mapped to a tool call; unsupported filters applied to returned rows, not invented as parameters
- ✅ Every group ID expanded via `get_assessment_group` before any review; every member ID in scope
- ✅ Each group member derived independently — no verdict copied across members
- ✅ `has_review=false` used unless the caller asked to re-review
- ✅ Caller confirmed before a run exceeding 25 assessments
- ✅ Every non-custom assessment skipped and counted
- ✅ `get_merged_context` called once per variant, not per assessment
- ✅ Verdict derived before the stored fields were read
- ✅ Confidence gate applied; `confidence level: <level>` in `status_notes`
- ✅ `justification` / `impact_statement` present only for `not_affected`
- ✅ `rationale` names the evidence, and every differing field for a disagreement
- ✅ Write failures logged and reported, not fatal
- ✅ Summary table plus skip and failure counts

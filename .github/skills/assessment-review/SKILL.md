---
name: assessment-review
description: Use when asked to review, audit, or second-opinion existing user/custom VEX assessments in VulnScout. Handles three scopes — a specific assessment ID (which may cover several package/variant targets in one row), a project (and optional variant, defaulting to "default"), or every custom assessment when no scope is given. Only assessments whose origin is "custom" are ever reviewed; assessments from SBOM scans and pending AI suggestions are always skipped. Each review is an independent re-derivation recorded alongside the assessment, one per target; it never modifies the assessment itself.
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
INPUT: review request + scope (assessment ID(s) | project [+ variant] | nothing)
  ↓
PHASE -1: Scope Resolution → map the inline scope to tool calls; resolve
          strict_mode and the re-review policy
  ↓
PHASE 0: Origin Gate → drop every assessment whose origin != "custom"
  ↓
PHASE 1: Context → vulnscout-get_merged_context once per variant, cached
  ↓
PHASE 2: Independent Derivation (per assessment, per target) → run
         cve-assessment Phases 1 → 3.5 BEFORE reading the stored fields
  ↓
PHASE 3: Diff & Compose → compare each target's derived verdict against the
         assessment's stored fields; compose one review's worth of fields per target
  ↓
PHASE 4: Write → vulnscout-write_assessment_review per target
  ↓
OUTPUT: summary table + skip counts
```

---

## Phase -1: Scope Resolution

The scope is stated inline in the prompt. Map it to exactly one of these:

| Prompt contains | Action |
|---|---|
| One or more assessment UUIDs (bare, or an `assessment:<uuid>` reference) | `vulnscout-get_custom_assessment(assessment_id)` per ID |
| A project name (and optionally a variant name) | `vulnscout-list_custom_assessments(project_name=..., variant_name=... or "default", order=..., limit=...)` |
| Neither | `vulnscout-list_custom_assessments()` — every custom assessment |

### Multi-target assessments

One VEX verdict in VulnScout can cover several (package, variant) pairs, but
they no longer live as separate assessment rows: they are **targets** on a
single assessment (`assessment.targets`, each `{variant_id, package,
outdated}`). `vulnscout-get_custom_assessment` returns the whole assessment —
its stored verdict plus every target — in one call; there is nothing to expand.

Targets share **authored content** (the one stored verdict), not **evidence** —
a package present in one variant may be absent in another. Reviews are keyed
the same way targets are: derive each target independently in Phase 2, and
write one review per target in Phase 4 (`vulnscout-write_assessment_review`
takes the target's `variant_id`/`package` alongside the assessment id). Nothing
needs to be collapsed into a single verdict — if two targets derive
differently, each gets its own review saying so, and the assessment's stored
fields are diffed against each target's own derivation independently. Still
call out in the summary when an assessment's targets disagree; it may mean the
assessment itself should be split so each target can be authored on its own
evidence, but the review no longer forces that choice by picking one answer.

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

By default, **skip assessments where every target already carries a review**,
by passing `has_review=false`. Re-running over a broad scope should not redo
settled work. `has_review` on a listing row is true when *any* target has a
review — an assessment with two targets and only one reviewed still comes back
with `has_review=true`, so check `target_reviews` (each target's own
`has_review`/`is_stale`) before assuming every target is covered, and derive
the still-unreviewed targets normally.

Two exceptions:
- The caller explicitly asks to re-review everything → omit `has_review`.
- A target's existing review is stale (`is_stale=true` on that target's entry,
  meaning the assessment's reviewed content changed after the review was
  written — note this is content-based, so it fires even when the analyst kept
  the original assessment timestamp) → review that target again. Stale
  reviews surface via `get_custom_assessment`; when listing with
  `has_review=false` an assessment with only stale targets left may be
  excluded if another of its targets is fresh, so fetch it explicitly if the
  caller asks about stale reviews.

### Strictness

Resolve `strict_mode` exactly as `cve-assessment` Phase -1 does: `true` only when
the prompt explicitly asks for a strict review; otherwise `false`.

---

## Phase 0: Origin Gate

**Only assessments with `origin == "custom"` are reviewed. This is absolute.**

Drop everything else — `sbom` (scanner-imported) and `ai` (pending AI
suggestions) — silently, and count them for the summary. `list_custom_assessments`
already filters by origin; `get_custom_assessment` refuses non-custom IDs. An
assessment has one `origin` for all of its targets, so a non-custom assessment
is dropped whole, not target by target. If a prompt asks you to review an SBOM
or AI assessment, decline that item, say why, and continue with the rest of the
scope.

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
one context — including the targets of one multi-target assessment, which
commonly span several variants and so need one context each.

---

## Phase 2: Independent Derivation

For each in-scope assessment, run `cve-assessment` Phase 1 once against its
`vuln_id`, then run Phases 2 through 3.5 once per **target**
(`assessment.targets`: each a `{variant_id, package}` pair) before reading the
assessment's stored fields:

- **Phase 1** — CVE intelligence from NVD plus one reference (once per assessment;
  `vuln_id` is fixed for the whole assessment, so this is not repeated per target)
- **Phase 2** — component presence under the target's variant `codebase_path`
- **Phase 3** — security objectives impact, with that variant's `risks` and
  `other_info` applied
- **Phase 3.5** — confidence score: HIGH, MEDIUM or LOW

**Derive each target's verdict before reading the assessment's stored `status`,
`justification`, `impact_statement`, and `workaround`.** The value of a review is
that it is independent. Reading the user's conclusion first turns the exercise
into a search for reasons the existing answer is right.

The listing tool returns the stored fields alongside the ID, so they will be in
your context. Reach your own conclusion first anyway, and state it before
comparing.

A multi-target assessment may derive differently per target — component
presence and objective impact depend on the target's package and variant —
and that is fine: each target's derivation becomes that target's own review in
Phase 4, independent of the others.

---

## Phase 3: Diff & Compose

Each target gets its own comparison: diff that target's Phase 2 derivation
against the assessment's stored fields on `status`, `justification`,
`impact_statement`, `workaround`, `responses`. A multi-target assessment whose
targets derive differently simply produces differing reviews — call that out
in the summary (Output) as a sign the assessment may be worth splitting, but
do not merge the targets' verdicts into one before writing.

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

Per target:

```
vulnscout-write_assessment_review(
    assessment_id=<id>,
    variant_id=<the target's variant_id>,
    package=<the target's package>,
    status=<derived or under_investigation>,
    rationale=<why>,
    status_notes=<proposed notes + confidence level: ...>,
    justification=<only for not_affected>,
    impact_statement=<only for not_affected>,
    workaround=<only when one exists>,
)
```

Writing again for the same target overwrites its previous review — that is the
intended behavior, not an error to avoid. A different target on the same
assessment gets its own review row and is never touched by writing another
target's.

**On failure, log the error and continue to the next target.** One rejected
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

`Target` is the assessment's package and variant. A multi-target assessment
gets one summary row per target, each carrying its own review and verdict;
call out explicitly when an assessment's targets disagree, and note that
splitting the assessment is worth considering in that case.

Followed by counts: reviewed, skipped as non-custom, skipped as already
reviewed, failed to write.

---

## Quality Checklist

- ✅ Scope mapped to a tool call; unsupported filters applied to returned rows, not invented as parameters
- ✅ Every target on a multi-target assessment derived and written independently — no verdict copied across targets
- ✅ Divergent per-target verdicts left as separate reviews, with the disagreement and a split recommendation called out in the summary
- ✅ `has_review=false` used unless the caller asked to re-review; per-target `target_reviews` checked rather than assuming the assessment-level flag means every target is covered
- ✅ Caller confirmed before a run exceeding 25 assessments
- ✅ Every non-custom assessment skipped and counted
- ✅ `get_merged_context` called once per variant, not per assessment
- ✅ Verdict derived before the stored fields were read
- ✅ Confidence gate applied; `confidence level: <level>` in `status_notes`
- ✅ `justification` / `impact_statement` present only for `not_affected`
- ✅ `rationale` names the evidence, and every differing field for a disagreement
- ✅ Write failures logged and reported, not fatal
- ✅ Summary table plus skip and failure counts

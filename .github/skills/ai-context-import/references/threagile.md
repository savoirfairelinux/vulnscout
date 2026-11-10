# Threagile → AI Context mapping

Reference for the [`ai-context-import`](../SKILL.md) skill. Field names and
values were checked against the Threagile source (`github.com/Threagile/threagile`,
commit `74e323e`, 2026-04-08: `pkg/types`, `pkg/risks/builtin`, `pkg/report`).
Older or newer releases may differ. When a value is not listed here, quote it as
is and add `[confirm: ...]`.

## Inputs and precedence

| File | Holds | Use for |
|---|---|---|
| `threagile.yaml` (any name; the model input) | `title`, `business_overview`, `technical_overview`, `data_assets`, `technical_assets` with nested `communication_links`, `trust_boundaries`, `shared_runtimes`, `individual_risk_categories`, `risk_tracking`, `security_requirements`, `abuse_cases`, `questions` | System text, Components, Interactions, custom risk categories, risk tracking |
| `risks.json` | One object per identified risk: `category`, `risk_status`, `severity`, `exploitation_likelihood`, `exploitation_impact`, `title`, `synthetic_id`, `most_relevant_technical_asset`, `most_relevant_communication_link`, `most_relevant_trust_boundary`, `most_relevant_shared_runtime`, `most_relevant_data_asset`, `data_breach_technical_assets` | Threats and Risks |
| `technical-assets.json` | Technical assets with their attributes | Components, when the YAML is missing |
| `report.pdf` | Everything above, rendered | Fallback for all of the above; risk-tracking justifications; STRIDE of custom categories |
| `risks.xlsx`, `tags.xlsx`, `stats.json`, `*.png` | Derived views | Ignore unless nothing else is available |

When several are present, use the YAML for the model, `risks.json` for the
identified risks, and the PDF only to fill gaps. If they disagree (for example
the PDF is older), say so in the summary and prefer the newest file.

### `report.pdf` chapters

Relevant chapters: "Management Summary", "Application Overview",
"Asset Register", "Identified Risks by Vulnerability category",
"Identified Risks by Technical Asset", "Trust Boundaries", "Shared Runtimes",
"STRIDE Classification of Identified Risks", "Risk Mitigation",
"Out-of-Scope Assets", "Security Requirements", "Abuse Cases" and "Questions".

**Do not import from "Risk Rules Checked by Threagile".** It lists every rule
with a "STRIDE:" line, including rules that found nothing. Import only risks
listed as identified.

Where to find things in the PDF (the layout varies between releases):

- **Category sections** (under "Identified Risks by Vulnerability category"):
  the category description, often with its STRIDE value and CWE, plus impact,
  false-positive guidance, a recommended mitigation and a check question. Each
  identified risk below lists its title, likelihood and impact, `synthetic_id`
  and tracking status.
- **Technical asset sections**: the asset description and attributes, plus the
  outgoing and incoming communication links with their attributes. The
  technical asset sections include out-of-scope assets.
- **Data asset sections**: the description and CIA rating of each data asset.
- **"Trust Boundaries" and "Shared Runtimes"**: the assets inside and any
  nested boundaries.
- **"Potential Model Failures"** (when present): categories that flag gaps in
  the model, not threats to the system. List them under **Not imported**.

## Identifiers

- Technical assets, data assets and trust boundaries are referenced by their `id`.
  Use the YAML key (the title) as the human name.
- A communication link ID is `<source-asset-id>><link-title>`: the title is
  lower-cased and every run of non-alphanumeric characters becomes `-`. For
  example, link `Customer Traffic` on `customer-client` is
  `customer-client>customer-traffic`.
- A risk `synthetic_id` is `<category>@<ids...>`, for example
  `unencrypted-communication@<link-id>@<source-id>@<target-id>`. `risk_tracking`
  keys use the same form, and `*` is a wildcard between `@` characters.
- Risk `title` values contain HTML (`<b>…</b>`); strip the tags.

## System tab

| Threagile | AI Context field |
|---|---|
| `title`, `business_overview`, `technical_overview`, `business_criticality`; `data_assets` (title, description, confidentiality/integrity/availability) | **System scope and assets**: one line per data asset with its CIA ratings |
| Assets with `used_as_client_by_human: true`, `type: external-entity`, or `out_of_scope: true` with an `owner`; link `authentication` and `authorization` | **Actors and access** |
| Assets with `internet: true`; links whose source is outside the target's trust boundary; `data_formats_accepted` | **Entry points and data flows** |
| `trust_boundaries` (title, `type`, `technical_assets_inside`, `trust_boundaries_nested`); `shared_runtimes` | **Trust boundaries**: one line per boundary, for example `Web DMZ (network-cloud-security-group): Apache Webserver, Marketing CMS` |

### Components (one per technical asset)

- **Name**: the asset title.
- **Description / role**: the asset `description`. Add `type`, `technology`,
  `machine`, `size` and `usage`, the data assets it processes and stores (by
  title), and `custom_developed_parts: true` when set. For an out-of-scope asset,
  add `Out of scope: <justification_out_of_scope>`.
- **Trust zone**: the title of the innermost trust boundary whose
  `technical_assets_inside` lists the asset. If no boundary lists it, use
  `Internet` when `internet: true`, otherwise `No trust boundary`.

Keep out-of-scope assets that are an endpoint of a link, so their interactions
can be modelled. List other out-of-scope assets only in **Actors and access** or
under **Not imported**.

### Interactions (one per communication link)

- **Name**: the link title.
- **Source**: the asset that declares the link. **Destination**: its `target`.
- **Interface / protocol**: `protocol`, then `authentication` and
  `authorization`, then any of `vpn`, `ip_filtered` and `readonly` that are true.
  For example: `https; auth: session-id; authz: end-user-identity-propagation`.
  Then append the link `description` when it adds details such as ports or
  configuration.
- **Data / commands**: `sent: <data asset titles>; received: <data asset titles>`
  from `data_assets_sent` and `data_assets_received`.
- **Trust boundary**: `<source boundary> → <target boundary>` when the two
  endpoints' trust zones differ; otherwise leave it empty.

## Threat model tab

### STRIDE category of each risk category

Custom categories (`individual_risk_categories`) carry their own `stride` value:
`spoofing`, `tampering`, `repudiation`, `information-disclosure`,
`denial-of-service` or `elevation-of-privilege`. These map to the options of the
same name. Built-in categories map as follows:

| STRIDE category | Threagile risk category IDs |
|---|---|
| **Spoofing** | `cross-site-request-forgery`, `missing-file-validation`, `missing-identity-store`, `service-registry-poisoning` |
| **Tampering** | `code-backdooring`, `container-baseimage-backdooring`, `cross-site-scripting`, `ldap-injection`, `missing-build-infrastructure`, `missing-cloud-hardening`, `missing-hardening`, `missing-waf`, `push-instead-of-pull-deployment`, `search-query-injection`, `sql-nosql-injection`, `unchecked-deployment`, `untrusted-deserialization` |
| **Information disclosure** | `accidental-secret-leak`, `incomplete-model`, `missing-vault`, `path-traversal`, `server-side-request-forgery`, `unencrypted-asset`, `unencrypted-communication`, `wrong-communication-link-content`, `xml-external-entity` |
| **Denial of service** | `dos-risky-access-across-trust-boundary` |
| **Elevation of privilege** | `container-platform-escape`, `missing-authentication`, `missing-authentication-second-factor`, `missing-identity-propagation`, `missing-identity-provider-isolation`, `missing-network-segmentation`, `missing-vault-isolation`, `mixed-targets-on-shared-runtime`, `unguarded-access-from-internet`, `unguarded-direct-datastore-access`, `unnecessary-communication-link`, `unnecessary-data-asset`, `unnecessary-data-transfer`, `unnecessary-technical-asset`, `wrong-trust-boundary-content` |

No built-in category maps to **Repudiation**. For a category that is neither
listed nor in the YAML (for example a custom category when only the PDF is
available), use the report chapter "STRIDE Classification of Identified Risks",
which groups identified categories under the six STRIDE headings. If the category
is not there either, list the risk under **Not imported**.

### Targets

Tick these, in order of preference:

1. The interaction for `most_relevant_communication_link`.
2. The component for `most_relevant_technical_asset`.
3. For a risk with only `most_relevant_trust_boundary` or
   `most_relevant_shared_runtime`: the components inside that boundary or runtime.
   Name the boundary in the threat description.

If the target is not modelled (for example an asset you skipped), list the risk
under **Not imported**.

### Rows

- **Few risks (about 30 or fewer, after dropping false positives):** one threat
  per risk. **Description**: the stripped `title`, then
  `(Source: risks.json <synthetic_id>)` or the report page.
- **More risks:** one threat per risk category, ticking every affected target.
  **Description**: the category title, a summary of the category description
  (custom categories describe this system, so keep more of their text), the
  affected instances, and the source. When the document gives false-positive
  guidance for a generic category, include it.

## Risks tab

One risk per threat (or, when grouping, one per distinct likelihood, impact and
status within a category). Tick the threat(s) it covers.

| Threagile | AI Context |
|---|---|
| `exploitation_likelihood`: `unlikely` / `likely` / `very-likely` / `frequent` | **Likelihood**: **Low** / **Medium** / **High** / **High** |
| `exploitation_impact`: `low` / `medium` / `high` / `very-high` | **Impact**: **Low** / **Medium** / **High** / **High** |
| `severity` (`low`, `medium`, `elevated`, `high`, `critical`) and the original likelihood and impact | Keep them in **Description**, for example `Severity critical (Threagile: very-likely / very-high)` |

Write the mapping used once in the summary, because `very-likely`/`frequent`
and `high`/`very-high` collapse into one level each.

### Status (`risk_status`, or the matching `risk_tracking` entry)

Read `justification`, `ticket`, `date` and `checked_by` from the `risk_tracking`
entry whose key matches the `synthetic_id` (wildcards allowed), or from the
risk's tracking line in the report chapter "Identified Risks by Vulnerability
category". With no tracking entry, the status is `unchecked`.

| Status | Mitigation | Residual risk / decision |
|---|---|---|
| `mitigated` | the justification | `Mitigated (<ticket>, <date>, checked by <checked_by>)` |
| `in-progress` | empty: the control is not in place yet | `Reduce: mitigation in progress — <justification> (<ticket>)` |
| `accepted` | empty, unless the justification names an existing control | `Accepted: <justification> (<ticket>, <date>)` |
| `in-discussion` | empty | `[confirm: in discussion in Threagile] <justification>` |
| `unchecked` | empty | `[confirm: not yet reviewed in Threagile]` |
| `false-positive` | do not import | list under **Not imported** with the justification |

Category-level mitigation advice in the report ("Mitigation:" in the category
section) is a recommendation, not a control in place. Never copy it into
**Mitigation**; mention it at most in **Residual risk / decision** as
`Recommended: …`, optionally followed by the category's "Check" question.

## Context tab

Threagile has no dedicated fields for this tab. Use only what applies:

- **Environment**: hosting facts that are stated, such as `machine` types, cloud
  or on-premises boundary `type`s, and internet-facing assets.
- **Other information**: `management_summary_comment`,
  `security_requirements`, `abuse_cases`, unanswered `questions` (prefix them
  with `[confirm: open question]`), and the model `title`, `date`, `author` and
  version as a document reference.
- **Variant description**: only when the model names the specific build,
  board or image; otherwise leave it out.

# VulnScout Skills

The built-in VulnScout Agent loads `cve-assessment` for assess actions and
`vulnscout assess`, and `assessment-review` for review actions. Changes here
affect both the built-in Agent and external clients.

## SBOM Dependencies and Lifecycle Skill

[`sbom-dependencies/SKILL.md`](./sbom-dependencies/SKILL.md) answers questions such
as “Which libraries does demo use on this board?” and “Are any SBOM packages EOL
or candidates for LTS?”. It discovers active variant-scoped SBOM packages and
traverses direct/transitive dependencies through the MCP server. Lifecycle
analysis requires dated upstream/vendor evidence and distinguishes unknowns,
downstream backports and SBOM declarations from actual runtime usage.

Copy or symlink `sbom-dependencies/` into the same agent skills folder described
below. Invoke it with the project and board/variant names; no package or
assessment changes are made.

## Vulnerability Assessment Skill

An AI agent skill for assessing the impact of a CVE (or GHSA advisory) on a software
project, and submitting the resulting assessment to
VulnScout via [VulnScout MCP](https://github.com/savoirfairelinux/vulnscout-mcp).

## What it does

Given a CVE/GHSA ID and optional project/deployment context, the skill guides an AI
agent through a structured workflow:

1. **Research** the vulnerability from public sources (NVD, GitHub Security Advisories)
2. **Analyze** whether the affected component is present in the target project, and at
   what version
3. **Assess** the impact against the project's defined security objectives, using each
   variant's STRIDE threat model and risks from VulnScout (reachability through entry
   points and trust boundaries, matching threats; declared mitigations count only
   when source or configuration evidence confirms them)
4. **Report** a status (`affected`, `fixed`, `not_affected`, or `under_investigation`)
   with a concise justification
5. **Submit** the assessment via the `vulnscout-write_assessment` MCP tool

## Installation

Copy or symlink the `cve-assessment/` directory into your AI agent's skills folder. You may need to restart the agent so it picks up the new skill:

```bash
# GitHub Copilot CLI
mkdir -p ~/.copilot/skills
cp -r cve-assessment ~/.copilot/skills/

# Claude Code
mkdir -p ~/.claude/skills
cp -r cve-assessment ~/.claude/skills/
```

The skill is invoked automatically when its `description` (in
[`cve-assessment/SKILL.md`](./cve-assessment/SKILL.md) frontmatter) matches the
context of your request, e.g. asking the agent to assess a CVE's impact on a project.

## Usage

This repository is intended to be used as an agent skill (e.g. with GitHub Copilot or
Claude). See [`cve-assessment/SKILL.md`](./cve-assessment/SKILL.md) for the full
workflow definition, [`cve-assessment/objectives/`](./cve-assessment/objectives/) for
how to define project-specific security objectives, and
[`cve-assessment/report-templates/`](./cve-assessment/report-templates/) for the
per-status report field guides.

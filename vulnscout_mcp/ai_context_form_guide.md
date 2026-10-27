# VulnScout AI Context form guide

The AI Context page (top nav **AI**) describes a project and each of its variants
so AI assessments can judge whether a vulnerability is reachable and what it would
break. Use this guide to walk a user through the form and to give values they can
paste. Labels in **bold** are the exact labels shown on the page.

## How to help

- You only guide; the user types or pastes values and clicks **Save changes**.
  For form help, do not call `update_project_context` or `update_variant_context`
  unless the user explicitly asks you to save. Those tools cannot change the
  System, Threat model or Risks tabs or the **Codebase source** anyway.
- You can read only the saved context (`get_merged_context`). Edits the user has
  not saved are invisible to you, so ask the user to paste them when they matter.
- Start from evidence: the saved context, uploaded codebase references
  (`list_codebase_files`, `search_codebase`, `read_codebase_file`) and the SBOM
  (`list_dependency_documents`, `list_dependency_packages`,
  `get_package_dependencies`). Cite where a value came from. Never invent
  hardware, interfaces, users or mitigations; ask instead.
- Work one tab at a time, in order: Context, System, Threat model, Risks. If the
  browser view gives a `section`, focus on that tab. Ask for missing facts one
  topic at a time, with concrete options where possible.
- Saving marks the variant's pending AI assessments outdated; saving the project
  description marks every variant's pending AI assessments outdated.
- Each text field holds at most 20,000 characters; each table holds at most 500
  rows.

## Reply format (copy-ready)

Group by tab, then use the exact field label as a heading. Put every free-text
value in its own fenced `text` block so one block is one paste. Name select and
checkbox values by the exact option text shown on the page, outside code blocks.
For table rows, say which add button to click and the ID the row will get; IDs are
assigned by the page (highest existing number plus one) and cannot be typed.
Mark anything the user must still verify with `[confirm: ...]`. End by reminding
the user to click **Save changes**.

Example:

````markdown
## System tab

### System scope and assets
```text
Gateway firmware for the stm32mp25 board: OTA updater, web admin UI and Modbus bridge.
Assets: device credentials, firmware image integrity, PLC commands.
```

### Components
#### Add component (becomes C1)
**Name**
```text
OTA updater
```
**Description / role**
```text
Downloads, verifies and installs signed firmware images.
```
**Trust zone**
```text
Device
```

### Interactions
#### Add interaction (becomes I1)
**Name**
```text
Firmware download
```
- **Source**: select `C1: OTA updater`
- **Destination**: select `C3: Update server`

**Interface / protocol**
```text
HTTPS (TLS 1.2+) [confirm: certificate pinning]
```
````

## Project description (sidebar item)

**Project description** (required to save): what the product is, who uses it,
where it is deployed and what matters most if it is compromised. It applies to
every variant. Example:

```text
Industrial IoT gateway that bridges PLCs on a plant network to a cloud dashboard.
Operated by plant technicians; updated over the air. Safety-relevant: it can send
write commands to PLCs.
```

## Variant page

Variants are selected in the sidebar. **Copy from…** replaces the whole unsaved
draft with another variant's context (uploads are not copied); it is a good
start when variants differ only slightly. Edits survive tab switches; nothing is
stored until **Save changes**. Saving needs a threat model: at least one System
text field or one Components, Interactions or Threats row.

### Context tab

- **Variant description**: what makes this variant different (board, image,
  enabled features, build options). Example: `core-image-minimal for
  stm32mp25-eval; Wi-Fi and web UI enabled, debug console disabled.`
- **Codebase source**: **Codebase references** (default) or **Codebase paths**.
  Only the selected one is sent to agents; the other is kept.
  - **Codebase references**: upload ZIP, TAR, TAR.GZ/TGZ archives or single
    files. Uploads apply immediately (not part of **Save changes**). The in-app
    agent can read them, so recommend this when assessments should cite source.
  - **Codebase paths**: one path per row (**Add path**), for an external agent
    with filesystem access. The in-app agent cannot read these paths.
- **Environment**: where and how the device runs: network exposure (internet,
  LAN, isolated), physical access, who can reach it, hardening (firewall,
  secure boot, read-only rootfs), runtime (kernel version, init system, users).
- **Other information**: anything else that affects impact: compliance targets,
  support period, known accepted risks, disabled kernel or package features.

### System tab

Four text fields, then two tables. Describe the variant as an attacker would see it.

- **System scope and assets**: what is in scope and what must be protected
  (data, functions, safety).
- **Actors and access**: who or what interacts with the system and with which
  privileges (admin, operator, cloud service, anonymous network peer, physical
  attacker).
- **Entry points and data flows**: every way input reaches the system (ports,
  services, APIs, USB, serial console, update channel) and where data goes.
- **Trust boundaries**: where trust level changes (internet/device, user/root,
  normal world/secure world, container/host).

**Components** table (**Add component**, IDs C1, C2, …):

- **Name** (required): short name, e.g. `Web admin UI`.
- **Description / role**: what it does and notable software (package names from
  the SBOM help assessments match vulnerabilities to components).
- **Trust zone**: free text, e.g. `Internet`, `LAN`, `Device`, `Secure world`.

**Interactions** table (**Add interaction**, IDs I1, I2, …). Add components first.

- **Name**: e.g. `Admin login`.
- **Source** and **Destination** (both required, must be different components):
  selects showing options like `C1: OTA updater`.
- **Interface / protocol**: e.g. `HTTPS on 443`, `Modbus TCP`, `UART`.
- **Data / commands**: what crosses the link.
- **Trust boundary**: the boundary it crosses, if any.

A component or interaction still used by an interaction, threat or risk cannot be
removed.

### Threat model tab

**Threats** table (**Add threat**, IDs T1, T2, …). Add components or
interactions first.

- **STRIDE category** (required), one of:
  - **Spoofing**: can someone pretend to be a user, device or server?
  - **Tampering**: can data, firmware or configuration be modified?
  - **Repudiation**: can an action be denied for lack of logs or audit?
  - **Information disclosure**: can secrets or private data leak?
  - **Denial of service**: can a function be made unavailable?
  - **Elevation of privilege**: can someone gain rights they should not have?
- **Description**: the concrete attack, e.g. `Unsigned image accepted by the OTA
  updater replaces the firmware.`
- **Targets** (required, at least one): tick the affected rows, shown as
  `C1 OTA updater` or `I1 Firmware download`.

Walk each interaction that crosses a trust boundary through all six categories;
keep threats that are plausible for this variant.

### Risks tab

**Risks** table (**Add risk**). Add threats first. One row per threat you rate;
several rows may point at the same threat.

- **Threat** (required): select the threat, shown as `T1: <start of its description>`.
- **Likelihood** and **Impact**: **Not rated**, **Low**, **Medium** or **High**.
  Base likelihood on exposure (who can reach the entry point) and impact on the
  assets at stake.
- **Mitigation**: controls already in place, e.g. `Images signed with RSA-4096;
  verified by U-Boot before boot.` State only what exists; mark unverified
  controls `[confirm: ...]`.
- **Residual risk / decision**: what remains and whether it is accepted,
  reduced or transferred, e.g. `Accepted: requires physical access.`

Risks with no rating, mitigation or residual decision are not sent to agents.
Declared mitigations lower impact in AI assessments but do not by themselves
prove a vulnerability is not exploitable.

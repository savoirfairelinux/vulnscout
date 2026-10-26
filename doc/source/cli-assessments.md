# Exporting and Importing Custom Assessments

VulnScout lets you export and re-import the assessments you have manually created through the web interface (review / triage decisions). This is useful for:

- Backing up your review work before re-importing SBOMs.
- Sharing assessment decisions across different VulnScout instances.
- Restoring triage state in CI pipelines after a database reset.

## VulnScout JSON

`export custom-data` exports custom assessments, pending AI
assessments, CVSS scores, and time estimates as one VulnScout JSON file. It
includes every variant in the selected project unless `-v` is provided.
After import, pending AI assessments are available from the Review page's **AI
Assessments** tab for approval or rejection.

```bash
./vulnscout -p demo export custom-data
```

Export one variant:

```bash
./vulnscout -p demo -v x86 export custom-data
```

Add `--amend` to reconcile current review data with the existing file in the
output directory:

```bash
./vulnscout -p demo export custom-data --amend
```

`import custom-data` restores entries according to the variant metadata stored in the file, so it rejects `-v`. Imported assessments use the current system time by default. Add `--timestamps original` to preserve assessment timestamps from the file; `--timestamps current` selects the default explicitly.

Current version 2 exports identify targets with variant names and packages,
not instance-local variant UUIDs. Legacy version 1 files remain importable;
unsupported future versions are rejected explicitly.

```bash
./vulnscout -p demo import custom-data /path/to/custom_vulnscout_data_all.json

./vulnscout -p demo import custom-data /path/to/custom_vulnscout_data_all.json --timestamps original
```

## OpenVEX

OpenVEX products carry no variant identity, so each document belongs to one
variant. With `-v`, `export custom-openvex` writes `custom_openvex_<variant>.json`;
without it, it writes one such file per project variant that has custom
assessments, and removes the file of a variant that no longer has any. `import
custom-openvex` imports into `-v`, or into the project's only variant when `-v`
is omitted. If the project has several variants, it exits with code 1 and lists
them; import each per-variant file with its own `-v`. Export fails, writing nothing,
when two variant names map to the same file name; export them one at a time with `-v`.

```bash
# Export a variant
./vulnscout -p demo -v x86 export custom-openvex

# Export every variant of the project
./vulnscout -p demo export custom-openvex

# Import into a variant
./vulnscout -p demo -v x86 import custom-openvex /path/to/custom_openvex_x86.json

# Ignore OpenVEX statement timestamps and use the current system time
./vulnscout -p demo -v x86 import custom-openvex /path/to/custom_openvex_x86.json --timestamps current
```

OpenVEX imports preserve statement timestamps by default. Add
`--timestamps current` to use the current system time, or
`--timestamps original` to select the default explicitly.

## Project and Variant Context

`export context` writes the AI context of the selected scope to
`context-export.json`. `import context` restores it:

```bash
./vulnscout -p demo export context

# Import into the projects and variants named in the file
./vulnscout import context /path/to/context-export.json

# Import every entry into project "staging", keeping variant names
./vulnscout -p staging import context /path/to/context-export.json

# Import a single-entry file into one variant
./vulnscout -p staging -v x86 import context /path/to/context-export.json
```

With `-p`, the file must name a single project. With `-p` and `-v`, it must
hold exactly one entry. `-v` without `-p` is rejected.
Create the target project and variants first, for example by importing their
SBOMs. Context import does not create them: unmatched entries are ignored, and
retargeting requires an existing destination. Imported context overwrites the
matching scope's existing context. The file format and its validation rules are
described in the [API reference](api.md).

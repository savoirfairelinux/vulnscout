# Exporting SBOM Files

VulnScout can export the enriched project data as standard SBOM formats. Exported files are written to the outputs directory (default: `.vulnscout/outputs/`).

```bash
# Export as SPDX 3.0 SBOM
./vulnscout export -p demo spdx

# Export as CycloneDX 1.6 SBOM
./vulnscout export -p demo cdx

# Export as OpenVEX document (vulnerabilities + assessments)
./vulnscout export -p demo openvex
```

One `export` call can write several formats:

```bash
./vulnscout export -p demo spdx cdx openvex
```

## Recorded files in SPDX exports

SPDX 2.3 (JSON/XML) and SPDX 3.0 JSON-LD exports include file records persisted
from the selected **active** SBOM scans, including companion documents and binary
outputs. Superseded scans and unselected variants are excluded. Export does not
reopen original SBOMs or source files. Paths and checksums are emitted only when
recorded: no contents are exported and no hashes are calculated or invented.

SPDX 2.3's schema requires a nonempty checksum list for a native `File`; the
normative file validator additionally requires SHA1 and a relative file path.
Only recorded files satisfying these requirements are emitted as native SPDX 2
file objects. Other records (including hashless records, SHA256-only records,
and absolute paths) are retained in a standard document `OTHER` annotation
whose comment begins `VulnScout recorded inventory v1:`. Its JSON payload stores
the recorded file properties and associated package references. These private
file identifiers are not referenced by native document relationships.
This keeps the document valid without inventing hashes or changing paths.
Other tools may ignore the annotation; VulnScout restores all its records with
either parser mode. SPDX 3 supports native hashless file records.

Each persisted file record has its own document-local identifier. Different
records with the same path remain distinct; a shared record is emitted once,
with associations to each supported package owner. SPDX 3 uses `contains`.
SPDX 2 uses labelled `OTHER` relationships rather than asserting package
file analysis (`filesAnalyzed` remains false); associations to annotation-only
records stay inside that annotation. Recorded SPDX 2
checksums and SPDX 3 hashes are translated when their algorithms are supported.
Native file types, licenses, and other supported properties are retained in the
matching format; properties without a native equivalent are retained in the
labelled comment metadata.

Both formats use a `VulnScout recorded file evidence v1:` JSON comment to
preserve supported original metadata and recorded file-level build observations
(type, parameters, outputs, and compilation-proof flag). Reimport distinguishes
**Listed only**, non-compilation build inputs, and proven compilation without
inventing a Build graph or compiler flags. Other tools may ignore this comment.
The original producer's build IDs and output references are historical evidence,
not references to reconstructed exported builds. These comments are not a full
build graph: build topology, lifecycle relationships, intermediate ownership,
and source-inventory completeness cannot be represented by this export.
Consequently, a reimport conservatively disables compiled-source CVE refinement
even when individual files retain compilation evidence. Reimport the original
companion SBOMs to restore complete build evidence and refinement.

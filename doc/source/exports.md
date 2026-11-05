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
absolute paths, and licenses referencing definitions or external documents
unavailable in the export) are retained in a standard document `OTHER` annotation
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
SPDX 3 Hash references are resolved during import within the scan (blank-node
identifiers remain document-local) and persisted as self-contained integrity
metadata, so export does not depend on the original graph. Unresolved references
from older imports are retained only in the evidence comment, not emitted as
dangling native integrity references.
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

## Compiler metadata and dependency nature

SBOM exports use the selected active source documents, not package-global or
superseded observations. A project export includes the active documents of all
its variants; a variant export excludes observations from other variants even
when the package names and versions match. The original input files need not
remain on disk.

SPDX 2.3 JSON/XML preserves native dependency relationship types, including
`BUILD_DEPENDENCY_OF`, `RUNTIME_DEPENDENCY_OF`, development, test, optional, and
provided dependencies. These inverse relationships point from the dependency
to its dependent. SPDX 3 emits `LifecycleScopedRelationship` for explicit
lifecycle scopes and preserves `hasPrerequisite`. Optional/provided
relationships use `hasOptionalDependency`/`hasProvidedDependency`. Generic
dependencies remain unscoped; an unqualified dependency is not assumed to be
a runtime dependency. Imported `dependencyOf` declarations are normalized to
the standard SPDX 3 `dependsOn` direction.

SPDX 3 also emits labelled compiler-metadata `build_Build` observations, with
`build_parameter` dictionary entries (`compile:flags:<language>` and
`compile:defines:<language>`) and associated package outputs. Flags and defines
remain raw strings: quoting, ordering, repeated entries, empty values, and
language/target distinctions are preserved. No input edges or intermediate
build graph are inferred from these observations.

All SBOM formats additionally carry a versioned portable JSON evidence payload:

| Output | Evidence location | Intentional native limitations |
| --- | --- | --- |
| SPDX 2.3 JSON/XML | Document `OTHER` annotation starting `VulnScout SBOM evidence v1:` | Compiler targets and declarations without an exact SPDX 2 equivalent use the annotation. |
| SPDX 3 JSON-LD | `SpdxDocument.comment` starting `VulnScout SBOM evidence v1:` | Original declaration spellings and source-document provenance remain in the comment alongside native relationships/build observations. |
| CycloneDX 1.4/1.5/1.6 JSON | `metadata.properties`, name `vulnscout:sbom-evidence:v1` | The native dependency graph has no per-edge lifecycle qualifier. Recorded files and their build observations are carried in the property rather than presented as software package components. |

The payload preserves dependency declarations (including original relationship
type, lifecycle scope, and evidence source), compiler targets with original
document identity, and remapped package associations. CycloneDX additionally
stores the same recorded file metadata, hashes, associations, and conservative
compilation observations described above. VulnScout restores this evidence on
reimport in either parser mode, including across repeated export/import cycles.
Original document/build identifiers inside evidence are historical labels, not
live references in the new SBOM. Other tools may ignore private annotations,
comments, and properties; cross-format conversion by such tools can lose them.
No export claims to preserve the complete build graph or source completeness.
OpenVEX is a vulnerability/assessment format, not a file or build inventory;
these additions do not change its output.

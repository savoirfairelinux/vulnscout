# Exporting SBOM Files

VulnScout can export the enriched project data as standard SBOM formats. Exported files are written to the outputs directory (default: `.vulnscout/outputs/`).

```bash
# Export as SPDX 3.0 SBOM
./vulnscout -p demo export spdx

# Export as CycloneDX 1.6 SBOM
./vulnscout -p demo export cdx

# Export as OpenVEX document (vulnerabilities + assessments)
./vulnscout -p demo export openvex
```

One `export` call can write several formats:

```bash
./vulnscout -p demo export spdx cdx openvex
```

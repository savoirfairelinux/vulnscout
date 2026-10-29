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

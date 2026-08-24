import type { RefreshType } from "../handlers/activeScanQueue";

export type RefreshMode = "complete" | "custom";

export const vulnerabilityRefreshSources: ReadonlyArray<{ source: RefreshType; label: string }> = [
    { source: "nvd", label: "NVD" },
    { source: "epss", label: "EPSS" },
    { source: "ghsa", label: "GHSA" },
    { source: "euvd", label: "ENISA EUVD" },
];

export const allVulnerabilityRefreshTypes = new Set<RefreshType>(
    vulnerabilityRefreshSources.map(({ source }) => source),
);

export function resolveRefreshSources(
    mode: RefreshMode,
    customSources: ReadonlySet<RefreshType>,
    availableSources: ReadonlySet<RefreshType> = allVulnerabilityRefreshTypes,
): Set<RefreshType> {
    const requestedSources = mode === "complete" ? availableSources : customSources;
    return new Set([...requestedSources].filter(source => availableSources.has(source)));
}

// Refresh sources that can be applied to the vulnerabilities a given set of scans produces.
export function refreshSourcesForScans(selectedScans: Set<string>): Set<RefreshType> {
    const sources = new Set<RefreshType>();
    // OSV persists every CVE-* alias of each record, so it yields CVEs with no NVD data yet.
    if (selectedScans.has("grype") || selectedScans.has("osv")) sources.add("nvd");
    if (selectedScans.has("grype") || selectedScans.has("nvd") || selectedScans.has("scc") || selectedScans.has("osv")) {
        sources.add("epss");
        sources.add("euvd");
    }
    return sources;
}

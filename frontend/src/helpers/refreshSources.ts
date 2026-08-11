import type { RefreshType } from "../handlers/activeScanQueue";

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

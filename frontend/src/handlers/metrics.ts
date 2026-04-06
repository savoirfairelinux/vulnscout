import { asStringArray } from "./assessments";
import type { Assessment } from "./assessments";
import type { Vulnerability, CVSS } from "./vulnerabilities";

const STATUS_VEX_TO_GRAPH: Record<string, string> = {
    under_investigation: "Pending Assessment",
    in_triage: "Pending Assessment",
    false_positive: "Not affected",
    not_affected: "Not affected",
    exploitable: "Exploitable",
    affected: "Exploitable",
    resolved: "Fixed",
    fixed: "Fixed",
    resolved_with_pedigree: "Fixed",
};

// ---------------------------------------------------------------------------
// Types for /api/metrics response
// ---------------------------------------------------------------------------

type MetricsEvolution = {
    labels: string[];
    data: number[];
};

type MetricsSource = {
    labels: string[];
    data: number[];
};

type TopPackageEntry = {
    id: number;
    name: string;
    version: string;
    count: number;
};

type TopVulnEntry = {
    rank: number;
    cve: string;
    package: string;
    severity: string;
    max_cvss: number;
    texts: Record<string, string>;
    original: Vulnerability;
};

export type MetricsData = {
    vuln_by_severity: number[];   // [Unknown, Low, Medium, High, Critical]
    vuln_by_status: number[];     // [Not affected, Fixed, Pending Assessment, Exploitable]
    vuln_evolution: MetricsEvolution;
    vuln_by_source: MetricsSource;
    top_packages: TopPackageEntry[];
    top_vulns: TopVulnEntry[];
};

export type { TopPackageEntry, TopVulnEntry };

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

function _asAssessmentFromVuln(data: any): Assessment {
    const sstat = data?.simplified_status
        || (STATUS_VEX_TO_GRAPH[data?.status ?? ''] ?? `[invalid] ${data?.status ?? ''}`);
    return {
        id: data?.id ?? "",
        vuln_id: data?.vuln_id ?? "",
        packages: asStringArray(data?.packages),
        variant_id: data?.variant_id ?? undefined,
        status: data?.status ?? "",
        simplified_status: sstat,
        status_notes: data?.status_notes ?? undefined,
        justification: data?.justification ?? undefined,
        impact_statement: data?.impact_statement ?? undefined,
        workaround: data?.workaround ?? undefined,
        timestamp: data?.timestamp ?? "",
        last_update: data?.last_update ?? undefined,
        responses: asStringArray(data?.responses),
    };
}

function _asVulnerabilityFromMetrics(data: any): Vulnerability | null {
    if (typeof data !== "object" || typeof data?.id !== "string") return null;
    const cvss: CVSS[] = Array.isArray(data?.severity?.cvss)
        ? data.severity.cvss.flatMap((c: any) => {
            if (typeof c?.base_score !== "number") return [];
            return [{
                author: c.author ?? "unknown",
                severity: c.severity ?? "unknown",
                version: c.version ?? "",
                vector_string: c.vector_string ?? "",
                base_score: Number(c.base_score),
                exploitability_score: Number(c.exploitability_score ?? 0),
                impact_score: Number(c.impact_score ?? 0),
            } satisfies CVSS];
          })
        : [];

    const assessments: Assessment[] = Array.isArray(data?.assessments)
        ? data.assessments.map(_asAssessmentFromVuln)
        : [];

    // Derive status/simplified_status from assessment list
    const sorted = [...assessments].sort(
        (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );
    const latest = sorted.at(-1);

    return {
        id: data.id,
        aliases: asStringArray(data?.aliases),
        related_vulnerabilities: asStringArray(data?.related_vulnerabilities),
        namespace: data?.namespace ?? "unknown",
        found_by: asStringArray(data?.found_by),
        datasource: data?.datasource ?? "unknown",
        packages: asStringArray(data?.packages),
        packages_current: asStringArray(data?.packages_current),
        variants: asStringArray(data?.variants),
        urls: asStringArray(data?.urls),
        published: typeof data?.published === "string" ? data.published : undefined,
        first_scan_date: typeof data?.first_scan_date === "string" ? data.first_scan_date : undefined,
        texts: typeof data?.texts === "object"
            ? Object.entries(data.texts).flatMap(([key, value]) =>
                typeof value === "string" ? [{ title: key, content: value }] : []
              )
            : [],
        severity: {
            severity: data?.severity?.severity ?? "unknown",
            min_score: Number(data?.severity?.min_score ?? 0),
            max_score: Number(data?.severity?.max_score ?? 0),
            cvss,
        },
        epss: {
            score: isNaN(Number(data?.epss?.score)) ? undefined : Number(data?.epss?.score),
            percentile: isNaN(Number(data?.epss?.percentile)) ? undefined : Number(data?.epss?.percentile),
        },
        effort: {
            optimistic: data?.effort?.optimistic as any,
            likely: data?.effort?.likely as any,
            pessimistic: data?.effort?.pessimistic as any,
        },
        fix: { state: data?.fix?.state ?? "unknown" },
        status: latest?.status ?? "unknown",
        simplified_status: latest?.simplified_status ?? data?.simplified_status ?? "unknown",
        assessments,
    };
}

function _asTopVuln(data: any): TopVulnEntry | null {
    if (typeof data !== "object") return null;
    const original = _asVulnerabilityFromMetrics(data?.vuln);
    if (!original) return null;
    return {
        rank: Number(data.rank ?? 0),
        cve: String(data.cve ?? ""),
        package: String(data.package ?? ""),
        severity: String(data.severity ?? "unknown"),
        max_cvss: Number(data.max_cvss ?? 0),
        texts: typeof data.texts === "object" ? data.texts : {},
        original,
    };
}

function _parseMetrics(data: any): MetricsData {
    const safeInts = (arr: any, len: number): number[] => {
        if (!Array.isArray(arr) || arr.length !== len) return new Array(len).fill(0);
        return arr.map(Number);
    };

    return {
        vuln_by_severity: safeInts(data?.vuln_by_severity, 5),
        vuln_by_status: safeInts(data?.vuln_by_status, 4),
        vuln_evolution: {
            labels: asStringArray(data?.vuln_evolution?.labels),
            data: Array.isArray(data?.vuln_evolution?.data)
                ? data.vuln_evolution.data.map(Number)
                : [],
        },
        vuln_by_source: {
            labels: asStringArray(data?.vuln_by_source?.labels),
            data: Array.isArray(data?.vuln_by_source?.data)
                ? data.vuln_by_source.data.map(Number)
                : [],
        },
        top_packages: Array.isArray(data?.top_packages)
            ? data.top_packages.map((p: any) => ({
                id: Number(p.id ?? 0),
                name: String(p.name ?? ""),
                version: String(p.version ?? "-"),
                count: Number(p.count ?? 0),
              }))
            : [],
        top_vulns: Array.isArray(data?.top_vulns)
            ? data.top_vulns.flatMap((v: any) => {
                const entry = _asTopVuln(v);
                return entry ? [entry] : [];
              })
            : [],
    };
}

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

class MetricsHandler {
    static async fetch(
        variantId?: string,
        projectId?: string,
        timeScale?: string,
    ): Promise<MetricsData> {
        const url = new URL(
            import.meta.env.VITE_API_URL + "/api/metrics",
            window.location.href,
        );
        if (variantId) url.searchParams.set("variant_id", variantId);
        else if (projectId) url.searchParams.set("project_id", projectId);
        if (timeScale) url.searchParams.set("time_scale", timeScale);

        const response = await fetch(url.toString(), { mode: "cors" });
        if (!response.ok) {
            throw new Error(`/api/metrics returned ${response.status}`);
        }
        const data = await response.json();
        return _parseMetrics(data);
    }
}

export default MetricsHandler;

import type { Assessment } from "./assessments";
import { asStringArray } from "./assessments";
import Iso8601Duration from "./iso8601duration";
import { Cvss2, Cvss3P0, Cvss3P1, Cvss4P0 } from 'ae-cvss-calculator';

type CVSS = {
    author: string;
    origin?: string;
    variant_id?: string;
    severity: string;
    version: string;
    vector_string: string;
    attack_vector?: string;
    base_score: number;
    exploitability_score: number;
    impact_score: number;
};

type StatusSummary = {
    counts: Record<string, number>;
    ordered: { status: string; count: number }[];
    total_assessments: number;
    dominant_status: string;
    has_active_status: boolean;
};

type Vulnerability = {
    id: string;
    aliases: string[];
    related_vulnerabilities: string[];
    namespace: string;
    found_by: string[];
    datasource: string;
    packages: string[];
    packages_current: string[];
    variants: string[];
    urls: string[];
    published?: string;
    data_fetched_at?: string;
    data_updated_at?: string;
    first_scan_date?: string;
    texts: {
        title: string;
        content: string;
        packages?: string[];
    }[];
    severity: {
        severity: string;
        min_score: number;
        max_score: number;
        cvss: CVSS[];
    };
    epss: {
        score: number | undefined;
        percentile: number | undefined;
    };
    effort: {
        optimistic: Iso8601Duration;
        likely: Iso8601Duration;
        pessimistic: Iso8601Duration;
    };
    fix: {
        state: string;
    };
    euvd?: {
        id: string | null;
        known_exploited: boolean;
        sources: string[];
        date_added: string | null;
        url: string | null;
    };
    simplified_status: string;
    status_summary?: StatusSummary;
    assessments: Assessment[];
};

export type { Vulnerability, CVSS };

const SEVERITY_ORDER = ['NONE', 'UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const STATUS_SORT_ORDER = ['unknown', 'Pending Assessment', 'Exploitable', 'Not affected', 'Fixed'];
const STATUS_DOMINANT_PRIORITY = ['Exploitable', 'Pending Assessment', 'Not affected', 'Fixed', 'unknown'];

const getStatusSortIndex = (status: string): number => {
    const index = STATUS_SORT_ORDER.indexOf(status);
    return index === -1 ? STATUS_SORT_ORDER.length : index;
}

const getStatusDominantIndex = (status: string): number => {
    const index = STATUS_DOMINANT_PRIORITY.indexOf(status);
    return index === -1 ? STATUS_DOMINANT_PRIORITY.length : index;
}

const isActiveStatus = (status: string): boolean => {
    return status !== 'Fixed' && status !== 'Not affected' && status !== 'unknown';
}

const getStatusSummaryEntries = (counts: Record<string, number>): { status: string; count: number }[] => {
    return Object.entries(counts)
        .map(([status, count]) => ({ status, count }))
        .sort((a, b) => {
            const priorityDelta = getStatusDominantIndex(a.status) - getStatusDominantIndex(b.status);
            if (priorityDelta !== 0) return priorityDelta;
            if (b.count !== a.count) return b.count - a.count;
            return a.status.localeCompare(b.status);
        });
}

const buildStatusSummary = (assessments: Assessment[]): StatusSummary => {
    if (assessments.length === 0) {
        return {
            counts: { unknown: 1 },
            ordered: [{ status: 'unknown', count: 1 }],
            total_assessments: 0,
            dominant_status: 'unknown',
            has_active_status: false,
        };
    }

    // Group assessments by variant_id. Assessments without a variant_id are
    // grouped together under a single fallback key so they contribute one slot.
    const byVariant = new Map<string, Assessment[]>();
    assessments.forEach((assessment) => {
        const key = assessment.variant_id ?? '__no_variant__';
        if (!byVariant.has(key)) byVariant.set(key, []);
        byVariant.get(key)!.push(assessment);
    });

    // For each variant keep only the most recent assessment.
    const latestPerVariant: Assessment[] = [];
    byVariant.forEach((variantAssessments) => {
        const latest = variantAssessments.reduce((best, a) =>
            new Date(a.timestamp).getTime() > new Date(best.timestamp).getTime() ? a : best
        );
        latestPerVariant.push(latest);
    });

    // Count how many variants share each simplified status.
    const counts = latestPerVariant.reduce((acc, assessment) => {
        const simplified = assessment.simplified_status || 'unknown';
        acc[simplified] = (acc[simplified] || 0) + 1;
        return acc;
    }, {} as Record<string, number>);

    const ordered = getStatusSummaryEntries(counts);
    const dominant_status = ordered[0]?.status ?? 'unknown';
    return {
        counts,
        ordered,
        total_assessments: assessments.length,
        dominant_status,
        has_active_status: ordered.some((entry) => isActiveStatus(entry.status)),
    };
}

const buildFallbackStatusSummary = (simplified_status: string): StatusSummary => {
    const fallbackStatus = simplified_status || 'unknown';
    return {
        counts: { [fallbackStatus]: 1 },
        ordered: [{ status: fallbackStatus, count: 1 }],
        total_assessments: 0,
        dominant_status: fallbackStatus,
        has_active_status: isActiveStatus(fallbackStatus),
    };
}

const getVulnerabilityStatusSummary = (vulnerability: Pick<Vulnerability, 'status_summary' | 'simplified_status'>): StatusSummary => {
    return vulnerability.status_summary ?? buildFallbackStatusSummary(vulnerability.simplified_status);
}

const getTopStatusSummaryLabel = (summary: StatusSummary, maxItems = 2): string => {
    const top = summary.ordered.slice(0, maxItems).map((entry) => entry.status);
    const hiddenCount = summary.ordered.length - top.length;
    if (hiddenCount > 0) {
        top.push(`+${hiddenCount} more`);
    }
    return top.join(', ');
}

const isVulnerabilityActive = (vulnerability: Vulnerability): boolean => {
    return getVulnerabilityStatusSummary(vulnerability).has_active_status;
}

const asCVSS = (data: any): CVSS | [] => {
    if (typeof data !== "object") return [];
    if (typeof data?.version !== "string") return [];
    if (typeof data?.base_score !== "number") return [];
    let score: CVSS = {
        author: "unknown",
        origin: "scanner",
        variant_id: undefined,
        severity: "unknown",
        version: data.version,
        vector_string: "",
        attack_vector: undefined,
        base_score: Number(data.base_score),
        exploitability_score: 0,
        impact_score: 0,
    };
    if (typeof data?.author === "string") score.author = data.author
    if (typeof data?.origin === "string") score.origin = data.origin
    if (typeof data?.variant_id === "string") score.variant_id = data.variant_id
    if (typeof data?.severity === "string") score.severity = data.severity
    if (typeof data?.vector_string === "string") {
        score.vector_string = data.vector_string
        if (score.vector_string.includes("AV:N")) score.attack_vector = "NETWORK"
        if (score.vector_string.includes("AV:A")) score.attack_vector = "ADJACENT"
        if (score.vector_string.includes("AV:L")) score.attack_vector = "LOCAL"
        if (score.vector_string.includes("AV:P")) score.attack_vector = "PHYSICAL"
    }
    if (typeof data?.exploitability_score === "number") score.exploitability_score = Number(data.exploitability_score)
    if (typeof data?.impact_score === "number") score.impact_score = Number(data.impact_score)
    return score
}

const asVulnerability = (data: any): Vulnerability | [] => {
    if (typeof data !== "object") return [];
    if (typeof data?.id !== "string") return [];
    let vuln: Vulnerability = {
        id: data.id,
        aliases: asStringArray(data?.aliases),
        related_vulnerabilities: asStringArray(data?.related_vulnerabilities),
        namespace: "unknown",
        found_by: asStringArray(data?.found_by),
        datasource: "unknown",
        packages: asStringArray(data?.packages),
        packages_current: asStringArray(data?.packages_current),
        variants: asStringArray(data?.variants),
        urls: asStringArray(data?.urls),
        texts: [],
        severity: {
            severity: "unknown",
            min_score: 0,
            max_score: 0,
            cvss: [],
        },
        epss: {
            score: undefined,
            percentile: undefined,
        },
        effort: {
            optimistic: new Iso8601Duration("P0D"),
            likely: new Iso8601Duration("P0D"),
            pessimistic: new Iso8601Duration("P0D"),
        },
        fix: {
            state: "unknown",
        },
        simplified_status: 'unknown',
        assessments: [],
    };
    if (typeof data?.namespace === "string") vuln.namespace = data.namespace
    if (typeof data?.datasource === "string") vuln.datasource = data.datasource
    if (Array.isArray(data?.texts)) vuln.texts = data.texts
    if (typeof data?.severity?.severity === "string") vuln.severity.severity = data.severity.severity
    if (typeof data?.severity?.min_score === "number") vuln.severity.min_score = Number(data.severity.min_score)
    if (typeof data?.severity?.max_score === "number") vuln.severity.max_score = Number(data.severity.max_score)
    if (Array.isArray(data?.severity?.cvss)) vuln.severity.cvss = data.severity.cvss.flatMap(asCVSS)
    if (!isNaN(Number(data?.epss?.score))) vuln.epss.score = Number(data.epss.score)
    if (!isNaN(Number(data?.epss?.percentile))) vuln.epss.percentile = Number(data.epss.percentile)
    if (typeof data?.effort?.optimistic === "string") vuln.effort.optimistic = new Iso8601Duration(data.effort.optimistic)
    if (typeof data?.effort?.likely === "string") vuln.effort.likely = new Iso8601Duration(data.effort.likely)
    if (typeof data?.effort?.pessimistic === "string") vuln.effort.pessimistic = new Iso8601Duration(data.effort.pessimistic)
    if (typeof data?.fix?.state === "string") vuln.fix.state = data.fix.state
    if (typeof data?.published === "string") vuln.published = data.published
    if (typeof data?.data_fetched_at === "string") vuln.data_fetched_at = data.data_fetched_at
    if (typeof data?.data_updated_at === "string") vuln.data_updated_at = data.data_updated_at
    if (typeof data?.first_scan_date === "string") vuln.first_scan_date = data.first_scan_date
    if (data?.euvd && typeof data.euvd === "object") {
        vuln.euvd = {
            id: typeof data.euvd.id === "string" ? data.euvd.id : null,
            known_exploited: Boolean(data.euvd.known_exploited),
            sources: asStringArray(data.euvd.sources),
            date_added: typeof data.euvd.date_added === "string" ? data.euvd.date_added : null,
            url: typeof data.euvd.url === "string" ? data.euvd.url : null,
        }
    }
    return vuln
}

class Vulnerabilities {
    static async list(variantId?: string, projectId?: string, compareVariantId?: string, operation?: string, variantIds?: string[], multiOperation?: string): Promise<Vulnerability[]> {
        const url = new URL(import.meta.env.VITE_API_URL + "/api/vulnerabilities", window.location.href);
        url.searchParams.set('format', 'list');
        if (variantId && compareVariantId) {
            url.searchParams.set('variant_id', variantId);
            url.searchParams.set('compare_variant_id', compareVariantId);
            if (operation) url.searchParams.set('operation', operation);
        } else if (variantIds && variantIds.length >= 2) {
            url.searchParams.set('variant_ids', variantIds.join(','));
            if (multiOperation) url.searchParams.set('operation', multiOperation);
            if (projectId) url.searchParams.set('project_id', projectId);
        } else if (variantId) {
            url.searchParams.set('variant_id', variantId);
        } else if (projectId) {
            url.searchParams.set('project_id', projectId);
        }
        const response = await fetch(url.toString(), {
            mode: "cors",
        });
        const data = await response.json();
        return data.flatMap(asVulnerability);
    }

    // Re-fetch a single vulnerability in the given (project) scope and return
    // its CVSS list. Used after saving a custom score in all-variants mode,
    // where the PATCH response is variant-scoped and cannot populate the union
    // gauges. Returns null when the request fails or the payload is invalid.
    static async fetchScopedCvss(vulnId: string, projectId?: string): Promise<CVSS[] | null> {
        const url = new URL(
            import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(vulnId)}`,
            window.location.href,
        );
        if (projectId) url.searchParams.set('project_id', projectId);
        const response = await fetch(url.toString(), { mode: 'cors' });
        if (!response.ok) return null;
        const refreshedVuln = asVulnerability(await response.json());
        if (!Array.isArray(refreshedVuln) && Array.isArray(refreshedVuln.severity?.cvss)) {
            return refreshedVuln.severity.cvss;
        }
        return null;
    }

    static enrich_with_assessments(vulns: Vulnerability[], assessments: Assessment[]): Vulnerability[] {
        const assessments_per_vuln = assessments.reduce((acc, assessment: Assessment) => {
            if (!acc[assessment.vuln_id]) {
                acc[assessment.vuln_id] = [];
            }
            acc[assessment.vuln_id].push(assessment);
            return acc;
        }, {} as {[key: string]: Assessment[]});

        return vulns.map((vuln) => {
            if (!assessments_per_vuln[vuln.id] || assessments_per_vuln[vuln.id].length < 1) {
                return {
                    ...vuln,
                    simplified_status: 'unknown',
                    status_summary: buildStatusSummary([]),
                    assessments: [],
                };
            }

            assessments_per_vuln[vuln.id].sort((a, b) => {
                return new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
            });
            const vulnAssessments = assessments_per_vuln[vuln.id];
            const statusSummary = buildStatusSummary(vulnAssessments);
            return {
                ...vuln,
                simplified_status: statusSummary.dominant_status,
                status_summary: statusSummary,
                assessments: vulnAssessments,
            };
        });
    }

    static append_assessment(vulns: Vulnerability[], assessment: Assessment): Vulnerability[] {
        return vulns.map((vuln) => {
            if (vuln.id === assessment.vuln_id) {
                const assessments = [...vuln.assessments, assessment].sort((a, b) => {
                    return new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
                });
                const statusSummary = buildStatusSummary(assessments);
                return {
                    ...vuln,
                    simplified_status: statusSummary.dominant_status,
                    status_summary: statusSummary,
                    assessments,
                };
            }

            return vuln
        })
    }

    static append_cvss(vulns: Vulnerability[], vuln_id: string, cvss: CVSS): Vulnerability[] {
        return vulns.map((vuln) => {
            if (vuln.id === vuln_id) {
                return {
                    ...vuln,
                    severity: {
                        ...vuln.severity,
                        cvss: [...vuln.severity.cvss, cvss]
                    }
                };
            }
            return vuln;
        });
    }

    static calculate_cvss_from_vector(vector: string, author = "vulnscout"): CVSS | null {
        const sev = (s: number) =>
            s === 0 ? "NONE" :
            s < 4.0 ? "LOW" :
            s < 7.0 ? "MEDIUM" :
            s < 9.0 ? "HIGH" : "CRITICAL";

        const detectAttackVector = (vec: string) =>
            vec.includes("AV:N") ? "NETWORK" :
            vec.includes("AV:A") ? "ADJACENT" :
            vec.includes("AV:L") ? "LOCAL" :
            vec.includes("AV:P") ? "PHYSICAL" : undefined;

        try {
            let cv: any, scores: any, version: string;

            if (vector.startsWith("CVSS:4.0")) {
                cv = new Cvss4P0(vector);
                scores = cv.calculateScores();
                version = "4.0";
            } else if (vector.startsWith("CVSS:3.1")) {
                cv = new Cvss3P1(vector);
                scores = cv.calculateScores(false);
                version = "3.1";
            } else if (vector.startsWith("CVSS:3.0")) {
                cv = new Cvss3P0(vector);
                scores = cv.calculateScores(false);
                version = "3.0";
            } else {
                cv = new Cvss2(vector);
                scores = cv.calculateScores();
                version = "2.0";
            }

            const base = Number(scores?.base ?? scores?.overall ?? 0);

            return {
                author,
                origin: "custom",
                severity: sev(base),
                version,
                vector_string: scores?.vector ?? vector,
                attack_vector: detectAttackVector(vector),
                base_score: base,
                exploitability_score: Number(scores?.exploitability ?? 0),
                impact_score: Number(scores?.impact ?? 0)
            };
        } catch (e) {
            // Suppress expected invalid vector errors (e.g., from tests providing malformed CVSS strings)
            if (!(e instanceof Error && e.message === 'invalid vector')) {

                console.error(e);
            }
            return null;
        }
    }



}


export default Vulnerabilities;
export {
    SEVERITY_ORDER,
    STATUS_SORT_ORDER,
    asVulnerability,
    asCVSS,
    buildStatusSummary,
    getStatusSortIndex,
    getTopStatusSummaryLabel,
    getVulnerabilityStatusSummary,
    isActiveStatus,
    isVulnerabilityActive,
};

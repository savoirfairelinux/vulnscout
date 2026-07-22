const STATUS_VEX_TO_GRAPH: { [key: string]: string } = {
    "under_investigation": "Pending Assessment",
    "in_triage": "Pending Assessment",
    "false_positive": "Not affected",
    "not_affected": "Not affected",
    "exploitable": "Exploitable",
    "affected": "Exploitable",
    "resolved": "Fixed",
    "fixed": "Fixed",
    "resolved_with_pedigree": "Fixed"
};

type VulnText = {
    title: string;
    content: string;
}

type Assessment = {
    id: string;
    vuln_id: string;
    packages: string[];
    variant_id?: string;
    origin: string;
    status: string;
    simplified_status: string;
    status_notes?: string;
    justification?: string;
    impact_statement?: string;
    workaround?: string;
    workaround_timestamp?: string;
    timestamp: string;
    last_update?: string;
    responses: string[];
    vuln_texts?: VulnText[];
    outdated?: boolean;
    superseded_by?: string[];
    stale_packages?: string[];
    superseded_map?: Record<string, string[]>;
    details_loaded?: boolean;
};

export type { Assessment };

type ReviewTimeEstimate = {
    vuln_id: string;
    variant_id?: string;
    optimistic: number;
    likely: number;
    pessimistic: number;
    optimistic_iso: string;
    likely_iso: string;
    pessimistic_iso: string;
    vuln_texts?: VulnText[];
};

type ReviewCustomCvss = {
    vuln_id: string;
    variant_id?: string;
    version: string;
    vector_string: string;
    base_score: number;
    author: string;
    origin?: string;
    vuln_texts?: VulnText[];
};

export type { ReviewTimeEstimate, ReviewCustomCvss };

const asStringArray = (data: any): string[] => {
    if (!Array.isArray(data)) return [];
    return data.filter((item: any) => typeof item === "string");
}

const asAssessment = (data: any): Assessment | [] => {
    if (Array.isArray(data)) {
        const [id, vuln_id, packageId, variant_id, timestamp, status] = data;
        if (typeof id !== "string" || typeof vuln_id !== "string"
            || (packageId !== null && typeof packageId !== "string")
            || (variant_id !== null && typeof variant_id !== "string")
            || typeof timestamp !== "string" || typeof status !== "string") return [];
        data = {
            id,
            vuln_id,
            packages: packageId ? [packageId] : [],
            variant_id,
            timestamp,
            status,
            details_loaded: false,
        };
    }
    if (typeof data !== "object") return [];
    if (typeof data?.id !== "string") return [];
    if (typeof data?.vuln_id !== "string") return [];
    if (typeof data?.status !== "string") return [];
    if (typeof data?.timestamp !== "string") return [];
    let item: Assessment = {
        id: data.id,
        vuln_id: data.vuln_id,
        packages: asStringArray(data?.packages),
        variant_id: undefined,
        origin: typeof data?.origin === "string" ? data.origin : "sbom",
        status: data.status,
        simplified_status: `[invalid status] ${data.status}`,
        status_notes: undefined,
        justification: undefined,
        impact_statement: undefined,
        workaround: undefined,
        workaround_timestamp: undefined,
        timestamp: data.timestamp,
        last_update: undefined,
        responses: asStringArray(data?.responses),
    };
    if (typeof STATUS_VEX_TO_GRAPH?.[data.status] === "string")
        item.simplified_status = STATUS_VEX_TO_GRAPH[data.status];
    if (typeof data?.variant_id === "string") item.variant_id = data.variant_id;
    if (typeof data?.status_notes === "string") item.status_notes = data.status_notes;
    if (typeof data?.justification === "string") item.justification = data.justification;
    if (typeof data?.impact_statement === "string") item.impact_statement = data.impact_statement;
    if (typeof data?.workaround === "string") item.workaround = data.workaround;
    if (typeof data?.workaround_timestamp === "string") item.workaround_timestamp = data.workaround_timestamp;
    if (typeof data?.last_update === "string") item.last_update = data.last_update;
    if (Array.isArray(data?.vuln_texts)) item.vuln_texts = data.vuln_texts;
    if (data?.outdated === true) item.outdated = true;
    if (Array.isArray(data?.superseded_by)) item.superseded_by = data.superseded_by.filter((s: any) => typeof s === "string");
    if (Array.isArray(data?.stale_packages)) item.stale_packages = data.stale_packages.filter((s: any) => typeof s === "string");
    if (data?.superseded_map && typeof data.superseded_map === "object" && !Array.isArray(data.superseded_map)) {
        const map: Record<string, string[]> = {};
        for (const [key, value] of Object.entries(data.superseded_map)) {
            if (Array.isArray(value)) map[key] = value.filter((s: any) => typeof s === "string");
        }
        item.superseded_map = map;
    }
    if (typeof data?.details_loaded === "boolean") item.details_loaded = data.details_loaded;
    return item
}

const removeDuplicateAssessments = (assessments: Assessment[]): Assessment[] => {
    const seen = new Set<string>();
    const uniqueAssessments: Assessment[] = [];

    for (const assessment of assessments) {
        // Create a unique key using vuln_id, packages, status, and descriptions
        const packagesKey = assessment.packages.sort().join(',');
        const descriptionsKey = [
            assessment.status_notes || '',
            assessment.justification || '',
            assessment.impact_statement || '',
            assessment.workaround || ''
        ].join('|');

        const duplicateKey = `${assessment.vuln_id}::${packagesKey}::${assessment.status}::${descriptionsKey}::${assessment.variant_id ?? ''}`;

        if (!seen.has(duplicateKey)) {
            seen.add(duplicateKey);
            uniqueAssessments.push(assessment);
        }
    }

    return uniqueAssessments;
}

class Assessments {
    /**
     * Fetch server API to list all packages
     * @returns {Promise<Assessment[]>} A promise that resolves to a list of packages
     */
    static async list(variantId?: string, projectId?: string): Promise<Assessment[]> {
        const url = new URL(import.meta.env.VITE_API_URL + "/api/assessments", window.location.href);
        // Initial Explorer rendering only needs status, timestamp, package and
        // variant scope. Full notes/responses are fetched for one vulnerability
        // when its modal opens.
        url.searchParams.set('format', 'compact');
        if (variantId) url.searchParams.set('variant_id', variantId);
        else if (projectId) url.searchParams.set('project_id', projectId);
        const response = await fetch(url.toString(), {
            mode: "cors",
        });
        const data = await response.json();
        const assessments = data.flatMap(asAssessment);
        return removeDuplicateAssessments(assessments);
    }

    /**
     * Fetch assessments not linked to any scan (handmade via the web UI)
     */
    static async listReview(variantId?: string, projectId?: string): Promise<Assessment[]> {
        const url = new URL(import.meta.env.VITE_API_URL + "/api/assessments/review", window.location.href);
        if (variantId) url.searchParams.set('variant_id', variantId);
        else if (projectId) url.searchParams.set('project_id', projectId);
        const response = await fetch(url.toString(), { mode: "cors" });
        const data = await response.json();
        return data.flatMap(asAssessment);
    }

    /**
     * Fetch pending AI-generated assessments (``origin == 'ai'``) for the review tab.
     */
    static async listReviewAi(variantId?: string, projectId?: string): Promise<Assessment[]> {
        const url = new URL(import.meta.env.VITE_API_URL + "/api/assessments/review/ai", window.location.href);
        if (variantId) url.searchParams.set('variant_id', variantId);
        else if (projectId) url.searchParams.set('project_id', projectId);
        const response = await fetch(url.toString(), { mode: "cors" });
        const data = await response.json();
        return data.flatMap(asAssessment);
    }

    /**
     * Fetch vulnerabilities with non-zero time estimates for the review tab.
     */
    static async listReviewTimeEstimates(variantId?: string, projectId?: string): Promise<ReviewTimeEstimate[]> {
        const url = new URL(import.meta.env.VITE_API_URL + "/api/assessments/review/time-estimates", window.location.href);
        if (variantId) url.searchParams.set('variant_id', variantId);
        else if (projectId) url.searchParams.set('project_id', projectId);
        const response = await fetch(url.toString(), { mode: "cors" });
        const data = await response.json();
        if (!Array.isArray(data)) return [];
        return data;
    }

    /**
     * Fetch vulnerabilities with custom CVSS scores for the review tab.
     */
    static async listReviewCustomCvss(variantId?: string, projectId?: string): Promise<ReviewCustomCvss[]> {
        const url = new URL(import.meta.env.VITE_API_URL + "/api/assessments/review/custom-cvss", window.location.href);
        if (variantId) url.searchParams.set('variant_id', variantId);
        else if (projectId) url.searchParams.set('project_id', projectId);
        const response = await fetch(url.toString(), { mode: "cors" });
        const data = await response.json();
        if (!Array.isArray(data)) return [];
        return data;
    }

    /** Approve a pending AI assessment group and return the promoted assessments.
     *
     * A grouped review row can span multiple variants, so pass every assessment
     * id in the row via ``ids`` to approve them all. When omitted, the backend
     * falls back to grouping by the addressed assessment's (vuln, variant). */
    static async approveAi(assessmentId: string, ids?: string[]): Promise<Assessment[]> {
        const url = new URL(
            import.meta.env.VITE_API_URL + `/api/assessments/${encodeURIComponent(assessmentId)}/approve`,
            window.location.href
        );
        const response = await fetch(url.toString(), {
            method: "POST",
            mode: "cors",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(ids && ids.length > 0 ? { ids } : {}),
        });
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || `HTTP ${response.status}`);
        }
        const data = await response.json();
        if (!Array.isArray(data?.assessments)) return [];
        return data.assessments.flatMap(asAssessment);
    }

    /** Reject a pending AI assessment group and return the deleted assessment ids.
     *
     * A grouped review row can span multiple variants, so pass every assessment
     * id in the row via ``ids`` to reject them all. When omitted, the backend
     * falls back to grouping by the addressed assessment's (vuln, variant). */
    static async rejectAi(assessmentId: string, ids?: string[]): Promise<string[]> {
        const url = new URL(
            import.meta.env.VITE_API_URL + `/api/assessments/${encodeURIComponent(assessmentId)}/reject`,
            window.location.href
        );
        const response = await fetch(url.toString(), {
            method: "POST",
            mode: "cors",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(ids && ids.length > 0 ? { ids } : {}),
        });
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || `HTTP ${response.status}`);
        }
        const data = await response.json();
        return asStringArray(data?.deleted);
    }
}

export default Assessments;
export { STATUS_VEX_TO_GRAPH, asStringArray, asAssessment, removeDuplicateAssessments };

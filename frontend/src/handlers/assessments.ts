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

type AssessmentTarget = {
    variant_id: string | null;
    package: string;
    outdated: boolean;
    /** Which underlying assessment record owns this (package, variant) pair —
     *  needed to PUT/DELETE it directly when a legacy per-row edit applies. */
    assessment_id: string;
};

type AssessmentGroup = {
    group_id: string | null;
    vuln_id: string;
    status: string;
    simplified_status: string;
    justification: string;
    impact_statement: string;
    status_notes: string;
    workaround: string;
    responses: string[];
    origin: string;
    timestamp: string;
    targets: AssessmentTarget[];
    assessment_ids: string[];
    /** Only populated by the cross-vuln review endpoint; vuln-scoped group
     *  endpoints omit it since the caller already knows the vulnerability. */
    vuln_texts?: VulnText[];
};

type BatchAssessmentItem = {
    vuln_id: string;
    packages: string[];
    status: string;
    justification?: string;
    impact_statement?: string;
    status_notes?: string;
    workaround?: string;
    variant_id?: string;
    /** Shared timestamp so all rows created by one batch action line up. */
    timestamp?: string;
};

type BatchResult = {
    status: 'success' | 'error';
    assessments: Assessment[];
    count: number;
    vuln_count: number;
};

export type { AssessmentGroup, AssessmentTarget, BatchAssessmentItem, BatchResult };

type ReviewTimeEstimate = {
    id: string;
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
    id: string;
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

/** A group is user-facing shorthand for "more than one (variant, package)
 *  target under one assessment id" — a single target is just an assessment. */
const isMultiTargetGroup = (targets: AssessmentTarget[]): boolean => targets.length > 1;

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

    /** Fetch server-built assessment groups for one vulnerability. */
    static async listGroups(vulnId: string, projectId?: string): Promise<AssessmentGroup[]> {
        const url = new URL(
            import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(vulnId)}/assessment-groups`,
            window.location.href
        );
        if (projectId) url.searchParams.set('project_id', projectId);
        const response = await fetch(url.toString(), { mode: 'cors' });
        if (!response.ok) throw new Error(`Failed to load assessment groups: ${response.status}`);
        return await response.json();
    }

    /** Fetch server-built assessment groups for the review table. */
    static async listReviewGroups(variantId?: string, projectId?: string, origin?: string): Promise<AssessmentGroup[]> {
        const url = new URL(import.meta.env.VITE_API_URL + '/api/reviews/assessment-groups', window.location.href);
        if (variantId) url.searchParams.set('variant_id', variantId);
        if (projectId) url.searchParams.set('project_id', projectId);
        if (origin) url.searchParams.set('origin', origin);
        const response = await fetch(url.toString(), { mode: 'cors' });
        if (!response.ok) throw new Error(`Failed to load review groups: ${response.status}`);
        return await response.json();
    }

    /** Fetch a single group by id. */
    static async getGroup(groupId: string): Promise<AssessmentGroup> {
        const url = new URL(
            import.meta.env.VITE_API_URL + `/api/assessment-groups/${encodeURIComponent(groupId)}`,
            window.location.href
        );
        const response = await fetch(url.toString(), { mode: 'cors' });
        if (!response.ok) throw new Error(`Failed to load group: ${response.status}`);
        return await response.json();
    }

    /** Reconcile a group to a desired content/target state in one request. */
    static async reconcileGroup(groupId: string, body: Record<string, unknown>): Promise<AssessmentGroup> {
        const url = new URL(
            import.meta.env.VITE_API_URL + `/api/assessment-groups/${encodeURIComponent(groupId)}/reconcile`,
            window.location.href
        );
        const response = await fetch(url.toString(), {
            method: 'POST',
            mode: 'cors',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || `HTTP ${response.status}`);
        }
        return await response.json();
    }

    /** Delete every assessment in a group; returns the deleted ids. */
    static async deleteGroup(groupId: string): Promise<string[]> {
        const url = new URL(
            import.meta.env.VITE_API_URL + `/api/assessment-groups/${encodeURIComponent(groupId)}`,
            window.location.href
        );
        const response = await fetch(url.toString(), { method: 'DELETE', mode: 'cors' });
        if (!response.ok) throw new Error(`Failed to delete group: ${response.status}`);
        const data = await response.json();
        return asStringArray(data?.deleted_ids);
    }

    /** Approve every AI-origin assessment in a group. */
    static async approveAiGroup(groupId: string): Promise<Assessment[]> {
        const url = new URL(
            import.meta.env.VITE_API_URL + `/api/assessment-groups/${encodeURIComponent(groupId)}/approve`,
            window.location.href
        );
        const response = await fetch(url.toString(), { method: 'POST', mode: 'cors' });
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || `HTTP ${response.status}`);
        }
        const data = await response.json();
        if (!Array.isArray(data?.assessments)) return [];
        return data.assessments.flatMap(asAssessment);
    }

    /** Reject every AI-origin assessment in a group, deleting it. */
    static async rejectAiGroup(groupId: string): Promise<string[]> {
        const url = new URL(
            import.meta.env.VITE_API_URL + `/api/assessment-groups/${encodeURIComponent(groupId)}/reject`,
            window.location.href
        );
        const response = await fetch(url.toString(), { method: 'POST', mode: 'cors' });
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || `HTTP ${response.status}`);
        }
        const data = await response.json();
        return asStringArray(data?.deleted);
    }

    /** Put a lone assessment into a group so it can gain more targets. */
    static async promoteToGroup(assessmentId: string): Promise<string> {
        const url = new URL(
            import.meta.env.VITE_API_URL + `/api/assessments/${encodeURIComponent(assessmentId)}/group`,
            window.location.href
        );
        const response = await fetch(url.toString(), { method: 'POST', mode: 'cors' });
        if (!response.ok) throw new Error(`Failed to create group: ${response.status}`);
        const data = await response.json();
        return data.group_id;
    }

    /** Create every assessment of one user action in a single request, so the
     *  backend can assign one group per vulnerability. */
    static async createBatch(items: BatchAssessmentItem[]): Promise<BatchResult> {
        const url = new URL(import.meta.env.VITE_API_URL + '/api/assessments/batch', window.location.href);
        const response = await fetch(url.toString(), {
            method: 'POST',
            mode: 'cors',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ assessments: items }),
        });
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            // The batch endpoint reports per-item failures in `errors`, not `error`.
            const detail = Array.isArray(err.errors) && err.errors.length > 0
                ? err.errors.map((e: { error?: string }) => e.error).filter(Boolean).join('; ')
                : err.error;
            throw new Error(detail || `HTTP ${response.status}`);
        }
        return await response.json();
    }
}

export default Assessments;
export { STATUS_VEX_TO_GRAPH, asStringArray, asAssessment, removeDuplicateAssessments, isMultiTargetGroup };

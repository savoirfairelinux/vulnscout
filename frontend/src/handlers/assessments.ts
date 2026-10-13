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

/** One (variant, package) pair an assessment actually applies to.
 *
 *  ``outdated`` is only populated by endpoints that annotate staleness
 *  per-target (the single-assessment and vulnerability-scoped listings);
 *  it is absent right after a create/update response. */
type AssessmentTargetPair = {
    variant_id: string | null;
    package: string;
    outdated?: boolean;
};

type Assessment = {
    id: string;
    vuln_id: string;
    packages: string[];
    variant_id?: string;
    variant_ids?: string[];
    /** The exact pairs this assessment covers.
     *
     *  ``packages`` and ``variant_ids`` are two independent flattened sets, so
     *  crossing them describes pairs that were never assessed.  Absent on
     *  payloads that predate the field. */
    targets?: AssessmentTargetPair[];
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
    /** Pending AI assessments only: the variant context changed after it was written. */
    context_outdated?: boolean;
    superseded_by?: string[];
    stale_packages?: string[];
    superseded_map?: Record<string, string[]>;
    details_loaded?: boolean;
};

export type { Assessment, AssessmentTargetPair };

/** Every variant this assessment applies to.
 *
 *  ``variant_ids`` carries the full target set.  ``variant_id`` is only a
 *  convenience shorthand the API fills in when every target shares one
 *  variant, so it is ``null`` for a genuine cross-variant assessment and must
 *  never be used on its own to decide which variants an assessment covers.
 *  Falls back to ``variant_id`` for payloads that predate ``variant_ids``.
 */
const assessmentVariantIds = (assessment: Assessment): string[] => {
    if (assessment.variant_ids && assessment.variant_ids.length > 0) return assessment.variant_ids;
    return assessment.variant_id ? [assessment.variant_id] : [];
};

/** True when *assessment* targets *variantId*. */
const appliesToVariant = (assessment: Assessment, variantId: string): boolean =>
    assessmentVariantIds(assessment).includes(variantId);

/** The packages this assessment covers *within* one variant.
 *
 *  Falls back to the whole package list for payloads with no target pairs,
 *  which is what the flat schema's one-variant-per-record shape meant.
 */
const assessmentPackagesInVariant = (assessment: Assessment, variantId: string): string[] => {
    if (assessment.targets && assessment.targets.length > 0) {
        return assessment.targets
            .filter(target => target.variant_id === variantId)
            .map(target => target.package);
    }
    return appliesToVariant(assessment, variantId) ? assessment.packages : [];
};

/** True when *assessment* covers the exact (variantId, pkg) pair.
 *
 *  Never test variant membership and package membership separately: an
 *  assessment covering (A, openssl) and (B, zlib) passes both tests for
 *  (A, zlib), a pair nobody assessed.
 */
const coversTarget = (assessment: Assessment, variantId: string, pkg: string): boolean =>
    assessmentPackagesInVariant(assessment, variantId).includes(pkg);

/** Identity of the (variant, package) pairs an assessment covers.
 *
 *  Crossing `packages` with `variant_ids` cannot tell (A,openssl)+(B,zlib) apart
 *  from (A,zlib)+(B,openssl), so two different assessments would share a key and
 *  one would be dropped as a duplicate. Falls back to the flat sets for payloads
 *  with no target pairs, which is what the one-variant-per-record shape meant.
 */
const assessmentCoverageKey = (assessment: Assessment): string => {
    if (assessment.targets && assessment.targets.length > 0) {
        return assessment.targets
            .map(target => JSON.stringify([target.variant_id ?? '', target.package]))
            .sort()
            .join(',');
    }
    const packagesKey = [...assessment.packages].sort().join(',');
    const variantsKey = assessmentVariantIds(assessment).slice().sort().join(',');
    return `${packagesKey}::${variantsKey}`;
};

export { assessmentVariantIds, appliesToVariant, assessmentPackagesInVariant, coversTarget };

/** Build exact desired pairs while preserving sparse existing coverage.
 * Newly selected package or variant dimensions are expanded as requested,
 * while absent cells between existing dimensions remain absent. */
function reconcileTargetPairs(
    existing: AssessmentTargetPair[], packages: string[], variantIds: string[],
): Array<{ package: string; variant_id: string }> {
    const existingKeys = new Set(existing.map(target =>
        `${target.package}\0${target.variant_id ?? ''}`));
    const existingPackages = new Set(existing.map(target => target.package));
    const existingVariants = new Set(existing.flatMap(target =>
        target.variant_id === null ? [] : [target.variant_id]));

    return packages.flatMap(packageId => variantIds.flatMap(variantId => {
        const key = `${packageId}\0${variantId}`;
        if (existingKeys.has(key)
                || !existingPackages.has(packageId)
                || !existingVariants.has(variantId)) {
            return [{ package: packageId, variant_id: variantId }];
        }
        return [];
    }));
}

type BatchAssessmentItem = {
    vuln_id: string;
    packages: string[];
    status: string;
    justification?: string;
    impact_statement?: string;
    status_notes?: string;
    workaround?: string;
    variant_id?: string;
    /** Multiple variants covered by this one assessment row. */
    variant_ids?: string[];
    /** Shared timestamp so all rows created by one batch action line up. */
    timestamp?: string;
};

type BatchResult = {
    status: 'success' | 'error';
    assessments: Assessment[];
    count: number;
    vuln_count: number;
};

export type { BatchAssessmentItem, BatchResult };
export { reconcileTargetPairs };

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

const asTargetPairs = (data: any[]): AssessmentTargetPair[] =>
    data
        .filter((item: any) => item && typeof item === "object"
            && typeof item.package === "string"
            && (item.variant_id === null || typeof item.variant_id === "string"))
        .map((item: any) => ({
            variant_id: item.variant_id,
            package: item.package,
            ...(typeof item.outdated === "boolean" ? { outdated: item.outdated } : {}),
        }));

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
            variant_ids: variant_id ? [variant_id] : [],
            targets: packageId && variant_id ? [{ variant_id, package: packageId }] : [],
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
        variant_ids: [],
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
    if (Array.isArray(data?.variant_ids)) item.variant_ids = asStringArray(data.variant_ids);
    if (Array.isArray(data?.targets)) item.targets = asTargetPairs(data.targets);
    if (typeof data?.status_notes === "string") item.status_notes = data.status_notes;
    if (typeof data?.justification === "string") item.justification = data.justification;
    if (typeof data?.impact_statement === "string") item.impact_statement = data.impact_statement;
    if (typeof data?.workaround === "string") item.workaround = data.workaround;
    if (typeof data?.workaround_timestamp === "string") item.workaround_timestamp = data.workaround_timestamp;
    if (typeof data?.last_update === "string") item.last_update = data.last_update;
    if (Array.isArray(data?.vuln_texts)) item.vuln_texts = data.vuln_texts;
    if (data?.outdated === true) item.outdated = true;
    if (data?.context_outdated === true) item.context_outdated = true;
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
        // Create a unique key using vuln_id, target coverage, status, and descriptions
        const descriptionsKey = [
            assessment.status_notes || '',
            assessment.justification || '',
            assessment.impact_statement || '',
            assessment.workaround || ''
        ].join('|');

        const duplicateKey = `${assessment.vuln_id}::${assessmentCoverageKey(assessment)}::${assessment.status}::${descriptionsKey}`;

        if (!seen.has(duplicateKey)) {
            seen.add(duplicateKey);
            uniqueAssessments.push(assessment);
        }
    }

    return uniqueAssessments;
}

/** "Multi-target" is user-facing shorthand for "more than one (variant,
 *  package) target under one assessment id" — a single target is the common case. */
const isMultiTarget = (targets: AssessmentTargetPair[]): boolean => targets.length > 1;

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

/** Fetch every assessment for one vulnerability, targets annotated with
     *  staleness. */
    static async listByVuln(vulnId: string, projectId?: string): Promise<Assessment[]> {
        const url = new URL(
            import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(vulnId)}/assessments`,
            window.location.href
        );
        if (projectId) url.searchParams.set('project_id', projectId);
        const response = await fetch(url.toString(), { mode: 'cors' });
        if (!response.ok) throw new Error(`Failed to load assessments: ${response.status}`);
        const data = await response.json();
        return data.flatMap(asAssessment);
    }

    /** Fetch assessments for the review table, annotated with vuln texts. */
    static async listForReview(variantId?: string, projectId?: string, origin?: string): Promise<Assessment[]> {
        const url = new URL(import.meta.env.VITE_API_URL + '/api/reviews/assessments', window.location.href);
        if (variantId) url.searchParams.set('variant_id', variantId);
        if (projectId) url.searchParams.set('project_id', projectId);
        if (origin) url.searchParams.set('origin', origin);
        const response = await fetch(url.toString(), { mode: 'cors' });
        if (!response.ok) throw new Error(`Failed to load review assessments: ${response.status}`);
        const data = await response.json();
        return data.flatMap(asAssessment);
    }

    /** Fetch a single assessment by id. */
    static async get(assessmentId: string): Promise<Assessment | []> {
        const url = new URL(
            import.meta.env.VITE_API_URL + `/api/assessments/${encodeURIComponent(assessmentId)}`,
            window.location.href
        );
        const response = await fetch(url.toString(), { mode: 'cors' });
        if (!response.ok) throw new Error(`Failed to load assessment: ${response.status}`);
        return asAssessment(await response.json());
    }

    /** Reconcile an assessment to a desired content/target state in one request. */
    static async reconcile(assessmentId: string, body: Record<string, unknown>): Promise<{
        status: string; updated: unknown[]; created: unknown[]; deleted: string[];
    }> {
        const url = new URL(
            import.meta.env.VITE_API_URL + `/api/assessments/${encodeURIComponent(assessmentId)}/reconcile`,
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

    /** Delete an assessment. */
    static async remove(assessmentId: string): Promise<void> {
        const url = new URL(
            import.meta.env.VITE_API_URL + `/api/assessments/${encodeURIComponent(assessmentId)}`,
            window.location.href
        );
        const response = await fetch(url.toString(), { method: 'DELETE', mode: 'cors' });
        if (!response.ok) throw new Error(`Failed to delete assessment: ${response.status}`);
    }

    /** Approve a pending AI-origin assessment. */
    static async approveAi(assessmentId: string): Promise<Assessment[]> {
        const url = new URL(
            import.meta.env.VITE_API_URL + `/api/assessments/${encodeURIComponent(assessmentId)}/approve`,
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

    /** Reject a pending AI-origin assessment, deleting it. */
    static async rejectAi(assessmentId: string): Promise<string[]> {
        const url = new URL(
            import.meta.env.VITE_API_URL + `/api/assessments/${encodeURIComponent(assessmentId)}/reject`,
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

    /** Create every assessment of one user action in a single request. */
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
export { STATUS_VEX_TO_GRAPH, asStringArray, asAssessment, removeDuplicateAssessments, isMultiTarget };

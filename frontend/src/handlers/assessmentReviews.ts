// Copyright (C) 2026 Savoir-faire Linux, Inc.
// SPDX-License-Identifier: GPL-3.0-only

/** An AI-generated second opinion on a single custom assessment. */
type AssessmentReview = {
    id: string;
    assessment_id: string;
    status: string;
    status_notes: string;
    justification: string;
    impact_statement: string;
    workaround: string;
    responses: string[];
    rationale: string;
    timestamp: string;
    /** Server-computed: whether the review's VEX fields match the assessment. */
    verdict: "agrees" | "differs";
    /** Server-computed: whether the assessment was edited after the review. */
    is_stale: boolean;
};

/** What the UI displays for an assessment's review state. */
type ReviewVerdict = "agrees" | "differs" | "stale" | "none";

export type { AssessmentReview, ReviewVerdict };

/**
 * Collapse a review into the single state the UI renders. A stale review shows
 * as stale regardless of whether it agreed, because it was written against a
 * version of the assessment that no longer exists.
 */
const verdictOf = (review: AssessmentReview | undefined): ReviewVerdict => {
    if (!review) return "none";
    if (review.is_stale) return "stale";
    return review.verdict;
};

class AssessmentReviews {
    /**
     * Fetch every review in a variant or project scope, keyed by assessment ID.
     * Returns an empty map on failure — a missing review panel must never break
     * the page that hosts it.
     */
    static async fetchForScope(
        variantId?: string,
        projectId?: string,
    ): Promise<Record<string, AssessmentReview>> {
        const url = new URL(
            import.meta.env.VITE_API_URL + "/api/assessment-reviews",
            window.location.href,
        );
        if (variantId) url.searchParams.set("variant_id", variantId);
        else if (projectId) url.searchParams.set("project_id", projectId);

        try {
            const response = await fetch(url.toString(), { mode: "cors" });
            if (!response.ok) return {};
            return await response.json();
        } catch {
            return {};
        }
    }

    /** Discard the review attached to an assessment. */
    static async remove(assessmentId: string): Promise<void> {
        const url = new URL(
            import.meta.env.VITE_API_URL
                + `/api/assessments/${encodeURIComponent(assessmentId)}/review`,
            window.location.href,
        );
        const response = await fetch(url.toString(), { mode: "cors", method: "DELETE" });
        if (!response.ok) {
            const data = await response.json().catch(() => ({}));
            throw new Error(data.error ?? "Failed to discard review");
        }
    }
}

export default AssessmentReviews;
export { verdictOf };

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

/** How a group's assessments were reviewed, counted by verdict. */
type ReviewSummary = {
    /** Assessments in the group, reviewed or not. */
    total: number;
    /** Assessments carrying a review. */
    reviewed: number;
    agrees: number;
    differs: number;
    stale: number;
};

export type { AssessmentReview, ReviewVerdict, ReviewSummary };

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

/**
 * Count the verdicts across a group's assessments.
 *
 * Group members share the same assessment text but target different variants
 * and packages, so each is reviewed independently against its own context.
 * That means one group can legitimately hold several different verdicts, or be
 * reviewed only in part, and the summary has to report both rather than let a
 * single member speak for the rest.
 */
const summarizeReviews = (
    assessmentIds: string[],
    reviews: Record<string, AssessmentReview>,
): ReviewSummary => {
    const verdicts = assessmentIds.map(id => verdictOf(reviews[id]));
    const count = (v: ReviewVerdict) => verdicts.filter(x => x === v).length;
    return {
        total: verdicts.length,
        reviewed: verdicts.filter(v => v !== "none").length,
        agrees: count("agrees"),
        differs: count("differs"),
        stale: count("stale"),
    };
};

/** Human-readable breakdown of a summary, for tooltips. */
const describeReviewSummary = (summary: ReviewSummary): string => {
    if (summary.reviewed === 0) return "Not reviewed";
    const parts: string[] = [];
    if (summary.agrees) parts.push(`${summary.agrees} agree`);
    if (summary.differs) parts.push(`${summary.differs} differ`);
    if (summary.stale) parts.push(`${summary.stale} stale`);
    const pending = summary.total - summary.reviewed;
    if (pending) parts.push(`${pending} not reviewed`);
    return parts.join(" · ");
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
export { verdictOf, summarizeReviews, describeReviewSummary };

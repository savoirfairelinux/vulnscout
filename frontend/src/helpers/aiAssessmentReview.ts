import type { QueuedAgentMessage } from '../types/agent';
import Assessments from '../handlers/assessments';
import AssessmentReviews from '../handlers/assessmentReviews';
import type { Variant } from '../handlers/variant';

export const assessmentReviewKey = (assessmentId: string) => `review:${assessmentId}`;

/** Compare server timestamps rather than relying on the browser's clock. */
export async function prepareAssessmentReviewVerification(assessmentId: string): Promise<() => Promise<void>> {
    const assessment = await Assessments.get(assessmentId);
    if (Array.isArray(assessment) || assessment.id !== assessmentId || assessment.origin !== 'custom'
        || !assessment.targets?.length || assessment.targets.some(target => !target.variant_id || !target.package)) {
        throw new Error(`Assessment ${assessmentId} is no longer a reviewable custom assessment.`);
    }
    const targets = assessment.targets;
    const previous = await AssessmentReviews.fetchForAssessment(assessmentId);
    return async () => {
        const saved = await AssessmentReviews.fetchForAssessment(assessmentId);
        const current = await Assessments.get(assessmentId);
        const sameTargets = !Array.isArray(current) && current.origin === 'custom'
            && current.targets?.length === targets.length && targets.every(target =>
                current.targets?.some(item => item.variant_id === target.variant_id && item.package === target.package));
        const complete = sameTargets && targets.every(target => {
            const review = saved.find(item => item.assessment_id === assessmentId
                && item.variant_id === target.variant_id && item.package === target.package);
            const before = previous.find(item => item.variant_id === target.variant_id && item.package === target.package);
            return review && !review.is_stale && Number.isFinite(Date.parse(review.timestamp))
                && (!before || Date.parse(review.timestamp) > Date.parse(before.timestamp));
        });
        if (!complete) throw new Error('Not every assessment target has a freshly saved review. Retry the request.');
    };
}

export async function resolveAssessmentReviewAction(
    assessmentId: string, variants: Variant[],
): Promise<Omit<QueuedAgentMessage, 'id'>> {
    const assessment = await Assessments.get(assessmentId);
    if (Array.isArray(assessment) || assessment.id !== assessmentId || assessment.origin !== 'custom'
        || !assessment.targets?.length) {
        throw new Error(`Assessment ${assessmentId} is no longer a reviewable custom assessment.`);
    }
    const variantIds = new Set<string>();
    const projectIds = new Set<string>();
    for (const target of assessment.targets) {
        const variant = variants.find(item => item.id === target.variant_id);
        if (!variant || !target.package) throw new Error(`Cannot resolve all targets for assessment ${assessmentId}.`);
        variantIds.add(variant.id);
        projectIds.add(variant.project_id);
    }
    if (projectIds.size !== 1) throw new Error(`Assessment ${assessmentId} targets more than one project.`);
    return {
        ...buildAssessmentReviewAction({
            ...assessment, packages: [...new Set(assessment.targets.map(target => target.package))],
        }),
        context: {
            page: 'review',
            projectId: [...projectIds][0],
            variantIds: [...variantIds].sort(),
            view: { section: 'assessments' },
        },
    };
}

/** Resolve the complete assessment by ID, not just the targets visible in the current scope. */
export function buildAssessmentReviewAction(assessment: {
    id: string;
    vuln_id: string;
    packages: string[];
}): Omit<QueuedAgentMessage, 'id'> {
    return {
        key: assessmentReviewKey(assessment.id), kind: 'review', assessmentId: assessment.id,
        text: `Review the user assessment ${assessment.id} for ${assessment.vuln_id}. Retrieve it with get_custom_assessment, ` +
            `independently re-derive the verdict for each of its targets using VulnScout MCP data, and record one ` +
            `review per target with write_assessment_review. Do not modify the assessment itself.`,
        title: `assessment ${assessment.id.slice(0, 8)}`,
        detail: [assessment.vuln_id, ...assessment.packages].join(' · '),
    };
}

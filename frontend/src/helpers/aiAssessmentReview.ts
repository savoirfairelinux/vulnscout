import type { QueuedAgentMessage } from '../components/AgentChat';
import Assessments from '../handlers/assessments';
import type { Variant } from '../handlers/variant';

export const assessmentReviewKey = (assessmentId: string) => `review:${assessmentId}`;

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
        key: assessmentReviewKey(assessment.id), kind: 'review',
        text: `Review the user assessment ${assessment.id} for ${assessment.vuln_id}. Retrieve it with get_custom_assessment, ` +
            `independently re-derive the verdict for each of its targets using VulnScout MCP data, and record one ` +
            `review per target with write_assessment_review. Do not modify the assessment itself.`,
        title: `assessment ${assessment.id.slice(0, 8)}`,
        detail: [assessment.vuln_id, ...assessment.packages].join(' · '),
    };
}

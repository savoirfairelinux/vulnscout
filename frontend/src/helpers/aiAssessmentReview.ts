import type { QueuedAgentMessage } from '../components/AgentChat';

export const assessmentReviewKey = (assessmentId: string) => `review:${assessmentId}`;

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

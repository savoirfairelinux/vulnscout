export const AGENT_WRITE_EVENT = 'vulnscout:agent-write';
// Mirrors the backend limit on /api/agent/messages (src/routes/agent.py).
export const AGENT_MESSAGE_MAX_LENGTH = 8000;

export type Activity = { id: string; name: string; status: 'running' | 'done' | 'failed' };
export type AgentMessage = { role: 'user' | 'assistant'; content: string; activity?: Activity[]; taskId?: string };
export type AgentUsage = { cost: number | null; input_tokens: number | null; output_tokens: number | null };
export type AgentStreamEvent =
    | { type: 'delta'; message_id: string; text: string }
    | { type: 'tool_start'; id: string; name: string }
    | { type: 'tool_end'; id: string; success: boolean; write?: boolean }
    | { type: 'status'; text: string }
    | { type: 'heartbeat' }
    | { type: 'done'; reply: string; model: string; usage: AgentUsage }
    | { type: 'error'; error: string };

export type QueuedAgentMessage = {
    id: string;
    text: string;
    key: string;
    kind: 'assess' | 'review' | 'message';
    title: string;
    detail?: string;
    context?: AgentContext;
    assessmentId?: string;
};

/** Where a queued AI action (Assess/Review with AI) currently stands in the AI queue. */
export type AgentActionState =
    | { status: 'running' | 'failed'; taskId: string }
    | { status: 'queued'; taskId: string; position: number };

export type AgentViewContext = {
    visibleVulnerabilityIds?: string[];
    visiblePackageIds?: string[];
    visibleScanIds?: string[];
    selectedScanTypes?: string[];
    selectedRefreshTypes?: string[];
    refreshMode?: string;
    hideEmptyScans?: boolean;
    excludeKernel?: boolean;
    excludeNative?: boolean;
    visibleCount?: number;
    selectionCount?: number;
    selectedVulnerabilityIds?: string[];
    selectedVariantIds?: string[];
    selectedExportKeys?: string[];
    enabledExportDocuments?: string[];
    selectedProjectId?: string;
    selectedProjectName?: string;
    selectedVariantId?: string;
    selectedVariantName?: string;
    openScanId?: string;
    exportType?: string;
    exportMode?: string;
    exportCategory?: string;
    openVulnerabilityId?: string;
    matchingVariantIds?: string[];
    search?: string;
    section?: string;
};

export type AgentContext = {
    page: string;
    projectId?: string;
    variantId?: string;
    baseVariantId?: string;
    compareOperation?: string;
    variantIds?: string[];
    multiOperation?: string;
    view?: AgentViewContext;
};

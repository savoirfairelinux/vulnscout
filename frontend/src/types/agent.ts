export const AGENT_WRITE_EVENT = 'vulnscout:agent-write';
// Mirrors the backend message limit of the AI queue (src/controllers/agent_queue.py).
export const AGENT_MESSAGE_MAX_LENGTH = 8000;

export type Activity = { id: string; name: string; status: 'running' | 'done' | 'failed' };
export type AgentMessage = { role: 'user' | 'assistant'; content: string; activity?: Activity[]; taskId?: string };
export type AgentUsage = { cost: number | null; input_tokens: number | null; output_tokens: number | null };
export type AgentActionKind = 'assess' | 'review' | 'message';
export type AgentTarget = { variant_id: string | null; package: string };
/** One structured action for the backend AI queue (POST /api/agent/queue). */
export type AgentAction =
    | { kind: 'assess'; vuln_id: string; targets?: AgentTarget[]; key?: string; context?: AgentContext }
    | { kind: 'review'; assessment_id: string; variant_id?: string; finding_ids?: string[]; key?: string; context?: AgentContext }
    | { kind: 'message'; text: string; key?: string };
export type AgentRequestStatus = 'queued' | 'running' | 'failed' | 'done' | 'cancelled';
/** The running turn of a conversation, as the backend reports it. */
export type AgentLiveTurn = { request_id: string; pending_message: string; live_reply: string; activity: Activity[]; progress: string };
/** A request record of the backend AI queue. */
export type AgentRequestRecord = {
    id: string;
    key: string;
    kind: AgentActionKind;
    lane: 'action' | 'chat';
    conversation_id: string;
    source: string;
    title: string;
    detail: string;
    /** null until the request starts when it was queued before the agent connection was set up. */
    model: string | null;
    status: AgentRequestStatus;
    error: string | null;
    error_code: string | null;
    position: number | null;
    created_at: number;
    started_at: number | null;
    finished_at: number | null;
    context: AgentContext | null;
    text: string | null;
    vuln_id: string | null;
    assessment_id: string | null;
    timeout: number;
    result: Record<string, unknown> | null;
};
export type AgentConversationSummary = {
    id: string;
    title: string;
    kind: 'main' | 'action';
    profile: string | null;
    archived: boolean;
    created_at: number;
    last_used: number;
    message_count: number;
    usage: AgentUsage;
    live: AgentLiveTurn | null;
};
export type AgentConversationDetail = AgentConversationSummary & { messages: AgentMessage[] };
/** Why the backend queue does not start requests (no configuration, signed out...). */
export type AgentQueuePaused = { code: string; reason: string };
export type AgentQueueState = {
    paused: AgentQueuePaused | null;
    requests: AgentRequestRecord[];
    history: AgentRequestRecord[];
    conversations: AgentConversationSummary[];
    /** Changes when the agent connection or model changes (in any tab). */
    connection_revision: number;
};
export type AgentQueueSnapshot = AgentQueueState & { epoch: string; seq: number };
export type AgentQueueSubmitted = {
    requests: Array<{ id: string; key: string; conversation_id: string }>;
    skipped: Array<{ key: string; request_id: string }>;
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

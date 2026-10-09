export const AGENT_WRITE_EVENT = 'vulnscout:agent-write';
// Mirrors the backend limit on /api/agent/messages (src/routes/agent.py).
export const AGENT_MESSAGE_MAX_LENGTH = 8000;

/** Where a queued AI action (Assess/Review with AI) currently stands. */
export type AgentActionState = { status: 'running' } | { status: 'queued'; position: number };

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

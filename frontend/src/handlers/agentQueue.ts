/**
 * Mirror of the backend AI queue (src/controllers/agent_queue.py).
 *
 * The backend owns the queue, its conversations and their transcripts; every tab follows it over one
 * `EventSource` while something is subscribed, and changes it through the queue routes. The state is
 * exposed through the `useSyncExternalStore` contract.
 */
import { agentRequest } from './agent';
import { RECONNECT_DELAYS_MS } from './operationStore';
import {
    AGENT_WRITE_EVENT, type Activity, type AgentAction, type AgentActionKind, type AgentActionState, type AgentContext,
    type AgentConversationDetail, type AgentConversationSummary, type AgentLiveTurn, type AgentMessage, type AgentQueuePaused,
    type AgentQueueState, type AgentQueueSubmitted, type AgentRequestRecord, type AgentRequestStatus, type AgentUsage,
} from '../types/agent';

export { RECONNECT_DELAYS_MS };
export const MAIN_CONVERSATION = 'main';
export const AGENT_CHAT_SOURCE = 'Agent chat';
/** The backend's limit of actions per queue request (`agent_queue.MAX_ACTIONS`); larger lists go in batches. */
export const ACTIONS_PER_REQUEST = 500;
export const agentActionLabels = { assess: 'Assess', review: 'Review', message: 'Message' } as const;
const STREAM_PATH = '/api/agent/queue/stream';

export type AgentTask = {
    id: string;
    key: string;
    kind: AgentActionKind;
    title: string;
    detail?: string;
    /** The message sent to the agent (for actions, the prompt the backend built). */
    text: string;
    source: string;
    context?: AgentContext;
    conversationId: string;
    status: AgentRequestStatus;
    error?: string;
    errorCode?: string;
    /** For a queued request, its place in its lane (1 = next to run). */
    position?: number;
    vulnId?: string;
    assessmentId?: string;
    result?: Record<string, unknown>;
};
export type AgentConversation = {
    id: string;
    title: string;
    kind: 'main' | 'action';
    /** The scope of the conversation's latest request, reused by follow-ups. */
    context?: AgentContext;
    messages: AgentMessage[];
    messageCount: number;
    usage: AgentUsage;
    pendingMessage: string;
    pendingTaskId?: string;
    liveReply: string;
    activity: Activity[];
    progress: string;
    /** Released on the backend; the transcript stays readable. */
    archived: boolean;
    createdAt: number;
    lastUsed: number;
};
/** Where a conversation stands, from the most to the least urgent of its requests. */
export type AgentConversationStatus = 'failed' | 'running' | 'queued' | 'idle';
/** A request to open the agent chat, optionally on one request of the AI queue. */
export type AgentChatRequest = { nonce: number; taskId?: string; view?: 'chat' | 'conversations' };
export type EnqueueOptions = {
    conversation: string | 'per-action';
    source: string;
    context?: AgentContext;
    timeout?: number;
};

type Transcript = { fingerprint: string; messages: AgentMessage[] };

const emptyUsage = (): AgentUsage => ({ cost: null, input_tokens: null, output_tokens: null });
const placeholderMain: AgentConversationSummary = {
    id: MAIN_CONVERSATION, title: AGENT_CHAT_SOURCE, kind: 'main', profile: null, archived: false,
    created_at: 0, last_used: 0, message_count: 0, usage: emptyUsage(), live: null,
};
const fingerprint = (summary: AgentConversationSummary) => `${summary.created_at}:${summary.message_count}`;

const listeners = new Set<() => void>();
const chatListeners = new Set<() => void>();
let tasks: AgentTask[] = [];
let history: AgentTask[] = [];
let paused: AgentQueuePaused | null = null;
let summaries = new Map<string, AgentConversationSummary>();
let conversations: Record<string, AgentConversation> = {};
const transcripts = new Map<string, Transcript>();
/** The transcript fingerprint last requested per conversation; only its response is kept. */
const requested = new Map<string, string>();
/** Failed transcript fetches retried per conversation (at most one per reconnect delay), and their timers. */
const transcriptRetries = new Map<string, number>();
const transcriptTimers = new Map<string, ReturnType<typeof setTimeout>>();
const loading = new Set<string>();
/** The last running turn per conversation, displayed until the transcript including it is loaded. */
const lingering = new Map<string, AgentLiveTurn>();
let activeConversationId = MAIN_CONVERSATION;
let chatRequest: AgentChatRequest = { nonce: 0 };
/** A request `openAgentChat` asked for before the stream reported it. */
let pendingFocus: string | undefined;
let connectionRevision: number | undefined;

let source: EventSource | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectAttempt = 0;
let lastEventId: string | null = null;
/** Swappable so tests can drive the store without a live server; jsdom has no EventSource. */
let createEventSource: (url: string) => EventSource | null = url =>
    typeof EventSource === 'undefined' ? null : new EventSource(url);

const emit = () => listeners.forEach(listener => listener());
const emitChatRequest = () => {
    chatListeners.forEach(listener => listener());
    emit();
};

function toTask(record: AgentRequestRecord): AgentTask {
    return {
        id: record.id, key: record.key, kind: record.kind, title: record.title, detail: record.detail || undefined,
        text: record.text ?? '', source: record.source, context: record.context ?? undefined,
        conversationId: record.conversation_id, status: record.status, error: record.error ?? undefined,
        errorCode: record.error_code ?? undefined, position: record.position ?? undefined,
        vulnId: record.vuln_id ?? undefined, assessmentId: record.assessment_id ?? undefined, result: record.result ?? undefined,
    };
}

function buildConversations() {
    const ordered = [...summaries.values()].sort((a, b) =>
        Number(b.id === MAIN_CONVERSATION) - Number(a.id === MAIN_CONVERSATION) || a.created_at - b.created_at);
    if (!summaries.has(MAIN_CONVERSATION)) ordered.unshift(placeholderMain);
    const latest = [...tasks].reverse().concat([...history].reverse());
    conversations = Object.fromEntries(ordered.map(summary => {
        const transcript = transcripts.get(summary.id);
        const current = transcript?.fingerprint === fingerprint(summary);
        if (summary.live) lingering.set(summary.id, summary.live);
        else if (current || !loading.has(summary.id)) lingering.delete(summary.id);
        const live = summary.live ?? lingering.get(summary.id);
        const context = summary.kind === 'main' ? undefined
            : latest.find(task => task.conversationId === summary.id && task.context)?.context;
        const conversation: AgentConversation = {
            id: summary.id, title: summary.title, kind: summary.kind, context,
            messages: transcript && transcript.fingerprint.startsWith(`${summary.created_at}:`) ? transcript.messages : [],
            messageCount: summary.message_count, usage: summary.usage,
            pendingMessage: live?.pending_message ?? '', pendingTaskId: live?.request_id, liveReply: live?.live_reply ?? '',
            activity: live?.activity ?? [], progress: live?.progress ?? '', archived: summary.archived,
            createdAt: summary.created_at * 1000, lastUsed: summary.last_used * 1000,
        };
        return [summary.id, conversation];
    }));
}

/** Fetch the transcript again after a failure, a few times with growing delays. */
function retryTranscript(id: string, wanted: string) {
    const attempt = transcriptRetries.get(id) ?? 0;
    if (attempt >= RECONNECT_DELAYS_MS.length || transcriptTimers.has(id)) return;
    transcriptRetries.set(id, attempt + 1);
    transcriptTimers.set(id, setTimeout(() => {
        transcriptTimers.delete(id);
        if (requested.get(id) !== wanted) return;
        requested.delete(id);
        update();
    }, RECONNECT_DELAYS_MS[attempt]));
}

/** Fetch the active conversation's transcript once per change of its message count. */
function syncTranscript() {
    const id = activeConversationId;
    const summary = summaries.get(id);
    if (!summary) return;
    const wanted = fingerprint(summary);
    if (transcripts.get(id)?.fingerprint === wanted || requested.get(id) === wanted) return;
    requested.set(id, wanted);
    if (!summary.message_count) {
        transcripts.set(id, { fingerprint: wanted, messages: [] });
        return;
    }
    loading.add(id);
    agentRequest<AgentConversationDetail>(`/conversations/${encodeURIComponent(id)}`).then(detail => {
        // A newer fetch replaced this one: its response may arrive first, so this one must not overwrite it.
        if (requested.get(id) !== wanted) return;
        transcriptRetries.delete(id);
        transcripts.set(id, { fingerprint: fingerprint(detail), messages: detail.messages });
    }, () => {
        if (requested.get(id) === wanted) retryTranscript(id, wanted);
    }).finally(() => {
        if (requested.get(id) !== wanted) return;
        loading.delete(id);
        update();
    });
}

function resolveFocus() {
    if (!pendingFocus) return;
    const task = findAgentTask(pendingFocus);
    if (!task) return;
    pendingFocus = undefined;
    if (summaries.has(task.conversationId)) activeConversationId = task.conversationId;
}

function update() {
    resolveFocus();
    if (summaries.size && !summaries.has(activeConversationId)) activeConversationId = MAIN_CONVERSATION;
    syncTranscript();
    buildConversations();
    emit();
}

function applyState(state: AgentQueueState) {
    paused = state.paused;
    tasks = state.requests.map(toTask);
    history = state.history.map(toTask);
    summaries = new Map(state.conversations.map(summary => [summary.id, summary]));
    connectionRevision = state.connection_revision;
    for (const id of [...transcripts.keys()]) if (!summaries.has(id)) transcripts.delete(id);
    update();
}

function parse<T>(event: Event): T | null {
    const message = event as MessageEvent;
    if (message.lastEventId) lastEventId = message.lastEventId;
    try {
        return JSON.parse(message.data) as T;
    } catch {
        return null;
    }
}

function scheduleReconnect() {
    if (reconnectTimer !== null) return;
    const delay = RECONNECT_DELAYS_MS[Math.min(reconnectAttempt, RECONNECT_DELAYS_MS.length - 1)];
    reconnectAttempt += 1;
    reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        openStream();
    }, delay);
}

function closeStream() {
    source?.close();
    source = null;
}

function openStream() {
    if (source !== null || reconnectTimer !== null) return;
    const base = import.meta.env.VITE_API_URL + STREAM_PATH;
    const stream = createEventSource(lastEventId === null ? base : `${base}?last_event_id=${encodeURIComponent(lastEventId)}`);
    if (!stream) return;
    source = stream;
    const onState = (event: Event) => {
        const state = parse<AgentQueueState>(event);
        if (state) applyState(state);
    };
    stream.addEventListener('snapshot', event => {
        reconnectAttempt = 0;
        onState(event);
    });
    stream.addEventListener('queue', onState);
    stream.addEventListener('request_progress', event => {
        const frame = parse<{ conversation_id: string; live: AgentLiveTurn | null }>(event);
        const summary = frame && summaries.get(frame.conversation_id);
        if (!summary) return;
        summaries.set(summary.id, { ...summary, live: frame.live });
        update();
    });
    stream.addEventListener('conversation', event => {
        const summary = parse<AgentConversationSummary>(event);
        if (!summary) return;
        summaries.set(summary.id, summary);
        update();
    });
    stream.addEventListener('agent_write', event => {
        const frame = parse<{ tool: string }>(event);
        if (frame) window.dispatchEvent(new CustomEvent(AGENT_WRITE_EVENT, { detail: { tool: frame.tool } }));
    });
    stream.addEventListener('heartbeat', event => {
        parse(event);
        reconnectAttempt = 0;
    });
    // The server is going away; reconnecting resumes from the last event, or resnapshots.
    stream.addEventListener('bye', () => {
        closeStream();
        scheduleReconnect();
    });
    stream.onerror = () => {
        closeStream();
        scheduleReconnect();
    };
}

function teardown() {
    if (reconnectTimer !== null) clearTimeout(reconnectTimer);
    reconnectTimer = null;
    closeStream();
    reconnectAttempt = 0;
}

buildConversations();

// ---- useSyncExternalStore API ----

export const subscribeAgentQueue = (listener: () => void) => {
    listeners.add(listener);
    openStream();
    return () => {
        listeners.delete(listener);
        if (!listeners.size) teardown();
    };
};
/** Follow chat open requests only, without opening the queue stream. */
export const subscribeAgentChatRequest = (listener: () => void) => {
    chatListeners.add(listener);
    return () => { chatListeners.delete(listener); };
};

/** Active work only: running, waiting and failed requests. */
export const getAgentQueue = () => tasks;
/** Recently finished (done or cancelled) requests, oldest first. */
export const getAgentHistory = () => history;
export const getAgentConversations = () => conversations;
export const getAgentConversation = (id = MAIN_CONVERSATION) => conversations[id] ?? conversations[MAIN_CONVERSATION];
export const getActiveConversationId = () => activeConversationId;
/** Why the backend does not start requests, if it does not. */
export const getAgentQueuePaused = () => paused;
export const getAgentChatRequest = () => chatRequest;
/** Changes when the agent connection or model changed in any tab; undefined until the first snapshot. */
export const getAgentConnectionRevision = () => connectionRevision;
export const findAgentTask = (id: string) => tasks.find(task => task.id === id) ?? history.find(task => task.id === id);

export function setActiveConversation(id: string) {
    if (!conversations[id] || id === activeConversationId) return;
    activeConversationId = id;
    update();
}

export function conversationStatus(queue: AgentTask[], id: string): AgentConversationStatus {
    const own = queue.filter(task => task.conversationId === id);
    return own.find(task => task.status === 'failed') ? 'failed' : own.find(task => task.status === 'running') ? 'running'
        : own.some(task => task.status === 'queued') ? 'queued' : 'idle';
}

/** Open the agent chat from anywhere in the app, optionally on one request and its conversation. */
export function openAgentChat(taskId?: string, view: 'chat' | 'conversations' = 'chat') {
    pendingFocus = taskId;
    resolveFocus();
    chatRequest = { nonce: chatRequest.nonce + 1, taskId, view };
    syncTranscript();
    buildConversations();
    emitChatRequest();
}

export function clearAgentChatFocus() {
    if (!chatRequest.taskId) return;
    chatRequest = { ...chatRequest, taskId: undefined };
    emitChatRequest();
}

/** Where the first active request matching an AI action stands, positioned by the backend. */
export function agentActionState(queue: AgentTask[], matches: (task: AgentTask) => boolean): AgentActionState | undefined {
    const task = queue.find(matches);
    if (!task) return undefined;
    if (task.status === 'running' || task.status === 'failed') return { status: task.status, taskId: task.id };
    if (task.status !== 'queued') return undefined;
    return { status: 'queued', taskId: task.id, position: task.position ?? 1 };
}

/** Trim view lists the backend would reject (over 100 IDs); explicit assessment scope is never truncated. */
export function boundedAgentContext(context: AgentContext): AgentContext {
    const view = context.view;
    if (!view) return context;
    const { visibleVulnerabilityIds, visiblePackageIds, visibleScanIds, selectedExportKeys,
        enabledExportDocuments, selectedVariantIds, selectedVulnerabilityIds, matchingVariantIds } = view;
    const bounded = (ids?: string[]) => ids && ids.length > 100 ? undefined : ids;
    return { ...context, view: {
        ...view,
        visibleVulnerabilityIds: bounded(visibleVulnerabilityIds), visiblePackageIds: bounded(visiblePackageIds),
        visibleScanIds: bounded(visibleScanIds), selectedExportKeys: bounded(selectedExportKeys),
        enabledExportDocuments: bounded(enabledExportDocuments), selectedVariantIds: bounded(selectedVariantIds),
        selectedVulnerabilityIds: bounded(selectedVulnerabilityIds), matchingVariantIds: bounded(matchingVariantIds),
        visibleCount: visibleVulnerabilityIds || visiblePackageIds || visibleScanIds
            ? Math.max(visibleVulnerabilityIds?.length ?? 0, visiblePackageIds?.length ?? 0, visibleScanIds?.length ?? 0) : undefined,
        selectionCount: selectedExportKeys || selectedVariantIds || enabledExportDocuments || selectedVulnerabilityIds || matchingVariantIds
            ? Math.max(selectedExportKeys?.length ?? 0, selectedVariantIds?.length ?? 0, enabledExportDocuments?.length ?? 0,
                selectedVulnerabilityIds?.length ?? 0, matchingVariantIds?.length ?? 0) : undefined,
    } };
}

/**
 * Queue actions on the backend. Assess and review actions go to `'per-action'` (one new conversation per
 * action key); a message goes to the main conversation or an existing one. Actions whose key is already
 * waiting are reported in `skipped` with the request holding it. View lists over the backend limit are dropped.
 * Requests take the model selected on the server (persisted by the agent chat), resolved by the backend.
 */
export function enqueueAgentActions(actions: AgentAction[], options: EnqueueOptions) {
    const bounded = actions.map(action => action.kind !== 'message' && action.context
        ? { ...action, context: boundedAgentContext(action.context) } : action);
    return agentRequest<AgentQueueSubmitted>('/queue', {
        method: 'POST',
        body: JSON.stringify({
            conversation: options.conversation, source: options.source, actions: bounded,
            ...(options.context ? { context: boundedAgentContext(options.context) } : {}),
            ...(options.timeout ? { timeout: options.timeout } : {}),
        }),
    });
}

const requestPath = (id: string) => `/queue/requests/${encodeURIComponent(id)}`;

/** Remove a waiting or failed request. */
export async function removeAgentTask(id: string) {
    await agentRequest(requestPath(id), { method: 'DELETE' });
}

/** Stop a running request (it keeps what it saved), or remove a waiting one. */
export async function stopAgentTask(id: string) {
    await agentRequest(`${requestPath(id)}/stop`, { method: 'POST' });
}

export async function retryAgentTask(id: string) {
    await agentRequest(`${requestPath(id)}/retry`, { method: 'POST' });
}

/** Remove every waiting and failed request; running ones continue. */
export async function clearAgentQueue() {
    await agentRequest('/queue', { method: 'DELETE' });
}

/** Delete a finished action conversation, like removing a chat from its history. */
export async function deleteAgentConversation(id: string) {
    await agentRequest(`/conversations/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

/** Delete every finished action conversation. */
export async function clearFinishedConversations() {
    await agentRequest('/conversations', { method: 'DELETE' });
}

/** Start the main conversation afresh; action conversations keep their own transcripts. */
export async function resetAgentConversation() {
    await agentRequest('/conversations/main/reset', { method: 'POST' });
    activeConversationId = MAIN_CONVERSATION;
    update();
}

// ---- test seams ----

/** Replaces the EventSource factory. Returns a function restoring the default. */
export const __setEventSourceFactory = (factory: (url: string) => EventSource | null): (() => void) => {
    const previous = createEventSource;
    createEventSource = factory;
    return () => { createEventSource = previous; };
};

export const __resetAgentQueue = () => {
    teardown();
    listeners.clear();
    chatListeners.clear();
    tasks = [];
    history = [];
    paused = null;
    summaries = new Map();
    transcripts.clear();
    requested.clear();
    transcriptTimers.forEach(timer => clearTimeout(timer));
    transcriptTimers.clear();
    transcriptRetries.clear();
    loading.clear();
    lingering.clear();
    activeConversationId = MAIN_CONVERSATION;
    chatRequest = { nonce: 0 };
    pendingFocus = undefined;
    connectionRevision = undefined;
    lastEventId = null;
    buildConversations();
};

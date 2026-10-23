import { agentErrorMessage, agentRequest } from './agent';
import { prepareAssessmentReviewVerification } from '../helpers/aiAssessmentReview';
import { AGENT_MESSAGE_MAX_LENGTH, AGENT_WRITE_EVENT, type Activity, type AgentActionState, type AgentContext, type AgentMessage, type AgentUsage, type QueuedAgentMessage } from '../types/agent';

export const MAIN_CONVERSATION = 'main';
export const AGENT_CHAT_SOURCE = 'Agent chat';
/** Finished action conversations kept live on the backend (which caps active threads at 20). */
const LIVE_CONVERSATION_LIMIT = 12;
const HISTORY_LIMIT = 50;
export const agentActionLabels = { assess: 'Assess', review: 'Review', message: 'Message' } as const;

export type AgentTask = QueuedAgentMessage & {
    source: string;
    context: AgentContext;
    conversationId: string;
    status: 'queued' | 'running' | 'failed' | 'done';
    error?: string;
};
export type AgentConversation = {
    id: string;
    title: string;
    /** Backend thread for action conversations; the main conversation uses the root session. */
    threadId?: string;
    context?: AgentContext;
    messages: AgentMessage[];
    usage: AgentUsage;
    pendingMessage: string;
    pendingTaskId?: string;
    liveReply: string;
    activity: Activity[];
    progress: string;
    initialized: boolean;
    /** Released on the backend to stay within its thread limit; the transcript stays readable. */
    archived: boolean;
    createdAt: number;
    lastUsed: number;
};
/** Where a conversation stands, from the most to the least urgent of its requests. */
export type AgentConversationStatus = 'failed' | 'running' | 'queued' | 'idle';
type Connection = { ready: boolean; model: string };
/** A request to open the agent chat, optionally on one request of the AI queue. */
export type AgentChatRequest = { nonce: number; taskId?: string };

const emptyUsage = (): AgentUsage => ({ cost: null, input_tokens: null, output_tokens: null });
const newConversation = (id: string, title: string, extra: Partial<AgentConversation> = {}): AgentConversation => ({
    id, title, messages: [], usage: emptyUsage(), pendingMessage: '', liveReply: '', activity: [], progress: '',
    initialized: false, archived: false, createdAt: Date.now(), lastUsed: Date.now(), ...extra,
});
const mainConversation = () => newConversation(MAIN_CONVERSATION, AGENT_CHAT_SOURCE);

const listeners = new Set<() => void>();
let tasks: AgentTask[] = [];
let history: AgentTask[] = [];
let conversations: Record<string, AgentConversation> = { [MAIN_CONVERSATION]: mainConversation() };
let activeConversationId = MAIN_CONVERSATION;
let running = false;
let connection: Connection | undefined;
let chatRequest: AgentChatRequest = { nonce: 0 };
const emit = () => listeners.forEach(listener => listener());

export const subscribeAgentQueue = (listener: () => void) => {
    listeners.add(listener);
    return () => { listeners.delete(listener); };
};
/** Active work only: running, waiting and failed requests. */
export const getAgentQueue = () => tasks;
/** Requests completed since the connection or main conversation was last reset, oldest first. */
export const getAgentHistory = () => history;
export const getAgentConversations = () => conversations;
export const getAgentConversation = (id = MAIN_CONVERSATION) => conversations[id] ?? conversations[MAIN_CONVERSATION];
export const getActiveConversationId = () => activeConversationId;
export const getAgentChatRequest = () => chatRequest;
export const findAgentTask = (id: string) => tasks.find(task => task.id === id) ?? history.find(task => task.id === id);

export function setActiveConversation(id: string) {
    if (!conversations[id] || id === activeConversationId) return;
    activeConversationId = id;
    emit();
}

export function conversationStatus(queue: AgentTask[], id: string): AgentConversationStatus {
    const own = queue.filter(task => task.conversationId === id);
    return own.find(task => task.status === 'failed') ? 'failed' : own.find(task => task.status === 'running') ? 'running'
        : own.length ? 'queued' : 'idle';
}

/** Open the agent chat from anywhere in the app, optionally on one request and its conversation. */
export function openAgentChat(taskId?: string) {
    const task = taskId ? findAgentTask(taskId) : undefined;
    if (task && conversations[task.conversationId]) activeConversationId = task.conversationId;
    chatRequest = { nonce: chatRequest.nonce + 1, taskId: task?.id };
    emit();
}

export function clearAgentChatFocus() {
    if (!chatRequest.taskId) return;
    chatRequest = { nonce: chatRequest.nonce };
    emit();
}

/** Where the first active request matching an AI action stands; position counts from the next request to run. */
export function agentActionState(queue: AgentTask[], matches: (task: AgentTask) => boolean): AgentActionState | undefined {
    const task = queue.find(matches);
    if (!task || task.status === 'done') return undefined;
    if (task.status === 'running' || task.status === 'failed') return { status: task.status, taskId: task.id };
    return { status: 'queued', taskId: task.id, position: queue.filter(item => item.status !== 'running').indexOf(task) + 1 };
}

function updateConversation(id: string, update: Partial<AgentConversation>) {
    const current = conversations[id];
    if (!current) return;
    conversations = { ...conversations, [id]: { ...current, ...update } };
    emit();
}

export function initializeAgentConversation(messages: AgentMessage[], usage: AgentUsage) {
    if (conversations[MAIN_CONVERSATION].initialized) return;
    updateConversation(MAIN_CONVERSATION, { messages, usage, initialized: true });
}

/** Start the main conversation afresh; action conversations keep their own transcripts. */
export function resetAgentConversation() {
    conversations = { ...conversations, [MAIN_CONVERSATION]: { ...mainConversation(), initialized: true } };
    history = history.filter(task => task.conversationId !== MAIN_CONVERSATION);
    activeConversationId = MAIN_CONVERSATION;
    emit();
}

export function resetAgentQueue() {
    if (running) throw new Error('Wait for the running AI request to finish before changing the connection.');
    tasks = [];
    history = [];
    conversations = { [MAIN_CONVERSATION]: mainConversation() };
    activeConversationId = MAIN_CONVERSATION;
    connection = undefined;
    emit();
}

export function configureAgentQueue(next: Connection) {
    if (!next.ready) return;
    connection = next;
    void drain();
}

const conversationTitle = (message: QueuedAgentMessage) =>
    `${agentActionLabels[message.kind]} ${message.title.replace(/ · batch \d+ of \d+$/, '')}`;

/**
 * Queue requests into the single agent chat. Messages go to an existing conversation (the main one by default),
 * or with `'per-action'` each action key (an assessed vulnerability or reviewed assessment) gets a new conversation.
 */
export function enqueueAgentMessages(
    messages: QueuedAgentMessage[], context: AgentContext, source = AGENT_CHAT_SOURCE,
    conversation: string | 'per-action' = MAIN_CONVERSATION,
) {
    const ids = new Set(tasks.map(task => task.id));
    const keys = new Set(tasks.map(task => task.key));
    // Batches may deliberately share a key; deduplicate against existing work, not siblings.
    const added = messages.filter(message => !ids.has(message.id) && !keys.has(message.key));
    if (added.some(message => !message.text.trim() || message.text.length > AGENT_MESSAGE_MAX_LENGTH)) {
        throw new Error(`AI messages must contain between 1 and ${AGENT_MESSAGE_MAX_LENGTH} characters.`);
    }
    if (conversation !== 'per-action' && !conversations[conversation]) throw new Error('This conversation is no longer available.');
    const created: Record<string, AgentConversation> = {};
    const byKey = new Map<string, string>();
    const queued = added.map(message => {
        const taskContext = structuredClone(message.context ?? context);
        let conversationId = conversation;
        if (conversation === 'per-action') {
            conversationId = byKey.get(message.key) ?? crypto.randomUUID();
            if (!byKey.has(message.key)) {
                byKey.set(message.key, conversationId);
                created[conversationId] = newConversation(conversationId, conversationTitle(message), {
                    threadId: conversationId, context: taskContext, initialized: true,
                });
            }
        }
        return { ...message, context: taskContext, source, conversationId, status: 'queued' as const };
    });
    conversations = { ...conversations, ...created };
    tasks = [...tasks, ...queued];
    emit();
    void drain();
}

/** Drop action conversations whose only requests were removed before they ever ran. */
function discardUnstartedConversations() {
    const used = new Set(tasks.map(task => task.conversationId));
    const unused = Object.values(conversations).filter(item =>
        item.id !== MAIN_CONVERSATION && !used.has(item.id) && !item.messages.length);
    if (!unused.length) return;
    conversations = Object.fromEntries(Object.entries(conversations).filter(([id]) => !unused.some(item => item.id === id)));
    if (!conversations[activeConversationId]) activeConversationId = MAIN_CONVERSATION;
}

export function removeAgentTask(id: string) {
    const task = tasks.find(item => item.id === id);
    if (!task || task.status === 'running') return;
    tasks = tasks.filter(item => item.id !== id);
    discardUnstartedConversations();
    emit();
    void drain();
}

export function clearAgentQueue() {
    tasks = tasks.filter(task => task.status === 'running');
    discardUnstartedConversations();
    emit();
}

/** Delete a finished action conversation, like removing a chat from its history. */
export function deleteAgentConversation(id: string) {
    const target = conversations[id];
    if (!target || id === MAIN_CONVERSATION || tasks.some(task => task.conversationId === id)) return;
    conversations = Object.fromEntries(Object.entries(conversations).filter(([key]) => key !== id));
    history = history.filter(task => task.conversationId !== id);
    if (activeConversationId === id) activeConversationId = MAIN_CONVERSATION;
    emit();
    if (target.threadId && !target.archived) {
        agentRequest('/conversation', { method: 'DELETE', headers: { 'X-Agent-Thread': target.threadId } }).catch(() => undefined);
    }
}

/** Delete every finished action conversation. */
export function clearFinishedConversations() {
    Object.keys(conversations).forEach(deleteAgentConversation);
}

export function retryAgentTask(id: string) {
    tasks = tasks.map(task => task.id === id && task.status === 'failed' ? { ...task, status: 'queued', error: undefined } : task);
    emit();
    void drain();
}

/** Release the oldest idle action conversations so the backend never hits its thread limit. */
async function releaseIdleConversations() {
    const busy = new Set(tasks.map(task => task.conversationId));
    const idle = Object.values(conversations)
        .filter(item => item.threadId && !item.archived && item.id !== activeConversationId && !busy.has(item.id))
        .sort((a, b) => b.lastUsed - a.lastUsed)
        .slice(LIVE_CONVERSATION_LIMIT);
    for (const item of idle) {
        try {
            await agentRequest('/conversation', { method: 'DELETE', headers: { 'X-Agent-Thread': item.threadId! } });
            updateConversation(item.id, { archived: true });
        } catch {
            // Retried after the next completed request.
        }
    }
}

/** Trim view lists only; explicit assessment scope must never be truncated. */
function contextForTurn(context: AgentContext): AgentContext {
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

async function drain() {
    const task = tasks[0];
    if (running || !task || task.status === 'failed' || !connection?.ready) return;
    const { model } = connection;
    const id = task.conversationId;
    const target = conversations[id];
    const headers: Record<string, string> = target?.threadId ? { 'X-Agent-Thread': target.threadId } : {};
    running = true;
    tasks = tasks.map(item => item.id === task.id ? { ...item, status: 'running' } : item);
    emit();
    let currentMessageId = '';
    let activity: Activity[] = [];
    let succeeded = false;
    try {
        if (!target) throw new Error('This conversation is no longer available.');
        if (target.archived) throw new Error('This conversation was archived. Continue in the main conversation.');
        if (!target.initialized) {
            const state = await agentRequest<{ messages: AgentMessage[]; usage: AgentUsage }>('', { headers });
            if (!conversations[id].initialized) updateConversation(id, { messages: state.messages, usage: state.usage, initialized: true });
        }
        updateConversation(id, {
            pendingMessage: task.text, pendingTaskId: task.id, liveReply: '', activity: [], progress: 'Connecting to Copilot...',
        });
        if (task.kind === 'review' && !task.assessmentId) throw new Error('Missing assessment ID for review verification.');
        const verify = task.kind === 'review' ? await prepareAssessmentReviewVerification(task.assessmentId!) : undefined;
        const result = await agentRequest<{ reply: string; model: string; usage: AgentUsage }>('/messages', {
            method: 'POST', headers,
            body: JSON.stringify({ message: task.text, context: contextForTurn(task.context), model }),
        }, event => {
            if (event.type === 'status') updateConversation(id, { progress: event.text });
            if (event.type === 'delta') {
                const continued = currentMessageId === event.message_id;
                currentMessageId = event.message_id;
                updateConversation(id, {
                    liveReply: (continued ? conversations[id].liveReply : '') + event.text,
                    progress: 'Writing response...',
                });
            }
            if (event.type === 'tool_start') {
                activity = [...activity, { id: event.id, name: event.name, status: 'running' as const }].slice(-50);
                updateConversation(id, { activity, progress: 'Checking VulnScout...' });
            }
            if (event.type === 'tool_end') {
                const tool = activity.find(item => item.id === event.id)?.name;
                activity = activity.map(item => item.id === event.id ? { ...item, status: event.success ? 'done' : 'failed' } : item);
                updateConversation(id, { activity, progress: 'Preparing response...' });
                if (event.success && event.write) window.dispatchEvent(new CustomEvent(AGENT_WRITE_EVENT, { detail: { tool } }));
            }
        });
        updateConversation(id, {
            messages: [...conversations[id].messages,
                { role: 'user', content: task.text, taskId: task.id }, { role: 'assistant', content: result.reply, activity, taskId: task.id }],
            usage: result.usage, lastUsed: Date.now(),
        });
        await verify?.();
        tasks = tasks.filter(item => item.id !== task.id);
        history = [...history, { ...task, status: 'done' as const }].slice(-HISTORY_LIMIT);
        succeeded = true;
    } catch (reason) {
        const error = agentErrorMessage(reason);
        tasks = tasks.map(item => item.id === task.id ? { ...item, status: 'failed', error } : item);
    } finally {
        running = false;
        updateConversation(id, { pendingMessage: '', pendingTaskId: undefined });
        emit();
        if (succeeded) void releaseIdleConversations();
        void drain();
    }
}

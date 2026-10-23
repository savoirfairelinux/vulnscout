import { agentErrorMessage, agentRequest } from './agent';
import { prepareAssessmentReviewVerification } from '../helpers/aiAssessmentReview';
import { AGENT_MESSAGE_MAX_LENGTH, AGENT_WRITE_EVENT, type Activity, type AgentContext, type AgentMessage, type AgentUsage, type QueuedAgentMessage } from '../types/agent';

export type AgentTask = QueuedAgentMessage & {
    threadId?: string;
    source: string;
    context: AgentContext;
    status: 'queued' | 'running' | 'failed';
    error?: string;
};
type Conversation = {
    messages: AgentMessage[];
    usage: AgentUsage;
    pendingMessage: string;
    liveReply: string;
    activity: Activity[];
    progress: string;
    error: string;
};
type Connection = { ready: boolean; model: string };
const listeners = new Set<() => void>();
let tasks: AgentTask[] = [];
let running = false;
let cleaning = false;
let generation = 0;
let cleanupError = '';
const connections = new Map<string, Connection>();
const conversations = new Map<string, Conversation>();
const owners = new Map<string, number>();
const releasedThreads = new Set<string>();
let lastConnection: Connection | undefined;
const emptyConversation: Conversation = {
    messages: [], usage: { cost: null, input_tokens: null, output_tokens: null },
    pendingMessage: '', liveReply: '', activity: [], progress: '', error: '',
};
const threadKey = (threadId?: string) => threadId ?? '';
const emit = () => listeners.forEach(listener => listener());
export const subscribeAgentQueue = (listener: () => void) => {
    listeners.add(listener);
    return () => { listeners.delete(listener); };
};
export const getAgentQueue = () => tasks;
export const getAgentQueueError = () => cleanupError;
export const getAgentConversation = (threadId?: string) => conversations.get(threadKey(threadId)) ?? emptyConversation;

function updateConversation(threadId: string | undefined, update: Partial<Conversation>) {
    conversations.set(threadKey(threadId), { ...getAgentConversation(threadId), ...update });
    emit();
}

export function initializeAgentConversation(threadId: string | undefined, messages: AgentMessage[], usage: AgentUsage) {
    if (!conversations.has(threadKey(threadId))) updateConversation(threadId, { messages, usage });
}

export function resetAgentConversation(threadId?: string) {
    conversations.delete(threadKey(threadId));
    emit();
}

export function resetAgentQueue() {
    if (running) throw new Error('Wait for the running AI request to finish before changing the connection.');
    tasks = [];
    generation++;
    cleaning = false;
    cleanupError = '';
    releasedThreads.clear();
    connections.clear();
    conversations.clear();
    lastConnection = undefined;
    emit();
}

/** Keep closed chats only until their queued work no longer needs the SDK session. */
export function retainAgentThread(threadId: string) {
    owners.set(threadId, (owners.get(threadId) ?? 0) + 1);
    releasedThreads.delete(threadId);
    return () => {
        const remaining = (owners.get(threadId) ?? 1) - 1;
        if (remaining) owners.set(threadId, remaining);
        else {
            owners.delete(threadId);
            releasedThreads.add(threadId);
            const version = generation;
            queueMicrotask(() => { if (generation === version) void cleanReleasedThreads(); });
        }
    };
}

async function cleanReleasedThreads() {
    if (running || cleaning) return;
    cleaning = true;
    const version = generation;
    try {
        for (const threadId of releasedThreads) {
            if (owners.has(threadId) || tasks.some(task => task.threadId === threadId)) continue;
            try {
                if (conversations.has(threadId) || connections.has(threadId)) {
                    await agentRequest('/conversation', { method: 'DELETE', headers: { 'X-Agent-Thread': threadId } });
                }
                if (generation !== version) return;
                releasedThreads.delete(threadId);
                connections.delete(threadId);
                conversations.delete(threadId);
            } catch (reason) {
                if (generation !== version) return;
                cleanupError = `Could not release a closed agent conversation: ${agentErrorMessage(reason)}`;
                emit();
            }
        }
    } finally {
        if (generation === version) {
            if (!releasedThreads.size) cleanupError = '';
            cleaning = false;
            emit();
            void drain();
        }
    }
}

export function configureAgentQueue(threadId: string | undefined, connection: Connection) {
    if (!connection.ready) return;
    connections.set(threadKey(threadId), connection);
    lastConnection = connection;
    void drain();
}

export function enqueueAgentMessages(
    messages: QueuedAgentMessage[], context: AgentContext, threadId?: string, source = 'Global chat',
) {
    const ids = new Set(tasks.map(task => task.id));
    const keys = new Set(tasks.filter(task => task.threadId === threadId).map(task => task.key));
    // Batches may deliberately share a key; deduplicate against existing work, not siblings.
    const added = messages.filter(message => !ids.has(message.id) && !keys.has(message.key));
    if (added.some(message => !message.text.trim() || message.text.length > AGENT_MESSAGE_MAX_LENGTH)) {
        throw new Error(`AI messages must contain between 1 and ${AGENT_MESSAGE_MAX_LENGTH} characters.`);
    }
    tasks = [...tasks, ...added.map(message => ({
        ...message, context: structuredClone(message.context ?? context), threadId, source, status: 'queued' as const,
    }))];
    emit();
    void cleanReleasedThreads();
}

export function removeAgentTask(id: string) {
    const task = tasks.find(item => item.id === id);
    if (!task || task.status === 'running') return;
    tasks = tasks.filter(item => item.id !== id);
    if (task.status === 'failed') updateConversation(task.threadId, { error: '' });
    emit();
    void cleanReleasedThreads();
}

export function clearAgentQueue() {
    tasks.filter(task => task.status !== 'running').forEach(task => {
        if (task.status === 'failed') updateConversation(task.threadId, { error: '' });
    });
    tasks = tasks.filter(task => task.status === 'running');
    emit();
    void cleanReleasedThreads();
}

export function retryAgentTask(id: string) {
    tasks = tasks.map(task => task.id === id && task.status === 'failed' ? { ...task, status: 'queued', error: undefined } : task);
    emit();
    void drain();
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
    if (running || cleaning || !task || task.status === 'failed') return;
    const connection = connections.get(threadKey(task.threadId)) ?? lastConnection;
    if (!connection?.ready) return;
    running = true;
    tasks = tasks.map(item => item.id === task.id ? { ...item, status: 'running' } : item);
    emit();
    let currentMessageId = '';
    let activity: Activity[] = [];
    try {
        if (!conversations.has(threadKey(task.threadId))) {
            const state = await agentRequest<{ messages: AgentMessage[]; usage: AgentUsage }>('', {
                headers: task.threadId ? { 'X-Agent-Thread': task.threadId } : {},
            });
            initializeAgentConversation(task.threadId, state.messages, state.usage);
        }
        updateConversation(task.threadId, {
            pendingMessage: task.text, liveReply: '', activity: [], progress: 'Connecting to Copilot...', error: '',
        });
        if (task.kind === 'review' && !task.assessmentId) throw new Error('Missing assessment ID for review verification.');
        const verify = task.kind === 'review' ? await prepareAssessmentReviewVerification(task.assessmentId!) : undefined;
        const result = await agentRequest<{ reply: string; model: string; usage: AgentUsage }>('/messages', {
            method: 'POST', headers: task.threadId ? { 'X-Agent-Thread': task.threadId } : {},
            body: JSON.stringify({ message: task.text, context: contextForTurn(task.context), model: connection.model }),
        }, event => {
            if (event.type === 'status') updateConversation(task.threadId, { progress: event.text });
            if (event.type === 'delta') {
                const continued = currentMessageId === event.message_id;
                currentMessageId = event.message_id;
                updateConversation(task.threadId, {
                    liveReply: (continued ? getAgentConversation(task.threadId).liveReply : '') + event.text,
                    progress: 'Writing response...',
                });
            }
            if (event.type === 'tool_start') {
                activity = [...activity, { id: event.id, name: event.name, status: 'running' as const }].slice(-50);
                updateConversation(task.threadId, { activity, progress: 'Checking VulnScout...' });
            }
            if (event.type === 'tool_end') {
                const tool = activity.find(item => item.id === event.id)?.name;
                activity = activity.map(item => item.id === event.id ? { ...item, status: event.success ? 'done' : 'failed' } : item);
                updateConversation(task.threadId, { activity, progress: 'Preparing response...' });
                if (event.success && event.write) window.dispatchEvent(new CustomEvent(AGENT_WRITE_EVENT, { detail: { tool } }));
            }
        });
        updateConversation(task.threadId, {
            messages: [...getAgentConversation(task.threadId).messages,
                { role: 'user', content: task.text }, { role: 'assistant', content: result.reply, activity }],
            usage: result.usage,
        });
        await verify?.();
        tasks = tasks.filter(item => item.id !== task.id);
    } catch (reason) {
        const error = agentErrorMessage(reason);
        tasks = tasks.map(item => item.id === task.id ? { ...item, status: 'failed', error } : item);
        updateConversation(task.threadId, { error });
    } finally {
        running = false;
        updateConversation(task.threadId, { pendingMessage: '' });
        emit();
        void cleanReleasedThreads();
    }
}

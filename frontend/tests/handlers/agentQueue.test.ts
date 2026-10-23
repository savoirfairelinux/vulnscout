import {
    MAIN_CONVERSATION, agentActionState, clearAgentChatFocus, clearAgentQueue, clearFinishedConversations, configureAgentQueue, conversationStatus, deleteAgentConversation,
    enqueueAgentMessages, getActiveConversationId, getAgentChatRequest, getAgentConversation, getAgentConversations,
    getAgentHistory, getAgentQueue, openAgentChat, removeAgentTask, resetAgentConversation, resetAgentQueue, retryAgentTask,
    setActiveConversation,
} from '../../src/handlers/agentQueue';
import type { AgentContext, QueuedAgentMessage } from '../../src/types/agent';

const usage = { cost: null, input_tokens: null, output_tokens: null };
const context: AgentContext = { page: 'vulnerabilities', projectId: 'project', variantId: 'variant' };
const action = (id: string, extra: Partial<QueuedAgentMessage> = {}): QueuedAgentMessage =>
    ({ id, key: id, kind: 'message', title: id, text: id, ...extra });
const json = (data: unknown): Response => ({
    ok: true, headers: { get: () => 'application/json' }, json: async () => data,
}) as unknown as Response;
const finished = (reply: string) => json({ reply, model: 'auto', usage });
const settle = async () => { for (let i = 0; i < 40; i++) await Promise.resolve(); };
const threadOf = (options?: RequestInit) => (options?.headers as Record<string, string> | undefined)?.['X-Agent-Thread'];

beforeEach(() => resetAgentQueue());

test('runs requests one at a time, keeps chat messages in the main conversation and each action in its own', async () => {
    const sent: Array<{ message: string; context: AgentContext; thread?: string }> = [];
    let finish: (response: Response) => void = () => {};
    global.fetch = jest.fn(async (input, options) => {
        if (!String(input).endsWith('/messages')) return json({ messages: [], usage });
        const body = JSON.parse(String(options?.body));
        sent.push({ ...body, thread: threadOf(options) });
        if (sent.length === 1) return new Promise<Response>(resolve => { finish = resolve; });
        return finished(`Reply to ${body.message}`);
    });
    configureAgentQueue({ ready: true, model: 'auto' });
    const scope = { ...context, view: { selectedVulnerabilityIds: ['CVE-1'] } };
    enqueueAgentMessages([action('chat')], scope);
    enqueueAgentMessages([
        action('cve-1 batch 1', { kind: 'assess', key: 'assess:CVE-1', title: 'CVE-1 · 3 targets · batch 1 of 2' }),
        action('cve-1 batch 2', { kind: 'assess', key: 'assess:CVE-1', title: 'CVE-1 · 3 targets · batch 2 of 2' }),
        action('cve-2', { kind: 'assess', key: 'assess:CVE-2', title: 'CVE-2 · 1 target', context: { ...context, variantId: 'other' } }),
    ], context, 'Vulnerability selection', 'per-action');
    enqueueAgentMessages([action('review', { kind: 'review', key: 'review:a1', title: 'assessment a1', assessmentId: 'a1' })],
        { page: 'review' }, 'Review', 'per-action');
    scope.view.selectedVulnerabilityIds.push('CVE-2');
    await settle();

    expect(sent.map(item => item.message)).toEqual(['chat']);
    expect(getAgentQueue().map(item => [item.source, item.status])).toEqual([
        ['Agent chat', 'running'], ['Vulnerability selection', 'queued'], ['Vulnerability selection', 'queued'],
        ['Vulnerability selection', 'queued'], ['Review', 'queued'],
    ]);
    const conversations = Object.values(getAgentConversations()).filter(item => item.id !== MAIN_CONVERSATION);
    expect(conversations.map(item => item.title)).toEqual(['Assess CVE-1 · 3 targets', 'Assess CVE-2 · 1 target', 'Review assessment a1']);
    expect(conversations.every(item => item.threadId === item.id)).toBe(true);
    const [cve1, cve2] = conversations;
    expect(getAgentQueue().filter(item => item.kind === 'assess').map(item => item.conversationId)).toEqual([cve1.id, cve1.id, cve2.id]);
    expect(cve2.context?.variantId).toBe('other');
    expect(() => resetAgentQueue()).toThrow(/running AI request/);

    finish(finished('Chat result'));
    await settle();
    expect(sent.map(item => item.message)).toEqual(['chat', 'cve-1 batch 1', 'cve-1 batch 2', 'cve-2']);
    expect(sent.map(item => item.thread)).toEqual([undefined, cve1.id, cve1.id, cve2.id]);
    expect(sent[0].context.view?.selectedVulnerabilityIds).toEqual(['CVE-1']);
    expect(getAgentConversation().messages.map(message => message.content)).toEqual(['chat', 'Chat result']);
    expect(getAgentConversation(cve1.id).messages.map(message => message.content))
        .toEqual(['cve-1 batch 1', 'Reply to cve-1 batch 1', 'cve-1 batch 2', 'Reply to cve-1 batch 2']);
    expect(getAgentConversation(cve1.id).messages[0].taskId).toBe('cve-1 batch 1');
    // The review fails verification here (no saved reviews were mocked) and pauses the queue.
    expect(getAgentQueue().map(item => [item.id, item.status])).toEqual([['review', 'failed']]);
    expect(getAgentHistory().map(item => [item.id, item.status])).toEqual([
        ['chat', 'done'], ['cve-1 batch 1', 'done'], ['cve-1 batch 2', 'done'], ['cve-2', 'done'],
    ]);
});

test('follow-ups continue an action conversation on its thread and pause on failure until retried', async () => {
    let attempts = 0;
    const threads: Array<string | undefined> = [];
    global.fetch = jest.fn(async (input, options) => {
        if (!String(input).endsWith('/messages')) return json({ messages: [], usage });
        threads.push(threadOf(options));
        attempts++;
        if (attempts === 1) throw new TypeError('offline');
        return finished('Recovered');
    });
    configureAgentQueue({ ready: true, model: 'auto' });
    enqueueAgentMessages([action('assess', { kind: 'assess', key: 'assess:1', title: 'CVE-1' })], context, 'Vulnerability CVE-1', 'per-action');
    const conversationId = getAgentQueue()[0].conversationId;
    enqueueAgentMessages([action('follow-up')], context, 'Assess CVE-1', conversationId);
    await settle();
    expect(attempts).toBe(1);
    expect(getAgentQueue()[0]).toMatchObject({ id: 'assess', status: 'failed', error: expect.stringContaining('Connection lost') });
    expect(agentActionState(getAgentQueue(), task => task.key === 'assess:1')).toEqual({ status: 'failed', taskId: 'assess' });
    retryAgentTask('assess');
    await settle();
    expect(attempts).toBe(3);
    expect(threads).toEqual([conversationId, conversationId, conversationId]);
    expect(getAgentConversation(conversationId).messages.filter(message => message.role === 'user').map(message => message.content))
        .toEqual(['assess', 'follow-up']);
    expect(() => enqueueAgentMessages([action('missing')], context, 'x', 'unknown')).toThrow(/no longer available/);
});

test('removing a failed action resumes the queue and drops conversations that never started', async () => {
    let attempts = 0;
    global.fetch = jest.fn(async input => {
        if (!String(input).endsWith('/messages')) return json({ messages: [], usage });
        attempts++;
        if (attempts === 1) throw new TypeError('offline');
        return finished('Next');
    });
    configureAgentQueue({ ready: true, model: 'auto' });
    enqueueAgentMessages([action('first', { key: 'a' }), action('second', { key: 'b' }), action('third', { key: 'c' })],
        context, 'Vulnerability selection', 'per-action');
    await settle();
    expect(Object.keys(getAgentConversations())).toHaveLength(4);
    removeAgentTask('third');
    expect(Object.keys(getAgentConversations())).toHaveLength(3);
    removeAgentTask('first');
    await settle();
    expect(getAgentQueue()).toEqual([]);
    expect(attempts).toBe(2);
    expect(Object.values(getAgentConversations()).map(item => item.title)).toEqual(['Agent chat', 'Message second']);
});

test('clear keeps running work; finished conversations can be deleted; the main conversation resets independently', async () => {
    let finish: (response: Response) => void = () => {};
    global.fetch = jest.fn(async input => !String(input).endsWith('/messages') ? json({ messages: [], usage })
        : new Promise<Response>(resolve => { finish = resolve; }));
    configureAgentQueue({ ready: true, model: 'auto' });
    enqueueAgentMessages([action('running'), action('waiting')], context);
    await settle();
    clearAgentQueue();
    expect(getAgentQueue().map(item => item.id)).toEqual(['running']);
    finish(finished('Still completed'));
    await settle();
    expect(getAgentConversation().messages[1].content).toBe('Still completed');
    expect(getAgentHistory().map(item => item.id)).toEqual(['running']);
    resetAgentConversation();
    expect(getAgentConversation().messages).toEqual([]);
    expect(getAgentHistory()).toEqual([]);

    const released: Array<string | undefined> = [];
    global.fetch = jest.fn(async (input, options) => {
        if (options?.method === 'DELETE') released.push(threadOf(options));
        return String(input).endsWith('/messages') ? finished('ok') : json({ messages: [], usage });
    });
    enqueueAgentMessages([action('one', { key: 'k1' }), action('two', { key: 'k2' })], context, 'Bulk', 'per-action');
    await settle();
    const [one, two] = getAgentHistory().map(task => task.conversationId);
    expect(conversationStatus(getAgentQueue(), one)).toBe('idle');
    setActiveConversation(one);
    deleteAgentConversation(one);
    expect(getAgentConversations()[one]).toBeUndefined();
    expect(getActiveConversationId()).toBe(MAIN_CONVERSATION);
    deleteAgentConversation(MAIN_CONVERSATION);
    expect(getAgentConversations()[MAIN_CONVERSATION]).toBeDefined();
    clearFinishedConversations();
    await settle();
    expect(Object.keys(getAgentConversations())).toEqual([MAIN_CONVERSATION]);
    expect(released).toEqual([one, two]);
});

test('waits for a ready connection and loads the main conversation before its first request', async () => {
    global.fetch = jest.fn(async input => String(input).endsWith('/messages') ? finished('Done') : json({ messages: [{ role: 'user', content: 'old' }], usage }));
    enqueueAgentMessages([action('first')], context);
    configureAgentQueue({ ready: false, model: 'auto' });
    await settle();
    expect(global.fetch).not.toHaveBeenCalled();
    configureAgentQueue({ ready: true, model: 'auto' });
    await settle();
    expect(getAgentConversation().messages.map(message => message.content)).toEqual(['old', 'first', 'Done']);
    resetAgentConversation();
    enqueueAgentMessages([action('second')], context);
    await settle();
    expect(getAgentConversation().messages.map(message => message.content)).toEqual(['second', 'Done']);
});

test('reports action positions and opens the chat on the conversation of a started request', async () => {
    let finish: (response: Response) => void = () => {};
    global.fetch = jest.fn(async input => !String(input).endsWith('/messages') ? json({ messages: [], usage })
        : new Promise<Response>(resolve => { finish = resolve; }));
    configureAgentQueue({ ready: true, model: 'auto' });
    enqueueAgentMessages([action('a', { key: 'k1' }), action('b', { key: 'k2' }), action('c', { key: 'k3' })], context, 'Bulk', 'per-action');
    await settle();
    const queue = getAgentQueue();
    expect(agentActionState(queue, task => task.key === 'k1')).toEqual({ status: 'running', taskId: 'a' });
    expect(agentActionState(queue, task => task.key === 'k3')).toEqual({ status: 'queued', taskId: 'c', position: 2 });
    expect(agentActionState(queue, task => task.key === 'none')).toBeUndefined();

    expect(conversationStatus(queue, queue[0].conversationId)).toBe('running');
    expect(conversationStatus(queue, queue[2].conversationId)).toBe('queued');
    // Even a waiting request opens its own conversation in the chat.
    openAgentChat('c');
    expect(getActiveConversationId()).toBe(queue[2].conversationId);
    expect(getAgentChatRequest()).toMatchObject({ nonce: 1, taskId: 'c' });
    openAgentChat('a');
    expect(getActiveConversationId()).toBe(queue[0].conversationId);
    clearAgentChatFocus();
    expect(getAgentChatRequest()).toEqual({ nonce: 2 });
    openAgentChat();
    expect(getAgentChatRequest()).toEqual({ nonce: 3, taskId: undefined });
    setActiveConversation('missing');
    expect(getActiveConversationId()).toBe(queue[0].conversationId);
    clearAgentQueue();
    finish(finished('done'));
    await settle();
});

test('archives the oldest idle action conversations beyond the live limit, never the one on screen', async () => {
    const released: Array<string | undefined> = [];
    global.fetch = jest.fn(async (input, options) => {
        if (options?.method === 'DELETE') { released.push(threadOf(options)); return json({ messages: [], usage }); }
        return String(input).endsWith('/messages') ? finished('ok') : json({ messages: [], usage });
    });
    configureAgentQueue({ ready: true, model: 'auto' });
    const actions = Array.from({ length: 14 }, (_, index) => action(`a${index}`, { key: `k${index}` }));
    enqueueAgentMessages(actions.slice(0, 1), context, 'Bulk', 'per-action');
    await settle();
    const first = getAgentHistory()[0].conversationId;
    setActiveConversation(first);
    for (const item of actions.slice(1)) {
        enqueueAgentMessages([item], context, 'Bulk', 'per-action');
        await settle();
        await new Promise(resolve => setTimeout(resolve, 2));
    }
    await settle();
    const archived = Object.values(getAgentConversations()).filter(item => item.archived);
    expect(archived.map(item => item.title)).toEqual(['Message a1']);
    expect(released).toEqual([archived[0].threadId]);
    expect(getAgentConversation(first).archived).toBe(false);
    enqueueAgentMessages([action('late')], context, 'x', archived[0].id);
    await settle();
    expect(getAgentQueue()[0]).toMatchObject({ status: 'failed', error: expect.stringContaining('archived') });
});

test('deduplicates active work across sources without dropping sibling requests and rejects oversized input', () => {
    const batch = [action('batch-1'), { ...action('batch-2'), key: 'batch-1' }];
    enqueueAgentMessages(batch, context, 'Vulnerability selection', 'per-action');
    enqueueAgentMessages(batch, context, 'Vulnerability selection', 'per-action');
    enqueueAgentMessages([{ ...action('duplicate'), key: 'batch-1' }], context, 'Vulnerability CVE-1');
    expect(getAgentQueue().map(item => item.id)).toEqual(['batch-1', 'batch-2']);
    expect(new Set(getAgentQueue().map(item => item.conversationId)).size).toBe(1);
    expect(() => enqueueAgentMessages([{ ...action('oversized'), text: 'a'.repeat(8001) }], context)).toThrow(/8000/);
    expect(() => enqueueAgentMessages([{ ...action('empty'), text: ' ' }], context)).toThrow(/8000/);
});

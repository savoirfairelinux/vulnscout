import { configureAgentQueue, enqueueAgentMessages, getAgentConversation, getAgentQueue,
    clearAgentQueue, getAgentQueueError, removeAgentTask, resetAgentQueue, retainAgentThread, retryAgentTask } from '../../src/handlers/agentQueue';
import type { AgentContext, QueuedAgentMessage } from '../../src/types/agent';

const usage = { cost: null, input_tokens: null, output_tokens: null };
const context: AgentContext = { page: 'vulnerabilities', projectId: 'project', variantId: 'variant' };
const action = (id: string): QueuedAgentMessage => ({ id, key: id, kind: 'message', title: id, text: id });
const json = (data: unknown): Response => ({
    ok: true, headers: { get: () => 'application/json' }, json: async () => data,
}) as unknown as Response;
const finished = (reply: string) => json({ reply, model: 'auto', usage });
const settle = async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); };

beforeEach(() => resetAgentQueue());

test('serializes global, bulk, review and vulnerability chats and freezes each request scope', async () => {
    const sent: Array<{ message: string; context: AgentContext; thread?: string }> = [];
    let finish: (response: Response) => void = () => {};
    global.fetch = jest.fn(async (input, options) => {
        if (!String(input).endsWith('/messages')) return json({ messages: [], usage });
        const body = JSON.parse(String(options?.body));
        sent.push({ ...body, thread: (options?.headers as Record<string, string>)['X-Agent-Thread'] });
        if (sent.length === 1) return new Promise<Response>(resolve => { finish = resolve; });
        return finished(body.message);
    });
    configureAgentQueue(undefined, { ready: true, model: 'auto' });
    const scope = { ...context, view: { selectedVulnerabilityIds: ['CVE-1'] } };
    enqueueAgentMessages([action('global')], scope);
    enqueueAgentMessages([action('bulk')], { ...context, variantId: 'bulk-variant' }, 'bulk', 'Bulk assessment chat');
    enqueueAgentMessages([action('review')], { page: 'review' }, 'review', 'Review chat');
    enqueueAgentMessages([action('vulnerability')], context, 'vulnerability', 'Vulnerability CVE-1');
    scope.view.selectedVulnerabilityIds.push('CVE-2');
    await settle();
    expect(sent.map(item => item.message)).toEqual(['global']);
    expect(getAgentQueue().map(item => item.status)).toEqual(['running', 'queued', 'queued', 'queued']);
    expect(() => resetAgentQueue()).toThrow(/running AI request/);
    removeAgentTask('global');
    expect(getAgentQueue()).toHaveLength(4);
    finish(finished('Global result'));
    await settle();
    expect(sent.map(item => item.message)).toEqual(['global', 'bulk', 'review', 'vulnerability']);
    expect(sent.map(item => item.thread)).toEqual([undefined, 'bulk', 'review', 'vulnerability']);
    expect(sent[0].context.view?.selectedVulnerabilityIds).toEqual(['CVE-1']);
    expect(sent[1].context.variantId).toBe('bulk-variant');
    expect(getAgentQueue()).toEqual([]);
    expect(getAgentConversation('bulk').messages[1].content).toBe('bulk');
});

test('pauses all chats on failure and supports retry and removal from any window', async () => {
    let attempts = 0;
    global.fetch = jest.fn(async input => {
        if (!String(input).endsWith('/messages')) return json({ messages: [], usage });
        attempts++;
        if (attempts === 1) throw new TypeError('offline');
        return finished('Recovered');
    });
    configureAgentQueue(undefined, { ready: true, model: 'auto' });
    enqueueAgentMessages([action('first')], context, 'bulk');
    enqueueAgentMessages([action('second')], context, 'vulnerability');
    await settle();
    expect(attempts).toBe(1);
    expect(getAgentQueue()[0]).toMatchObject({ id: 'first', status: 'failed', error: expect.stringContaining('Connection lost') });
    retryAgentTask('first');
    await settle();
    expect(attempts).toBe(3);
    expect(getAgentQueue()).toEqual([]);
});

test('clear preserves running work and does not require an originating chat to remain mounted', async () => {
    let finish: (response: Response) => void = () => {};
    global.fetch = jest.fn(async input => !String(input).endsWith('/messages') ? json({ messages: [], usage })
        : new Promise<Response>(resolve => { finish = resolve; }));
    configureAgentQueue('closed-chat', { ready: true, model: 'auto' });
    enqueueAgentMessages([action('running'), action('waiting')], context, 'closed-chat');
    await settle();
    clearAgentQueue();
    expect(getAgentQueue().map(item => item.id)).toEqual(['running']);
    finish(finished('Still completed'));
    await settle();
    expect(getAgentConversation('closed-chat').messages[1].content).toBe('Still completed');
    expect(getAgentQueue()).toEqual([]);
});

test('deduplicates active batches without dropping sibling requests and rejects oversized input', () => {
    const batch = [action('batch-1'), { ...action('batch-2'), key: 'batch-1' }];
    enqueueAgentMessages(batch, context, 'thread');
    enqueueAgentMessages(batch, context, 'thread');
    enqueueAgentMessages([{ ...action('duplicate'), key: 'batch-1' }], context, 'thread');
    expect(getAgentQueue().map(item => item.id)).toEqual(['batch-1', 'batch-2']);
    expect(() => enqueueAgentMessages([{ ...action('oversized'), text: 'a'.repeat(8001) }], context)).toThrow(/8000/);
    expect(() => enqueueAgentMessages([{ ...action('empty'), text: ' ' }], context)).toThrow(/8000/);
});

test('releases an unmounted chat only after its last queued request, without exceeding backend thread capacity', async () => {
    const requests: Array<{ path: string; method?: string }> = [];
    let finish: (response: Response) => void = () => {};
    global.fetch = jest.fn(async (input, options) => {
        requests.push({ path: String(input), method: options?.method });
        if (String(input).endsWith('/messages')) return new Promise<Response>(resolve => { finish = resolve; });
        return json({ messages: [], usage });
    });
    const release = retainAgentThread('closed');
    configureAgentQueue('closed', { ready: true, model: 'auto' });
    enqueueAgentMessages([action('work')], context, 'closed');
    await settle();
    release();
    await settle();
    expect(requests.some(request => request.method === 'DELETE')).toBe(false);
    finish(finished('Completed before cleanup'));
    await settle();
    expect(getAgentQueue()).toEqual([]);
    expect(requests.filter(request => request.method === 'DELETE')).toEqual([{ path: '/api/agent/conversation', method: 'DELETE' }]);
    expect(getAgentConversation('closed').messages).toEqual([]);
    expect(getAgentQueueError()).toBe('');
});

test('keeps closed failed threads available for retry and reports cleanup errors explicitly', async () => {
    let failCleanup = true;
    global.fetch = jest.fn(async (input, options) => {
        if (options?.method === 'DELETE' && failCleanup) throw new TypeError('offline');
        if (String(input).endsWith('/messages')) throw new TypeError('offline');
        return json({ messages: [], usage });
    });
    const release = retainAgentThread('failed');
    configureAgentQueue('failed', { ready: true, model: 'auto' });
    enqueueAgentMessages([action('work')], context, 'failed');
    await settle();
    release();
    await settle();
    expect(getAgentQueue()[0].status).toBe('failed');
    expect(global.fetch).not.toHaveBeenCalledWith('/api/agent/conversation', expect.objectContaining({ method: 'DELETE' }));
    removeAgentTask('work');
    await settle();
    expect(getAgentQueueError()).toContain('Could not release a closed agent conversation');
    failCleanup = false;
    clearAgentQueue();
    await settle();
    expect(getAgentQueueError()).toBe('');
});

test('balances multiple owners and ignores StrictMode-style release and reattach', async () => {
    global.fetch = jest.fn(async () => json({ messages: [], usage }));
    const first = retainAgentThread('shared');
    const second = retainAgentThread('shared');
    configureAgentQueue('shared', { ready: true, model: 'auto' });
    first();
    await settle();
    expect(global.fetch).not.toHaveBeenCalled();
    second();
    const reattached = retainAgentThread('shared');
    await settle();
    expect(global.fetch).not.toHaveBeenCalled();
    reattached();
    await settle();
    expect(global.fetch).toHaveBeenCalledTimes(1);
});

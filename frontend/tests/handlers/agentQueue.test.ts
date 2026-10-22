import { configureAgentQueue, enqueueAgentMessages, getAgentConversation, getAgentQueue,
    clearAgentQueue, removeAgentTask, resetAgentQueue, retryAgentTask } from '../../src/handlers/agentQueue';
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

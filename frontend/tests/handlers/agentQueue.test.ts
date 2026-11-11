/**
 * The agent queue store mirrors the backend AI queue over its event stream.
 *
 * Frames are delivered through a stand-in EventSource; the queue routes are mocked on fetch.
 */
import {
    MAIN_CONVERSATION, RECONNECT_DELAYS_MS, __resetAgentQueue, __setEventSourceFactory, agentActionState, boundedAgentContext,
    clearAgentChatFocus, clearAgentQueue, clearFinishedConversations, conversationStatus,
    deleteAgentConversation, enqueueAgentActions, findAgentTask, getActiveConversationId, getAgentChatRequest,
    getAgentConnectionRevision, getAgentConversation, getAgentConversations, getAgentHistory, getAgentQueue, getAgentQueuePaused, openAgentChat,
    removeAgentTask, resetAgentConversation, retryAgentTask, setActiveConversation, stopAgentTask, subscribeAgentChatRequest,
    subscribeAgentQueue,
} from '../../src/handlers/agentQueue';
import {
    AGENT_WRITE_EVENT, type AgentConversationSummary, type AgentQueueState, type AgentRequestRecord,
} from '../../src/types/agent';

class FakeEventSource {
    static instances: FakeEventSource[] = [];
    readonly url: string;
    closed = false;
    onerror: (() => void) | null = null;
    private readonly handlers = new Map<string, Array<(event: MessageEvent) => void>>();

    constructor(url: string) {
        this.url = url;
        FakeEventSource.instances.push(this);
    }

    addEventListener(type: string, handler: (event: MessageEvent) => void) {
        this.handlers.set(type, [...(this.handlers.get(type) ?? []), handler]);
    }

    close() {
        this.closed = true;
    }

    send(type: string, data: unknown, id?: string) {
        const event = { data: typeof data === 'string' ? data : JSON.stringify(data), lastEventId: id ?? '' } as MessageEvent;
        (this.handlers.get(type) ?? []).forEach(handler => handler(event));
    }

    static latest() {
        return FakeEventSource.instances[FakeEventSource.instances.length - 1];
    }
}

const usage = { cost: null, input_tokens: null, output_tokens: null };
const request = (id: string, extra: Partial<AgentRequestRecord> = {}): AgentRequestRecord => ({
    id, key: `message:${id}`, kind: 'message', lane: 'chat', conversation_id: MAIN_CONVERSATION, source: 'Agent chat',
    title: id, detail: '', model: 'auto', status: 'queued', error: null, error_code: null, position: 1, created_at: 1,
    started_at: null, finished_at: null, context: null, text: id, vuln_id: null, assessment_id: null, timeout: 900,
    result: null, ...extra,
});
const conversation = (id: string, extra: Partial<AgentConversationSummary> = {}): AgentConversationSummary => ({
    id, title: id === MAIN_CONVERSATION ? 'Agent chat' : `Assess ${id}`, kind: id === MAIN_CONVERSATION ? 'main' : 'action',
    profile: null, archived: false, created_at: 10, last_used: 20, message_count: 0, usage, live: null, ...extra,
});
const state = (extra: Partial<AgentQueueState> = {}): AgentQueueState & { epoch: string; seq: number } => ({
    epoch: 'e', seq: 1, paused: null, requests: [], history: [], connection_revision: 0, conversations: [conversation(MAIN_CONVERSATION)], ...extra,
});
const json = (data: unknown, status = 200): Response => ({
    ok: status < 400, status, headers: { get: () => 'application/json' }, json: async () => data,
}) as unknown as Response;
const settle = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };

let restoreFactory: () => void;
let fetchMock: jest.Mock;
let unsubscribe: (() => void) | undefined;

beforeEach(() => {
    __resetAgentQueue();
    FakeEventSource.instances = [];
    restoreFactory = __setEventSourceFactory(url => new FakeEventSource(url) as unknown as EventSource);
    fetchMock = jest.fn(async () => json({}));
    global.fetch = fetchMock;
});

afterEach(() => {
    unsubscribe?.();
    unsubscribe = undefined;
    restoreFactory();
    jest.useRealTimers();
});

const connect = (snapshot = state()) => {
    const listener = jest.fn();
    unsubscribe = subscribeAgentQueue(listener);
    FakeEventSource.latest().send('snapshot', snapshot, 'e:1');
    return listener;
};

test('mirrors the snapshot and its deltas', () => {
    expect(getAgentConversation().id).toBe(MAIN_CONVERSATION);
    const listener = connect(state({
        paused: { code: 'not_ready', reason: 'Sign in first.' },
        requests: [
            request('r1', { status: 'running', position: null, conversation_id: 'c1', kind: 'assess', key: 'assess:CVE-1:',
                vuln_id: 'CVE-1', detail: 'pkg', error: null, context: { page: 'vulnerabilities', projectId: 'p' }, lane: 'action' }),
            request('r2', { status: 'queued', position: 2 }),
            request('r3', { status: 'failed', position: null, error: 'boom', error_code: 'agent_error' }),
        ],
        history: [request('old', { status: 'done', position: null })],
        conversations: [conversation('c1', { created_at: 5 }), conversation(MAIN_CONVERSATION)],
    }));
    expect(FakeEventSource.latest().url).toBe('http://localhost/api/agent/queue/stream');
    expect(listener).toHaveBeenCalled();
    expect(getAgentQueuePaused()).toEqual({ code: 'not_ready', reason: 'Sign in first.' });
    expect(getAgentQueue().map(task => [task.id, task.status, task.position])).toEqual([
        ['r1', 'running', undefined], ['r2', 'queued', 2], ['r3', 'failed', undefined],
    ]);
    expect(getAgentQueue()[0]).toMatchObject({ vulnId: 'CVE-1', detail: 'pkg', conversationId: 'c1' });
    expect(getAgentQueue()[2]).toMatchObject({ error: 'boom', errorCode: 'agent_error' });
    expect(getAgentHistory().map(task => task.id)).toEqual(['old']);
    expect(findAgentTask('old')?.status).toBe('done');
    expect(Object.keys(getAgentConversations())).toEqual([MAIN_CONVERSATION, 'c1']);
    expect(getAgentConversation('c1')).toMatchObject({ kind: 'action', context: { page: 'vulnerabilities', projectId: 'p' },
        createdAt: 5000, lastUsed: 20000 });
    expect(getAgentConversation('missing').id).toBe(MAIN_CONVERSATION);

    FakeEventSource.latest().send('queue', { ...state(), requests: [request('r2', { status: 'running', position: null })] }, 'e:2');
    expect(getAgentQueue().map(task => task.id)).toEqual(['r2']);
    expect(getAgentQueuePaused()).toBeNull();
    expect(getAgentConversations().c1).toBeUndefined();

    FakeEventSource.latest().send('queue', 'not json', 'e:3');
    expect(getAgentQueue().map(task => task.id)).toEqual(['r2']);
});

test('shows a running turn as it progresses and loads the transcript once it is saved', async () => {
    const messages = [{ role: 'user', content: 'hi' }, { role: 'assistant', content: 'hello' }];
    let resolveDetail: (response: Response) => void = () => {};
    fetchMock.mockImplementation(() => new Promise<Response>(resolve => { resolveDetail = resolve; }));
    connect();
    const live = { request_id: 'r1', pending_message: 'hi', live_reply: 'hel', activity: [], progress: 'Thinking' };
    FakeEventSource.latest().send('request_progress', { request_id: 'r1', conversation_id: MAIN_CONVERSATION, live });
    expect(getAgentConversation()).toMatchObject({ pendingMessage: 'hi', pendingTaskId: 'r1', liveReply: 'hel', progress: 'Thinking' });
    FakeEventSource.latest().send('request_progress', { request_id: 'r1', conversation_id: 'unknown', live });

    FakeEventSource.latest().send('conversation', conversation(MAIN_CONVERSATION, { message_count: 2 }));
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe('/api/agent/conversations/main');
    // The finished turn stays visible until its transcript arrives.
    expect(getAgentConversation()).toMatchObject({ pendingMessage: 'hi', messages: [] });
    FakeEventSource.latest().send('conversation', conversation(MAIN_CONVERSATION, { message_count: 2 }));
    expect(fetchMock).toHaveBeenCalledTimes(1);

    resolveDetail(json({ ...conversation(MAIN_CONVERSATION, { message_count: 2 }), messages }));
    await settle();
    expect(getAgentConversation()).toMatchObject({ pendingMessage: '', liveReply: '', messageCount: 2 });
    expect(getAgentConversation().messages.map(message => message.content)).toEqual(['hi', 'hello']);

    // A reset main conversation (new created_at, no messages) clears the transcript without fetching.
    FakeEventSource.latest().send('conversation', conversation(MAIN_CONVERSATION, { created_at: 30 }));
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(getAgentConversation().messages).toEqual([]);
    FakeEventSource.latest().send('conversation', 'bad');
});

test('fetches only the active conversation transcript and retries a failed fetch a few times', async () => {
    jest.useFakeTimers();
    fetchMock.mockResolvedValue(json({ error: 'nope' }, 404));
    connect(state({ conversations: [conversation(MAIN_CONVERSATION), conversation('c1', { message_count: 2 })] }));
    expect(fetchMock).not.toHaveBeenCalled();
    setActiveConversation('c1');
    setActiveConversation('c1');
    setActiveConversation('unknown');
    expect(getActiveConversationId()).toBe('c1');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe('/api/agent/conversations/c1');
    await settle();
    FakeEventSource.latest().send('queue', state({ conversations: [conversation(MAIN_CONVERSATION), conversation('c1', { message_count: 2 })] }));
    expect(fetchMock).toHaveBeenCalledTimes(1);  // a snapshot does not bypass the retry delay
    for (const delay of RECONNECT_DELAYS_MS) {
        jest.advanceTimersByTime(delay);
        await settle();
    }
    expect(fetchMock).toHaveBeenCalledTimes(1 + RECONNECT_DELAYS_MS.length);
    jest.advanceTimersByTime(60_000);
    expect(fetchMock).toHaveBeenCalledTimes(1 + RECONNECT_DELAYS_MS.length);  // then it gives up
    expect(getAgentConversation('c1').messages).toEqual([]);

    // A deleted active conversation falls back to the main one.
    FakeEventSource.latest().send('queue', state());
    expect(getActiveConversationId()).toBe(MAIN_CONVERSATION);
});

test('a failed transcript fetch recovers once the server answers', async () => {
    jest.useFakeTimers();
    const messages = [{ role: 'user', content: 'hi' }];
    fetchMock.mockResolvedValueOnce(json({ error: 'busy' }, 503))
        .mockResolvedValueOnce(json({ ...conversation(MAIN_CONVERSATION, { message_count: 1 }), messages }));
    connect(state({ conversations: [conversation(MAIN_CONVERSATION, { message_count: 1 })] }));
    await settle();
    expect(getAgentConversation().messages).toEqual([]);
    jest.advanceTimersByTime(RECONNECT_DELAYS_MS[0]);
    await settle();
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(getAgentConversation().messages.map(message => message.content)).toEqual(['hi']);
});

test('a stale transcript response never overwrites a newer one', async () => {
    const resolvers: Array<(response: Response) => void> = [];
    fetchMock.mockImplementation(() => new Promise<Response>(resolve => { resolvers.push(resolve); }));
    connect(state({ conversations: [conversation(MAIN_CONVERSATION, { message_count: 1 })] }));
    FakeEventSource.latest().send('conversation', conversation(MAIN_CONVERSATION, { message_count: 2 }));
    expect(resolvers).toHaveLength(2);
    const two = [{ role: 'user', content: 'hi' }, { role: 'assistant', content: 'hello' }];
    resolvers[1](json({ ...conversation(MAIN_CONVERSATION, { message_count: 2 }), messages: two }));
    await settle();
    resolvers[0](json({ ...conversation(MAIN_CONVERSATION, { message_count: 1 }), messages: two.slice(0, 1) }));
    await settle();
    expect(getAgentConversation().messages.map(message => message.content)).toEqual(['hi', 'hello']);
});

test('follows the connection revision', () => {
    expect(getAgentConnectionRevision()).toBeUndefined();
    connect(state({ connection_revision: 3 }));
    expect(getAgentConnectionRevision()).toBe(3);
    FakeEventSource.latest().send('queue', state({ connection_revision: 4 }), 'e:2');
    expect(getAgentConnectionRevision()).toBe(4);
});

test('relays agent writes to the window', () => {
    const seen = jest.fn();
    window.addEventListener(AGENT_WRITE_EVENT, seen);
    connect();
    FakeEventSource.latest().send('agent_write', { tool: 'write_assessment', request_id: 'r1', conversation_id: 'c1' });
    window.removeEventListener(AGENT_WRITE_EVENT, seen);
    expect((seen.mock.calls[0][0] as CustomEvent).detail).toEqual({ tool: 'write_assessment' });
});

test('reconnects with backoff from the last event and stops when nobody listens', () => {
    jest.useFakeTimers();
    connect();
    const first = FakeEventSource.latest();
    first.send('heartbeat', {}, 'e:4');
    first.onerror?.();
    expect(first.closed).toBe(true);
    expect(FakeEventSource.instances).toHaveLength(1);
    jest.advanceTimersByTime(RECONNECT_DELAYS_MS[0]);
    const second = FakeEventSource.latest();
    expect(second.url).toBe('http://localhost/api/agent/queue/stream?last_event_id=e%3A4');

    second.onerror?.();
    jest.advanceTimersByTime(RECONNECT_DELAYS_MS[0]);
    expect(FakeEventSource.instances).toHaveLength(2);
    jest.advanceTimersByTime(RECONNECT_DELAYS_MS[1] - RECONNECT_DELAYS_MS[0]);
    const third = FakeEventSource.latest();
    expect(FakeEventSource.instances).toHaveLength(3);

    third.send('bye', {});
    expect(third.closed).toBe(true);
    unsubscribe?.();
    unsubscribe = undefined;
    jest.advanceTimersByTime(RECONNECT_DELAYS_MS[RECONNECT_DELAYS_MS.length - 1]);
    expect(FakeEventSource.instances).toHaveLength(3);
});

test('does nothing without an EventSource', () => {
    restoreFactory();
    restoreFactory = __setEventSourceFactory(() => null);
    const listener = jest.fn();
    unsubscribe = subscribeAgentQueue(listener);
    expect(getAgentQueue()).toEqual([]);
    expect(getAgentConversation().title).toBe('Agent chat');
});

test('posts actions with the bounded context and no model', async () => {
    fetchMock.mockResolvedValue(json({ requests: [{ id: 'r1', key: 'k', conversation_id: 'c1' }], skipped: [] }, 202));
    const many = Array.from({ length: 101 }, (_, index) => `CVE-${index}`);
    const context = { page: 'vulnerabilities', view: { visibleVulnerabilityIds: many, selectedVulnerabilityIds: ['CVE-1'] } };
    const result = await enqueueAgentActions([
        { kind: 'assess', vuln_id: 'CVE-1', context },
        { kind: 'review', assessment_id: 'a1' },
        { kind: 'message', text: 'hi' },
    ], { conversation: 'per-action', source: 'Test', context, timeout: 60 });
    expect(result.requests[0].id).toBe('r1');
    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/agent/queue');
    expect(options.method).toBe('POST');
    const body = JSON.parse(options.body);
    expect(body).toMatchObject({ conversation: 'per-action', source: 'Test', timeout: 60 });
    expect(body.model).toBeUndefined();
    expect(body.context.view).toMatchObject({ selectedVulnerabilityIds: ['CVE-1'], selectionCount: 1, visibleCount: 101 });
    expect(body.context.view.visibleVulnerabilityIds).toBeUndefined();
    expect(body.actions[0].context.view.visibleVulnerabilityIds).toBeUndefined();
    expect(body.actions[1]).toEqual({ kind: 'review', assessment_id: 'a1' });

    fetchMock.mockResolvedValue(json({ error: 'Unknown vulnerability.' }, 400));
    await expect(enqueueAgentActions([{ kind: 'message', text: 'x' }], { conversation: MAIN_CONVERSATION, source: 'Chat' }))
        .rejects.toThrow('Unknown vulnerability.');
    const second = JSON.parse(fetchMock.mock.calls[1][1].body);
    expect(second).toEqual({ conversation: MAIN_CONVERSATION, source: 'Chat', actions: [{ kind: 'message', text: 'x' }] });
});

test('bounds only oversized view lists', () => {
    expect(boundedAgentContext({ page: 'review' })).toEqual({ page: 'review' });
    expect(boundedAgentContext({ page: 'packages', view: { visiblePackageIds: ['a'], search: 'x' } }).view)
        .toEqual(expect.objectContaining({ visiblePackageIds: ['a'], visibleCount: 1, selectionCount: undefined, search: 'x' }));
});

test('changes the queue through its routes', async () => {
    fetchMock.mockImplementation(async (url: string) => url.endsWith('/main/reset') ? json(conversation(MAIN_CONVERSATION)) : json({}));
    connect(state({ conversations: [conversation(MAIN_CONVERSATION), conversation('c 1')] }));
    setActiveConversation('c 1');
    await removeAgentTask('r/1');
    await stopAgentTask('r1');
    await retryAgentTask('r1');
    await clearAgentQueue();
    await deleteAgentConversation('c 1');
    await clearFinishedConversations();
    await resetAgentConversation();
    expect(fetchMock.mock.calls.map(([url, options]) => [options?.method, url])).toEqual([
        ['DELETE', '/api/agent/queue/requests/r%2F1'],
        ['POST', '/api/agent/queue/requests/r1/stop'],
        ['POST', '/api/agent/queue/requests/r1/retry'],
        ['DELETE', '/api/agent/queue'],
        ['DELETE', '/api/agent/conversations/c%201'],
        ['DELETE', '/api/agent/conversations'],
        ['POST', '/api/agent/conversations/main/reset'],
    ]);
    expect(getActiveConversationId()).toBe(MAIN_CONVERSATION);

    fetchMock.mockResolvedValue({ ok: false, status: 502, headers: { get: () => 'text/html' } } as unknown as Response);
    await expect(stopAgentTask('r1')).rejects.toThrow(/Agent service unavailable/);
    fetchMock.mockResolvedValue(json({}, 409));
    await expect(retryAgentTask('r1')).rejects.toThrow('Agent request failed (409)');
});

test('opens the chat on a request once the stream reports it', () => {
    const chat = jest.fn();
    const stopChat = subscribeAgentChatRequest(chat);
    connect(state({ conversations: [conversation(MAIN_CONVERSATION), conversation('c1')] }));
    expect(FakeEventSource.instances).toHaveLength(1);

    openAgentChat('r1');
    expect(chat).toHaveBeenCalledTimes(1);
    expect(getAgentChatRequest()).toEqual({ nonce: 1, taskId: 'r1', view: 'chat' });
    expect(getActiveConversationId()).toBe(MAIN_CONVERSATION);
    FakeEventSource.latest().send('queue', state({
        requests: [request('r1', { conversation_id: 'c1' })],
        conversations: [conversation(MAIN_CONVERSATION), conversation('c1')],
    }));
    expect(getActiveConversationId()).toBe('c1');

    clearAgentChatFocus();
    clearAgentChatFocus();
    expect(getAgentChatRequest()).toEqual({ nonce: 1, taskId: undefined, view: 'chat' });
    openAgentChat(undefined, 'conversations');
    expect(getAgentChatRequest()).toEqual({ nonce: 2, taskId: undefined, view: 'conversations' });
    expect(chat).toHaveBeenCalledTimes(3);
    stopChat();
});

test('reports where actions and conversations stand', () => {
    connect(state({
        requests: [
            request('run', { status: 'running', position: null, key: 'a', conversation_id: 'c1' }),
            request('wait', { status: 'queued', position: 3, key: 'b', conversation_id: 'c2' }),
            request('fail', { status: 'failed', position: null, key: 'c', conversation_id: 'c3' }),
            request('nopos', { status: 'queued', position: null, key: 'd', conversation_id: 'c3' }),
        ],
        history: [request('done', { status: 'done', key: 'e' })],
    }));
    const queue = getAgentQueue();
    expect(agentActionState(queue, task => task.key === 'a')).toEqual({ status: 'running', taskId: 'run' });
    expect(agentActionState(queue, task => task.key === 'b')).toEqual({ status: 'queued', taskId: 'wait', position: 3 });
    expect(agentActionState(queue, task => task.key === 'c')).toEqual({ status: 'failed', taskId: 'fail' });
    expect(agentActionState(queue, task => task.key === 'd')).toEqual({ status: 'queued', taskId: 'nopos', position: 1 });
    expect(agentActionState(getAgentHistory(), task => task.key === 'e')).toBeUndefined();
    expect(agentActionState(queue, task => task.key === 'z')).toBeUndefined();
    expect(['c1', 'c2', 'c3', 'c4'].map(id => conversationStatus(queue, id))).toEqual(['running', 'queued', 'failed', 'idle']);
});

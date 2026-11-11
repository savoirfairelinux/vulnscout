import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
// @ts-expect-error TS6133
import React from 'react';

import AgentChat from '../../src/components/AgentChat';
import { bulkAssessmentKeyPrefix } from '../../src/helpers/aiAssessment';
import { AGENT_WRITE_EVENT } from '../../src/types/agent';
import type {
    AgentAction, AgentContext, AgentConversationSummary, AgentLiveTurn, AgentMessage, AgentQueuePaused, AgentRequestRecord,
} from '../../src/types/agent';
import { __resetAgentQueue, __setEventSourceFactory, getAgentQueue, openAgentChat } from '../../src/handlers/agentQueue';

const usage = { cost: null, input_tokens: null, output_tokens: null };
const signedIn = { authenticated: true, login: 'tester', configured: true, device_login: true,
    token_connected: true, messages: [], model: 'auto', usage };
const signedOut = { ...signedIn, authenticated: false, token_connected: false, login: null };
const context: AgentContext = { page: 'vulnerabilities', projectId: 'project', variantId: 'variant',
    view: { visibleVulnerabilityIds: ['CVE-2024-1234'] } };
const models = { models: [{ id: 'auto', name: 'Auto' }] };

function jsonResponse(data: unknown, status = 200): Response {
    return { ok: status < 400, status, headers: { get: () => 'application/json' }, json: async () => data } as unknown as Response;
}

/** A stand-in for the backend AI queue: the stream every tab follows, its requests, conversations and routes. */
type Posted = { conversation: string; source: string; context?: AgentContext; actions: AgentAction[] };
let handlers = new Map<string, (event: MessageEvent) => void>();
let records: AgentRequestRecord[] = [];
let finished: AgentRequestRecord[] = [];
let summaries: AgentConversationSummary[] = [];
let transcripts: Record<string, AgentMessage[]> = {};
let paused: AgentQueuePaused | null = null;
let connectionRevision = 0;
let posted: Posted[] = [];
let routes: string[] = [];
let restoreEventSource = () => undefined as void;

const summary = (id: string, title: string, extra: Partial<AgentConversationSummary> = {}): AgentConversationSummary => ({
    id, title, kind: id === 'main' ? 'main' : 'action', profile: null, archived: false, created_at: 1, last_used: 1,
    message_count: 0, usage, live: null, ...extra,
});
const record = (id: string, extra: Partial<AgentRequestRecord> = {}): AgentRequestRecord => ({
    id, key: `message:${id}`, kind: 'message', lane: 'chat', conversation_id: 'main', source: 'Agent chat', title: id, detail: '',
    model: 'auto', status: 'queued', error: null, error_code: null, position: null, created_at: 1, started_at: null,
    finished_at: null, context: null, text: id, vuln_id: null, assessment_id: null, timeout: 900, result: null, ...extra,
});
const deliver = (type: string, data: unknown) => act(() => {
    handlers.get(type)?.({ data: JSON.stringify(data), lastEventId: '' } as MessageEvent);
});
const publish = () => {
    const positions: Record<string, number> = {};
    records = records.map(item => ({ ...item, position: item.status === 'queued' ? (positions[item.lane] = (positions[item.lane] ?? 0) + 1) : null }));
    deliver('queue', { paused, requests: records, history: finished, conversations: summaries, connection_revision: connectionRevision });
};
/** Hold requests (and their action conversations) on the backend. */
const hold = (...items: AgentRequestRecord[]) => {
    for (const item of items) {
        if (!summaries.some(conversation => conversation.id === item.conversation_id)) {
            summaries.push(summary(item.conversation_id, `${item.kind === 'assess' ? 'Assess' : 'Review'} ${item.title}`));
        }
    }
    records = [...records, ...items];
    publish();
};
const setStatus = (id: string, status: AgentRequestRecord['status'], error: string | null = null) => {
    const item = { ...[...records, ...finished].find(entry => entry.id === id)!, status, error };
    records = records.filter(entry => entry.id !== id);
    finished = finished.filter(entry => entry.id !== id);
    if (status === 'done' || status === 'cancelled') finished.push(item); else records.push(item);
    publish();
};
const updateConversation = (id: string, change: Partial<AgentConversationSummary>) => {
    summaries = summaries.map(item => item.id === id ? { ...item, ...change } : item);
    return summaries.find(item => item.id === id)!;
};
/** Report the running turn of a conversation, as the backend streams it. */
const progress = (id: string, live: AgentLiveTurn | null) => {
    updateConversation(id, { live });
    deliver('request_progress', { request_id: live?.request_id, conversation_id: id, live });
};
/** Save a conversation's transcript; the store fetches it once its message count changes. */
const saveTranscript = (id: string, messages: AgentMessage[], extra: Partial<AgentConversationSummary> = {}) => {
    transcripts[id] = messages;
    deliver('conversation', updateConversation(id, { live: null, message_count: messages.length, ...extra }));
};

function accept(body: Posted) {
    const created: AgentRequestRecord[] = [];
    const skipped: Array<{ key: string; request_id: string }> = [];
    const batch = posted.length - 1;
    for (const action of body.actions) {
        const key = action.key ?? (action.kind === 'assess' ? `assess:${action.vuln_id}:` : `message:${batch}`);
        const held = records.find(item => item.key === key);
        if (held) {
            skipped.push({ key, request_id: held.id });
            continue;
        }
        const id = `req-${batch}-${created.length}`;
        created.push(action.kind === 'message'
            ? record(id, { key, conversation_id: body.conversation, source: body.source, text: action.text, title: action.text })
            : action.kind === 'assess' ? record(id, { key, kind: 'assess', lane: 'action', conversation_id: `conv-${id}`, source: body.source,
                title: action.vuln_id, text: `Assess ${action.vuln_id}`, vuln_id: action.vuln_id, context: body.context ?? null })
                : record(id, { key, kind: 'review', lane: 'action', conversation_id: `conv-${id}`, source: body.source }));
    }
    hold(...created);
    return { requests: created.map(item => ({ id: item.id, key: item.key, conversation_id: item.conversation_id })), skipped };
}

/** Serve the agent API from the fake backend; `custom` answers first when it returns a response. */
function serve(state: object = signedIn, custom: (path: string, options?: RequestInit) => Response | Promise<Response> | undefined = () => undefined) {
    global.fetch = (async (input: RequestInfo | URL, options?: RequestInit) => {
        const path = String(input);
        const method = options?.method ?? 'GET';
        const answer = custom(path, options);
        if (answer) return answer;
        if (path === '/api/agent/queue' && method === 'POST') {
            const body = JSON.parse(String(options?.body)) as Posted;
            posted.push(body);
            return jsonResponse(accept(body), 202);
        }
        const request = path.match(/^\/api\/agent\/queue\/requests\/([^/]+)(\/stop|\/retry)?$/);
        if (request || method !== 'GET' && (path === '/api/agent/queue' || path.startsWith('/api/agent/conversations'))) routes.push(`${method} ${path}`);
        if (request) {
            const [, id, action] = request;
            if (action === '/stop') setStatus(id, 'cancelled');
            else if (action === '/retry') setStatus(id, 'queued');
            else {
                records = records.filter(item => item.id !== id);
                publish();
            }
            return jsonResponse({ status: action === '/stop' ? 'stopping' : action === '/retry' ? 'queued' : 'removed' });
        }
        if (path === '/api/agent/queue' && method === 'DELETE') {
            records = records.filter(item => item.status === 'running');
            publish();
            return jsonResponse({ removed: [] });
        }
        if (path === '/api/agent/conversations/main/reset') {
            transcripts.main = [];
            updateConversation('main', { created_at: 2, message_count: 0 });
            publish();
            return jsonResponse({ status: 'reset' });
        }
        if (path.startsWith('/api/agent/conversations') && method === 'DELETE') {
            const id = path.split('/')[4];
            summaries = summaries.filter(item => id ? item.id !== id : item.id === 'main' || records.some(task => task.conversation_id === item.id));
            publish();
            return jsonResponse({ status: 'deleted' });
        }
        if (path.startsWith('/api/agent/conversations/')) {
            const id = decodeURIComponent(path.split('/')[4]);
            return jsonResponse({ ...summaries.find(item => item.id === id), messages: transcripts[id] ?? [] });
        }
        if (path.endsWith('/models')) return jsonResponse(models);
        return jsonResponse(state);
    }) as typeof fetch;
}

/** Render the chat and deliver the backend snapshot once it follows the stream. */
function renderChat(chatContext: AgentContext = context, onClose = () => undefined) {
    const view = render(<AgentChat onClose={onClose} context={chatContext} />);
    publish();
    return view;
}

beforeEach(() => {
    __resetAgentQueue();
    handlers = new Map();
    records = [];
    finished = [];
    summaries = [summary('main', 'Agent chat')];
    transcripts = {};
    paused = null;
    connectionRevision = 0;
    posted = [];
    routes = [];
    restoreEventSource = __setEventSourceFactory(() => ({
        addEventListener: (type: string, handler: (event: MessageEvent) => void) => handlers.set(type, handler),
        close: () => undefined,
        onerror: null,
    }) as unknown as EventSource);
});
afterEach(() => {
    restoreEventSource();
    jest.useRealTimers();
});

test('device flow polls at the interval returned by the server', async () => {
    jest.useFakeTimers();
    const requests: string[] = [];
    global.fetch = async input => {
        const path = String(input);
        requests.push(path);
        if (path.endsWith('/auth/poll')) return jsonResponse(requests.filter(item => item.endsWith('/auth/poll')).length === 1
            ? { status: 'pending', interval: 2 } : { status: 'connected', login: 'tester' });
        if (path.endsWith('/auth')) return jsonResponse({ user_code: 'ABCD-EFGH', verification_uri: 'https://github.com/login/device', interval: 1 });
        if (path.endsWith('/models')) return jsonResponse(models);
        return jsonResponse(signedOut);
    };

    render(<AgentChat onClose={() => undefined} context={context} />);
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByText('Step 1 of 3')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    fireEvent.click(screen.getByRole('button', { name: /sign in with github/i }));
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByText('Step 3 of 3')).toBeInTheDocument();
    expect(screen.getByText('ABCD-EFGH')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Start using' })).toBeDisabled();
    await act(async () => { jest.advanceTimersByTime(1000); await Promise.resolve(); });
    expect(requests.filter(item => item.endsWith('/auth/poll'))).toHaveLength(1);
    await act(async () => { jest.advanceTimersByTime(1000); await Promise.resolve(); });
    expect(requests.filter(item => item.endsWith('/auth/poll'))).toHaveLength(1);
    await act(async () => { jest.advanceTimersByTime(1000); await Promise.resolve(); });
    expect(requests.filter(item => item.endsWith('/auth/poll'))).toHaveLength(2);
    expect(screen.getByText('Connection verified')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Start using' }));
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByRole('button', { name: 'Configure model provider' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Sign out' })).not.toBeInTheDocument();
});

test('connects a local provider when already signed in and restores the GitHub account on disconnect', async () => {
    const connections: { provider: string; base_url: string; api_key: string }[] = [];
    let connected = false;
    global.fetch = async (input, options) => {
        const path = String(input);
        if (path.endsWith('/provider') && options?.method === 'POST') {
            connections.push(JSON.parse(String(options.body)));
            connected = true;
            return jsonResponse({ provider: 'local', model: '' });
        }
        if (path.endsWith('/provider') && options?.method === 'DELETE') {
            connected = false;
            return jsonResponse({ provider: null, model: 'auto' });
        }
        if (path.endsWith('/models')) return jsonResponse(connected ? {
            models: [{ id: 'Qwen/Qwen3-Coder', name: 'Qwen/Qwen3-Coder' }],
        } : models);
        return jsonResponse(connected ? { ...signedIn, provider: 'local', login: null,
            token_connected: false, model: '' } : signedIn);
    };

    render(<AgentChat onClose={() => undefined} context={context} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Configure model provider' }));
    fireEvent.click(screen.getByRole('radio', { name: /local model/i }));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.queryByRole('textbox', { name: 'Provider model' })).not.toBeInTheDocument();
    expect(screen.queryByRole('textbox', { name: 'Provider API base URL' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Use custom endpoint URL/ }));
    fireEvent.change(screen.getByRole('textbox', { name: 'Provider API base URL' }), { target: { value: 'http://localhost:11434/v1' } });
    fireEvent.click(screen.getByRole('button', { name: 'Verify connection' }));
    expect(await screen.findByText('Connection verified')).toBeInTheDocument();
    expect(connections).toEqual([{ provider: 'local', base_url: 'http://localhost:11434/v1', api_key: '' }]);
    fireEvent.click(screen.getByRole('button', { name: 'Start using' }));
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Agent model' })).toHaveValue(''));
    expect(screen.getByRole('textbox', { name: 'Message the agent' })).toBeDisabled();
    fireEvent.change(screen.getByRole('combobox', { name: 'Agent model' }), { target: { value: 'Qwen/Qwen3-Coder' } });
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Agent model' })).toHaveValue('Qwen/Qwen3-Coder'));
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Message the agent' })).toBeEnabled());
    expect(screen.queryByRole('button', { name: 'Disconnect provider' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Configure model provider' }));
    fireEvent.click(screen.getByRole('button', { name: 'Disconnect provider' }));
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Agent model' })).toHaveValue('auto'));
    fireEvent.click(screen.getByRole('button', { name: 'Configure model provider' }));
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeInTheDocument();
});

test('waiting requests stay on the backend through a connection change; a running one blocks it', async () => {
    const changes: string[] = [];
    serve(signedIn, (path, options) => {
        if (path.endsWith('/provider') || path.endsWith('/auth')) {
            changes.push(`${options?.method} ${path}`);
            return jsonResponse({ provider: 'openai', model: 'auto', cleanup_error: null });
        }
        return undefined;
    });
    renderChat();
    hold(record('waiting', { kind: 'assess', lane: 'action', conversation_id: 'conv-waiting', title: 'CVE-1' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Configure model provider' }));
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeEnabled();

    setStatus('waiting', 'running');
    expect(screen.getByRole('button', { name: 'Sign out' })).toBeDisabled();
    fireEvent.click(screen.getByRole('radio', { name: /^openai/i }));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    fireEvent.change(screen.getByLabelText('Provider API key'), { target: { value: 'test-key' } });
    fireEvent.click(screen.getByRole('button', { name: 'Verify connection' }));
    expect(screen.getByRole('alert')).toHaveTextContent('Wait for the running AI request to finish, or stop it, before changing the connection.');
    expect(changes).toEqual([]);

    setStatus('waiting', 'queued');
    fireEvent.click(screen.getByRole('button', { name: 'Verify connection' }));
    await screen.findByText('Connection verified');
    expect(changes).toEqual(['POST /api/agent/provider']);
    expect(getAgentQueue()).toEqual([expect.objectContaining({ id: 'waiting', status: 'queued' })]);
    expect(routes).toEqual([]);
});

test('reloads the connection and model when another tab changes them', async () => {
    const choices = { models: [{ id: 'auto', name: 'Auto' }, { id: 'gpt-5', name: 'GPT-5' }] };
    let model = 'auto';
    serve(signedIn, path => path.endsWith('/models') ? jsonResponse(choices)
        : path === '/api/agent' ? jsonResponse({ ...signedIn, model }) : undefined);
    renderChat();
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Agent model' })).toHaveValue('auto'));
    model = 'gpt-5';
    publish();
    expect(screen.getByRole('combobox', { name: 'Agent model' })).toHaveValue('auto');
    connectionRevision += 1;
    publish();
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Agent model' })).toHaveValue('gpt-5'));
});

test('connector wizard shows only the selected authentication fields', async () => {
    global.fetch = async input => String(input).endsWith('/models') ? jsonResponse(models) : jsonResponse(signedOut);

    render(<AgentChat onClose={() => undefined} context={context} />);
    await screen.findByText('Select a connector');
    expect(screen.getByRole('radio', { name: /github copilot/i })).toBeChecked();
    expect(screen.getByRole('button', { name: 'Back' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByRole('button', { name: 'Sign in with GitHub' })).toBeInTheDocument();
    expect(screen.queryByLabelText('Provider API key')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Back' }));
    fireEvent.click(screen.getByRole('radio', { name: /microsoft foundry/i }));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.queryByRole('textbox', { name: 'Provider model' })).not.toBeInTheDocument();
    expect(screen.getByLabelText('Provider API key')).toBeRequired();
    expect(screen.queryByRole('textbox', { name: 'Provider API base URL' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Use custom endpoint URL/ }));
    expect(screen.getByRole('textbox', { name: 'Provider API base URL' })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Back' }));
    fireEvent.click(screen.getByRole('radio', { name: /anthropic/i }));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByLabelText('Provider API key')).toBeRequired();
    expect(screen.queryByRole('textbox', { name: 'Provider API base URL' })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Back' }));
    fireEvent.click(screen.getByRole('radio', { name: /local model/i }));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByLabelText('Provider API key')).not.toBeRequired();
    expect(screen.getByRole('button', { name: /Use custom endpoint URL \(required\)/ })).toBeInTheDocument();
});

test('keeps model selection above both views and exposes sign-out only through the plug', async () => {
    const requests: string[] = [];
    const modelRequests: unknown[] = [];
    global.fetch = async (input, options) => {
        const path = String(input);
        if (path.endsWith('/models')) return jsonResponse({ models: [...models.models, { id: 'gpt-6-sol', name: 'GPT 6.0 Sol' }] });
        if (path.endsWith('/model') && options?.method === 'POST') {
            modelRequests.push(JSON.parse(String(options.body)));
            return jsonResponse({ model: 'gpt-6-sol' });
        }
        if (path.endsWith('/auth') && options?.method === 'DELETE') {
            requests.push(path);
            return jsonResponse({ cleanup_error: null });
        }
        return jsonResponse(signedIn);
    };
    const { container } = render(<AgentChat context={context} onClose={() => undefined} />);
    const model = await screen.findByRole('combobox', { name: 'Agent model' });
    expect(container.querySelector('header')).not.toContainElement(model);
    expect(screen.getByRole('textbox', { name: 'Message the agent' }).closest('form')).not.toContainElement(model);
    fireEvent.click(screen.getByRole('button', { name: 'AI queue (0)' }));
    expect(screen.getByRole('combobox', { name: 'Agent model' })).toBe(model);
    fireEvent.change(model, { target: { value: 'gpt-6-sol' } });
    await waitFor(() => expect(model).toBeEnabled());
    expect(model).toHaveValue('gpt-6-sol');
    expect(modelRequests).toEqual([{ model: 'gpt-6-sol' }]);
    fireEvent.click(screen.getByRole('button', { name: 'Back to conversation' }));
    expect(screen.queryByRole('button', { name: 'Sign out' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Configure model provider' }));
    expect(screen.queryByRole('combobox', { name: 'Agent model' })).not.toBeInTheDocument();
    expect(screen.getByText('GitHub Copilot · tester')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    await screen.findByText('Select a connector');
    expect(requests).toEqual(['/api/agent/auth']);
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Configure model provider' })).not.toBeInTheDocument());
});

test('queues a message in the main conversation and follows its turn from the stream, with Stop', async () => {
    serve();
    renderChat();
    await screen.findByRole('button', { name: 'Summarize vulnerabilities' });
    fireEvent.change(screen.getByRole('textbox', { name: 'Message the agent' }), { target: { value: 'Assess this' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0]).toEqual({ conversation: 'main', source: 'Agent chat', actions: [{ kind: 'message', text: 'Assess this' }],
        context: expect.objectContaining({ page: 'vulnerabilities', projectId: 'project', variantId: 'variant' }) });
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Message the agent' })).toHaveValue(''));
    const log = within(screen.getByRole('log', { name: 'Agent conversation' }));
    expect(log.getByRole('status')).toHaveTextContent('Waiting in the AI queue · #1');
    expect(screen.queryByRole('checkbox', { name: /allow changes/i })).not.toBeInTheDocument();

    setStatus('req-0-0', 'running');
    progress('main', { request_id: 'req-0-0', pending_message: 'Assess this', live_reply: 'First ',
        activity: [{ id: 'call', name: 'get_vulnerability', status: 'running' }], progress: 'Reading the vulnerability' });
    expect(log.getByText('Assess this')).toBeInTheDocument();
    expect(log.getByText('get vulnerability')).toBeInTheDocument();
    expect(log.getByText('First')).toBeInTheDocument();
    expect(log.getByRole('status')).toHaveTextContent('Reading the vulnerability');
    expect(screen.getByTestId('ai-queue-walking')).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Agent model' })).toBeDisabled();
    fireEvent.click(log.getByRole('button', { name: 'Stop' }));
    await waitFor(() => expect(routes).toEqual(['POST /api/agent/queue/requests/req-0-0/stop']));

    saveTranscript('main', [{ role: 'user', content: 'Assess this', taskId: 'req-0-0' },
        { role: 'assistant', content: 'First answer', taskId: 'req-0-0', activity: [{ id: 'call', name: 'get_vulnerability', status: 'done' }] }]);
    expect(await log.findByText('First answer')).toBeInTheDocument();
    expect(log.queryByRole('button', { name: 'Stop' })).not.toBeInTheDocument();
    expect(screen.getByTestId('ai-queue-idle')).toBeInTheDocument();
});

test('text typed while a message is being queued stays in the composer', async () => {
    let release = () => {};
    const held = new Promise<void>(resolve => { release = resolve; });
    serve(signedIn, (path, options) => {
        if (path !== '/api/agent/queue' || options?.method !== 'POST') return undefined;
        const body = JSON.parse(String(options.body)) as Posted;
        posted.push(body);
        return held.then(() => jsonResponse(accept(body), 202));
    });
    renderChat();
    await screen.findByRole('button', { name: 'Summarize vulnerabilities' });
    const composer = screen.getByRole('textbox', { name: 'Message the agent' });
    fireEvent.change(composer, { target: { value: 'First' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));
    await waitFor(() => expect(posted).toHaveLength(1));
    fireEvent.change(composer, { target: { value: 'Second, typed meanwhile' } });
    await act(async () => release());
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Waiting in the AI queue · #1'));
    expect(composer).toHaveValue('Second, typed meanwhile');
});

test('sends every selected variant so the backend enforces the displayed scope', async () => {
    const variantIds = Array.from({ length: 60 }, (_, index) => `variant-${index}`);
    serve();
    renderChat({ page: 'metrics', projectId: 'project', variantIds });
    const input = await screen.findByRole('textbox', { name: 'Message the agent' });
    await waitFor(() => expect(input).toBeEnabled());
    fireEvent.change(input, { target: { value: 'Summarize' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].context?.variantIds).toEqual(variantIds);
    expect(posted[0].context).not.toHaveProperty('variantCount');
});

test('notifies views of each write the backend reports', async () => {
    const writes: string[] = [];
    const onWrite = (event: Event) => writes.push((event as CustomEvent<{ tool: string }>).detail.tool);
    window.addEventListener(AGENT_WRITE_EVENT, onWrite);
    serve();
    try {
        renderChat();
        await screen.findByRole('button', { name: 'Summarize vulnerabilities' });
        deliver('agent_write', { tool: 'write_assessment', request_id: 'req', conversation_id: 'main' });
        expect(writes).toEqual(['write_assessment']);
    } finally {
        window.removeEventListener(AGENT_WRITE_EVENT, onWrite);
    }
});

test('reset discards the main transcript on the backend but retains the connection', async () => {
    serve();
    transcripts.main = [{ role: 'user', content: 'Previous question' }, { role: 'assistant', content: 'Previous answer' }];
    updateConversation('main', { message_count: 2 });
    window.localStorage.setItem('vulnscout.agent.skipDiscardConfirmation', 'true');

    renderChat();
    await screen.findByText('Previous question');
    fireEvent.click(screen.getByRole('button', { name: 'New conversation' }));
    await waitFor(() => expect(screen.queryByText('Previous question')).not.toBeInTheDocument());
    expect(routes).toEqual(['POST /api/agent/conversations/main/reset']);
    expect(screen.getByRole('button', { name: 'Configure model provider' })).toBeInTheDocument();
});

test('the connector setup replaces the conversation instead of pushing it down', async () => {
    serve();
    transcripts.main = [{ role: 'user', content: 'Previous question' }];
    updateConversation('main', { message_count: 1 });

    renderChat();
    expect(await screen.findByText('Previous question')).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Configure model provider' }));
    expect(screen.getByRole('region', { name: 'Agent connection setup' })).toHaveTextContent('Select a connector');
    expect(screen.queryByRole('log', { name: 'Agent conversation' })).not.toBeInTheDocument();
    expect(screen.getByText('Previous question')).not.toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Configure model provider' }));
    expect(screen.queryByRole('region', { name: 'Agent connection setup' })).not.toBeInTheDocument();
    expect(screen.getByRole('log', { name: 'Agent conversation' })).toHaveTextContent('Previous question');
});

test('a failed request stays in its conversation with retry and remove, without blocking the composer', async () => {
    serve();
    renderChat();
    hold(record('failed', { text: 'Continue', status: 'failed', error: 'Response interrupted' }),
        record('next', { kind: 'assess', lane: 'action', conversation_id: 'conv-next', title: 'CVE-2' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Response interrupted');
    expect(within(screen.getByRole('log', { name: 'Agent conversation' })).getByText('Continue')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'AI queue (2), failed' })).toBeInTheDocument();
    await screen.findByRole('textbox', { name: 'Message the agent' });
    // The next request runs regardless of the failed one.
    expect(screen.getByTestId('ai-queue-walking')).toBeInTheDocument();
    // The queue does not open on its own; it is only shown from the header button.
    expect(screen.queryByRole('navigation', { name: 'Conversations' })).not.toBeInTheDocument();
    const composer = screen.getByRole('textbox', { name: 'Message the agent' });
    await waitFor(() => expect(composer).toBeEnabled());
    fireEvent.change(composer, { target: { value: 'Something else' } });
    expect(screen.getByRole('button', { name: 'Send message' })).toBeEnabled();

    fireEvent.click(screen.getByRole('button', { name: 'Retry failed action' }));
    await waitFor(() => expect(routes).toEqual(['POST /api/agent/queue/requests/failed/retry']));
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    setStatus('failed', 'failed', 'Provider unavailable');
    fireEvent.click(await screen.findByRole('button', { name: 'Remove failed action' }));
    await waitFor(() => expect(routes).toContain('DELETE /api/agent/queue/requests/failed'));
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'AI queue (1)' })).toBeInTheDocument();
});

test('a failed mutation reports its error', async () => {
    serve(signedIn, (path, options) => options?.method === 'POST' && path.endsWith('/retry')
        ? jsonResponse({ error: 'Only failed requests can be retried.' }, 409) : undefined);
    renderChat();
    hold(record('failed', { status: 'failed', error: 'Provider unavailable' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Retry failed action' }));
    await waitFor(() => expect(screen.getAllByRole('alert')[1]).toHaveTextContent('Only failed requests can be retried.'));
});

test('a request failing in another conversation links to it', async () => {
    serve();
    renderChat();
    hold(record('elsewhere', { kind: 'assess', lane: 'action', conversation_id: 'conv-x', title: 'CVE-9', status: 'failed',
        error: 'Too many packages', text: 'Assess CVE-9' }));
    const banner = await screen.findByText('AI request failed: CVE-9.');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    fireEvent.click(within(banner.parentElement!).getByRole('button', { name: 'View' }));
    expect(screen.getByRole('heading', { name: 'Assess CVE-9' })).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('Too many packages');
    expect(screen.queryByText('AI request failed: CVE-9.')).not.toBeInTheDocument();
});

test('a paused backend queue explains why its waiting requests do not start', async () => {
    serve();
    paused = { code: 'signed_out', reason: 'Sign in to an AI provider to run queued requests.' };
    renderChat();
    hold(record('waiting', { kind: 'assess', lane: 'action', conversation_id: 'conv-w', title: 'CVE-1' }));
    expect(await screen.findByText('AI queue paused: Sign in to an AI provider to run queued requests.')).toBeInTheDocument();
    expect(screen.getByTestId('ai-queue-idle')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'AI queue (1), paused' }));
    const list = within(screen.getByRole('navigation', { name: 'Conversations' }));
    expect(list.getByRole('status')).toHaveTextContent('AI queue paused: Sign in to an AI provider to run queued requests.');
    expect(within(list.getByRole('region', { name: 'Waiting' })).getByText('Agent chat · waiting · #1')).toBeInTheDocument();
});

test('large vulnerability view disables the unavailable summary action', async () => {
    global.fetch = async input => String(input).endsWith('/models') ? jsonResponse(models) : jsonResponse(signedIn);
    render(<AgentChat onClose={() => undefined} context={{ ...context, view: {
        visibleVulnerabilityIds: Array.from({ length: 101 }, (_, index) => `CVE-${index}`),
    } }} />);
    expect(await screen.findByRole('button', { name: 'Summarize vulnerabilities' })).toBeDisabled();
    expect(screen.getByText(/Filter to 100 or fewer vulnerabilities/)).toBeInTheDocument();
});

test('sign-out shows a remote cleanup error after discarding local identity', async () => {
    global.fetch = async (input, options) => {
        const path = String(input);
        if (path.endsWith('/models')) return jsonResponse(models);
        if (path.endsWith('/auth') && options?.method === 'DELETE') return jsonResponse({
            authenticated: false, cleanup_error: 'Could not delete the stored conversation on the Copilot server.',
        });
        return jsonResponse(signedIn);
    };

    render(<AgentChat onClose={() => undefined} context={context} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Configure model provider' }));
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not delete the stored conversation');
    expect(screen.getByText('Select a connector')).toBeInTheDocument();
});

test('keyboard send queues the message; the transcript renders structured Markdown, usage, and response copy', async () => {
    const reply = '# Report\n\n## Findings\n\n### Details\n\n- First\n\n1. Second\n\n> Evidence\n\n[Source](https://example.com) with `code`.\n\n```text\nlog\n```\n\n| Name | Result |\n| --- | --- |\n| Example | Passed |';
    const copied: string[] = [];
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async (text: string) => { copied.push(text); } } });
    serve();
    renderChat();
    await screen.findByRole('button', { name: 'Summarize vulnerabilities' });
    const composer = screen.getByRole('textbox', { name: 'Message the agent' });
    fireEvent.change(composer, { target: { value: 'Review evidence' } });
    fireEvent.keyDown(composer, { key: 'Enter', code: 'Enter' });
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0].actions).toEqual([{ kind: 'message', text: 'Review evidence' }]);
    setStatus('req-0-0', 'done');
    saveTranscript('main', [{ role: 'user', content: 'Review evidence' }, { role: 'assistant', content: reply,
        activity: [{ id: 'call', name: 'list_assessments_by_vuln', status: 'failed' }] }],
    { usage: { cost: 0.5, input_tokens: 10, output_tokens: 2 } });
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Report' })).toBeInTheDocument());
    expect(screen.getByRole('heading', { name: 'Findings' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Details' })).toBeInTheDocument();
    expect(screen.getByRole('blockquote')).toHaveTextContent('Evidence');
    expect(screen.getByRole('link', { name: 'Source' })).toHaveAttribute('href', 'https://example.com');
    expect(screen.getByRole('table')).toHaveTextContent('Passed');
    expect(screen.getByText('list assessments by vuln')).toBeInTheDocument();
    fireEvent.click(screen.getByText('Conversation usage'));
    expect(screen.getByText('SDK cost 0.5000')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Copy response' }));
    await waitFor(() => expect(copied).toEqual([reply]));
    fireEvent.click(screen.getByRole('button', { name: 'Copy code block' }));
    await waitFor(() => expect(copied).toEqual([reply, 'log']));
    expect(screen.getByRole('button', { name: 'Copy code block' })).toHaveAttribute('title', 'Copied');
});

test('code block copy reports an unavailable clipboard', async () => {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async () => { throw new Error('denied'); } } });
    serve();
    transcripts.main = [{ role: 'user', content: 'Give a value' }, { role: 'assistant', content: '```text\nvalue\n```' }];
    updateConversation('main', { message_count: 2 });
    renderChat();
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Message the agent' })).toBeEnabled());
    fireEvent.click(await screen.findByRole('button', { name: 'Copy code block' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Clipboard unavailable');
});

test('AI Context page offers help for the open form tab', async () => {
    serve();
    const sent = () => posted.map(body => (body.actions[0] as { text: string }).text);
    const aiView = { selectedProjectId: 'p1', selectedProjectName: 'Gateway', selectedVariantId: 'v1', selectedVariantName: 'Board A' };
    const { rerender } = renderChat({ page: 'ai', view: { ...aiView, section: 'threat_model' } });

    const help = await screen.findByRole('button', { name: 'Help fill this tab' });
    await waitFor(() => expect(help).toBeEnabled());
    fireEvent.click(help);
    await waitFor(() => expect(sent()).toHaveLength(1));
    expect(sent()[0]).toContain('Threat model tab of the AI Context form for variant "Board A" of project "Gateway"');
    expect(sent()[0]).toContain('get_ai_context_form_guide');
    expect(posted[0].conversation).toBe('main');

    rerender(<AgentChat onClose={() => undefined} context={{ page: 'ai', view: { selectedProjectId: 'p1', selectedProjectName: 'Gateway', section: 'project_description' } }} />);
    const projectHelp = await screen.findByRole('button', { name: 'Help write project description' });
    await waitFor(() => expect(projectHelp).toBeEnabled());
    fireEvent.click(projectHelp);
    await waitFor(() => expect(sent()).toHaveLength(2));
    expect(sent()[1]).toContain('Project description in the AI Context form for project "Gateway"');

    rerender(<AgentChat onClose={() => undefined} context={{ page: 'ai', view: aiView }} />);
    expect(screen.queryByRole('button', { name: /^Help (fill|write)/ })).not.toBeInTheDocument();
    rerender(<AgentChat onClose={() => undefined} context={context} />);
    expect(screen.queryByRole('button', { name: /^Help (fill|write)/ })).not.toBeInTheDocument();
});

test('model rejection restores the choice and retry reloads the connection', async () => {
    const requests: string[] = [];
    global.fetch = async (input, options) => {
        const path = String(input);
        requests.push(path);
        if (path.endsWith('/models')) return jsonResponse({ models: [...models.models, { id: 'alternate', name: 'Alternate' }] });
        if (path.endsWith('/model') && options?.method === 'POST') return jsonResponse({ error: 'Model unavailable' }, 400);
        return jsonResponse(signedIn);
    };

    render(<AgentChat onClose={() => undefined} context={context} />);
    const select = await screen.findByRole('combobox', { name: 'Agent model' });
    await screen.findByRole('option', { name: 'Alternate' });
    fireEvent.change(select, { target: { value: 'alternate' } });
    expect(await screen.findByRole('alert')).toHaveTextContent('Model unavailable');
    expect(select).toHaveValue('auto');
    fireEvent.click(screen.getByRole('button', { name: 'Retry connection' }));
    await waitFor(() => expect(requests.filter(path => path === '/api/agent')).toHaveLength(2));
});

test('reset confirmation can be cancelled and then saves the preference', async () => {
    const showModal = HTMLDialogElement.prototype.showModal;
    const close = HTMLDialogElement.prototype.close;
    HTMLDialogElement.prototype.showModal = function () { this.setAttribute('open', ''); };
    HTMLDialogElement.prototype.close = function () { this.removeAttribute('open'); };
    let closed = false;
    serve();
    transcripts.main = [{ role: 'user', content: 'Earlier question' }];
    updateConversation('main', { message_count: 1 });

    try {
        renderChat(context, () => { closed = true; });
        await screen.findByText('Earlier question');
        fireEvent.click(screen.getByRole('button', { name: 'New conversation' }));
        const dialog = screen.getByRole('dialog');
        expect(dialog).toHaveAttribute('open');
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        expect(dialog).not.toHaveAttribute('open');
        expect(routes).toEqual([]);
        fireEvent.click(screen.getByRole('button', { name: 'New conversation' }));
        fireEvent.click(screen.getByRole('checkbox', { name: 'Never ask again' }));
        fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
        await waitFor(() => expect(screen.queryByText('Earlier question')).not.toBeInTheDocument());
        expect(window.localStorage.getItem('vulnscout.agent.skipDiscardConfirmation')).toBe('true');
        fireEvent.click(screen.getByRole('button', { name: 'Close agent' }));
        expect(closed).toBe(true);
    } finally {
        HTMLDialogElement.prototype.showModal = showModal;
        HTMLDialogElement.prototype.close = close;
    }
});

test('device authorization can be cancelled and the code copied', async () => {
    const copied: string[] = [];
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async (text: string) => { copied.push(text); } } });
    global.fetch = async input => {
        const path = String(input);
        if (path.endsWith('/auth')) return jsonResponse({ user_code: 'ABCD-EFGH', verification_uri: 'https://github.com/login/device', interval: 300 });
        return jsonResponse(signedOut);
    };

    render(<AgentChat onClose={() => undefined} context={context} />);
    await screen.findByText('Select a connector');
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    fireEvent.click(await screen.findByRole('button', { name: /sign in with github/i }));
    await screen.findByText('ABCD-EFGH');
    fireEvent.click(screen.getByRole('button', { name: 'Copy code' }));
    await waitFor(() => expect(copied).toEqual(['ABCD-EFGH']));
    fireEvent.click(screen.getByRole('button', { name: 'Back' }));
    expect(screen.getByRole('button', { name: /sign in with github/i })).toBeInTheDocument();
});

test('scrolling away from the latest message exposes a return control', async () => {
    global.fetch = async input => String(input).endsWith('/models') ? jsonResponse(models) : jsonResponse(signedIn);
    render(<AgentChat onClose={() => undefined} context={context} />);
    await screen.findByRole('button', { name: 'Summarize vulnerabilities' });
    const log = screen.getByRole('log', { name: 'Agent conversation' });
    Object.defineProperties(log, {
        scrollHeight: { configurable: true, value: 300 },
        clientHeight: { configurable: true, value: 100 },
        scrollTop: { configurable: true, writable: true, value: 0 },
    });
    fireEvent.scroll(log);
    fireEvent.click(screen.getByRole('button', { name: 'Jump to latest message' }));
    expect(log.scrollTop).toBe(300);
});

test('the conversations view lists every conversation and opens each one in the chat, waiting ones included', async () => {
    serve();
    const chat = renderChat();
    expect(screen.getByRole('heading', { name: 'Agent chat' })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Message the agent' })).toBeEnabled());
    hold(record('bulk', { kind: 'assess', lane: 'action', conversation_id: 'conv-bulk', status: 'running', source: 'Vulnerability selection',
        title: 'CVE-1 · 1 target', text: 'First request' }),
    record('next', { kind: 'assess', lane: 'action', conversation_id: 'conv-next', source: 'Vulnerability selection',
        title: 'CVE-2 · 1 target', detail: 'default · pkg@2', text: 'Next request', context }));
    progress('conv-bulk', { request_id: 'bulk', pending_message: 'First request', live_reply: '', activity: [], progress: 'Thinking' });
    const walker = screen.getByTestId('ai-queue-walking');
    expect(walker).toHaveAttribute('aria-hidden', 'true');
    expect(walker.querySelectorAll('animate, animateTransform')).toHaveLength(4);
    for (const animation of walker.querySelectorAll('animate, animateTransform')) {
        expect(animation).toHaveAttribute('dur', '1.6s');
        expect(animation).toHaveAttribute('repeatCount', 'indefinite');
    }
    expect(walker.querySelector('.agent-walker-still')).toHaveAttribute('data-icon', 'person-walking');
    expect(screen.getByRole('combobox', { name: 'Agent model' })).toBeDisabled();

    // Bulk assessment requests open the list, not an arbitrary CVE conversation.
    const toggle = screen.getByRole('button', { name: 'AI queue (2)' });
    act(() => openAgentChat(undefined, 'conversations'));
    expect(toggle).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByRole('heading', { name: 'Conversations' })).toBeInTheDocument();
    expect(screen.queryByRole('log', { name: 'Agent conversation' })).not.toBeInTheDocument();
    const list = within(screen.getByRole('navigation', { name: 'Conversations' }));
    expect(list.getByText('1 running · 1 waiting')).toBeInTheDocument();
    expect(list.getByRole('button', { name: 'Open main conversation' })).toHaveAttribute('aria-current', 'true');
    expect(within(list.getByRole('region', { name: 'Running' })).getByText('Vulnerability selection · running')).toBeInTheDocument();
    expect(within(list.getByRole('region', { name: 'Waiting' })).getByText('Vulnerability selection · waiting · #1')).toBeInTheDocument();

    // A waiting action opens as a conversation showing its pending request.
    fireEvent.click(list.getByRole('button', { name: 'Open conversation Assess CVE-2 · 1 target' }));
    expect(screen.getByRole('heading', { name: 'Assess CVE-2 · 1 target' })).toBeInTheDocument();
    const log = within(screen.getByRole('log', { name: 'Agent conversation' }));
    expect(log.getByText('Next request')).toBeInTheDocument();
    expect(log.getByRole('status')).toHaveTextContent('Waiting in the AI queue · #1');
    expect(log.getByText('Request details').closest('details')).toHaveTextContent('Targetsdefault · pkg@2');
    expect(screen.getByRole('combobox', { name: 'Agent model' })).toBeDisabled();

    // The back arrow returns to the list; Escape returns to the conversation.
    fireEvent.click(screen.getByRole('button', { name: 'All conversations' }));
    fireEvent.keyDown(screen.getByRole('navigation', { name: 'Conversations' }), { key: 'Escape' });
    expect(screen.getByRole('heading', { name: 'Assess CVE-2 · 1 target' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'AI queue (2)' }));
    fireEvent.click(screen.getByRole('button', { name: 'Open conversation Assess CVE-1 · 1 target' }));
    expect(within(screen.getByRole('log', { name: 'Agent conversation' })).getByText('First request')).toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: 'Message the agent' })).toHaveAttribute('placeholder', 'Follow up in this conversation...');
    fireEvent.change(screen.getByRole('textbox', { name: 'Message the agent' }), { target: { value: 'Follow-up' } });
    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0]).toMatchObject({ conversation: 'conv-bulk', source: 'Assess CVE-1 · 1 target', actions: [{ kind: 'message', text: 'Follow-up' }] });

    // Stopping from the list keeps the conversation; it is finished once the backend stops it.
    fireEvent.click(screen.getByRole('button', { name: 'All conversations' }));
    fireEvent.click(screen.getByRole('button', { name: 'Stop Assess CVE-1 · 1 target' }));
    await waitFor(() => expect(routes).toEqual(['POST /api/agent/queue/requests/bulk/stop']));
    chat.unmount();
});

test.each(['remove', 'clear'])('%s releases a failed action without retrying it', async action => {
    serve();
    renderChat();
    hold(record('q1', { kind: 'assess', lane: 'action', conversation_id: 'conv-1', title: 'CVE-1', text: 'Assess CVE-1', status: 'failed', error: 'Connection lost' }),
        record('q2', { kind: 'assess', lane: 'action', conversation_id: 'conv-2', title: 'CVE-2', text: 'Assess CVE-2' }));
    fireEvent.click(await screen.findByRole('button', { name: 'AI queue (2), failed' }));
    const list = within(screen.getByRole('navigation', { name: 'Conversations' }));
    expect(list.getByRole('status')).toHaveTextContent('A request failed. Open its conversation to retry or remove it.');
    expect(within(list.getByRole('region', { name: 'Needs attention' })).getByText('Agent chat · failed')).toBeInTheDocument();
    if (action === 'remove') {
        fireEvent.click(list.getByRole('button', { name: 'Open conversation Assess CVE-1' }));
        fireEvent.click(screen.getByRole('button', { name: 'Remove failed action' }));
        await waitFor(() => expect(routes).toEqual(['DELETE /api/agent/queue/requests/q1']));
        expect(getAgentQueue().map(task => task.id)).toEqual(['q2']);
    } else {
        fireEvent.click(list.getByRole('button', { name: 'Clear waiting' }));
        await waitFor(() => expect(routes).toEqual(['DELETE /api/agent/queue']));
        expect(getAgentQueue()).toEqual([]);
    }
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

test('lists conversations by status with remove and clear controls', async () => {
    serve(signedOut);
    renderChat();
    await screen.findByText('Step 1 of 3');
    hold(record('q1', { kind: 'assess', lane: 'action', conversation_id: 'conv-1', title: '2 targets', detail: 'default · pkg@1.0.0', source: 'Vulnerability CVE-1' }),
        record('q2', { kind: 'review', lane: 'action', conversation_id: 'conv-2', title: 'assessment 1a2b3c4d', source: 'Vulnerability CVE-1' }));
    expect(screen.getByTestId('ai-queue-walking').querySelector('.agent-walker-motion')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'AI queue (2)' }));

    const list = within(screen.getByRole('navigation', { name: 'Conversations' }));
    expect(list.getByText('0 running · 2 waiting')).toBeInTheDocument();
    const items = within(list.getByRole('region', { name: 'Waiting' })).getAllByRole('listitem');
    expect(items[0]).toHaveTextContent('Assess 2 targets');
    expect(items[0]).toHaveTextContent('waiting · #1');
    expect(items[1]).toHaveTextContent('Review assessment 1a2b3c4d');

    fireEvent.click(list.getByRole('button', { name: 'Remove Assess 2 targets from queue' }));
    await waitFor(() => expect(getAgentQueue().map(item => item.id)).toEqual(['q2']));
    expect(routes).toEqual(['DELETE /api/agent/queue/requests/q1']);
    fireEvent.click(list.getByRole('button', { name: 'Clear waiting' }));
    await waitFor(() => expect(getAgentQueue()).toEqual([]));
    expect(screen.getByTestId('ai-queue-idle')).toHaveAttribute('data-icon', 'person');
    expect(screen.queryByTestId('ai-queue-walking')).not.toBeInTheDocument();
    summaries = summaries.filter(item => item.id === 'main');
    publish();
    expect(list.getByText(/start their own conversations here/)).toBeInTheDocument();
    fireEvent.click(list.getByRole('button', { name: 'Open main conversation' }));
    expect(screen.getByRole('heading', { name: 'Agent chat' })).toBeInTheDocument();
});

test('finished conversations can be reopened and deleted from the list', async () => {
    serve();
    summaries.push(summary('conv-a', 'Assess CVE-A', { message_count: 2, created_at: 2 }), summary('conv-b', 'Assess CVE-B', { message_count: 2, created_at: 3 }));
    transcripts['conv-a'] = [{ role: 'user', content: 'Assess A' }, { role: 'assistant', content: 'Done: Assess A' }];
    finished = [record('a', { status: 'done', conversation_id: 'conv-a' }), record('b', { status: 'done', conversation_id: 'conv-b' })];
    renderChat();
    fireEvent.click(await screen.findByRole('button', { name: 'AI queue (0)' }));
    const list = within(screen.getByRole('navigation', { name: 'Conversations' }));
    const done = within(list.getByRole('region', { name: 'Finished' })).getAllByRole('listitem');
    expect(done).toHaveLength(2);
    expect(done[0]).toHaveTextContent('1 request');
    fireEvent.click(list.getByRole('button', { name: 'Open conversation Assess CVE-A' }));
    await waitFor(() => expect(screen.getByText('Done: Assess A')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: 'All conversations' }));
    fireEvent.click(screen.getByRole('button', { name: 'Delete conversation Assess CVE-A' }));
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Open conversation Assess CVE-A' })).not.toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: 'Delete all' }));
    await waitFor(() => expect(screen.queryByRole('region', { name: 'Finished' })).not.toBeInTheDocument());
    expect(routes).toEqual(['DELETE /api/agent/conversations/conv-a', 'DELETE /api/agent/conversations']);
});

test.each([0, 1, 2, 101])('does not offer Assess displayed for %i visible vulnerabilities', async count => {
    global.fetch = async input => String(input).endsWith('/models') ? jsonResponse(models) : jsonResponse(signedIn);
    render(<AgentChat context={{ ...context, view: {
        visibleVulnerabilityIds: Array.from({ length: count }, (_, index) => `CVE-${index}`),
        selectedVulnerabilityIds: ['CVE-1', 'CVE-2'],
    } }} onClose={() => undefined} />);
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Message the agent' })).toBeEnabled());
    expect(screen.queryByRole('button', { name: 'Assess displayed' })).not.toBeInTheDocument();
    expect(screen.getByText(`${count} displayed`)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Prioritize next steps' })).toBeEnabled();
    expect(getAgentQueue()).toEqual([]);
});

test.each(['Assess vulnerability', 'Assess this vulnerability'])('%s queues the open vulnerability in its own conversation', async label => {
    serve();
    const openContext = { ...context, view: { openVulnerabilityId: 'CVE-3', visibleVulnerabilityIds: ['CVE-1', 'CVE-2', 'CVE-3'] } };
    renderChat(openContext);
    hold(record('a', { kind: 'assess', lane: 'action', conversation_id: 'conv-a', title: 'CVE-1' }),
        record('b', { kind: 'assess', lane: 'action', conversation_id: 'conv-b', title: 'CVE-2' }));
    await waitFor(() => expect(screen.getByRole('button', { name: label })).toBeEnabled());
    expect(screen.queryByRole('button', { name: 'Assess displayed' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: label }));
    await waitFor(() => expect(posted).toHaveLength(1));
    expect(posted[0]).toMatchObject({
        conversation: 'per-action', source: 'Vulnerability CVE-3',
        actions: [{ kind: 'assess', vuln_id: 'CVE-3', key: `${bulkAssessmentKeyPrefix(openContext)}CVE-3` }],
        context: { view: { selectedVulnerabilityIds: ['CVE-3'], selectionCount: 1 } },
    });
    // A waiting request opens its own conversation, showing the pending request and its place in line.
    expect(await screen.findByRole('heading', { name: 'Assess CVE-3' })).toBeInTheDocument();
    expect(within(screen.getByRole('log', { name: 'Agent conversation' })).getByRole('status')).toHaveTextContent('Waiting in the AI queue · #3');

    // Queuing it again opens the request already holding it.
    act(() => openAgentChat(undefined, 'conversations'));
    fireEvent.click(screen.getByRole('button', { name: 'Open main conversation' }));
    fireEvent.click(screen.getByRole('button', { name: label }));
    await waitFor(() => expect(posted).toHaveLength(2));
    expect(await screen.findByRole('heading', { name: 'Assess CVE-3' })).toBeInTheDocument();
    expect(getAgentQueue()).toHaveLength(3);
});

test('reports a rejected assessment request', async () => {
    serve(signedIn, (path, options) => path === '/api/agent/queue' && options?.method === 'POST'
        ? jsonResponse({ error: 'Unknown vulnerability: CVE-3' }, 400) : undefined);
    renderChat({ ...context, view: { openVulnerabilityId: 'CVE-3' } });
    await waitFor(() => expect(screen.getByRole('button', { name: 'Assess vulnerability' })).toBeEnabled());
    fireEvent.click(screen.getByRole('button', { name: 'Assess vulnerability' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Unknown vulnerability: CVE-3');
    expect(screen.getByRole('heading', { name: 'Agent chat' })).toBeInTheDocument();
});

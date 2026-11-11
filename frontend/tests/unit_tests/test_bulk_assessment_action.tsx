import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import fetchMock from 'jest-fetch-mock';
import type React from 'react';
import MultiEditBar from '../../src/components/MultiEditBar';
import type { Vulnerability } from '../../src/handlers/vulnerabilities';
import * as store from '../../src/handlers/agentQueue';
import type { AgentAction, AgentRequestRecord } from '../../src/types/agent';

fetchMock.enableMocks();

/** Stands in for the queue stream; `frame` delivers backend state to every open stream. */
let streams: Array<{ handlers: Map<string, (event: MessageEvent) => void>; close: () => void; onerror: null }> = [];
const frame = (requests: AgentRequestRecord[]) => act(() => {
    const data = JSON.stringify({ paused: null, requests, history: [], conversations: [] });
    streams.forEach(stream => stream.handlers.get('queue')?.({ data, lastEventId: '' } as MessageEvent));
});
type Posted = { conversation: string; source: string; context: Record<string, unknown>; actions: Array<Extract<AgentAction, { kind: 'assess' }>> };
let posted: Posted[] = [];
let records: AgentRequestRecord[] = [];
const record = (action: Posted['actions'][number], body: Posted, index: number): AgentRequestRecord => ({
    id: `r${records.length + index + 1}`, key: action.key ?? '', kind: 'assess', lane: 'action',
    conversation_id: `c${records.length + index + 1}`, source: body.source, title: `${action.vuln_id} · 1 target`, detail: '',
    model: 'auto', status: 'queued', error: null, error_code: null, position: records.length + index + 1, created_at: 1,
    started_at: null, finished_at: null, context: (action.context ?? body.context) as AgentRequestRecord['context'],
    text: '', vuln_id: action.vuln_id, assessment_id: null, timeout: 900, result: null,
});
/** Queue the posted actions like the backend does (skipping keys still active) and publish the queue. */
const accept = (body: Posted) => {
    const fresh = body.actions.filter(action => !records.some(item => item.key === action.key));
    const created = fresh.map((action, index) => record(action, body, index));
    records = [...records, ...created];
    frame(records);
    return {
        requests: created.map(item => ({ id: item.id, key: item.key, conversation_id: item.conversation_id })),
        skipped: body.actions.filter(action => !fresh.includes(action))
            .map(action => ({ key: action.key, request_id: records.find(item => item.key === action.key)?.id })),
    };
};
const setStatus = (index: number, status: AgentRequestRecord['status']) => {
    records = records.map((item, at) => at === index ? { ...item, status, position: status === 'queued' ? item.position : null } : item);
    frame(records);
};
const finish = (index: number) => {
    records = records.filter((_, at) => at !== index);
    frame(records);
};

const vulnerabilities = ['CVE-1', 'CVE-2', 'CVE-3'].map((id, index) => ({
    id, packages: [`pkg@${index + 1}`, 'old@1'], packages_current: [`pkg@${index + 1}`],
    assessments: [],
})) as unknown as Vulnerability[];
const baseProps = {
    vulnerabilities, selectedVulns: [] as string[],
    resetVulns: jest.fn(), appendAssessment: jest.fn(), patchVuln: jest.fn(),
    triggerBanner: jest.fn(), hideBanner: jest.fn(),
    projectId: 'project-1', variantId: 'variant-1',
};
type Props = React.ComponentProps<typeof MultiEditBar>;
const bar = (props: Partial<Props> = {}) => <MultiEditBar {...baseProps} {...props} />;
const assessButton = () => screen.getByRole('button', { name: /^Assess with AI/ });
const queue = store.getAgentQueue;
let openedBefore = 0;
const chatOpenings = () => store.getAgentChatRequest().nonce - openedBefore;
let queueResponse: ((body: Posted) => Promise<{ body: string; status: number; headers: Record<string, string> }>) | undefined;
let restoreFactory: () => void;

beforeEach(() => {
    store.__resetAgentQueue();
    streams = [];
    posted = [];
    records = [];
    queueResponse = undefined;
    restoreFactory = store.__setEventSourceFactory(() => {
        const handlers = new Map<string, (event: MessageEvent) => void>();
        const stream = { handlers, close: () => undefined, onerror: null, addEventListener: (type: string, handler: (event: MessageEvent) => void) => handlers.set(type, handler) };
        streams.push(stream);
        return stream as unknown as EventSource;
    });
    openedBefore = store.getAgentChatRequest().nonce;
    jest.clearAllMocks();
    fetchMock.resetMocks();
    fetchMock.mockResponse(async request => {
        if (request.url.endsWith('/api/agent/queue')) {
            const body = await request.json() as Posted;
            posted.push(body);
            if (queueResponse) return queueResponse(body);
            return { body: JSON.stringify(accept(body)), status: 202, headers: { 'content-type': 'application/json' } };
        }
        if (request.url.includes('variant-active-packages')) {
            const id = request.url.match(/vulnerabilities\/([^/]+)/)?.[1];
            const index = vulnerabilities.findIndex(vuln => vuln.id === id);
            return JSON.stringify([
                { variant_id: 'variant-1', findings: [
                    { package: `pkg@${index + 1}`, outdated: false }, { package: 'old@1', outdated: true },
                ] },
                { variant_id: 'outside-scope', findings: [{ package: `pkg@${index + 1}`, outdated: false }] },
            ]);
        }
        return '[]';
    });
});

afterEach(() => restoreFactory());

test('offers disabled Assess with AI without a selection', () => {
    render(bar());
    expect(assessButton()).toBeDisabled();
    expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
});

test('queues exactly the selected vulnerabilities, their own packages, and the current scope', async () => {
    render(bar({ selectedVulns: ['CVE-1', 'CVE-2'] }));
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(2));
    expect(posted).toHaveLength(1);
    expect(posted[0]).toMatchObject({ conversation: 'per-action', source: 'Vulnerability selection',
        context: { page: 'vulnerabilities', projectId: 'project-1', variantId: 'variant-1' } });
    expect(posted[0].actions).toEqual([1, 2].map(index => ({
        kind: 'assess', vuln_id: `CVE-${index}`,
        targets: [{ variant_id: 'variant-1', package: `pkg@${index}` }],
        key: expect.stringMatching(new RegExp(`^assess:.*:CVE-${index}$`)),
        context: expect.objectContaining({
            page: 'vulnerabilities', projectId: 'project-1', variantId: 'variant-1',
            view: { selectedVulnerabilityIds: [`CVE-${index}`], selectionCount: 1 },
        }),
    })));
    await waitFor(() => expect(chatOpenings()).toBe(1));
    expect(store.getAgentChatRequest()).toMatchObject({ view: 'conversations', taskId: undefined });
    expect(baseProps.resetVulns).not.toHaveBeenCalled();
    // Once queued, the button shows the queue position and opens the queued request instead of queueing it again.
    expect(assessButton()).toBeEnabled();
    expect(assessButton()).toHaveAccessibleName('Assess with AI (queued, position 1)');
    expect(assessButton()).toHaveTextContent('Queued · #1');
    expect(assessButton()).toHaveTextContent('Assess with AI');
    fireEvent.click(assessButton());
    expect(posted).toHaveLength(1);
    expect(chatOpenings()).toBe(2);
    expect(store.getAgentChatRequest().view).toBe('conversations');
});

test('opens a single assessment in the chat and posts only vulnerabilities not already queued', async () => {
    const { rerender } = render(bar({ selectedVulns: ['CVE-1'] }));
    fireEvent.click(assessButton());
    await waitFor(() => expect(chatOpenings()).toBe(1));
    expect(store.getAgentChatRequest()).toMatchObject({ view: 'chat', taskId: 'r1' });
    expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
    expect(screen.queryByRole('log', { name: 'Agent conversation' })).not.toBeInTheDocument();
    rerender(bar({ selectedVulns: ['CVE-1', 'CVE-2'] }));
    expect(assessButton()).toBeEnabled();
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(2));
    await waitFor(() => expect(chatOpenings()).toBe(2));
    expect(posted[1].actions.map(action => action.vuln_id)).toEqual(['CVE-2']);
    expect(fetchMock.mock.calls.filter(([url]) => String(url).includes('CVE-1/variant-active-packages'))).toHaveLength(1);
});

test('opens the existing request when the backend reports it already queued', async () => {
    records = [{ ...record({ kind: 'assess', vuln_id: 'CVE-1', key: 'other' }, { conversation: '', source: '', context: {}, actions: [] }, 0), id: 'held' }];
    queueResponse = async () => ({ body: JSON.stringify({ requests: [], skipped: [{ key: 'k', request_id: 'held' }] }), status: 202,
        headers: { 'content-type': 'application/json' } });
    render(bar({ selectedVulns: ['CVE-1'] }));
    fireEvent.click(assessButton());
    await waitFor(() => expect(chatOpenings()).toBe(1));
    expect(store.getAgentChatRequest().taskId).toBe('held');
});

test('follows running and failed requests from the backend, allowing a new run once they finish', async () => {
    render(bar({ selectedVulns: ['CVE-1'] }));
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(1));
    setStatus(0, 'running');
    expect(assessButton()).toHaveTextContent('Running…');
    expect(assessButton()).toHaveTextContent('Assess with AI');
    expect(assessButton()).toHaveAccessibleName('Assess with AI (running)');
    setStatus(0, 'failed');
    expect(assessButton()).toHaveTextContent('Failed · view');
    fireEvent.click(assessButton());
    expect(store.getAgentChatRequest()).toMatchObject({ view: 'chat', taskId: 'r1' });
    finish(0);
    expect(assessButton()).toBeEnabled();
    expect(assessButton()).toHaveAccessibleName('Assess with AI');
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(1));
    expect(posted).toHaveLength(2);
});

test('reports lookup failures atomically without launching a partial queue, and supports retry', async () => {
    fetchMock.mockResponseOnce('[]').mockResponseOnce('failure', { status: 503 });
    render(bar({ selectedVulns: ['CVE-1', 'CVE-2'] }));
    fireEvent.click(assessButton());
    await waitFor(() => expect(baseProps.triggerBanner).toHaveBeenCalledWith(expect.any(String), 'error'));
    expect(posted).toEqual([]);
    expect(chatOpenings()).toBe(0);
    expect(assessButton()).toBeEnabled();
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(2));
});

test('reports a rejected assessment without opening the chat', async () => {
    queueResponse = async () => ({ body: JSON.stringify({ error: 'Too many packages for variant v1 to assess in one request.' }),
        status: 400, headers: { 'content-type': 'application/json' } });
    render(bar({ selectedVulns: ['CVE-1'] }));
    fireEvent.click(assessButton());
    await waitFor(() => expect(baseProps.triggerBanner).toHaveBeenCalledWith(
        'CVE-1: Too many packages for variant v1 to assess in one request. Open its details to refine the package selection.', 'error'));
    expect(chatOpenings()).toBe(0);
    expect(assessButton()).toBeEnabled();

    fetchMock.mockRejectOnce(new TypeError('Failed to fetch'));
    fireEvent.click(assessButton());
    await waitFor(() => expect(baseProps.triggerBanner).toHaveBeenLastCalledWith(expect.any(String), 'error'));
});

test('disables during preparation and cancels stale preparation when selection changes', async () => {
    let resolve: ((value: string) => void) | undefined;
    fetchMock.mockResponseOnce(() => new Promise<string>(done => { resolve = done; }));
    const { rerender } = render(bar({ selectedVulns: ['CVE-1'] }));
    fireEvent.click(assessButton());
    expect(assessButton()).toBeDisabled();
    expect(assessButton()).toHaveTextContent('Preparing');
    const signal = fetchMock.mock.calls[0][1]?.signal;
    rerender(bar({ selectedVulns: ['CVE-2'] }));
    expect(signal?.aborted).toBe(true);
    await act(async () => { resolve?.('[]'); });
    expect(posted).toEqual([]);
    expect(chatOpenings()).toBe(0);
    expect(assessButton()).toBeEnabled();
    expect(baseProps.triggerBanner).not.toHaveBeenCalled();
});

test('keeps the selected multi-variant scope in the agent context', async () => {
    render(bar({
        selectedVulns: ['CVE-1'], variantId: undefined,
        variantIds: ['variant-1', 'outside-scope'], multiOperation: 'intersection',
    }));
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(1));
    expect(posted[0].actions[0].context).toMatchObject({
        projectId: 'project-1', variantIds: ['variant-1', 'outside-scope'], multiOperation: 'intersection',
    });
    expect(posted[0].actions[0]).toMatchObject({ targets: [
        { variant_id: 'variant-1', package: 'pkg@1' }, { variant_id: 'outside-scope', package: 'pkg@1' },
    ] });
});

test('limits concurrent target resolution and keeps selection order', async () => {
    const selected = Array.from({ length: 6 }, (_, index) => ({
        ...vulnerabilities[0], id: `CVE-${index + 1}`,
    }));
    const resolve: (() => void)[] = [];
    const respond = fetchMock.getMockImplementation();
    fetchMock.mockImplementation((input, init) => String(input instanceof Request ? input.url : input).includes('variant-active-packages')
        ? new Promise<Response>(done => {
            resolve.push(() => done(new Response(JSON.stringify([
                { variant_id: 'variant-1', findings: [{ package: 'pkg@1', outdated: false }] },
            ]))));
        })
        : respond!(input, init));
    render(bar({ vulnerabilities: selected, selectedVulns: selected.map(vuln => vuln.id) }));
    fireEvent.click(assessButton());
    expect(fetchMock).toHaveBeenCalledTimes(4);
    await act(async () => { resolve[1](); resolve[0](); });
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(6));
    await act(async () => { resolve.slice(2).forEach(done => done()); });
    await waitFor(() => expect(queue()).toHaveLength(6));
    expect(posted[0].actions.map(action => action.vuln_id)).toEqual(selected.map(vuln => vuln.id));
});

test('keeps scopes independent and preserves queued work after unmount', async () => {
    const { rerender, unmount } = render(bar({ selectedVulns: ['CVE-1'] }));
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(1));
    rerender(bar({ selectedVulns: ['CVE-1'], variantId: 'outside-scope' }));
    expect(assessButton()).toBeEnabled();
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(2));
    expect(queue().map(item => item.context?.variantId)).toEqual(['variant-1', 'outside-scope']);
    rerender(bar({ selectedVulns: ['CVE-1'] }));
    expect(assessButton()).toHaveTextContent('Queued');
    unmount();
    expect(fetchMock.mock.calls.filter(([url]) => String(url instanceof Request ? url.url : url).includes('/api/agent/'))).toHaveLength(2);
});

test('submits no further batch once the selection changes, keeping the accepted ones', async () => {
    const limit = jest.replaceProperty(store as { ACTIONS_PER_REQUEST: number }, 'ACTIONS_PER_REQUEST', 1);
    try {
        let release: (() => void) | undefined;
        queueResponse = body => new Promise(done => {
            release = () => done({ body: JSON.stringify(accept(body)), status: 202, headers: { 'content-type': 'application/json' } });
        });
        const { rerender } = render(bar({ selectedVulns: ['CVE-1', 'CVE-2'] }));
        fireEvent.click(assessButton());
        await waitFor(() => expect(posted).toHaveLength(1));
        rerender(bar({ selectedVulns: ['CVE-3'] }));
        await act(async () => { release?.(); });
        await waitFor(() => expect(queue()).toHaveLength(1));
        expect(posted.map(body => body.actions.map(action => action.vuln_id))).toEqual([['CVE-1']]);
        expect(chatOpenings()).toBe(0);
        expect(baseProps.triggerBanner).not.toHaveBeenCalled();
    } finally {
        limit.restore();
    }
});

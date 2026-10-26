import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import fetchMock from 'jest-fetch-mock';
import type React from 'react';
import MultiEditBar from '../../src/components/MultiEditBar';
import type { Vulnerability } from '../../src/handlers/vulnerabilities';
import * as store from '../../src/handlers/agentQueue';

const { getAgentQueue, resetAgentQueue } = store;
fetchMock.enableMocks();
let runningId: string | undefined;
// The real queue only drains with a connected chat; drive task status directly instead.
const startQueued = () => act(() => {
    const item = getAgentQueue()[0];
    if (item) {
        runningId = item.id;
        item.status = 'running';
        store.enqueueAgentMessages([], { page: 'vulnerabilities' });
    }
});
const finishRunning = () => act(() => {
    const item = getAgentQueue().find(task => task.id === runningId);
    if (item) item.status = 'queued';
    if (runningId) store.removeAgentTask(runningId);
});
const failRunning = () => act(() => {
    const item = getAgentQueue().find(task => task.id === runningId);
    if (item) item.status = 'failed';
    store.enqueueAgentMessages([], { page: 'vulnerabilities' });
});

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
const queue = getAgentQueue;
let openedBefore = 0;
const chatOpenings = () => store.getAgentChatRequest().nonce - openedBefore;

beforeEach(() => {
    resetAgentQueue();
    runningId = undefined;
    openedBefore = store.getAgentChatRequest().nonce;
    jest.clearAllMocks();
    fetchMock.resetMocks();
    fetchMock.mockResponse(request => {
        if (request.url.includes('variant-active-packages')) {
            const id = request.url.match(/vulnerabilities\/([^/]+)/)?.[1];
            const index = vulnerabilities.findIndex(vuln => vuln.id === id);
            return Promise.resolve(JSON.stringify([
                { variant_id: 'variant-1', findings: [
                    { package: `pkg@${index + 1}`, outdated: false }, { package: 'old@1', outdated: true },
                ] },
                { variant_id: 'outside-scope', findings: [{ package: `pkg@${index + 1}`, outdated: false }] },
            ]));
        }
        return Promise.resolve('[]');
    });
});

test('offers disabled Assess with AI without a selection', () => {
    render(bar());
    expect(assessButton()).toBeDisabled();
    expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
});

test('queues exactly the selected vulnerabilities, their own packages, and the current scope', async () => {
    render(bar({ selectedVulns: ['CVE-1', 'CVE-2'] }));
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(2));
    expect(queue()[0].text).toContain('Assess CVE-1');
    expect(queue()[0].text).toContain('variant_id variant-1: pkg@1');
    expect(queue()[0].text).not.toContain('pkg@2');
    expect(queue()[1].text).toContain('Assess CVE-2');
    expect(queue()[1].text).toContain('variant_id variant-1: pkg@2');
    for (const item of queue()) {
        expect(item.text).not.toContain('old@1');
        expect(item.text).not.toContain('outside-scope');
        expect(item.text).not.toContain('CVE-3');
    }
    expect(queue().map(item => item.context)).toEqual([1, 2].map(index => expect.objectContaining({
        page: 'vulnerabilities', projectId: 'project-1', variantId: 'variant-1',
        view: { selectedVulnerabilityIds: [`CVE-${index}`], selectionCount: 1 },
    })));
    expect(queue().every(item => item.source === 'Vulnerability selection')).toBe(true);
    // Each vulnerability is assessed in its own conversation of the agent chat.
    const [first, second] = queue().map(item => store.getAgentConversation(item.conversationId));
    expect([first.title, second.title]).toEqual(['Assess CVE-1 · 1 target', 'Assess CVE-2 · 1 target']);
    expect(first.threadId).not.toBe(second.threadId);
    expect(chatOpenings()).toBe(1);
    expect(store.getAgentChatRequest()).toMatchObject({ view: 'conversations', taskId: undefined });
    expect(baseProps.resetVulns).not.toHaveBeenCalled();
    // Once queued, the button shows the queue position and opens the queued request instead of queueing it again.
    expect(assessButton()).toBeEnabled();
    expect(assessButton()).toHaveAccessibleName('Assess with AI (queued, position 1)');
    expect(assessButton()).toHaveTextContent('Queued · #1');
    expect(assessButton()).toHaveTextContent('Assess with AI');
    fireEvent.click(assessButton());
    expect(queue()).toHaveLength(2);
    expect(chatOpenings()).toBe(2);
    expect(store.getAgentChatRequest().view).toBe('conversations');
});

test('opens the main agent chat instead of rendering its own and skips overlapping actions when the selection changes', async () => {
    const { rerender } = render(bar({ selectedVulns: ['CVE-1'] }));
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(1));
    expect(chatOpenings()).toBe(1);
    expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
    expect(screen.queryByRole('log', { name: 'Agent conversation' })).not.toBeInTheDocument();
    rerender(bar({ selectedVulns: [] }));
    expect(queue()).toHaveLength(1);
    rerender(bar({ selectedVulns: ['CVE-1', 'CVE-2'] }));
    expect(assessButton()).toBeEnabled();
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(2));
    expect(chatOpenings()).toBe(2);
    expect(queue().map(item => item.title.split(' · ')[0])).toEqual(['CVE-1', 'CVE-2']);
    expect(fetchMock.mock.calls.filter(([url]) => String(url).includes('CVE-1/variant-active-packages'))).toHaveLength(1);
});

test('tracks running actions, clearing pending items, and allows retry only after completion', async () => {
    render(bar({ selectedVulns: ['CVE-1'] }));
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(1));
    startQueued();
    expect(assessButton()).toHaveTextContent('Running…');
    expect(assessButton()).toHaveTextContent('Assess with AI');
    expect(assessButton()).toHaveAccessibleName('Assess with AI (running)');
    act(() => store.clearAgentQueue());
    expect(assessButton()).toHaveAccessibleName('Assess with AI (running)');
    finishRunning();
    expect(assessButton()).toBeEnabled();
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(1));
    act(() => store.removeAgentTask(queue()[0].id));
    expect(assessButton()).toBeEnabled();
});

test('reports lookup failures atomically without launching a partial queue, and supports retry', async () => {
    fetchMock.mockResponseOnce('[]').mockResponseOnce('failure', { status: 503 });
    render(bar({ selectedVulns: ['CVE-1', 'CVE-2'] }));
    fireEvent.click(assessButton());
    await waitFor(() => expect(baseProps.triggerBanner).toHaveBeenCalledWith(expect.any(String), 'error'));
    expect(queue()).toEqual([]);
    expect(chatOpenings()).toBe(0);
    expect(assessButton()).toBeEnabled();
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(2));
});

test('retains a failed assessment and later CVEs until it succeeds or is removed', async () => {
    render(bar({ selectedVulns: ['CVE-1', 'CVE-2'] }));
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(2));
    const firstId = queue()[0].id;
    startQueued();
    expect(queue()[0].id).toBe(firstId);
    failRunning();
    expect(queue()).toHaveLength(2);
    expect(queue()[0].id).toBe(firstId);
    expect(assessButton()).toHaveTextContent('Failed · view');
    fireEvent.click(assessButton());
    expect(store.getAgentChatRequest().view).toBe('conversations');
    expect(queue()).toHaveLength(2);
    startQueued();
    finishRunning();
    expect(queue().map(item => item.title.split(' · ')[0])).toEqual(['CVE-2']);
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
    expect(queue()).toEqual([]);
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
    expect(queue()[0].context).toMatchObject({
        projectId: 'project-1', variantIds: ['variant-1', 'outside-scope'], multiOperation: 'intersection',
    });
    expect(queue()[0].text).toContain('variant_id variant-1: pkg@1');
    expect(queue()[0].text).toContain('variant_id outside-scope: pkg@1');
});

test('rejects an oversized vulnerability without queuing any selected vulnerabilities', async () => {
    const packageId = 'x'.repeat(8000);
    fetchMock.mockResponseOnce(JSON.stringify([
        { variant_id: 'variant-1', findings: [{ package: packageId, outdated: false }] },
    ]));
    render(bar({
        vulnerabilities: [{ ...vulnerabilities[0], packages: [packageId], packages_current: [packageId] }],
        selectedVulns: ['CVE-1'],
    }));
    fireEvent.click(assessButton());
    await waitFor(() => expect(baseProps.triggerBanner).toHaveBeenCalledWith(expect.stringContaining('Too many packages'), 'error'));
    expect(queue()).toEqual([]);
    expect(assessButton()).toBeEnabled();
});

test('limits concurrent target resolution and keeps selection order', async () => {
    const selected = Array.from({ length: 6 }, (_, index) => ({
        ...vulnerabilities[0], id: `CVE-${index + 1}`,
    }));
    const resolve: (() => void)[] = [];
    fetchMock.mockResponse(() => new Promise<string>(done => {
        resolve.push(() => done(JSON.stringify([
            { variant_id: 'variant-1', findings: [{ package: 'pkg@1', outdated: false }] },
        ])));
    }));
    render(bar({ vulnerabilities: selected, selectedVulns: selected.map(vuln => vuln.id) }));
    fireEvent.click(assessButton());
    expect(fetchMock).toHaveBeenCalledTimes(4);
    await act(async () => { resolve[1](); resolve[0](); });
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(6));
    await act(async () => { resolve.slice(2).forEach(done => done()); });
    await waitFor(() => expect(queue()).toHaveLength(6));
    expect(queue().map(item => item.title.split(' · ')[0])).toEqual(selected.map(vuln => vuln.id));
});

test('keeps scopes independent and preserves queued work after unmount', async () => {
    const { rerender, unmount } = render(bar({ selectedVulns: ['CVE-1'] }));
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(1));
    rerender(bar({ selectedVulns: ['CVE-1'], variantId: 'outside-scope' }));
    expect(assessButton()).toBeEnabled();
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(2));
    expect(queue().map(item => item.context.variantId)).toEqual(['variant-1', 'outside-scope']);
    rerender(bar({ selectedVulns: ['CVE-1'] }));
    expect(assessButton()).toHaveTextContent('Queued');
    unmount();
    expect(queue()).toHaveLength(2);
    expect(fetchMock.mock.calls.some(([url]) => String(url).includes('/api/agent/'))).toBe(false);
});

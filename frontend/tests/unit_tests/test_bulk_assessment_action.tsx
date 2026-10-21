import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import fetchMock from 'jest-fetch-mock';
import type React from 'react';
import MultiEditBar from '../../src/components/MultiEditBar';
import type AgentChat from '../../src/components/AgentChat';
import type { Vulnerability } from '../../src/handlers/vulnerabilities';

fetchMock.enableMocks();
type ChatProps = React.ComponentProps<typeof AgentChat>;
let chatProps: ChatProps | undefined;
let chatMounts = 0;
let runningId: string | undefined;

jest.mock('../../src/components/AgentChat', () => ({
    __esModule: true,
    default: (props: ChatProps) => {
        const ReactLib = jest.requireActual('react');
        ReactLib.useEffect(() => { chatMounts++; }, []);
        chatProps = props;
        return <div data-testid="agent-chat">
            <button onClick={props.onClose}>Close chat</button>
            <button onClick={() => {
                runningId = props.queue?.[0]?.id;
                if (runningId) props.onQueuedMessageSent?.(runningId);
            }}>Start queued</button>
            <button onClick={() => runningId && props.onQueuedMessageDone?.(runningId)}>Finish running</button>
            <button onClick={() => props.onQueueClear?.()}>Clear queue</button>
            <button onClick={() => {
                const id = props.queue?.[0]?.id;
                if (id) props.onQueueRemove?.(id);
            }}>Remove queued</button>
        </div>;
    },
}));

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
const queue = () => chatProps?.queue ?? [];

beforeEach(() => {
    chatProps = undefined;
    chatMounts = 0;
    runningId = undefined;
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
    expect(screen.queryByTestId('agent-chat')).not.toBeInTheDocument();
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
    expect(chatProps?.context).toMatchObject({
        page: 'vulnerabilities', projectId: 'project-1', variantId: 'variant-1',
        view: { selectedVulnerabilityIds: ['CVE-1', 'CVE-2'], selectionCount: 2 },
    });
    expect(baseProps.resetVulns).not.toHaveBeenCalled();
    expect(assessButton()).toBeDisabled();
    expect(assessButton()).toHaveTextContent('Queued');
    fireEvent.click(assessButton());
    expect(queue()).toHaveLength(2);
});

test('keeps the conversation and captured targets when hidden or selection changes; skips overlapping actions', async () => {
    const { rerender } = render(bar({ selectedVulns: ['CVE-1'] }));
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(1));
    const threadId = chatProps?.threadId;
    fireEvent.click(screen.getByRole('button', { name: 'Close chat' }));
    expect(screen.getByTestId('agent-chat')).not.toBeVisible();
    rerender(bar({ selectedVulns: [] }));
    expect(queue()).toHaveLength(1);
    rerender(bar({ selectedVulns: ['CVE-1', 'CVE-2'] }));
    expect(assessButton()).toBeEnabled();
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(2));
    expect(chatProps?.threadId).toBe(threadId);
    expect(chatMounts).toBe(1);
    expect(screen.getByTestId('agent-chat')).toBeVisible();
    expect(queue().map(item => item.title.split(' · ')[0])).toEqual(['CVE-1', 'CVE-2']);
    expect(fetchMock.mock.calls.filter(([url]) => String(url).includes('CVE-1/variant-active-packages'))).toHaveLength(1);
});

test('tracks running actions, clearing pending items, and allows retry only after completion', async () => {
    render(bar({ selectedVulns: ['CVE-1'] }));
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(1));
    fireEvent.click(screen.getByRole('button', { name: 'Start queued' }));
    expect(assessButton()).toHaveTextContent('Running');
    expect(assessButton()).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Clear queue' }));
    expect(assessButton()).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Finish running' }));
    expect(assessButton()).toBeEnabled();
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(1));
    fireEvent.click(screen.getByRole('button', { name: 'Remove queued' }));
    expect(assessButton()).toBeEnabled();
});

test('reports lookup failures atomically without launching a partial queue, and supports retry', async () => {
    fetchMock.mockResponseOnce('[]').mockResponseOnce('failure', { status: 503 });
    render(bar({ selectedVulns: ['CVE-1', 'CVE-2'] }));
    fireEvent.click(assessButton());
    await waitFor(() => expect(baseProps.triggerBanner).toHaveBeenCalledWith(expect.any(String), 'error'));
    expect(screen.queryByTestId('agent-chat')).not.toBeInTheDocument();
    expect(assessButton()).toBeEnabled();
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(2));
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
    expect(screen.queryByTestId('agent-chat')).not.toBeInTheDocument();
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
    expect(chatProps?.context).toMatchObject({
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
    expect(screen.queryByTestId('agent-chat')).not.toBeInTheDocument();
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

test('discards the old thread and queue when scope changes and deletes the active thread on unmount', async () => {
    const { rerender, unmount } = render(bar({ selectedVulns: ['CVE-1'] }));
    fireEvent.click(assessButton());
    await waitFor(() => expect(queue()).toHaveLength(1));
    const threadId = chatProps?.threadId;
    rerender(bar({ selectedVulns: ['CVE-1'], variantId: 'other-variant' }));
    expect(screen.queryByTestId('agent-chat')).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith('/api/agent/conversation', {
        method: 'DELETE', credentials: 'same-origin', headers: { 'X-Agent-Thread': threadId },
    });
    rerender(bar({ selectedVulns: ['CVE-1'] }));
    fireEvent.click(assessButton());
    await waitFor(() => expect(screen.getByTestId('agent-chat')).toBeInTheDocument());
    expect(chatProps?.threadId).not.toBe(threadId);
    const secondThreadId = chatProps?.threadId;
    unmount();
    expect(fetchMock).toHaveBeenCalledWith('/api/agent/conversation', {
        method: 'DELETE', credentials: 'same-origin', headers: { 'X-Agent-Thread': secondThreadId },
    });
});

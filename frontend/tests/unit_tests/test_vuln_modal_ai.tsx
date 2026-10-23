import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
import React from 'react';

import type { Vulnerability } from "../../src/handlers/vulnerabilities";
import type { AssessmentTargetPair } from "../../src/handlers/assessments";
import VulnModal from '../../src/components/VulnModal';
import * as store from '../../src/handlers/agentQueue';

const { getAgentQueue, resetAgentQueue } = store;
let lastSentId: string | undefined;
const lastQueue = getAgentQueue;
const queuedMessage = () => getAgentQueue()[0]?.text ?? '';
let openedBefore = 0;
const chatOpenings = () => store.getAgentChatRequest().nonce - openedBefore;
// The real queue only drains with a connected chat; drive task status directly instead.
const mark = (status: 'running' | 'failed') => act(() => {
    const item = getAgentQueue()[0];
    if (item) {
        lastSentId = item.id;
        item.status = status;
        store.enqueueAgentMessages([], { page: 'vulnerabilities' });
    }
});
const finishRunning = () => act(() => {
    const item = getAgentQueue().find(task => task.id === lastSentId);
    if (item) item.status = 'queued';
    if (lastSentId) store.removeAgentTask(lastSentId);
});

const defaultAiTargets: AssessmentTargetPair[] = [
    { variant_id: 'v1', package: 'pkg@1.0.0' },
    { variant_id: 'v2', package: 'pkg@1.0.0' },
];
let mockAiTargets: AssessmentTargetPair[] = defaultAiTargets;

jest.mock('../../src/components/StatusEditor', () => ({
    __esModule: true,
    default: (props: { onAssessWithAi?: (targets: AssessmentTargetPair[]) => void; aiAssessState?: (targets: AssessmentTargetPair[]) => unknown }) => (
        <div data-testid="status-editor">
            {props.onAssessWithAi && <button type="button" onClick={() => props.onAssessWithAi?.(mockAiTargets)}>Assess with AI</button>}
            <span data-testid="assess-state">{(() => {
                const state = props.aiAssessState?.(mockAiTargets) as { status: string; position?: number } | undefined;
                return state ? `${state.status}${state.position ? ` #${state.position}` : ''}` : 'idle';
            })()}</span>
        </div>
    ),
}));

const vulnerability: Vulnerability = {
    id: 'CVE-2010-1234',
    aliases: [],
    related_vulnerabilities: [],
    namespace: 'nvd:cve',
    found_by: ['hardcoded'],
    datasource: 'https://nvd.nist.gov/vuln/detail/CVE-2010-1234',
    packages: ['pkg@1.0.0'],
    packages_current: [],
    urls: [],
    texts: [],
    severity: { severity: 'low', min_score: 3, max_score: 3, cvss: [] },
    epss: { score: 0, percentile: 0 },
    effort: {},
    fix: { state: 'unknown' },
    simplified_status: 'active',
    variants: [],
    assessments: [{
        id: 'assessment-1',
        vuln_id: 'CVE-2010-1234',
        packages: ['pkg@1.0.0'],
        status: 'affected',
        simplified_status: 'active',
        timestamp: '2021-01-01T00:00:00Z',
        origin: 'custom',
        responses: [],
    }, {
        id: 'assessment-sbom',
        vuln_id: 'CVE-2010-1234',
        packages: ['pkg@1.0.0'],
        status: 'affected',
        simplified_status: 'active',
        timestamp: '2020-01-01T00:00:00Z',
        origin: 'sbom',
        responses: [],
    }],
} as unknown as Vulnerability;

function renderModal(props: Partial<React.ComponentProps<typeof VulnModal>> = {}) {
    return render(<VulnModal vuln={vulnerability} onClose={() => {}} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} {...props} />);
}

describe('VulnModal AI actions', () => {
    beforeEach(() => {
        resetAgentQueue();
        openedBefore = store.getAgentChatRequest().nonce;
        lastSentId = undefined;
        mockAiTargets = defaultAiTargets;
        fetchMock.resetMocks();
        fetchMock.mockResponse(req => {
            if (req.url.endsWith(`/api/vulnerabilities/${vulnerability.id}/variants`)) {
                return Promise.resolve(JSON.stringify([
                    { id: 'v1', name: 'default', project_id: 'p' },
                    { id: 'v2', name: 'release', project_id: 'p' },
                ]));
            }
            return Promise.resolve(JSON.stringify([]));
        });
    });

    test('AI header button opens the main agent chat and enables edit mode without rendering a chat', async () => {
        const user = userEvent.setup();
        renderModal();

        expect(screen.queryByRole('button', { name: /^assess .* with ai$/i })).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: /edit$/i })).toHaveTextContent('Edit');
        const aiButton = screen.getByRole('button', { name: `Open agent chat for ${vulnerability.id}` });
        expect(aiButton).toHaveTextContent('AI');
        expect(aiButton).toHaveAttribute('aria-controls', 'agent-panel');

        await user.click(aiButton);
        expect(chatOpenings()).toBe(1);
        expect(screen.getByTitle('Exit editing mode')).toBeInTheDocument();
        expect(getAgentQueue()).toEqual([]);
        expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
        expect(screen.queryByRole('log', { name: 'Agent conversation' })).not.toBeInTheDocument();
    });

    test('Assess with AI queues the selected targets into the main chat and opens it', async () => {
        const user = userEvent.setup();
        renderModal({ isEditing: true });
        await waitFor(() => expect(fetchMock.mock.calls.some(([req]) => String(req instanceof Request ? req.url : req).endsWith('/variants'))).toBe(true));

        await waitFor(async () => {
            await user.click(screen.getByRole('button', { name: 'Assess with AI' }));
            expect(queuedMessage()).toContain('variant "release" (variant_id v2)');
        });
        expect(chatOpenings()).toBe(1);
        expect(store.getAgentChatRequest().taskId).toBe(getAgentQueue()[0].id);
        expect(getAgentQueue()[0]).toMatchObject({ source: `Vulnerability ${vulnerability.id}`, title: `${vulnerability.id} · 2 targets` });
        expect(store.getAgentConversation(getAgentQueue()[0].conversationId).title).toBe(`Assess ${vulnerability.id} · 2 targets`);
        const message = queuedMessage();
        expect(message).toContain(`Assess ${vulnerability.id} for exactly these targets (packages listed per variant)`);
        expect(message).toContain('variant "default" (variant_id v1): pkg@1.0.0');
        expect(message).toContain('write_assessment');
    });

    test('Assess with AI splits large selections into batches of whole variants within the message limit', async () => {
        const user = userEvent.setup();
        mockAiTargets = Array.from({ length: 200 }, (_, index) => ({
            variant_id: index % 2 ? 'v2' : 'v1',
            package: `very-long-package-name-for-batching-${index}@1.0.0-r${index}`,
        }));
        renderModal({ isEditing: true });
        await waitFor(() => expect(fetchMock.mock.calls.some(([req]) => String(req instanceof Request ? req.url : req).endsWith('/variants'))).toBe(true));
        await user.click(screen.getByRole('button', { name: 'Assess with AI' }));

        const messages: string[] = [];
        while (lastQueue().length) {
            messages.push(lastQueue()[0].text);
            mark('running');
            finishRunning();
        }
        expect(messages.length).toBeGreaterThan(1);
        messages.forEach((message, index) => {
            expect(message.length).toBeLessThanOrEqual(8000);
            expect(message).toContain(`Assess ${vulnerability.id} (batch ${index + 1} of ${messages.length}) for exactly these targets`);
        });
        // Each variant is listed in exactly one batch with all of its packages.
        const variantLines = messages.flatMap(message => message.split('\n').filter(line => line.startsWith('- variant ')));
        expect(variantLines).toHaveLength(2);
        for (const variantId of ['v1', 'v2']) {
            const line = variantLines.find(item => item.includes(`(variant_id ${variantId}):`)) ?? '';
            expect(line.split(': ')[1].split(', ')).toEqual(
                mockAiTargets.filter(target => target.variant_id === variantId).map(target => target.package));
        }
    });

    test('Assess with AI refuses a variant whose packages exceed the message limit', async () => {
        const user = userEvent.setup();
        mockAiTargets = Array.from({ length: 200 }, (_, index) => ({
            variant_id: 'v2',
            package: `very-long-package-name-for-batching-${index}@1.0.0-r${index}`,
        }));
        renderModal({ isEditing: true });
        await waitFor(() => expect(fetchMock.mock.calls.some(([req]) => String(req instanceof Request ? req.url : req).endsWith('/variants'))).toBe(true));
        await user.click(screen.getByRole('button', { name: 'Assess with AI' }));

        expect(await screen.findByText(/Too many packages selected for variant release/)).toBeInTheDocument();
        expect(getAgentQueue()).toEqual([]);
        expect(chatOpenings()).toBe(0);
    });

    test('Review with AI is shown only for user assessments and queues a review', async () => {
        const user = userEvent.setup();
        renderModal();

        const reviewButtons = screen.getAllByRole('button', { name: /review assessment .* with ai/i });
        expect(reviewButtons).toHaveLength(1);
        expect(reviewButtons[0]).toHaveAccessibleName('Review assessment assessment-1 with AI');
        expect(reviewButtons[0].previousElementSibling).toHaveTextContent('User');

        await user.click(reviewButtons[0]);
        expect(chatOpenings()).toBe(1);
        const message = queuedMessage();
        expect(message).toContain(`Review the user assessment assessment-1 for ${vulnerability.id}`);
        expect(message).toContain('write_assessment_review');
        expect(screen.getByTitle('Exit editing mode')).toBeInTheDocument();

        // While queued the button shows its position and opens the queued request instead of queueing it again.
        const queuedButton = screen.getByRole('button', { name: 'Review assessment assessment-1 with AI (queued, position 1)' });
        expect(queuedButton).toBeEnabled();
        expect(queuedButton).toHaveTextContent('Queued · #1');
        await user.click(queuedButton);
        expect(lastQueue()).toHaveLength(1);
        expect(chatOpenings()).toBe(2);
        expect(store.getAgentChatRequest().taskId).toBe(lastQueue()[0].id);

        mark('running');
        const runningButton = screen.getByRole('button', { name: 'Review assessment assessment-1 with AI (running)' });
        expect(runningButton).toHaveTextContent('Running…');
        await user.click(runningButton);
        expect(lastQueue()).toHaveLength(1);

        // Once finished the same review can be requested again.
        finishRunning();
        const idleButton = screen.getByRole('button', { name: 'Review assessment assessment-1 with AI' });
        expect(idleButton).toBeEnabled();
        await user.click(idleButton);
        expect(lastQueue()).toHaveLength(1);
    });

    test('identical Assess with AI requests are queued once, distinct actions queue in order', async () => {
        const user = userEvent.setup();
        renderModal({ isEditing: true });
        await user.click(screen.getByRole('button', { name: 'Assess with AI' }));
        await user.click(screen.getByRole('button', { name: 'Assess with AI' }));
        expect(lastQueue()).toHaveLength(1);
        expect(screen.getByTestId('assess-state')).toHaveTextContent('queued #1');

        await user.click(screen.getByRole('button', { name: 'Review assessment assessment-1 with AI' }));
        expect(lastQueue().map(item => item.kind)).toEqual(['assess', 'review']);
        expect(lastQueue()[0]).toMatchObject({ title: `${vulnerability.id} · 2 targets`, detail: expect.stringContaining('pkg@1.0.0') });
        expect(lastQueue()[1]).toMatchObject({ title: 'assessment assessme', detail: `${vulnerability.id} · pkg@1.0.0` });

        mark('running');
        expect(screen.getByTestId('assess-state')).toHaveTextContent('running');
        expect(screen.getByRole('button', { name: 'Review assessment assessment-1 with AI (queued, position 1)' })).toHaveTextContent('Queued · #1');

        act(() => store.clearAgentQueue());
        expect(lastQueue()).toHaveLength(1);
        expect(screen.getByRole('button', { name: 'Review assessment assessment-1 with AI' })).toBeEnabled();
        finishRunning();
        expect(screen.getByTestId('assess-state')).toHaveTextContent('idle');
    });

    test('keeps a failed action queued and retryable without losing subsequent actions', async () => {
        const user = userEvent.setup();
        renderModal({ isEditing: true });
        await user.click(screen.getByRole('button', { name: 'Assess with AI' }));
        await user.click(screen.getByRole('button', { name: 'Review assessment assessment-1 with AI' }));
        const firstId = lastQueue()[0].id;
        mark('running');
        mark('failed');
        expect(lastQueue()).toHaveLength(2);
        expect(lastQueue()[0].id).toBe(firstId);
        expect(screen.getByTestId('assess-state')).toHaveTextContent('failed');
        mark('running');
        finishRunning();
        expect(lastQueue().map(item => item.kind)).toEqual(['review']);
    });

    test('navigating to another CVE keeps queued work for the previous one and queues the new CVE separately', async () => {
        const user = userEvent.setup();
        const { rerender } = renderModal({ isEditing: true });
        await user.click(screen.getByRole('button', { name: 'Assess with AI' }));

        const other = { ...vulnerability, id: 'CVE-2010-9999' } as Vulnerability;
        rerender(<VulnModal vuln={other} isEditing={true} onClose={() => {}} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);
        expect(screen.getByTestId('assess-state')).toHaveTextContent('idle');
        await user.click(screen.getByRole('button', { name: 'Assess with AI' }));

        expect(getAgentQueue().map(item => item.source)).toEqual([`Vulnerability ${vulnerability.id}`, `Vulnerability ${other.id}`]);
        expect(screen.getByTestId('assess-state')).toHaveTextContent('queued #2');
        expect(fetchMock.mock.calls.some(([req]) => String(req instanceof Request ? req.url : req).includes('/api/agent/'))).toBe(false);
    });

    test('read-only modal hides all AI actions', () => {
        renderModal({ readOnly: true });
        expect(screen.queryByRole('button', { name: /open agent chat/i })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /with ai/i })).not.toBeInTheDocument();
    });
});

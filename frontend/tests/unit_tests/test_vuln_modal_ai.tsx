import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
import React from 'react';

import type { Vulnerability } from "../../src/handlers/vulnerabilities";
import type { AssessmentTargetPair } from "../../src/handlers/assessments";
import VulnModal from '../../src/components/VulnModal';

type ChatProps = { threadId?: string; active?: boolean; queuedMessage?: { id: string; text: string }; onQueuedMessageSent?: (id: string) => void };
const chatProps: ChatProps[] = [];
let chatMounts = 0;

jest.mock('../../src/components/AgentChat', () => ({
    __esModule: true,
    default: function MockAgentChat(props: ChatProps & { onClose: () => void }) {
        const ReactLib = jest.requireActual('react');
        ReactLib.useEffect(() => { chatMounts += 1; }, []);
        chatProps.push(props);
        return <div data-testid="agent-chat">
            <span data-testid="queued-message">{props.queuedMessage?.text ?? ''}</span>
            <button type="button" onClick={props.onClose}>Close chat</button>
            <button type="button" onClick={() => props.queuedMessage && props.onQueuedMessageSent?.(props.queuedMessage.id)}>Accept queued</button>
        </div>;
    },
}));

const defaultAiTargets: AssessmentTargetPair[] = [
    { variant_id: 'v1', package: 'pkg@1.0.0' },
    { variant_id: 'v2', package: 'pkg@1.0.0' },
];
let mockAiTargets: AssessmentTargetPair[] = defaultAiTargets;

jest.mock('../../src/components/StatusEditor', () => ({
    __esModule: true,
    default: (props: { onAssessWithAi?: (targets: AssessmentTargetPair[]) => void }) => (
        <div data-testid="status-editor">
            {props.onAssessWithAi && <button type="button" onClick={() => props.onAssessWithAi?.(mockAiTargets)}>Assess with AI</button>}
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
        chatProps.length = 0;
        chatMounts = 0;
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

    test('AI header button toggles the chat and enables edit mode only on open', async () => {
        const user = userEvent.setup();
        renderModal();

        expect(screen.queryByRole('button', { name: /^assess .* with ai$/i })).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: /edit$/i })).toHaveTextContent('Edit');
        const aiButton = screen.getByRole('button', { name: `Toggle AI chat for ${vulnerability.id}` });
        expect(aiButton).toHaveTextContent('AI');
        expect(aiButton).toHaveAttribute('aria-expanded', 'false');

        await user.click(aiButton);
        expect(screen.getByTestId('agent-chat')).toBeInTheDocument();
        expect(aiButton).toHaveAttribute('aria-expanded', 'true');
        expect(screen.getByTitle('Exit editing mode')).toBeInTheDocument();
        expect(screen.getByTestId('queued-message')).toHaveTextContent('');

        await user.click(aiButton);
        expect(screen.getByTestId('agent-chat')).not.toBeVisible();
        expect(screen.getByTitle('Exit editing mode')).toBeInTheDocument();
    });

    test('closing the chat from inside the panel keeps edit mode', async () => {
        const user = userEvent.setup();
        renderModal({ isEditing: true });

        await user.click(screen.getByRole('button', { name: `Toggle AI chat for ${vulnerability.id}` }));
        await user.click(screen.getByRole('button', { name: 'Close chat' }));
        expect(screen.getByTestId('agent-chat')).not.toBeVisible();
        expect(screen.getByTitle('Exit editing mode')).toBeInTheDocument();
    });

    test('Assess with AI opens the chat with the selected targets', async () => {
        const user = userEvent.setup();
        renderModal({ isEditing: true });
        await waitFor(() => expect(fetchMock.mock.calls.some(([req]) => String(req instanceof Request ? req.url : req).endsWith('/variants'))).toBe(true));

        await waitFor(async () => {
            await user.click(screen.getByRole('button', { name: 'Assess with AI' }));
            expect(screen.getByTestId('queued-message')).toHaveTextContent('variant "release" (variant_id v2)');
        });
        const message = screen.getByTestId('queued-message').textContent ?? '';
        expect(message).toContain(`Assess ${vulnerability.id} for exactly these targets`);
        expect(message).toContain('variant "default" (variant_id v1), package pkg@1.0.0');
        expect(message).toContain('write_assessment');
    });

    test('Assess with AI splits large selections into batches within the message limit', async () => {
        const user = userEvent.setup();
        mockAiTargets = Array.from({ length: 200 }, (_, index) => ({
            variant_id: index % 2 ? 'v2' : 'v1',
            package: `very-long-package-name-for-batching-${index}@1.0.0-r${index}`,
        }));
        renderModal({ isEditing: true });
        await waitFor(() => expect(fetchMock.mock.calls.some(([req]) => String(req instanceof Request ? req.url : req).endsWith('/variants'))).toBe(true));
        await user.click(screen.getByRole('button', { name: 'Assess with AI' }));

        const messages: string[] = [];
        while (chatProps[chatProps.length - 1].queuedMessage) {
            messages.push(chatProps[chatProps.length - 1].queuedMessage!.text);
            await user.click(screen.getByRole('button', { name: 'Accept queued' }));
        }
        expect(messages.length).toBeGreaterThan(1);
        messages.forEach((message, index) => {
            expect(message.length).toBeLessThanOrEqual(8000);
            expect(message).toContain(`Assess ${vulnerability.id} (batch ${index + 1} of ${messages.length}) for exactly these targets`);
        });
        const packages = messages.flatMap(message => [...message.matchAll(/package (\S+)/g)].map(match => match[1]));
        expect(packages).toEqual(mockAiTargets.map(target => target.package));
    });

    test('Review with AI is shown only for user assessments and queues a review', async () => {
        const user = userEvent.setup();
        renderModal();

        const reviewButtons = screen.getAllByRole('button', { name: /review assessment .* with ai/i });
        expect(reviewButtons).toHaveLength(1);
        expect(reviewButtons[0]).toHaveAccessibleName('Review assessment assessment-1 with AI');
        expect(reviewButtons[0].previousElementSibling).toHaveTextContent('User');

        await user.click(reviewButtons[0]);
        const message = screen.getByTestId('queued-message').textContent ?? '';
        expect(message).toContain(`Review the user assessment assessment-1 for ${vulnerability.id}`);
        expect(message).toContain('write_assessment_review');
        expect(screen.getByTitle('Exit editing mode')).toBeInTheDocument();

        // Further actions queue behind the pending one instead of replacing it.
        await user.click(reviewButtons[0]);
        await user.click(reviewButtons[0]);
        const queuedIds = new Set<string>();
        for (let index = 0; index < 3; index += 1) {
            const head = chatProps[chatProps.length - 1].queuedMessage;
            expect(head?.text).toContain('Review the user assessment assessment-1');
            queuedIds.add(head!.id);
            await user.click(screen.getByRole('button', { name: 'Accept queued' }));
        }
        expect(queuedIds.size).toBe(3);
        expect(chatProps[chatProps.length - 1].queuedMessage).toBeUndefined();
    });

    const deleteCalls = () => fetchMock.mock.calls.filter(([req, init]) =>
        String(req instanceof Request ? req.url : req).endsWith('/api/agent/conversation') && init?.method === 'DELETE');

    test('closing and reopening the chat keeps the same session', async () => {
        const user = userEvent.setup();
        renderModal();
        const aiButton = screen.getByRole('button', { name: `Toggle AI chat for ${vulnerability.id}` });

        await user.click(aiButton);
        const threadId = chatProps[chatProps.length - 1].threadId;
        expect(threadId).toBeTruthy();
        await user.click(screen.getByRole('button', { name: 'Close chat' }));
        expect(chatProps[chatProps.length - 1].active).toBe(false);
        await user.click(aiButton);

        expect(screen.getByTestId('agent-chat')).toBeVisible();
        expect(chatProps[chatProps.length - 1]).toMatchObject({ threadId, active: true });
        expect(chatMounts).toBe(1);
        expect(deleteCalls()).toHaveLength(0);
    });

    test('navigating to another CVE discards the session', async () => {
        const user = userEvent.setup();
        const { rerender } = renderModal();
        await user.click(screen.getByRole('button', { name: `Toggle AI chat for ${vulnerability.id}` }));
        const threadId = chatProps[chatProps.length - 1].threadId;

        const other = { ...vulnerability, id: 'CVE-2010-9999' } as Vulnerability;
        rerender(<VulnModal vuln={other} onClose={() => {}} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);

        expect(screen.queryByTestId('agent-chat')).not.toBeInTheDocument();
        expect(deleteCalls()).toHaveLength(1);
        expect((deleteCalls()[0][1]?.headers as Record<string, string>)['X-Agent-Thread']).toBe(threadId);

        await user.click(screen.getByRole('button', { name: `Toggle AI chat for ${other.id}` }));
        expect(chatProps[chatProps.length - 1].threadId).not.toBe(threadId);
    });

    test('closing the modal discards the session', async () => {
        const user = userEvent.setup();
        const { unmount } = renderModal();
        await user.click(screen.getByRole('button', { name: `Toggle AI chat for ${vulnerability.id}` }));
        await user.click(screen.getByRole('button', { name: 'Close chat' }));
        expect(deleteCalls()).toHaveLength(0);

        unmount();
        expect(deleteCalls()).toHaveLength(1);
    });

    test('read-only modal hides all AI actions', () => {
        renderModal({ readOnly: true });
        expect(screen.queryByRole('button', { name: /toggle ai chat/i })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /with ai/i })).not.toBeInTheDocument();
    });
});

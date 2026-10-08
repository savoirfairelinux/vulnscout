import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
import React from 'react';

import type { Vulnerability } from "../../src/handlers/vulnerabilities";
import type { AssessmentTargetPair } from "../../src/handlers/assessments";
import VulnModal from '../../src/components/VulnModal';

const chatProps: { queuedMessage?: { id: string; text: string } }[] = [];

jest.mock('../../src/components/AgentChat', () => ({
    __esModule: true,
    default: (props: { onClose: () => void; queuedMessage?: { id: string; text: string } }) => {
        chatProps.push(props);
        return <div data-testid="agent-chat">
            <span data-testid="queued-message">{props.queuedMessage?.text ?? ''}</span>
            <button type="button" onClick={props.onClose}>Close chat</button>
        </div>;
    },
}));

jest.mock('../../src/components/StatusEditor', () => ({
    __esModule: true,
    default: (props: { onAssessWithAi?: (targets: AssessmentTargetPair[]) => void }) => (
        <div data-testid="status-editor">
            {props.onAssessWithAi && <button type="button" onClick={() => props.onAssessWithAi?.([
                { variant_id: 'v1', package: 'pkg@1.0.0' },
                { variant_id: 'v2', package: 'pkg@1.0.0' },
            ])}>Assess with AI</button>}
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
        expect(screen.queryByTestId('agent-chat')).not.toBeInTheDocument();
        expect(screen.getByTitle('Exit editing mode')).toBeInTheDocument();
    });

    test('closing the chat from inside the panel keeps edit mode', async () => {
        const user = userEvent.setup();
        renderModal({ isEditing: true });

        await user.click(screen.getByRole('button', { name: `Toggle AI chat for ${vulnerability.id}` }));
        await user.click(screen.getByRole('button', { name: 'Close chat' }));
        expect(screen.queryByTestId('agent-chat')).not.toBeInTheDocument();
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

        // Queuing a second action reuses the open chat with a fresh message id.
        const firstId = chatProps[chatProps.length - 1].queuedMessage?.id;
        await user.click(reviewButtons[0]);
        expect(chatProps[chatProps.length - 1].queuedMessage?.id).not.toEqual(firstId);
    });

    test('read-only modal hides all AI actions', () => {
        renderModal({ readOnly: true });
        expect(screen.queryByRole('button', { name: /toggle ai chat/i })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /with ai/i })).not.toBeInTheDocument();
    });
});

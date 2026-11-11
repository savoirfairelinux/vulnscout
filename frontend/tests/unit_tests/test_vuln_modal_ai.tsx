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
import type { AgentAction, AgentRequestRecord } from '../../src/types/agent';

const { getAgentQueue } = store;
const lastQueue = getAgentQueue;
let openedBefore = 0;
const chatOpenings = () => store.getAgentChatRequest().nonce - openedBefore;

/** Stands in for the queue stream; `publish` delivers the fake backend's queue to every open stream. */
let streams: Array<Map<string, (event: MessageEvent) => void>> = [];
let records: AgentRequestRecord[] = [];
type Posted = { conversation: string; source: string; context: Record<string, unknown>; actions: AgentAction[] };
let posted: Posted[] = [];
let queueError: string | undefined;
const publish = () => act(() => {
    const data = JSON.stringify({ paused: null, requests: records, history: [], conversations: [] });
    streams.forEach(handlers => handlers.get('queue')?.({ data, lastEventId: '' } as MessageEvent));
});
const serverKey = (action: AgentAction) => action.key ?? (action.kind === 'assess'
    ? `assess:${action.vuln_id}:${(action.targets ?? []).map(target => `${target.variant_id}|${target.package}`).sort().join(',')}`
    : action.kind === 'review' ? `review:${action.assessment_id}` : 'message');
/** Queue the posted actions like the backend: one request per key not already active, positioned in order. */
const accept = (body: Posted) => {
    const created: AgentRequestRecord[] = [];
    const skipped: Array<{ key: string; request_id: string }> = [];
    for (const action of body.actions) {
        const key = serverKey(action);
        const held = records.find(item => item.key === key);
        if (held) {
            skipped.push({ key, request_id: held.id });
            continue;
        }
        const id = `r${posted.length}-${created.length}`;
        created.push({
            id, key, kind: action.kind, lane: 'action', conversation_id: `c-${id}`, source: body.source,
            title: action.kind === 'assess' ? `${action.vuln_id} · ${action.targets?.length} targets`
                : action.kind === 'review' ? `assessment ${action.assessment_id.slice(0, 8)}` : 'message',
            detail: '', model: 'auto', status: 'queued', error: null, error_code: null, position: null, created_at: 1,
            started_at: null, finished_at: null, context: body.context as AgentRequestRecord['context'], text: '',
            vuln_id: action.kind === 'assess' ? action.vuln_id : null, assessment_id: action.kind === 'review' ? action.assessment_id : null,
            timeout: 900, result: null,
        });
    }
    records = [...records, ...created];
    reposition();
    return { requests: created.map(item => ({ id: item.id, key: item.key, conversation_id: item.conversation_id })), skipped };
};
const reposition = () => {
    let position = 0;
    records = records.map(item => ({ ...item, position: item.status === 'queued' ? ++position : null }));
    publish();
};
const mark = (index: number, status: 'running' | 'failed') => {
    records = records.map((item, at) => at === index ? { ...item, status } : item);
    reposition();
};
const finish = (index: number) => {
    records = records.filter((_, at) => at !== index);
    reposition();
};
const agentPosts = () => posted.length;

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
    let restoreFactory: () => void;
    afterEach(() => restoreFactory());
    beforeEach(() => {
        store.__resetAgentQueue();
        streams = [];
        records = [];
        posted = [];
        queueError = undefined;
        restoreFactory = store.__setEventSourceFactory(() => {
            const handlers = new Map<string, (event: MessageEvent) => void>();
            streams.push(handlers);
            return { addEventListener: (type: string, handler: (event: MessageEvent) => void) => handlers.set(type, handler),
                close: () => undefined, onerror: null } as unknown as EventSource;
        });
        openedBefore = store.getAgentChatRequest().nonce;
        mockAiTargets = defaultAiTargets;
        fetchMock.resetMocks();
        fetchMock.mockResponse(async req => {
            if (req.url.endsWith('/api/agent/queue')) {
                const body = await req.json() as Posted;
                posted.push(body);
                const response = queueError ? { error: queueError } : accept(body);
                return { body: JSON.stringify(response), status: queueError ? 400 : 202, headers: { 'content-type': 'application/json' } };
            }
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

    test('Assess with AI queues the selected targets in their own conversation and opens it', async () => {
        const user = userEvent.setup();
        renderModal({ isEditing: true });
        await waitFor(() => expect(fetchMock.mock.calls.some(([req]) => String(req instanceof Request ? req.url : req).endsWith('/variants'))).toBe(true));

        await user.click(screen.getByRole('button', { name: 'Assess with AI' }));
        await waitFor(() => expect(chatOpenings()).toBe(1));
        expect(posted).toEqual([{
            conversation: 'per-action', source: `Vulnerability ${vulnerability.id}`,
            context: { page: 'vulnerabilities', view: { openVulnerabilityId: vulnerability.id, matchingVariantIds: ['v1', 'v2'], selectionCount: 2 } },
            actions: [{ kind: 'assess', vuln_id: vulnerability.id, targets: defaultAiTargets }],
        }]);
        expect(store.getAgentChatRequest().taskId).toBe(getAgentQueue()[0].id);
        expect(screen.getByTestId('assess-state')).toHaveTextContent('queued #1');
    });

    test('Assess with AI reports a request the backend rejects', async () => {
        const user = userEvent.setup();
        queueError = 'Too many packages for variant release to assess in one request.';
        renderModal({ isEditing: true });
        await user.click(screen.getByRole('button', { name: 'Assess with AI' }));

        expect(await screen.findByText(/Too many packages for variant release/)).toBeInTheDocument();
        expect(getAgentQueue()).toEqual([]);
        expect(chatOpenings()).toBe(0);
    });

    test('Assess with AI without targets queues nothing', async () => {
        const user = userEvent.setup();
        mockAiTargets = [];
        renderModal({ isEditing: true });
        await user.click(screen.getByRole('button', { name: 'Assess with AI' }));
        expect(await screen.findByText(`No active assessment targets for ${vulnerability.id}.`)).toBeInTheDocument();
        expect(agentPosts()).toBe(0);
    });

    test('Review with AI is shown only for user assessments and queues a review', async () => {
        const user = userEvent.setup();
        renderModal();

        const reviewButtons = screen.getAllByRole('button', { name: /review assessment .* with ai/i });
        expect(reviewButtons).toHaveLength(1);
        expect(reviewButtons[0]).toHaveAccessibleName('Review assessment assessment-1 with AI');
        expect(reviewButtons[0].previousElementSibling).toHaveTextContent('User');

        await user.click(reviewButtons[0]);
        await waitFor(() => expect(chatOpenings()).toBe(1));
        expect(posted[0].actions).toEqual([{ kind: 'review', assessment_id: 'assessment-1' }]);
        expect(screen.getByTitle('Exit editing mode')).toBeInTheDocument();

        // While queued the button shows its position and opens the queued request instead of queueing it again.
        const queuedButton = screen.getByRole('button', { name: 'Review assessment assessment-1 with AI (queued, position 1)' });
        expect(queuedButton).toBeEnabled();
        expect(queuedButton).toHaveTextContent('Queued · #1');
        await user.click(queuedButton);
        expect(agentPosts()).toBe(1);
        expect(chatOpenings()).toBe(2);
        expect(store.getAgentChatRequest().taskId).toBe(lastQueue()[0].id);

        mark(0, 'running');
        const runningButton = screen.getByRole('button', { name: 'Review assessment assessment-1 with AI (running)' });
        expect(runningButton).toHaveTextContent('Running…');
        await user.click(runningButton);
        expect(agentPosts()).toBe(1);

        // Once finished the same review can be requested again.
        finish(0);
        const idleButton = screen.getByRole('button', { name: 'Review assessment assessment-1 with AI' });
        expect(idleButton).toBeEnabled();
        await user.click(idleButton);
        await waitFor(() => expect(lastQueue()).toHaveLength(1));
        expect(agentPosts()).toBe(2);
    });

    test('identical Assess with AI requests are queued once and distinct actions follow the backend positions', async () => {
        const user = userEvent.setup();
        renderModal({ isEditing: true });
        await user.click(screen.getByRole('button', { name: 'Assess with AI' }));
        await waitFor(() => expect(screen.getByTestId('assess-state')).toHaveTextContent('queued #1'));
        await user.click(screen.getByRole('button', { name: 'Assess with AI' }));
        expect(agentPosts()).toBe(1);

        await user.click(screen.getByRole('button', { name: 'Review assessment assessment-1 with AI' }));
        await waitFor(() => expect(lastQueue().map(item => item.kind)).toEqual(['assess', 'review']));

        mark(0, 'running');
        expect(screen.getByTestId('assess-state')).toHaveTextContent('running');
        expect(screen.getByRole('button', { name: 'Review assessment assessment-1 with AI (queued, position 1)' })).toHaveTextContent('Queued · #1');

        // Another tab's change reaches this one through the stream.
        finish(1);
        expect(screen.getByRole('button', { name: 'Review assessment assessment-1 with AI' })).toBeEnabled();
        finish(0);
        expect(screen.getByTestId('assess-state')).toHaveTextContent('idle');
    });

    test('a failed action shows as failed without blocking a new action', async () => {
        const user = userEvent.setup();
        renderModal({ isEditing: true });
        await user.click(screen.getByRole('button', { name: 'Assess with AI' }));
        await waitFor(() => expect(lastQueue()).toHaveLength(1));
        mark(0, 'failed');
        expect(screen.getByTestId('assess-state')).toHaveTextContent('failed');
        await user.click(screen.getByRole('button', { name: 'Review assessment assessment-1 with AI' }));
        await waitFor(() => expect(lastQueue().map(item => [item.kind, item.status])).toEqual([['assess', 'failed'], ['review', 'queued']]));
    });

    test('navigating to another CVE keeps queued work for the previous one and queues the new CVE separately', async () => {
        const user = userEvent.setup();
        const { rerender } = renderModal({ isEditing: true });
        await user.click(screen.getByRole('button', { name: 'Assess with AI' }));
        await waitFor(() => expect(lastQueue()).toHaveLength(1));

        const other = { ...vulnerability, id: 'CVE-2010-9999' } as Vulnerability;
        rerender(<VulnModal vuln={other} isEditing={true} onClose={() => {}} appendAssessment={() => {}} appendCVSS={() => null} patchVuln={() => {}} />);
        expect(screen.getByTestId('assess-state')).toHaveTextContent('idle');
        await user.click(screen.getByRole('button', { name: 'Assess with AI' }));

        await waitFor(() => expect(getAgentQueue().map(item => item.source)).toEqual([`Vulnerability ${vulnerability.id}`, `Vulnerability ${other.id}`]));
        expect(screen.getByTestId('assess-state')).toHaveTextContent('queued #2');
    });

    test('read-only modal hides all AI actions', () => {
        renderModal({ readOnly: true });
        expect(screen.queryByRole('button', { name: /open agent chat/i })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /with ai/i })).not.toBeInTheDocument();
    });
});

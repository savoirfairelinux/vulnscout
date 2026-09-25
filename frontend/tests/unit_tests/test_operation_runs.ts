import { groupQueueItems, isQueueItemActive, runStatus } from '../../src/helpers/operationRuns';
import type { Operation, OperationStatus } from '../../src/types/operation';

const step = (opId: string, status: OperationStatus, overrides: Partial<Operation> = {}): Operation => ({
    op_id: opId,
    kind: 'scan',
    source: 'grype',
    label: 'Grype Scan',
    lane: 'pipeline',
    scope: null,
    status,
    progress: { current: 0, total: 0, message: '' },
    logs: [],
    error: null,
    queue_id: null,
    position: null,
    options: {},
    cancellable: true,
    created_at: '2026-09-25T10:00:00+00:00',
    started_at: null,
    finished_at: null,
    result: null,
    ...overrides,
});

describe('groupQueueItems', () => {
    it('keeps lone operations and places each run where its first step appears', () => {
        const items = groupQueueItems([
            step('upload', 'done'),
            step('scan:nvd:v1', 'queued', { queue_id: 'q-1', position: 2 }),
            step('refresh:nvd', 'done', { queue_id: 'q-solo', position: 1 }),
            step('scan:grype:v1', 'running', { queue_id: 'q-1', position: 1 }),
        ]);

        expect(items.map(item => item.type === 'run'
            ? `run:${item.steps.map(member => member.op_id).join(',')}`
            : item.operation.op_id)).toEqual([
            'upload',
            'run:scan:grype:v1,scan:nvd:v1',
            'refresh:nvd',
        ]);
    });

    it('treats a run as active until every step has settled', () => {
        const [run] = groupQueueItems([
            step('a', 'done', { queue_id: 'q-1' }),
            step('b', 'queued', { queue_id: 'q-1' }),
        ]);
        const [lone] = groupQueueItems([step('c', 'error')]);

        expect(isQueueItemActive(run)).toBe(true);
        expect(isQueueItemActive(lone)).toBe(false);
    });
});

describe('runStatus', () => {
    it.each([
        [['queued', 'queued'], 'queued'],
        [['done', 'queued'], 'running'],
        [['running', 'queued'], 'running'],
        [['done', 'error', 'cancelled'], 'error'],
        [['done', 'cancelled'], 'cancelled'],
        [['done', 'done'], 'done'],
    ] as [OperationStatus[], OperationStatus][])('%j settles as %s', (statuses, expected) => {
        expect(runStatus(statuses.map((status, index) => step(`op-${index}`, status)))).toBe(expected);
    });
});

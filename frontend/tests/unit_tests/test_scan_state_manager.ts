import { ScanStateManager } from '../../src/handlers/scanStateManager';
import type { ScanManagerSnapshot } from '../../src/handlers/scanStateManager';

type Status = {
    status: string;
    error?: string | null;
    progress?: string | null;
    logs?: string[];
    total?: number;
    done_count?: number;
};

function makeManager(statusReplies: Record<string, Status>) {
    const triggerFn = jest.fn(async () => ({ ok: true }));
    const statusFn = jest.fn(async (vid: string) => statusReplies[vid] ?? { status: 'idle' });
    const manager = new ScanStateManager(triggerFn, statusFn, 'Test');
    return { manager, triggerFn, statusFn };
}

describe('ScanStateManager.restoreFromStatus', () => {
    beforeEach(() => {
        jest.useFakeTimers();
    });

    afterEach(() => {
        jest.clearAllTimers();
        jest.useRealTimers();
    });

    test('seeds running scans into the snapshot', () => {
        const { manager } = makeManager({});
        manager.restoreFromStatus([
            {
                variantId: 'v1',
                name: 'Variant 1',
                status: { status: 'running', progress: 'scanning', logs: ['line'], total: 10, done_count: 3 },
            },
        ]);

        const snap: ScanManagerSnapshot = manager.getSnapshot();
        expect(snap).toHaveLength(1);
        expect(snap[0]).toMatchObject({
            variantId: 'v1',
            variantName: 'Variant 1',
            status: 'running',
            progress: 'scanning',
            logs: ['line'],
            total: 10,
            doneCount: 3,
        });
    });

    test('defaults progress to "starting" and fills missing fields', () => {
        const { manager } = makeManager({});
        manager.restoreFromStatus([
            { variantId: 'v1', name: 'V1', status: { status: 'running' } },
        ]);

        expect(manager.getSnapshot()[0]).toMatchObject({
            progress: 'starting',
            logs: [],
            total: 0,
            doneCount: 0,
        });
    });

    test('ignores entries that are not running', () => {
        const { manager } = makeManager({});
        manager.restoreFromStatus([
            { variantId: 'v1', name: 'V1', status: { status: 'done' } },
            { variantId: 'v2', name: 'V2', status: { status: 'idle' } },
            { variantId: 'v3', name: 'V3', status: { status: 'error' } },
        ]);
        expect(manager.getSnapshot()).toHaveLength(0);
    });

    test('does not clobber a variant already tracked in this session', () => {
        const { manager } = makeManager({});
        manager.restoreFromStatus([
            { variantId: 'v1', name: 'Original', status: { status: 'running', progress: 'first' } },
        ]);
        manager.restoreFromStatus([
            { variantId: 'v1', name: 'Replacement', status: { status: 'running', progress: 'second' } },
        ]);

        const snap = manager.getSnapshot();
        expect(snap).toHaveLength(1);
        expect(snap[0]).toMatchObject({ variantName: 'Original', progress: 'first' });
    });

    test('does nothing and starts no timer when nothing is running', () => {
        const setInterval = jest.spyOn(global, 'setInterval');
        const { manager } = makeManager({});
        manager.restoreFromStatus([
            { variantId: 'v1', name: 'V1', status: { status: 'done' } },
        ]);
        expect(setInterval).not.toHaveBeenCalled();
        expect(manager.getSnapshot()).toHaveLength(0);
        setInterval.mockRestore();
    });

    test('starts polling and reflects completion of a restored scan', async () => {
        const { manager, statusFn } = makeManager({
            v1: { status: 'done', progress: 'Done', total: 5, done_count: 5 },
        });
        manager.restoreFromStatus([
            { variantId: 'v1', name: 'V1', status: { status: 'running', progress: 'scanning' } },
        ]);
        expect(manager.getSnapshot()[0].status).toBe('running');

        // Advance to the next poll tick (3s interval) and flush the async poll.
        await jest.advanceTimersByTimeAsync(3000);

        expect(statusFn).toHaveBeenCalledWith('v1');
        expect(manager.getSnapshot()[0].status).toBe('done');
    });
});

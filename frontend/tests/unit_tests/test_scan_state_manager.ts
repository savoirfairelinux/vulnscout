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

describe('ScanStateManager.subscribe', () => {
    test('notifies listeners on state change and stops after unsubscribe', () => {
        const { manager } = makeManager({});
        const listener = jest.fn();
        const unsubscribe = manager.subscribe(listener);

        manager.restoreFromStatus([
            { variantId: 'v1', name: 'V1', status: { status: 'running' } },
        ]);
        expect(listener).toHaveBeenCalled();

        const callsAfterFirst = listener.mock.calls.length;
        unsubscribe();

        manager.dismissAll();
        expect(listener).toHaveBeenCalledTimes(callsAfterFirst);
    });
});

describe('ScanStateManager.setOnDone', () => {
    beforeEach(() => {
        jest.useFakeTimers();
    });

    afterEach(() => {
        jest.clearAllTimers();
        jest.useRealTimers();
    });

    test('fires the onDone callback when all scans finish', async () => {
        const { manager } = makeManager({
            v1: { status: 'done' },
        });
        const onDone = jest.fn();
        manager.setOnDone(onDone);

        manager.restoreFromStatus([
            { variantId: 'v1', name: 'V1', status: { status: 'running' } },
        ]);

        await jest.advanceTimersByTimeAsync(3000);
        expect(onDone).toHaveBeenCalledTimes(1);
    });

    test('can clear the onDone callback', async () => {
        const { manager } = makeManager({ v1: { status: 'done' } });
        const onDone = jest.fn();
        manager.setOnDone(onDone);
        manager.setOnDone(null);

        manager.restoreFromStatus([
            { variantId: 'v1', name: 'V1', status: { status: 'running' } },
        ]);
        await jest.advanceTimersByTimeAsync(3000);
        expect(onDone).not.toHaveBeenCalled();
    });
});

describe('ScanStateManager.dismiss / dismissAll', () => {
    beforeEach(() => {
        jest.useFakeTimers();
    });

    afterEach(() => {
        jest.clearAllTimers();
        jest.useRealTimers();
    });

    test('dismiss removes a single variant and stops polling when none remain running', () => {
        const clearInterval = jest.spyOn(global, 'clearInterval');
        const { manager } = makeManager({});
        manager.restoreFromStatus([
            { variantId: 'v1', name: 'V1', status: { status: 'running' } },
        ]);
        expect(manager.getSnapshot()).toHaveLength(1);

        manager.dismiss('v1');
        expect(manager.getSnapshot()).toHaveLength(0);
        expect(clearInterval).toHaveBeenCalled();
        clearInterval.mockRestore();
    });

    test('dismiss keeps polling while another variant is still running', () => {
        const clearInterval = jest.spyOn(global, 'clearInterval');
        const { manager } = makeManager({});
        manager.restoreFromStatus([
            { variantId: 'v1', name: 'V1', status: { status: 'running' } },
            { variantId: 'v2', name: 'V2', status: { status: 'running' } },
        ]);

        manager.dismiss('v1');
        expect(manager.getSnapshot()).toHaveLength(1);
        expect(clearInterval).not.toHaveBeenCalled();
        clearInterval.mockRestore();
    });

    test('dismissAll clears every variant and stops polling', () => {
        const { manager } = makeManager({});
        manager.restoreFromStatus([
            { variantId: 'v1', name: 'V1', status: { status: 'running' } },
            { variantId: 'v2', name: 'V2', status: { status: 'running' } },
        ]);

        manager.dismissAll();
        expect(manager.getSnapshot()).toHaveLength(0);
    });
});

describe('ScanStateManager.triggerScan (parallel)', () => {
    beforeEach(() => {
        jest.useFakeTimers();
    });

    afterEach(() => {
        jest.clearAllTimers();
        jest.useRealTimers();
    });

    test('returns immediately when no variants are provided', async () => {
        const { manager, triggerFn } = makeManager({});
        await manager.triggerScan([]);
        expect(triggerFn).not.toHaveBeenCalled();
        expect(manager.getSnapshot()).toHaveLength(0);
    });

    test('triggers every variant and marks them running', async () => {
        const { manager, triggerFn } = makeManager({});
        await manager.triggerScan([
            { id: 'v1', name: 'V1' },
            { id: 'v2', name: 'V2' },
        ]);

        expect(triggerFn).toHaveBeenCalledWith('v1', {});
        expect(triggerFn).toHaveBeenCalledWith('v2', {});
        const snap = manager.getSnapshot();
        expect(snap).toHaveLength(2);
        expect(snap.every((s) => s.status === 'running')).toBe(true);
    });

    test('marks a variant as error when its trigger fails', async () => {
        const triggerFn = jest.fn(async (vid: string) =>
            vid === 'v2' ? { ok: false, error: 'boom' } : { ok: true },
        );
        const statusFn = jest.fn(async () => ({ status: 'running' }));
        const manager = new ScanStateManager(triggerFn, statusFn, 'Test');

        await manager.triggerScan([
            { id: 'v1', name: 'V1' },
            { id: 'v2', name: 'V2' },
        ]);

        const snap = manager.getSnapshot();
        const v2 = snap.find((s) => s.variantId === 'v2');
        expect(v2).toMatchObject({ status: 'error', error: 'boom', progress: null });
    });

    test('uses a default error message when trigger fails without one', async () => {
        const triggerFn = jest.fn(async () => ({ ok: false }));
        const statusFn = jest.fn(async () => ({ status: 'idle' }));
        const manager = new ScanStateManager(triggerFn, statusFn, 'Grype');

        await manager.triggerScan([{ id: 'v1', name: 'V1' }]);
        expect(manager.getSnapshot()[0]).toMatchObject({
            status: 'error',
            error: 'Failed to start Grype scan',
        });
    });
});

describe('ScanStateManager.triggerScan (serial)', () => {
    beforeEach(() => {
        jest.useFakeTimers();
    });

    afterEach(() => {
        jest.clearAllTimers();
        jest.useRealTimers();
    });

    type TriggerFn = (vid: string) => Promise<{ ok: boolean; error?: string }>;

    function makeSerialManager(
        statusReplies: Record<string, Status>,
        triggerFn: TriggerFn = jest.fn(async () => ({ ok: true })),
    ) {
        const statusFn = jest.fn(async (vid: string) => statusReplies[vid] ?? { status: 'idle' });
        const manager = new ScanStateManager(triggerFn, statusFn, 'Test', true);
        return { manager, triggerFn, statusFn };
    }

    test('runs the first variant and queues the rest', async () => {
        const { manager, triggerFn } = makeSerialManager({});
        await manager.triggerScan([
            { id: 'v1', name: 'V1' },
            { id: 'v2', name: 'V2' },
            { id: 'v3', name: 'V3' },
        ]);

        const snap = manager.getSnapshot();
        expect(snap.find((s) => s.variantId === 'v1')?.status).toBe('running');
        expect(snap.find((s) => s.variantId === 'v2')?.status).toBe('queued');
        expect(snap.find((s) => s.variantId === 'v3')?.status).toBe('queued');
        expect(snap.map((s) => [s.variantPosition, s.variantCount])).toEqual([
            [1, 3],
            [2, 3],
            [3, 3],
        ]);
        expect(triggerFn).toHaveBeenCalledTimes(1);
        expect(triggerFn).toHaveBeenCalledWith('v1', {});
    });

    test('advances the queue as each scan finishes', async () => {
        const replies: Record<string, Status> = {
            v1: { status: 'done' },
            v2: { status: 'done' },
        };
        const { manager, triggerFn } = makeSerialManager(replies);

        await manager.triggerScan([
            { id: 'v1', name: 'V1' },
            { id: 'v2', name: 'V2' },
        ]);
        expect(triggerFn).toHaveBeenCalledWith('v1', {});

        // First poll: v1 finishes -> v2 starts
        await jest.advanceTimersByTimeAsync(3000);
        expect(triggerFn).toHaveBeenCalledWith('v2', {});
        expect(manager.getSnapshot().find((s) => s.variantId === 'v2')?.status).toBe('running');

        // Second poll: v2 finishes
        await jest.advanceTimersByTimeAsync(3000);
        expect(manager.getSnapshot().find((s) => s.variantId === 'v2')?.status).toBe('done');
    });

    test('marks the first variant as error and advances when its trigger fails', async () => {
        const triggerFn = jest.fn(async (vid: string) =>
            vid === 'v1' ? { ok: false, error: 'no start' } : { ok: true },
        );
        const { manager } = makeSerialManager({ v2: { status: 'done' } }, triggerFn);

        await manager.triggerScan([
            { id: 'v1', name: 'V1' },
            { id: 'v2', name: 'V2' },
        ]);

        const snap = manager.getSnapshot();
        expect(snap.find((s) => s.variantId === 'v1')).toMatchObject({
            status: 'error',
            error: 'no start',
        });
        // v2 should have been advanced to running
        expect(snap.find((s) => s.variantId === 'v2')?.status).toBe('running');
        expect(triggerFn).toHaveBeenCalledWith('v2', {});
    });

    test('queued variant trigger failure keeps the queue moving', async () => {
        const triggerFn = jest.fn(async (vid: string) =>
            vid === 'v2' ? { ok: false, error: 'queued fail' } : { ok: true },
        );
        const { manager } = makeSerialManager(
            { v1: { status: 'done' } },
            triggerFn,
        );

        await manager.triggerScan([
            { id: 'v1', name: 'V1' },
            { id: 'v2', name: 'V2' },
            { id: 'v3', name: 'V3' },
        ]);

        // v1 finishes -> v2 starts but fails -> v3 starts
        await jest.advanceTimersByTimeAsync(3000);

        const snap = manager.getSnapshot();
        expect(snap.find((s) => s.variantId === 'v2')).toMatchObject({ status: 'error' });
        expect(triggerFn).toHaveBeenCalledWith('v3', {});
    });
});

describe('ScanStateManager polling transitions', () => {
    beforeEach(() => {
        jest.useFakeTimers();
    });

    afterEach(() => {
        jest.clearAllTimers();
        jest.useRealTimers();
    });

    test('moves a running scan to error on error status', async () => {
        const { manager } = makeManager({
            v1: { status: 'error', error: 'scan crashed', logs: ['boom'] },
        });
        manager.restoreFromStatus([
            { variantId: 'v1', name: 'V1', status: { status: 'running' } },
        ]);

        await jest.advanceTimersByTimeAsync(3000);
        expect(manager.getSnapshot()[0]).toMatchObject({
            status: 'error',
            error: 'scan crashed',
            logs: ['boom'],
        });
    });

    test('uses default error message when error status has none', async () => {
        const { manager } = makeManager({ v1: { status: 'error' } });
        manager.restoreFromStatus([
            { variantId: 'v1', name: 'V1', status: { status: 'running' } },
        ]);

        await jest.advanceTimersByTimeAsync(3000);
        expect(manager.getSnapshot()[0].error).toBe('Test scan failed');
    });

    test('updates progress while a scan is still running', async () => {
        const statusFn = jest
            .fn<Promise<Status>, [string]>()
            .mockResolvedValueOnce({ status: 'running', progress: '50%', total: 10, done_count: 5, logs: ['half'] })
            .mockResolvedValue({ status: 'done', progress: 'Done' });
        const triggerFn = jest.fn(async () => ({ ok: true }));
        const manager = new ScanStateManager(triggerFn, statusFn, 'Test');

        manager.restoreFromStatus([
            { variantId: 'v1', name: 'V1', status: { status: 'running' } },
        ]);

        await jest.advanceTimersByTimeAsync(3000);
        expect(manager.getSnapshot()[0]).toMatchObject({
            status: 'running',
            progress: '50%',
            total: 10,
            doneCount: 5,
            logs: ['half'],
        });

        await jest.advanceTimersByTimeAsync(3000);
        expect(manager.getSnapshot()[0].status).toBe('done');
    });

    test('keeps polling when statusFn throws (network hiccup)', async () => {
        const statusFn = jest
            .fn<Promise<Status>, [string]>()
            .mockRejectedValueOnce(new Error('network'))
            .mockResolvedValue({ status: 'done' });
        const triggerFn = jest.fn(async () => ({ ok: true }));
        const manager = new ScanStateManager(triggerFn, statusFn, 'Test');

        manager.restoreFromStatus([
            { variantId: 'v1', name: 'V1', status: { status: 'running' } },
        ]);

        // First tick throws but polling continues
        await jest.advanceTimersByTimeAsync(3000);
        expect(manager.getSnapshot()[0].status).toBe('running');

        // Second tick succeeds
        await jest.advanceTimersByTimeAsync(3000);
        expect(manager.getSnapshot()[0].status).toBe('done');
    });
});

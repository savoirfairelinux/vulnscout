const queuedScan = [{ variantId: 'variant-1', status: 'running' }];
let finishScan: () => void;
const scanCompletion = new Promise<void>(resolve => {
    finishScan = resolve;
});

jest.mock('../../src/handlers/grypeScanState', () => ({
    getSnapshot: () => queuedScan,
    waitForCompletion: () => scanCompletion,
}));
jest.mock('../../src/handlers/nvdScanState', () => ({
    getSnapshot: () => [],
    waitForCompletion: () => Promise.resolve(),
}));
jest.mock('../../src/handlers/osvScanState', () => ({
    getSnapshot: () => [],
    waitForCompletion: () => Promise.resolve(),
}));
jest.mock('../../src/handlers/sccScanState', () => ({
    getSnapshot: () => [],
    waitForCompletion: () => Promise.resolve(),
}));
jest.mock('../../src/handlers/bulkRefresh', () => ({
    BulkNvdRefreshHandler: { trigger: jest.fn() },
    BulkEpssRefreshHandler: { trigger: jest.fn() },
    BulkGhsaRefreshHandler: { trigger: jest.fn() },
    BulkEuvdRefreshHandler: { trigger: jest.fn() },
}));
jest.mock('../../src/handlers/nvd_progress', () => ({ __esModule: true, default: { getProgress: jest.fn() } }));
jest.mock('../../src/handlers/epss_progress', () => ({ __esModule: true, default: { getProgress: jest.fn() } }));
jest.mock('../../src/handlers/ghsa_progress', () => ({ __esModule: true, default: { getProgress: jest.fn() } }));
jest.mock('../../src/handlers/euvd_progress', () => ({ __esModule: true, default: { getProgress: jest.fn() } }));

import {
    dismissRefreshQueueEntry,
    getRefreshQueueSnapshot,
    hasActiveRefreshes,
    queueVulnerabilityRefresh,
    restoreActiveRefreshes,
    waitForRefreshCompletion,
} from '../../src/handlers/activeScanQueue';
import { BulkEpssRefreshHandler, BulkNvdRefreshHandler } from '../../src/handlers/bulkRefresh';
import EPSSProgressHandler from '../../src/handlers/epss_progress';
import NVDProgressHandler from '../../src/handlers/nvd_progress';

describe('active scan queue', () => {
    const idleProgress = { in_progress: false, phase: 'idle', current: 0, total: 0, message: '' };

    beforeEach(() => {
        jest.useFakeTimers();
        jest.clearAllMocks();
    });

    afterEach(() => {
        jest.useRealTimers();
        for (const type of ['nvd', 'epss', 'ghsa', 'euvd'] as const) dismissRefreshQueueEntry(type);
    });

    it('queues separate sources and waits for backend completion before advancing', async () => {
        (BulkNvdRefreshHandler.trigger as jest.Mock).mockResolvedValue({ total: 1 });
        (BulkEpssRefreshHandler.trigger as jest.Mock).mockResolvedValue({ total: 1 });
        (NVDProgressHandler.getProgress as jest.Mock)
            .mockResolvedValueOnce({ in_progress: false, phase: 'idle', current: 0, total: 0, message: '' })
            .mockResolvedValueOnce({ in_progress: true, phase: 'refreshing', current: 1, total: 1, message: 'NVD 1/1' })
            .mockResolvedValueOnce({ in_progress: false, phase: 'completed', current: 1, total: 1, message: 'Complete', started_at: 'nvd-cycle' });
        (EPSSProgressHandler.getProgress as jest.Mock)
            .mockResolvedValueOnce({ in_progress: false, phase: 'idle', current: 0, total: 0, message: '' })
            .mockResolvedValueOnce({ in_progress: true, phase: 'refreshing', current: 1, total: 1, message: 'EPSS 1/1' })
            .mockResolvedValueOnce({ in_progress: false, phase: 'completed', current: 1, total: 1, message: 'Complete', started_at: 'epss-cycle' });

        expect(queueVulnerabilityRefresh({
            refreshTypes: ['nvd', 'epss'],
            nvdMode: 'local',
            loadVulnerabilities: async () => [{ id: 'CVE-2024-0001' }] as never,
        })).toBe(true);
        expect(getRefreshQueueSnapshot().map(entry => [entry.variantId, entry.status])).toEqual([
            ['nvd', 'queued'],
            ['epss', 'queued'],
        ]);
        expect(BulkNvdRefreshHandler.trigger).not.toHaveBeenCalled();

        finishScan!();
        await scanCompletion;
        await jest.advanceTimersByTimeAsync(0);
        expect(BulkNvdRefreshHandler.trigger).toHaveBeenCalledTimes(1);
        expect(BulkEpssRefreshHandler.trigger).not.toHaveBeenCalled();

        await jest.advanceTimersByTimeAsync(3000);
        expect(BulkEpssRefreshHandler.trigger).not.toHaveBeenCalled();
        await jest.advanceTimersByTimeAsync(3000);
        expect(BulkEpssRefreshHandler.trigger).toHaveBeenCalledTimes(1);
        expect(getRefreshQueueSnapshot().map(entry => entry.status)).toEqual(['done', 'running']);

        await jest.advanceTimersByTimeAsync(6000);
        expect(getRefreshQueueSnapshot().map(entry => entry.status)).toEqual(['done', 'done']);

        dismissRefreshQueueEntry('nvd');
        expect(getRefreshQueueSnapshot().map(entry => entry.variantId)).toEqual(['epss']);
    });

    it('marks backend refresh errors and continues with the next source', async () => {
        (BulkNvdRefreshHandler.trigger as jest.Mock).mockResolvedValue({ total: 1 });
        (BulkEpssRefreshHandler.trigger as jest.Mock).mockResolvedValue({ total: 1 });
        (NVDProgressHandler.getProgress as jest.Mock)
            .mockResolvedValueOnce(idleProgress)
            .mockResolvedValueOnce({ ...idleProgress, phase: 'error', message: 'NVD failed', started_at: 'nvd-cycle' });
        (EPSSProgressHandler.getProgress as jest.Mock)
            .mockResolvedValueOnce(idleProgress)
            .mockResolvedValueOnce({ ...idleProgress, phase: 'completed', current: 1, total: 1, message: 'Complete', started_at: 'epss-cycle' });

        expect(queueVulnerabilityRefresh({
            refreshTypes: ['nvd', 'epss'],
            nvdMode: 'local',
            loadVulnerabilities: async () => [{ id: 'CVE-2024-0001' }] as never,
        })).toBe(true);

        await jest.advanceTimersByTimeAsync(3000);
        expect(getRefreshQueueSnapshot()[0]).toMatchObject({ status: 'error', error: 'NVD failed' });
        expect(BulkEpssRefreshHandler.trigger).toHaveBeenCalledTimes(1);

        await jest.advanceTimersByTimeAsync(3000);
        expect(getRefreshQueueSnapshot()[1]).toMatchObject({ status: 'done', progress: 'Complete' });
    });

    it('keeps cancellation distinct from successful completion', async () => {
        (BulkNvdRefreshHandler.trigger as jest.Mock).mockResolvedValue({ total: 2 });
        (NVDProgressHandler.getProgress as jest.Mock)
            .mockResolvedValueOnce(idleProgress)
            .mockResolvedValueOnce({ ...idleProgress, phase: 'cancelled', current: 1, total: 2, message: 'Cancelled', started_at: 'nvd-cycle' });

        expect(queueVulnerabilityRefresh({
            refreshTypes: ['nvd'],
            nvdMode: 'local',
            loadVulnerabilities: async () => [{ id: 'CVE-2024-0001' }, { id: 'CVE-2024-0002' }] as never,
        })).toBe(true);
        await jest.advanceTimersByTimeAsync(3000);

        expect(getRefreshQueueSnapshot()[0]).toMatchObject({
            status: 'cancelled',
            progress: 'Cancelled',
            doneCount: 1,
            total: 2,
        });
    });

    it('releases queued scans only after every refresh source finishes', async () => {
        (BulkNvdRefreshHandler.trigger as jest.Mock).mockResolvedValue({ total: 1 });
        (BulkEpssRefreshHandler.trigger as jest.Mock).mockResolvedValue({ total: 1 });
        (NVDProgressHandler.getProgress as jest.Mock)
            .mockResolvedValueOnce(idleProgress)
            .mockResolvedValueOnce({ ...idleProgress, phase: 'completed', current: 1, total: 1, started_at: 'nvd-cycle' });
        (EPSSProgressHandler.getProgress as jest.Mock)
            .mockResolvedValueOnce(idleProgress)
            .mockResolvedValueOnce({ ...idleProgress, phase: 'completed', current: 1, total: 1, started_at: 'epss-cycle' });

        expect(queueVulnerabilityRefresh({
            refreshTypes: ['nvd', 'epss'],
            nvdMode: 'local',
            loadVulnerabilities: async () => [{ id: 'CVE-2024-0001' }] as never,
        })).toBe(true);

        const onRefreshesFinished = jest.fn();
        void waitForRefreshCompletion().then(onRefreshesFinished);
        await jest.advanceTimersByTimeAsync(3000);
        expect(onRefreshesFinished).not.toHaveBeenCalled();

        await jest.advanceTimersByTimeAsync(3000);
        expect(onRefreshesFinished).toHaveBeenCalledTimes(1);
    });

    it('restores an active backend refresh after a page reload', async () => {
        (NVDProgressHandler.getProgress as jest.Mock)
            .mockResolvedValueOnce({ ...idleProgress, in_progress: true, phase: 'refreshing', current: 1, total: 2, message: 'NVD 1/2' })
            .mockResolvedValueOnce({ ...idleProgress, phase: 'completed', current: 2, total: 2, message: 'Complete' });
        (EPSSProgressHandler.getProgress as jest.Mock).mockResolvedValue(idleProgress);

        await restoreActiveRefreshes();
        expect(getRefreshQueueSnapshot()).toEqual([
            expect.objectContaining({ variantId: 'nvd', status: 'running', doneCount: 1, total: 2 }),
        ]);

        const onRefreshFinished = jest.fn();
        void waitForRefreshCompletion().then(onRefreshFinished);
        await jest.advanceTimersByTimeAsync(3000);

        expect(getRefreshQueueSnapshot()[0]).toMatchObject({ status: 'done', doneCount: 2, total: 2 });
        expect(onRefreshFinished).toHaveBeenCalledTimes(1);
    });

    it('preserves cancellation for a restored refresh', async () => {
        (NVDProgressHandler.getProgress as jest.Mock)
            .mockResolvedValueOnce({ ...idleProgress, in_progress: true, phase: 'refreshing', current: 1, total: 2 })
            .mockResolvedValueOnce({ ...idleProgress, phase: 'cancelled', current: 1, total: 2 });

        await restoreActiveRefreshes();
        await jest.advanceTimersByTimeAsync(3000);

        expect(getRefreshQueueSnapshot()[0]).toMatchObject({ status: 'cancelled', doneCount: 1, total: 2 });
    });

    it('fails a restored refresh with an invalid terminal state', async () => {
        (NVDProgressHandler.getProgress as jest.Mock)
            .mockResolvedValueOnce({ ...idleProgress, in_progress: true, phase: 'refreshing' })
            .mockResolvedValueOnce({ ...idleProgress, phase: 'paused' });

        await restoreActiveRefreshes();
        await jest.advanceTimersByTimeAsync(3000);

        expect(getRefreshQueueSnapshot()[0]).toMatchObject({
            status: 'error',
            error: 'Unexpected NVD refresh state: paused',
        });
    });

    it('fails a restored refresh after repeated progress errors', async () => {
        (NVDProgressHandler.getProgress as jest.Mock)
            .mockResolvedValueOnce({ ...idleProgress, in_progress: true, phase: 'refreshing' })
            .mockRejectedValue(new Error('offline'));

        await restoreActiveRefreshes();
        await jest.advanceTimersByTimeAsync(30000);

        expect(getRefreshQueueSnapshot()[0]).toMatchObject({
            status: 'error',
            error: 'Lost NVD refresh progress',
        });
    });

    it('restores backend refresh errors as terminal entries', async () => {
        (NVDProgressHandler.getProgress as jest.Mock)
            .mockResolvedValueOnce({ ...idleProgress, in_progress: true, phase: 'refreshing' })
            .mockResolvedValueOnce({ ...idleProgress, phase: 'error', message: 'Backend failed' });

        await restoreActiveRefreshes();
        expect(hasActiveRefreshes()).toBe(true);
        await jest.advanceTimersByTimeAsync(3000);

        expect(getRefreshQueueSnapshot()[0]).toMatchObject({ status: 'error', error: 'Backend failed' });
        expect(hasActiveRefreshes()).toBe(false);
    });

    it('ignores idle, unavailable, and empty restore responses', async () => {
        (NVDProgressHandler.getProgress as jest.Mock).mockResolvedValue(idleProgress);
        (EPSSProgressHandler.getProgress as jest.Mock).mockRejectedValue(new Error('offline'));

        await restoreActiveRefreshes();

        expect(getRefreshQueueSnapshot()).toEqual([]);
        expect(hasActiveRefreshes()).toBe(false);
    });

    it('does not mistake stale completion for a new cycle when baseline loading fails', async () => {
        (BulkNvdRefreshHandler.trigger as jest.Mock).mockResolvedValue({ total: 1 });
        (NVDProgressHandler.getProgress as jest.Mock)
            .mockRejectedValueOnce(new Error('baseline unavailable'))
            .mockResolvedValueOnce({ ...idleProgress, phase: 'completed', current: 1, total: 1, message: 'Old completion', started_at: 'old-cycle' })
            .mockResolvedValueOnce({ ...idleProgress, in_progress: true, phase: 'refreshing', message: 'Refreshing', started_at: 'new-cycle' })
            .mockResolvedValueOnce({ ...idleProgress, phase: 'completed', current: 1, total: 1, message: 'Complete', started_at: 'new-cycle' });

        expect(queueVulnerabilityRefresh({
            refreshTypes: ['nvd'],
            nvdMode: 'local',
            loadVulnerabilities: async () => [{ id: 'CVE-2024-0001' }] as never,
        })).toBe(true);

        await jest.advanceTimersByTimeAsync(3000);
        expect(getRefreshQueueSnapshot()[0].status).toBe('running');
        await jest.advanceTimersByTimeAsync(6000);
        expect(getRefreshQueueSnapshot()[0].status).toBe('done');
    });

    it('fails an unexpected inactive backend phase', async () => {
        (BulkNvdRefreshHandler.trigger as jest.Mock).mockResolvedValue({ total: 1 });
        (NVDProgressHandler.getProgress as jest.Mock)
            .mockResolvedValueOnce(idleProgress)
            .mockResolvedValueOnce({ ...idleProgress, phase: 'paused', message: 'Paused', started_at: 'nvd-cycle' });

        expect(queueVulnerabilityRefresh({
            refreshTypes: ['nvd'],
            nvdMode: 'local',
            loadVulnerabilities: async () => [{ id: 'CVE-2024-0001' }] as never,
        })).toBe(true);
        await jest.advanceTimersByTimeAsync(3000);

        expect(getRefreshQueueSnapshot()[0]).toMatchObject({
            status: 'error',
            error: 'Unexpected NVD refresh state: paused',
        });
    });

    it('fails after repeated progress endpoint errors', async () => {
        (BulkNvdRefreshHandler.trigger as jest.Mock).mockResolvedValue({ total: 1 });
        (NVDProgressHandler.getProgress as jest.Mock)
            .mockResolvedValueOnce(idleProgress)
            .mockRejectedValue(new Error('offline'));

        expect(queueVulnerabilityRefresh({
            refreshTypes: ['nvd'],
            nvdMode: 'local',
            loadVulnerabilities: async () => [{ id: 'CVE-2024-0001' }] as never,
        })).toBe(true);

        await jest.advanceTimersByTimeAsync(30000);
        expect(getRefreshQueueSnapshot()[0]).toMatchObject({
            status: 'error',
            error: 'Lost NVD refresh progress',
        });
    });

    it('fails when the backend never exposes the accepted refresh cycle', async () => {
        (BulkNvdRefreshHandler.trigger as jest.Mock).mockResolvedValue({ total: 1 });
        (NVDProgressHandler.getProgress as jest.Mock).mockResolvedValue(idleProgress);

        expect(queueVulnerabilityRefresh({
            refreshTypes: ['nvd'],
            nvdMode: 'local',
            loadVulnerabilities: async () => [{ id: 'CVE-2024-0001' }] as never,
        })).toBe(true);

        await jest.advanceTimersByTimeAsync(60000);
        expect(getRefreshQueueSnapshot()[0]).toMatchObject({
            status: 'error',
            error: 'NVD refresh did not start',
        });
    });

    it('contains loader and trigger failures in the affected entries', async () => {
        expect(queueVulnerabilityRefresh({
            refreshTypes: ['nvd', 'epss'],
            nvdMode: 'local',
            loadVulnerabilities: async () => { throw new Error('reload failed'); },
        })).toBe(true);
        await jest.advanceTimersByTimeAsync(0);
        expect(getRefreshQueueSnapshot().map(entry => [entry.status, entry.error])).toEqual([
            ['error', 'reload failed'],
            ['error', 'reload failed'],
        ]);

        (BulkNvdRefreshHandler.trigger as jest.Mock).mockResolvedValue(null);
        expect(queueVulnerabilityRefresh({
            refreshTypes: ['nvd'],
            nvdMode: 'local',
            loadVulnerabilities: async () => [{ id: 'CVE-2024-0001' }] as never,
        })).toBe(true);
        await jest.advanceTimersByTimeAsync(0);
        expect(getRefreshQueueSnapshot()[0]).toMatchObject({
            status: 'error',
            error: 'Failed to start NVD refresh',
        });
    });

    it('finishes sources with no matching IDs and rejects a duplicate active queue', async () => {
        expect(queueVulnerabilityRefresh({
            refreshTypes: ['ghsa'],
            nvdMode: 'local',
            loadVulnerabilities: async () => [{ id: 'CVE-2024-0001' }] as never,
        })).toBe(true);
        expect(queueVulnerabilityRefresh({
            refreshTypes: ['nvd'],
            nvdMode: 'local',
            loadVulnerabilities: async () => [],
        })).toBe(false);

        await jest.advanceTimersByTimeAsync(0);
        expect(getRefreshQueueSnapshot()[0]).toMatchObject({
            status: 'done',
            progress: 'No matching vulnerabilities',
        });
    });
});
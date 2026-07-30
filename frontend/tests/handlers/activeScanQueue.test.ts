import { waitFor } from '@testing-library/react';

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

import {
    dismissRefreshQueueEntry,
    getRefreshQueueSnapshot,
    queueVulnerabilityRefresh,
} from '../../src/handlers/activeScanQueue';

describe('active scan queue', () => {
    afterEach(() => dismissRefreshQueueEntry());

    it('keeps vulnerability refresh queued until active scans finish', async () => {
        const runRefresh = jest.fn().mockResolvedValue(undefined);

        expect(queueVulnerabilityRefresh(runRefresh)).toBe(true);
        expect(getRefreshQueueSnapshot()[0]?.status).toBe('queued');
        expect(runRefresh).not.toHaveBeenCalled();

        finishScan!();
        await scanCompletion;

        await waitFor(() => {
            expect(runRefresh).toHaveBeenCalledTimes(1);
            expect(getRefreshQueueSnapshot()[0]?.status).toBe('done');
        });
    });
});
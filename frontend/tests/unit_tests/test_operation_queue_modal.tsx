import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';

jest.mock('../../src/handlers/activeScanQueue', () => ({
    subscribeToRefreshQueue: () => () => undefined,
    getRefreshQueueSnapshot: jest.fn(),
    dismissRefreshQueueEntry: jest.fn(),
}));
jest.mock('../../src/handlers/grypeScanState', () => ({
    subscribe: () => () => undefined,
    getSnapshot: jest.fn(),
    dismiss: jest.fn(),
}));
jest.mock('../../src/handlers/nvdScanState', () => ({
    subscribe: () => () => undefined,
    getSnapshot: jest.fn(),
    dismiss: jest.fn(),
}));
jest.mock('../../src/handlers/osvScanState', () => ({
    subscribe: () => () => undefined,
    getSnapshot: jest.fn(),
    dismiss: jest.fn(),
}));
jest.mock('../../src/handlers/sccScanState', () => ({
    subscribe: () => () => undefined,
    getSnapshot: jest.fn(),
    dismiss: jest.fn(),
}));
jest.mock('../../src/handlers/exportQueue', () => ({
    subscribe: () => () => undefined,
    getSnapshot: jest.fn(),
    dismiss: jest.fn(),
}));

import OperationQueueModal from '../../src/components/OperationQueueModal';
import { dismissRefreshQueueEntry, getRefreshQueueSnapshot } from '../../src/handlers/activeScanQueue';
import { dismiss as grypeDismiss, getSnapshot as grypeGetSnapshot } from '../../src/handlers/grypeScanState';
import { dismiss as nvdDismiss, getSnapshot as nvdGetSnapshot } from '../../src/handlers/nvdScanState';
import { dismiss as osvDismiss, getSnapshot as osvGetSnapshot } from '../../src/handlers/osvScanState';
import { dismiss as sccDismiss, getSnapshot as sccGetSnapshot } from '../../src/handlers/sccScanState';
import { dismiss as exportDismiss, getSnapshot as exportGetSnapshot } from '../../src/handlers/exportQueue';

const completedEntry = (variantId: string, variantName: string) => ({
    variantId,
    variantName,
    status: 'done',
    error: null,
    progress: 'Complete',
    logs: [],
    total: 1,
    doneCount: 1,
});

describe('OperationQueueModal', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        [getRefreshQueueSnapshot, grypeGetSnapshot, nvdGetSnapshot, osvGetSnapshot, sccGetSnapshot, exportGetSnapshot]
            .forEach(snapshot => (snapshot as jest.Mock).mockReturnValue([]));
    });

    it('closes from its close button, backdrop, and Escape key', () => {
        const onClose = jest.fn();
        const { rerender } = render(<OperationQueueModal isOpen={true} onClose={onClose} />);

        expect(screen.getByRole('dialog', { name: 'Operation queue' })).toBeInTheDocument();
    expect(screen.getByText('This window can be safely closed. Track the operation queue in the navigation bar.')).toBeInTheDocument();
        expect(screen.getByText('No operations to display.')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Close operation queue' }));
        fireEvent.mouseDown(screen.getByRole('dialog', { name: 'Operation queue' }));
        fireEvent.keyDown(document, { key: 'Escape' });
        expect(onClose).toHaveBeenCalledTimes(3);

        rerender(<OperationQueueModal isOpen={false} onClose={onClose} />);
        expect(screen.queryByRole('dialog', { name: 'Operation queue' })).not.toBeInTheDocument();
    });

    it('renders each vulnerability refresh source as an independent collapse', () => {
        (getRefreshQueueSnapshot as jest.Mock).mockReturnValue([
            { variantId: 'nvd', variantName: 'NVD', status: 'queued', error: null, progress: 'Queued', logs: ['Waiting'], total: 0, doneCount: 0 },
            { variantId: 'epss', variantName: 'EPSS', status: 'queued', error: null, progress: 'Queued', logs: ['Waiting'], total: 0, doneCount: 0 },
        ]);
        render(<OperationQueueModal isOpen={true} onClose={jest.fn()} />);

        const nvdCollapse = screen.getByRole('button', { name: /vulnerability data refresh.*nvd queued/i });
        const epssCollapse = screen.getByRole('button', { name: /vulnerability data refresh.*epss queued/i });
        expect(nvdCollapse).toHaveAttribute('aria-expanded', 'false');
        expect(epssCollapse).toHaveAttribute('aria-expanded', 'false');

        fireEvent.click(nvdCollapse);
        expect(nvdCollapse).toHaveAttribute('aria-expanded', 'true');
        expect(epssCollapse).toHaveAttribute('aria-expanded', 'false');
    });

    it('dismisses completed operations through their owning queues', () => {
        (grypeGetSnapshot as jest.Mock).mockReturnValue([completedEntry('grype-id', 'Grype')]);
        (nvdGetSnapshot as jest.Mock).mockReturnValue([completedEntry('nvd-id', 'NVD')]);
        (osvGetSnapshot as jest.Mock).mockReturnValue([completedEntry('osv-id', 'OSV')]);
        (sccGetSnapshot as jest.Mock).mockReturnValue([completedEntry('scc-id', 'SCC')]);
        (getRefreshQueueSnapshot as jest.Mock).mockReturnValue([completedEntry('epss', 'EPSS')]);
        (exportGetSnapshot as jest.Mock).mockReturnValue([completedEntry('export-id', 'Project export')]);

        render(<OperationQueueModal isOpen={true} onClose={jest.fn()} />);
        screen.getAllByTitle('Close').forEach(button => fireEvent.click(button));

        expect(grypeDismiss).toHaveBeenCalledWith('grype-id');
        expect(nvdDismiss).toHaveBeenCalledWith('nvd-id');
        expect(osvDismiss).toHaveBeenCalledWith('osv-id');
        expect(sccDismiss).toHaveBeenCalledWith('scc-id');
        expect(dismissRefreshQueueEntry).toHaveBeenCalledWith('epss');
        expect(exportDismiss).toHaveBeenCalledWith('export-id');
    });
});
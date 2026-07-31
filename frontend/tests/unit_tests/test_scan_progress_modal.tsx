import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';

jest.mock('../../src/handlers/activeScanQueue', () => ({
    subscribeToRefreshQueue: () => () => undefined,
    getRefreshQueueSnapshot: jest.fn(),
    dismissRefreshQueueEntry: jest.fn(),
}));

import ScanProgressModal from '../../src/components/ScanProgressModal';
import { getRefreshQueueSnapshot } from '../../src/handlers/activeScanQueue';

describe('ScanProgressModal', () => {
    beforeEach(() => (getRefreshQueueSnapshot as jest.Mock).mockReturnValue([]));

    it('closes from its close button, backdrop, and Escape key', () => {
        const onClose = jest.fn();
        const { rerender } = render(<ScanProgressModal isOpen={true} onClose={onClose} />);

        expect(screen.getByRole('dialog', { name: 'Scan progress' })).toBeInTheDocument();
    expect(screen.getByText('This window can be safely closed. Track scan progress in the navigation bar.')).toBeInTheDocument();
        expect(screen.getByText('No scan progress to display.')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Close scan progress' }));
        fireEvent.mouseDown(screen.getByRole('dialog', { name: 'Scan progress' }));
        fireEvent.keyDown(document, { key: 'Escape' });
        expect(onClose).toHaveBeenCalledTimes(3);

        rerender(<ScanProgressModal isOpen={false} onClose={onClose} />);
        expect(screen.queryByRole('dialog', { name: 'Scan progress' })).not.toBeInTheDocument();
    });

    it('renders each vulnerability refresh source as an independent collapse', () => {
        (getRefreshQueueSnapshot as jest.Mock).mockReturnValue([
            { variantId: 'nvd', variantName: 'NVD', status: 'queued', error: null, progress: 'Queued', logs: ['Waiting'], total: 0, doneCount: 0 },
            { variantId: 'epss', variantName: 'EPSS', status: 'queued', error: null, progress: 'Queued', logs: ['Waiting'], total: 0, doneCount: 0 },
        ]);
        render(<ScanProgressModal isOpen={true} onClose={jest.fn()} />);

        const nvdCollapse = screen.getByRole('button', { name: /vulnerability data refresh.*nvd queued/i });
        const epssCollapse = screen.getByRole('button', { name: /vulnerability data refresh.*epss queued/i });
        expect(nvdCollapse).toHaveAttribute('aria-expanded', 'false');
        expect(epssCollapse).toHaveAttribute('aria-expanded', 'false');

        fireEvent.click(nvdCollapse);
        expect(nvdCollapse).toHaveAttribute('aria-expanded', 'true');
        expect(epssCollapse).toHaveAttribute('aria-expanded', 'false');
    });
});
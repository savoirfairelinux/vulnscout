import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { faCircleInfo } from '@fortawesome/free-solid-svg-icons';

import OperationQueuePanel from '../../src/components/OperationQueuePanel';
import type { ScanEntryState } from '../../src/handlers/scanStateManager';

describe('OperationQueuePanel', () => {
    const colors = {
        border: 'border-cyan-500/60',
        headerBg: 'bg-cyan-900/40',
        iconText: 'text-cyan-300',
        titleText: 'text-cyan-200',
        subtitleText: 'text-cyan-300/80',
        bar: 'bg-cyan-500',
    };

    const makeEntry = (status: ScanEntryState['status'], overrides: Partial<ScanEntryState> = {}): ScanEntryState => ({
        variantId: 'variant-1',
        variantName: 'Variant 1',
        status,
        error: null,
        progress: status === 'done' ? 'Done' : 'Running',
        logs: [],
        total: 4,
        doneCount: status === 'done' ? 4 : 2,
        ...overrides,
    });

    it('keeps a scan queued until progress content arrives', async () => {
        const { rerender } = render(
            <OperationQueuePanel
                entry={makeEntry('queued', { progress: 'Queued', logs: ['Waiting for previous scan to finish…'] })}
                label="Grype Scan"
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
            />,
        );

        const toggle = screen.getByRole('button', { name: /grype scan – variant 1 queued/i });
        expect(toggle).toHaveAttribute('aria-expanded', 'false');
        expect(screen.queryByText('Waiting for previous scan to finish…')).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /close/i })).not.toBeInTheDocument();

        rerender(
            <OperationQueuePanel
                entry={makeEntry('running', { progress: 'starting', total: 0, doneCount: 0 })}
                label="Grype Scan"
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
            />,
        );

        expect(screen.getByRole('button', { name: /grype scan – variant 1 queued/i }))
            .toHaveAttribute('aria-expanded', 'false');

        rerender(
            <OperationQueuePanel
                entry={makeEntry('running', { progress: '1 / 4', logs: ['Scanning package metadata'] })}
                label="Grype Scan"
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
            />,
        );

        await waitFor(() => expect(screen.getByRole('button', { name: /grype scan – variant 1 in progress/i }))
            .toHaveAttribute('aria-expanded', 'true'));
        expect(screen.getByText('Scanning package metadata')).toBeInTheDocument();
    });

    it('shows the queued state without a dismiss button', () => {
        render(
            <OperationQueuePanel
                entry={makeEntry('queued', { progress: 'Queued', logs: ['Waiting for previous scan to finish…'] })}
                label="Grype Scan"
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
            />,
        );

        expect(screen.getByText(/grype scan – variant 1 queued/i)).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /close/i })).not.toBeInTheDocument();
        expect(document.body.querySelector('.animate-pulse')).not.toBeInTheDocument();
    });

    it('shows the position for a multi-variant scan', () => {
        render(
            <OperationQueuePanel
                entry={makeEntry('running', {
                    variantName: 'hyper-v',
                    variantPosition: 2,
                    variantCount: 3,
                })}
                label="sbom-cve-check Scan"
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
            />,
        );

        expect(screen.getByText(/sbom-cve-check scan – hyper-v in progress \(variant 2 of 3\)/i)).toBeInTheDocument();
    });

    it('omits the position for a single-variant scan', () => {
        render(
            <OperationQueuePanel
                entry={makeEntry('running', { variantPosition: 1, variantCount: 1 })}
                label="NVD Scan"
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
            />,
        );

        expect(screen.getByText(/nvd scan – variant 1 in progress/i)).toBeInTheDocument();
        expect(screen.queryByText(/variant 1 of 1/i)).not.toBeInTheDocument();
    });

    it('renders running logs then collapses a completed scan with a success indicator', async () => {
        const user = userEvent.setup();
        const onDismiss = jest.fn();

        const { rerender } = render(
            <OperationQueuePanel
                entry={makeEntry('running', {
                    progress: '2 / 4',
                        logs: ['[ERROR] scanning', '✓ finished step'],
                })}
                label="NVD Scan"
                icon={faCircleInfo}
                colors={colors}
                onDismiss={onDismiss}
            />,
        );

        expect(screen.getByText(/nvd scan – variant 1 in progress/i)).toBeInTheDocument();
        expect(screen.queryByText('Waiting for first results…')).not.toBeInTheDocument();
        expect(screen.getByText('[ERROR] scanning')).toHaveClass('text-red-400');
        expect(screen.getByText('✓ finished step')).toHaveClass('text-green-400', 'font-semibold');

        rerender(
            <OperationQueuePanel
                entry={makeEntry('done', {
                    progress: '4 / 4',
                    logs: ['✓ completed'],
                })}
                label="NVD Scan"
                icon={faCircleInfo}
                colors={colors}
                onDismiss={onDismiss}
            />,
        );

        await waitFor(() => expect(screen.getByRole('button', { name: /nvd scan – variant 1 complete/i }))
            .toHaveAttribute('aria-expanded', 'false'));
        expect(screen.getByLabelText('Complete')).toHaveClass('text-green-400');
        expect(screen.queryByText('✓ completed')).not.toBeInTheDocument();

        await user.click(screen.getByRole('button', { name: /close/i }));
        expect(onDismiss).toHaveBeenCalledTimes(1);
        expect(screen.getByText(/nvd scan – variant 1 complete/i)).toBeInTheDocument();
    });

    it('renders zero-total completion at 100% and clamps excessive progress', async () => {
        const user = userEvent.setup();
        const { container, rerender } = render(
            <OperationQueuePanel
                entry={makeEntry('done', { total: 0, doneCount: 0 })}
                label="NVD Scan"
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
            />,
        );
        await user.click(screen.getByRole('button', { name: /nvd scan – variant 1 complete/i }));
        expect(container.querySelector('.bg-green-500')).toHaveStyle({ width: '100%' });

        rerender(
            <OperationQueuePanel
                entry={makeEntry('running', { total: 2, doneCount: 3, logs: ['Finishing'] })}
                label="NVD Scan"
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
            />,
        );
        expect(container.querySelector('.bg-cyan-500')).toHaveStyle({ width: '100%' });
    });

    it('labels cancellation without a success indicator', () => {
        render(
            <OperationQueuePanel
                entry={makeEntry('cancelled', { progress: 'Cancelled', doneCount: 1, total: 4 })}
                label="Vulnerability Data Refresh"
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
            />,
        );

        expect(screen.getByRole('button', { name: /vulnerability data refresh – variant 1 cancelled/i })).toBeInTheDocument();
        expect(screen.queryByLabelText('Complete')).not.toBeInTheDocument();
    });
});

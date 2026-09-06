import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { faCircleInfo } from '@fortawesome/free-solid-svg-icons';

import OperationQueuePanel from '../../src/components/OperationQueuePanel';
import type { Operation, OperationStatus } from '../../src/types/operation';

describe('OperationQueuePanel', () => {
    const colors = {
        border: 'border-cyan-500/60',
        headerBg: 'bg-cyan-900/40',
        iconText: 'text-cyan-300',
        titleText: 'text-cyan-200',
        subtitleText: 'text-cyan-300/80',
        bar: 'bg-cyan-500',
    };

    const makeOperation = (status: OperationStatus, overrides: Partial<Operation> = {}): Operation => ({
        op_id: 'scan:grype:variant-1',
        kind: 'scan',
        source: 'grype',
        label: 'Grype Scan',
        lane: 'pipeline',
        scope: { variant_id: 'variant-1', variant_name: 'Variant 1', project_id: 'project-1' },
        status,
        progress: {
            current: status === 'done' ? 4 : 2,
            total: 4,
            message: status === 'done' ? 'Done' : 'Running',
        },
        logs: [],
        error: null,
        queue_id: null,
        position: null,
        options: {},
        cancellable: true,
        created_at: '2026-08-19T10:00:00+00:00',
        started_at: null,
        finished_at: null,
        result: null,
        ...overrides,
    });

    it('keeps an operation collapsed until progress content arrives', async () => {
        const { rerender } = render(
            <OperationQueuePanel
                operation={makeOperation('queued', {
                    progress: { current: 0, total: 0, message: 'Queued' },
                    logs: ['Waiting for previous scan to finish…'],
                })}
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
                operation={makeOperation('running', { progress: { current: 0, total: 0, message: 'starting' } })}
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
            />,
        );

        expect(screen.getByRole('button', { name: /grype scan – variant 1 queued/i }))
            .toHaveAttribute('aria-expanded', 'false');

        rerender(
            <OperationQueuePanel
                operation={makeOperation('running', {
                    progress: { current: 1, total: 4, message: '1 / 4' },
                    logs: ['Scanning package metadata'],
                })}
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
                operation={makeOperation('queued', {
                    progress: { current: 0, total: 0, message: 'Queued' },
                    logs: ['Waiting for previous scan to finish…'],
                })}
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
                operation={makeOperation('running', {
                    label: 'sbom-cve-check Scan',
                    scope: { variant_id: 'variant-2', variant_name: 'hyper-v', project_id: 'project-1' },
                })}
                icon={faCircleInfo}
                colors={colors}
                positionLabel=" (variant 2 of 3)"
                onDismiss={jest.fn()}
            />,
        );

        expect(screen.getByText(/sbom-cve-check scan – hyper-v in progress \(variant 2 of 3\)/i)).toBeInTheDocument();
    });

    it('omits the position for a single-variant scan', () => {
        render(
            <OperationQueuePanel
                operation={makeOperation('running', { label: 'NVD Scan' })}
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
            />,
        );

        expect(screen.getByText(/nvd scan – variant 1 in progress/i)).toBeInTheDocument();
        expect(screen.queryByText(/variant 1 of 1/i)).not.toBeInTheDocument();
    });

    it('falls back to the operation label when there is no variant scope', () => {
        render(
            <OperationQueuePanel
                operation={makeOperation('running', {
                    kind: 'refresh',
                    label: 'EPSS refresh',
                    scope: null,
                    logs: ['Fetching scores'],
                })}
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
            />,
        );

        expect(screen.getByText(/epss refresh – epss refresh in progress/i)).toBeInTheDocument();
    });

    it('renders running logs then collapses a completed operation with a success indicator', async () => {
        const user = userEvent.setup();
        const onDismiss = jest.fn();

        const { rerender } = render(
            <OperationQueuePanel
                operation={makeOperation('running', {
                    label: 'NVD Scan',
                    progress: { current: 2, total: 4, message: '2 / 4' },
                    logs: ['[ERROR] scanning', '✓ finished step'],
                })}
                icon={faCircleInfo}
                colors={colors}
                onDismiss={onDismiss}
            />,
        );

        expect(screen.getByText(/nvd scan – variant 1 in progress/i)).toBeInTheDocument();
        expect(screen.getByText('[ERROR] scanning')).toHaveClass('text-red-400');
        expect(screen.getByText('✓ finished step')).toHaveClass('text-green-400', 'font-semibold');

        rerender(
            <OperationQueuePanel
                operation={makeOperation('done', {
                    label: 'NVD Scan',
                    progress: { current: 4, total: 4, message: '4 / 4' },
                    logs: ['✓ completed'],
                })}
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

    it('expands a failed operation and labels it as failed', () => {
        render(
            <OperationQueuePanel
                operation={makeOperation('error', {
                    label: 'NVD Scan',
                    error: 'nvd api unreachable',
                    logs: ['[ERROR] nvd api unreachable'],
                })}
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
            />,
        );

        expect(screen.getByRole('button', { name: /nvd scan – variant 1 failed/i }))
            .toHaveAttribute('aria-expanded', 'true');
        expect(screen.getByText('[ERROR] nvd api unreachable')).toHaveClass('text-red-400');
        expect(screen.queryByLabelText('Complete')).not.toBeInTheDocument();
    });

    it('renders zero-total completion at 100% and clamps excessive progress', async () => {
        const user = userEvent.setup();
        const { container, rerender } = render(
            <OperationQueuePanel
                operation={makeOperation('done', {
                    label: 'NVD Scan',
                    progress: { current: 0, total: 0, message: 'Done' },
                })}
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
            />,
        );
        await user.click(screen.getByRole('button', { name: /nvd scan – variant 1 complete/i }));
        expect(container.querySelector('.bg-green-500')).toHaveStyle({ width: '100%' });

        rerender(
            <OperationQueuePanel
                operation={makeOperation('running', {
                    label: 'NVD Scan',
                    progress: { current: 3, total: 2, message: 'Finishing' },
                    logs: ['Finishing'],
                })}
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
            />,
        );
        expect(container.querySelector('.bg-cyan-500')).toHaveStyle({ width: '100%' });
    });

    it('shows the completion percentage next to the progress message', () => {
        render(
            <OperationQueuePanel
                operation={makeOperation('running', {
                    label: 'NVD Scan',
                    progress: { current: 1, total: 4, message: '1 / 4' },
                    logs: ['Working'],
                })}
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
            />,
        );

        expect(screen.getByText(/1 \/ 4 \(25%\)/)).toBeInTheDocument();
    });

    it('labels cancellation without a success indicator', () => {
        render(
            <OperationQueuePanel
                operation={makeOperation('cancelled', {
                    label: 'Vulnerability Data Refresh',
                    progress: { current: 1, total: 4, message: 'Cancelled' },
                })}
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
            />,
        );

        expect(screen.getByRole('button', { name: /vulnerability data refresh – variant 1 cancelled/i })).toBeInTheDocument();
        expect(screen.queryByLabelText('Complete')).not.toBeInTheDocument();
    });

    it('offers cancellation only while the operation is still active', async () => {
        const user = userEvent.setup();
        const onCancel = jest.fn();

        const { rerender } = render(
            <OperationQueuePanel
                operation={makeOperation('queued', { progress: { current: 0, total: 0, message: 'Queued' } })}
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
                onCancel={onCancel}
            />,
        );

        await user.click(screen.getByRole('button', { name: 'Cancel Grype Scan – Variant 1' }));
        expect(onCancel).toHaveBeenCalledTimes(1);

        rerender(
            <OperationQueuePanel
                operation={makeOperation('running', { logs: ['Scanning'] })}
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
                onCancel={onCancel}
            />,
        );
        expect(screen.getByRole('button', { name: 'Cancel Grype Scan – Variant 1' })).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /close/i })).not.toBeInTheDocument();

        rerender(
            <OperationQueuePanel
                operation={makeOperation('done')}
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
                onCancel={onCancel}
            />,
        );
        expect(screen.queryByRole('button', { name: 'Cancel Grype Scan – Variant 1' })).not.toBeInTheDocument();
        expect(screen.getByRole('button', { name: /close/i })).toBeInTheDocument();
    });
});

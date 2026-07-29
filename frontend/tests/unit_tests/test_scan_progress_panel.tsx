import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { faCircleInfo } from '@fortawesome/free-solid-svg-icons';

import ScanProgressPanel from '../../src/components/ScanProgressPanel';
import type { ScanEntryState } from '../../src/handlers/scanStateManager';

describe('ScanProgressPanel', () => {
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

    it('shows the queued state without a dismiss button', () => {
        render(
            <ScanProgressPanel
                entry={makeEntry('queued', { progress: 'Queued', logs: ['Waiting for previous scan to finish…'] })}
                label="Grype Scan"
                icon={faCircleInfo}
                colors={colors}
                onDismiss={jest.fn()}
            />,
        );

        expect(screen.getByText(/grype scan – variant 1 queued/i)).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /close/i })).not.toBeInTheDocument();
        expect(document.body.querySelector('.animate-pulse')).toBeInTheDocument();
    });

    it('shows the position for a multi-variant scan', () => {
        render(
            <ScanProgressPanel
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
            <ScanProgressPanel
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

    it('renders running and complete states with the expected log styling', async () => {
        const user = userEvent.setup();
        const onDismiss = jest.fn();

        const { rerender } = render(
            <ScanProgressPanel
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
            <ScanProgressPanel
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

        await user.click(screen.getByRole('button', { name: /close/i }));
        expect(onDismiss).toHaveBeenCalledTimes(1);
        expect(screen.getByText(/nvd scan – variant 1 complete/i)).toBeInTheDocument();
        expect(document.body.querySelector('.bg-green-500')).toBeInTheDocument();
    });
});

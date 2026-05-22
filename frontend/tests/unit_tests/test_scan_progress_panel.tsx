/// <reference types="jest" />
import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import { render, screen, fireEvent } from '@testing-library/react';
import "@testing-library/jest-dom";
import type { ScanEntryState } from '../../src/handlers/scanStateManager';
import { faBug } from '@fortawesome/free-solid-svg-icons';
import ScanProgressPanel from '../../src/components/ScanProgressPanel';

const colors = {
    border: 'border-purple-700/60',
    headerBg: 'bg-purple-900/40',
    iconText: 'text-purple-400',
    titleText: 'text-purple-200',
    subtitleText: 'text-purple-300/80',
    bar: 'bg-purple-500',
};

function makeEntry(overrides: Partial<ScanEntryState> = {}): ScanEntryState {
    return {
        variantId: 'v1',
        variantName: 'MyVariant',
        status: 'running',
        error: null,
        progress: null,
        logs: [],
        total: 0,
        doneCount: 0,
        ...overrides,
    };
}

describe('ScanProgressPanel', () => {

    test('renders label and variant name with "in progress" status', () => {
        render(<ScanProgressPanel entry={makeEntry()} label="Grype Scan" icon={faBug} colors={colors} onDismiss={jest.fn()} />);
        expect(screen.getByText('Grype Scan – MyVariant in progress')).toBeInTheDocument();
    });

    test('shows "queued" status text for queued entry', () => {
        render(<ScanProgressPanel entry={makeEntry({ status: 'queued' })} label="Grype Scan" icon={faBug} colors={colors} onDismiss={jest.fn()} />);
        expect(screen.getByText('Grype Scan – MyVariant queued')).toBeInTheDocument();
    });

    test('shows "failed" status text for error entry', () => {
        render(<ScanProgressPanel entry={makeEntry({ status: 'error', logs: ['some error'] })} label="Grype Scan" icon={faBug} colors={colors} onDismiss={jest.fn()} />);
        expect(screen.getByText('Grype Scan – MyVariant failed')).toBeInTheDocument();
    });

    test('shows "complete" status text for done entry', () => {
        render(<ScanProgressPanel entry={makeEntry({ status: 'done' })} label="Grype Scan" icon={faBug} colors={colors} onDismiss={jest.fn()} />);
        expect(screen.getByText('Grype Scan – MyVariant complete')).toBeInTheDocument();
    });

    test('shows progress string when set', () => {
        render(<ScanProgressPanel entry={makeEntry({ progress: 'Processing 50 of 100' })} label="Grype Scan" icon={faBug} colors={colors} onDismiss={jest.fn()} />);
        expect(screen.getByText('Processing 50 of 100')).toBeInTheDocument();
    });

    test('shows percentage when total > 0', () => {
        render(<ScanProgressPanel entry={makeEntry({ total: 100, doneCount: 75 })} label="Grype Scan" icon={faBug} colors={colors} onDismiss={jest.fn()} />);
        expect(screen.getByText(/75%/)).toBeInTheDocument();
    });

    test('does not show dismiss button while running', () => {
        render(<ScanProgressPanel entry={makeEntry({ status: 'running' })} label="Grype Scan" icon={faBug} colors={colors} onDismiss={jest.fn()} />);
        expect(screen.queryByTitle('Close')).not.toBeInTheDocument();
    });

    test('does not show dismiss button while queued', () => {
        render(<ScanProgressPanel entry={makeEntry({ status: 'queued' })} label="Grype Scan" icon={faBug} colors={colors} onDismiss={jest.fn()} />);
        expect(screen.queryByTitle('Close')).not.toBeInTheDocument();
    });

    test('shows dismiss button when done', () => {
        render(<ScanProgressPanel entry={makeEntry({ status: 'done' })} label="Grype Scan" icon={faBug} colors={colors} onDismiss={jest.fn()} />);
        expect(screen.getByTitle('Close')).toBeInTheDocument();
    });

    test('calls onDismiss when dismiss button is clicked', () => {
        const onDismiss = jest.fn();
        render(<ScanProgressPanel entry={makeEntry({ status: 'done' })} label="Grype Scan" icon={faBug} colors={colors} onDismiss={onDismiss} />);
        fireEvent.click(screen.getByTitle('Close'));
        expect(onDismiss).toHaveBeenCalledTimes(1);
    });

    test('shows dismiss button for error entry', () => {
        render(<ScanProgressPanel entry={makeEntry({ status: 'error', logs: ['err'] })} label="Grype Scan" icon={faBug} colors={colors} onDismiss={jest.fn()} />);
        expect(screen.getByTitle('Close')).toBeInTheDocument();
    });

    test('renders log lines', () => {
        render(<ScanProgressPanel entry={makeEntry({ logs: ['line 1', '✓ done', '[2024] ERROR bad'] })} label="Grype Scan" icon={faBug} colors={colors} onDismiss={jest.fn()} />);
        expect(screen.getByText('line 1')).toBeInTheDocument();
        expect(screen.getByText('✓ done')).toBeInTheDocument();
        expect(screen.getByText('[2024] ERROR bad')).toBeInTheDocument();
    });

    test('shows "Waiting for first results…" when running with no logs', () => {
        render(<ScanProgressPanel entry={makeEntry({ status: 'running', logs: [] })} label="Grype Scan" icon={faBug} colors={colors} onDismiss={jest.fn()} />);
        expect(screen.getByText('Waiting for first results…')).toBeInTheDocument();
    });

    test('shows progress with percentage when progress string and total are set', () => {
        render(<ScanProgressPanel entry={makeEntry({ progress: 'CVE batch 3/10', total: 10, doneCount: 3 })} label="Grype Scan" icon={faBug} colors={colors} onDismiss={jest.fn()} />);
        expect(screen.getByText(/CVE batch 3\/10/)).toBeInTheDocument();
        expect(screen.getByText(/30%/)).toBeInTheDocument();
    });

});

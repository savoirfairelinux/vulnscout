/// <reference types="jest" />
import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import { render, screen, waitFor } from '@testing-library/react';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import type { Scan } from '../../src/handlers/scans';
import ScanHistory from '../../src/pages/ScanHistory';

// Stable snapshot reference for useSyncExternalStore compatibility
const EMPTY_SCAN_SNAPSHOT: never[] = Object.freeze([]) as never[];

// Mock all scan state stores — return idle/empty by default
jest.mock('../../src/handlers/grypeScanState', () => ({
    subscribe: jest.fn((cb: () => void) => { void cb; return () => {}; }),
    getSnapshot: jest.fn(() => EMPTY_SCAN_SNAPSHOT),
    setOnDone: jest.fn(),
    triggerScan: jest.fn(),
    dismiss: jest.fn(),
}));
jest.mock('../../src/handlers/nvdScanState', () => ({
    subscribe: jest.fn((cb: () => void) => { void cb; return () => {}; }),
    getSnapshot: jest.fn(() => EMPTY_SCAN_SNAPSHOT),
    setOnDone: jest.fn(),
    triggerScan: jest.fn(),
    dismiss: jest.fn(),
}));
jest.mock('../../src/handlers/osvScanState', () => ({
    subscribe: jest.fn((cb: () => void) => { void cb; return () => {}; }),
    getSnapshot: jest.fn(() => EMPTY_SCAN_SNAPSHOT),
    setOnDone: jest.fn(),
    triggerScan: jest.fn(),
    dismiss: jest.fn(),
}));
jest.mock('../../src/handlers/variant', () => ({
    __esModule: true,
    default: {
        listAll: jest.fn().mockResolvedValue([]),
        list: jest.fn().mockResolvedValue([]),
    },
}));

beforeEach(() => {
    fetchMock.resetMocks();
});

// --- Shared mock scan factory ---

const baseScan: Scan = {
    id: 'scan-1',
    description: null,
    scan_type: 'sbom',
    scan_source: null,
    timestamp: '2026-04-21T13:29:00.000Z',
    variant_id: 'v1',
    variant_name: 'default',
    project_name: 'default',
    finding_count: 15441,
    package_count: 261,
    vuln_count: 15333,
    is_first: false,
    findings_added: 4439,
    findings_removed: 1357,
    findings_upgraded: 0,
    findings_unchanged: 10936,
    packages_added: 232,
    packages_removed: 21,
    packages_upgraded: 16,
    packages_unchanged: 13,
    vulns_added: 4053,
    vulns_removed: 30,
    vulns_unchanged: 11293,
    assessment_count: null,
    assessments_added: null,
    assessments_removed: null,
    assessments_unchanged: null,
    newly_detected_findings: null,
    newly_detected_vulns: null,
    newly_detected_assessments: null,
    branch_finding_count: null,
    branch_vuln_count: null,
    branch_package_count: null,
    global_finding_count: 15441,
    global_vuln_count: 15333,
    global_package_count: 261,
    global_assessment_count: null,
    formats: ['SPDX'],
};

function renderWithScan(scan: Scan) {
    fetchMock.mockResponseOnce(JSON.stringify([scan]));
    return render(<ScanHistory variantId="v1" />);
}

describe('ScanHistory card — Current result section', () => {

    test('shows "Current result" heading', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('Current result')).toBeInTheDocument());
    });

    test('displays package count with "packages" label', async () => {
        renderWithScan(baseScan);
        await waitFor(() => {
            expect(screen.getByText('261')).toBeInTheDocument();
            expect(screen.getByText('packages')).toBeInTheDocument();
        });
    });

    test('uses "unique vulnerabilities" label (not "vulnerabilities")', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('unique vulnerabilities')).toBeInTheDocument());
    });

    test('uses "vulnerability matches" label (not "findings")', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('vulnerability matches')).toBeInTheDocument());
    });

    test('shows "View all" button when global_finding_count is set', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('View all')).toBeInTheDocument());
    });

    test('hides "View all" button when global_finding_count is null', async () => {
        renderWithScan({ ...baseScan, global_finding_count: null, global_vuln_count: null, global_package_count: null });
        // Wait for the card to render before asserting absence
        await waitFor(() => expect(screen.getByText('Current result')).toBeInTheDocument());
        expect(screen.queryByText('View all')).not.toBeInTheDocument();
    });

    test('shows "Details" button in Section A when Section B is hidden (first scan)', async () => {
        const firstScan: Scan = {
            ...baseScan,
            is_first: true,
            vulns_added: null,
            findings_added: null,
            vulns_removed: null,
            vulns_unchanged: null,
            findings_removed: null,
            findings_upgraded: null,
            findings_unchanged: null,
            packages_added: null,
            packages_removed: null,
            packages_upgraded: null,
            packages_unchanged: null,
        };
        renderWithScan(firstScan);
        await waitFor(() => expect(screen.getByText('Current result')).toBeInTheDocument());
        expect(screen.getByText('Details')).toBeInTheDocument();
        expect(screen.queryByText('Changes since previous scan')).not.toBeInTheDocument();
    });

});

describe('ScanHistory card — Changes since previous scan section', () => {

    test('shows "Changes since previous scan" heading when deltas are present', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());
    });

    test('hides "Changes since previous scan" section when deltas are null (first SBOM scan)', async () => {
        const firstScan: Scan = {
            ...baseScan,
            is_first: true,
            vulns_added: null,
            vulns_removed: null,
            vulns_unchanged: null,
            findings_added: null,
            findings_removed: null,
            findings_upgraded: null,
            findings_unchanged: null,
            packages_added: null,
            packages_removed: null,
            packages_upgraded: null,
            packages_unchanged: null,
        };
        renderWithScan(firstScan);
        // Wait for the card to render before asserting absence
        await waitFor(() => expect(screen.getByText('Current result')).toBeInTheDocument());
        expect(screen.queryByText('Changes since previous scan')).not.toBeInTheDocument();
    });

    test('uses "no longer present" label (not "removed")', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getAllByText(/no longer present/).length).toBeGreaterThan(0));
    });

    test('uses "still present" label for SBOM scans (not "unchanged")', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getAllByText(/still present/).length).toBeGreaterThan(0));
    });

    test('uses "previously known" label for tool scans', async () => {
        const toolScan: Scan = {
            ...baseScan,
            scan_type: 'tool',
            scan_source: 'grype',
            vulns_added: 10,
            vulns_removed: 0,
            vulns_unchanged: 5,
            findings_added: 10,
            findings_removed: 0,
            findings_upgraded: 0,
            findings_unchanged: 5,
            packages_added: null,
            packages_removed: null,
            packages_upgraded: null,
            packages_unchanged: null,
        };
        renderWithScan(toolScan);
        await waitFor(() => expect(screen.getAllByText(/previously known/).length).toBeGreaterThan(0));
    });

    test('shows "No changes detected" when all deltas are zero', async () => {
        const noChangesScan: Scan = {
            ...baseScan,
            vulns_added: 0,
            vulns_removed: 0,
            vulns_unchanged: 0,
            findings_added: 0,
            findings_removed: 0,
            findings_upgraded: 0,
            findings_unchanged: 0,
            packages_added: 0,
            packages_removed: 0,
            packages_upgraded: 0,
            packages_unchanged: 0,
        };
        renderWithScan(noChangesScan);
        await waitFor(() => expect(screen.getByText('No changes detected')).toBeInTheDocument());
    });

    test('shows Packages row for SBOM scans', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('Packages:')).toBeInTheDocument());
    });

    test('hides Packages row for tool scans', async () => {
        const toolScan: Scan = { ...baseScan, scan_type: 'tool', scan_source: 'grype' };
        renderWithScan(toolScan);
        // Wait for the card to render before asserting absence
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());
        expect(screen.queryByText('Packages:')).not.toBeInTheDocument();
    });

    test('shows "Changes since previous scan" for first tool scan when deltas are non-null', async () => {
        const firstToolScan: Scan = {
            ...baseScan,
            scan_type: 'tool',
            scan_source: 'grype',
            is_first: true,
            vulns_added: 10,
            vulns_removed: 0,
            vulns_unchanged: 0,
            findings_added: 10,
            findings_removed: 0,
            findings_upgraded: 0,
            findings_unchanged: 0,
            packages_added: null,
            packages_removed: null,
            packages_upgraded: null,
            packages_unchanged: null,
        };
        renderWithScan(firstToolScan);
        await waitFor(() =>
            expect(screen.getByText('Changes since previous scan')).toBeInTheDocument()
        );
    });

    test('shows "No changes detected" for tool scan with all-zero deltas (packages excluded)', async () => {
        const noChangesToolScan: Scan = {
            ...baseScan,
            scan_type: 'tool',
            scan_source: 'osv',
            vulns_added: 0,
            vulns_removed: 0,
            vulns_unchanged: 0,
            findings_added: 0,
            findings_removed: 0,
            findings_upgraded: 0,
            findings_unchanged: 0,
            // packages_* are null for tool scans — must not block "No changes detected"
            packages_added: null,
            packages_removed: null,
            packages_upgraded: null,
            packages_unchanged: null,
        };
        renderWithScan(noChangesToolScan);
        await waitFor(() => expect(screen.getByText('No changes detected')).toBeInTheDocument());
    });

    test('shows "Details" button to open diff modal', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('Details')).toBeInTheDocument());
    });

});

describe('ScanHistory card — First scan footnote', () => {

    test('shows footnote when Section B is hidden', async () => {
        const firstScan: Scan = {
            ...baseScan,
            vulns_added: null,
            findings_added: null,
            packages_added: null,
            vulns_removed: null,
            vulns_unchanged: null,
            findings_removed: null,
            findings_upgraded: null,
            findings_unchanged: null,
            packages_removed: null,
            packages_upgraded: null,
            packages_unchanged: null,
        };
        renderWithScan(firstScan);
        await waitFor(() =>
            expect(screen.getByText(/A vulnerability match is one vulnerability affecting one package/)).toBeInTheDocument()
        );
    });

    test('hides footnote when Section B is visible', async () => {
        renderWithScan(baseScan);
        // Wait for the card to render before asserting absence
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());
        expect(screen.queryByText(/A vulnerability match is one vulnerability affecting one package/)).not.toBeInTheDocument();
    });

});

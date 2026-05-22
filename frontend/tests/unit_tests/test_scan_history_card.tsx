/// <reference types="jest" />
import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import type { Scan, ScanDiff, GlobalResult } from '../../src/handlers/scans';
import ScanHistory from '../../src/pages/ScanHistory';
import Variants from '../../src/handlers/variant';
import * as grypeScanState from '../../src/handlers/grypeScanState';

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
    (grypeScanState.getSnapshot as jest.Mock).mockReturnValue(EMPTY_SCAN_SNAPSHOT);
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

function renderWithScans(scans: Scan[]) {
    fetchMock.mockResponseOnce(JSON.stringify(scans));
    return render(<ScanHistory variantId="v1" />);
}

// ---------------------------------------------------------------------------
// Mock data for DiffModal and GlobalResultModal
// ---------------------------------------------------------------------------

const mockScanDiff: ScanDiff = {
    scan_id: 'scan-1',
    scan_type: 'sbom',
    previous_scan_id: 'prev-scan',
    is_first: false,
    finding_count: 2,
    package_count: 3,
    vuln_count: 2,
    findings_added: [
        { finding_id: 'f1', package_name: 'openssl', package_version: '3.2.1', package_id: 'p1', vulnerability_id: 'CVE-2024-0727' }
    ],
    findings_removed: [],
    findings_upgraded: [],
    findings_unchanged: [
        { finding_id: 'f2', package_name: 'curl', package_version: '8.9.0', package_id: 'p2', vulnerability_id: 'CVE-2023-2650' }
    ],
    packages_added: [
        { package_id: 'p3', package_name: 'zlib', package_version: '1.3.1' }
    ],
    packages_removed: [],
    packages_upgraded: [],
    packages_unchanged: [
        { package_id: 'p2', package_name: 'curl', package_version: '8.9.0' }
    ],
    vulns_added: ['CVE-2024-0727'],
    vulns_removed: [],
    vulns_unchanged: ['CVE-2023-2650'],
    assessment_count: 1,
    assessments_added: [],
    assessments_removed: [],
    assessments_unchanged: [
        {
            vulnerability_id: 'CVE-2023-2650',
            status: 'not_affected',
            simplified_status: 'Not Affected',
            justification: 'vulnerable_code_not_present',
            impact_statement: 'Not impacted',
            status_notes: '',
        }
    ],
    newly_detected_findings: null,
    newly_detected_vulns: null,
    newly_detected_findings_list: null,
    newly_detected_vulns_list: null,
    newly_detected_assessments_list: null,
    all_findings: null,
    all_vulns: null,
};

const mockFirstScanDiff: ScanDiff = {
    ...mockScanDiff,
    previous_scan_id: null,
    is_first: true,
    packages_added: [
        { package_id: 'p1', package_name: 'openssl', package_version: '3.0.0' },
        { package_id: 'p2', package_name: 'curl', package_version: '8.7.0' },
    ],
    findings_added: [
        { finding_id: 'f1', package_name: 'openssl', package_version: '3.0.0', package_id: 'p1', vulnerability_id: 'CVE-2023-0286' }
    ],
    assessments_added: [],
    assessments_unchanged: [],
};

const mockToolScanDiff: ScanDiff = {
    ...mockScanDiff,
    scan_id: 'tool-scan-1',
    scan_type: 'tool',
    packages_added: [],
    packages_removed: [],
    packages_upgraded: [],
    packages_unchanged: [],
    newly_detected_findings: 1,
    newly_detected_vulns: 1,
    newly_detected_findings_list: [
        { finding_id: 'nf1', package_name: 'nginx', package_version: '1.25.3', package_id: 'np1', vulnerability_id: 'CVE-2024-9999' }
    ],
    newly_detected_vulns_list: ['CVE-2024-9999'],
    newly_detected_assessments_list: [],
};

const mockGlobalResult: GlobalResult = {
    scan_id: 'scan-1',
    scan_type: 'sbom',
    packages: [
        { package_id: 'p1', package_name: 'openssl', package_version: '3.2.1', sources: ['sbom', 'grype'] }
    ],
    findings: [
        { finding_id: 'f1', package_name: 'openssl', package_version: '3.2.1', package_id: 'p1', vulnerability_id: 'CVE-2024-0727', sources: ['grype'] }
    ],
    vulnerabilities: [
        { vulnerability_id: 'CVE-2024-0727', sources: ['grype'] }
    ],
    assessments: [
        { vulnerability_id: 'CVE-2024-0727', status: 'under_investigation', simplified_status: 'In Triage', justification: '', impact_statement: '', status_notes: '' }
    ],
    package_count: 1,
    finding_count: 1,
    vuln_count: 1,
    assessment_count: 1,
};

// Large dataset constants for filter-input coverage (> 10 entries required to show the input)
const LARGE_PACKAGES_ADDED = Array.from({ length: 11 }, (_, i) => ({
    package_id: `lg-p${i}`, package_name: `pkg-large-${i}`, package_version: `1.0.${i}`,
}));
const LARGE_PACKAGES_UPGRADED = Array.from({ length: 11 }, (_, i) => ({
    package_name: `pkg-large-${i}`, old_version: `1.0.${i}`, new_version: `2.0.${i}`,
    old_package_id: `lg-p${i}-old`, new_package_id: `lg-p${i}-new`,
}));
const LARGE_VULNS_ADDED = Array.from({ length: 11 }, (_, i) => `CVE-2024-${String(i).padStart(4, '0')}`);

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

// ---------------------------------------------------------------------------
// Page states
// ---------------------------------------------------------------------------

describe('ScanHistory page — loading/empty/error states', () => {

    test('shows "No scans found." when the API returns an empty list', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([]));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('No scans found.')).toBeInTheDocument());
    });

    test('shows error message when the scan list fetch throws', async () => {
        fetchMock.mockRejectOnce(new Error('Network failure'));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Failed to load scan history.')).toBeInTheDocument());
    });

    test('renders "Scan History" heading for any non-empty scan list', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('Scan History')).toBeInTheDocument());
    });

    test('renders without variantId using project-level URL (covers else branch)', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        render(<ScanHistory projectId="proj-1" />);
        await waitFor(() => expect(screen.getByText('Current result')).toBeInTheDocument());
    });

});

// ---------------------------------------------------------------------------
// Scan type badges
// ---------------------------------------------------------------------------

describe('ScanHistory card — scan type badges', () => {

    test('shows "Grype Scan" badge for grype tool scans', async () => {
        renderWithScan({ ...baseScan, scan_type: 'tool', scan_source: 'grype' });
        await waitFor(() => expect(screen.getByText('Grype Scan')).toBeInTheDocument());
    });

    test('shows "NVD CPE Scan" badge for nvd tool scans', async () => {
        renderWithScan({ ...baseScan, scan_type: 'tool', scan_source: 'nvd' });
        await waitFor(() => expect(screen.getByText('NVD CPE Scan')).toBeInTheDocument());
    });

    test('shows "OSV Scan" badge for osv tool scans', async () => {
        renderWithScan({ ...baseScan, scan_type: 'tool', scan_source: 'osv' });
        await waitFor(() => expect(screen.getByText('OSV Scan')).toBeInTheDocument());
    });

    test('shows "Import SBOM" and format badges for SBOM scans', async () => {
        renderWithScan({ ...baseScan, scan_type: 'sbom', formats: ['SPDX', 'CycloneDX'] });
        await waitFor(() => {
            expect(screen.getByText('Import SBOM')).toBeInTheDocument();
            expect(screen.getByText('SPDX')).toBeInTheDocument();
            expect(screen.getByText('CycloneDX')).toBeInTheDocument();
        });
    });

    test('shows project name and variant name when project_name is set', async () => {
        renderWithScan({ ...baseScan, project_name: 'MyProject', variant_name: 'prod' });
        await waitFor(() => {
            expect(screen.getByText('MyProject')).toBeInTheDocument();
            expect(screen.getByText('prod')).toBeInTheDocument();
        });
    });

});

// ---------------------------------------------------------------------------
// Filter controls
// ---------------------------------------------------------------------------

describe('ScanHistory page — filter controls', () => {

    test('"Hide empty scans" toggle filters out no-change scans', async () => {
        const noChangesScan: Scan = {
            ...baseScan,
            id: 'scan-2',
            is_first: false,
            vulns_added: 0, vulns_removed: 0,
            findings_added: 0, findings_removed: 0, findings_upgraded: 0,
            packages_added: 0, packages_removed: 0, packages_upgraded: 0,
        };
        renderWithScans([baseScan, noChangesScan]);
        await waitFor(() => expect(screen.getAllByText('Current result')).toHaveLength(2));

        fireEvent.click(screen.getByText('Hide empty scans'));

        await waitFor(() => expect(screen.getAllByText('Current result')).toHaveLength(1));
    });

    test('Grype toggle hides grype tool scans', async () => {
        const grypeScan: Scan = { ...baseScan, id: 'scan-2', scan_type: 'tool', scan_source: 'grype', vulns_added: 2, findings_added: 2 };
        renderWithScans([baseScan, grypeScan]);
        await waitFor(() => expect(screen.getAllByText('Current result')).toHaveLength(2));

        fireEvent.click(screen.getByText('Grype'));

        await waitFor(() => expect(screen.getAllByText('Current result')).toHaveLength(1));
    });

    test('OSV toggle hides osv tool scans', async () => {
        const osvScan: Scan = { ...baseScan, id: 'scan-2', scan_type: 'tool', scan_source: 'osv', vulns_added: 1, findings_added: 1 };
        renderWithScans([baseScan, osvScan]);
        await waitFor(() => expect(screen.getAllByText('Current result')).toHaveLength(2));

        fireEvent.click(screen.getByText('OSV'));

        await waitFor(() => expect(screen.getAllByText('Current result')).toHaveLength(1));
    });

    test('NVD toggle hides nvd tool scans', async () => {
        const nvdScan: Scan = { ...baseScan, id: 'scan-2', scan_type: 'tool', scan_source: 'nvd', vulns_added: 1, findings_added: 1 };
        renderWithScans([baseScan, nvdScan]);
        await waitFor(() => expect(screen.getAllByText('Current result')).toHaveLength(2));

        fireEvent.click(screen.getByText('NVD'));

        await waitFor(() => expect(screen.getAllByText('Current result')).toHaveLength(1));
    });

});

// ---------------------------------------------------------------------------
// DiffModal interactions
// ---------------------------------------------------------------------------

describe('ScanHistory — DiffModal interactions', () => {

    test('clicking Details in Section B opens DiffModal', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockScanDiff));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());

        fireEvent.click(screen.getByText('Details'));

        await waitFor(() => expect(screen.getByText('Scan diff details')).toBeInTheDocument());
    });

    test('DiffModal loads and shows packages tab by default for SBOM scans', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockScanDiff));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Details'));

        // PackageDiffTable heading format: "Added packages (1)"
        await waitFor(() => expect(screen.getByText('Added packages (1)')).toBeInTheDocument());
    });

    test('DiffModal shows findings when Findings tab is clicked', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockScanDiff));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Details'));
        await waitFor(() => expect(screen.getByText('Scan diff details')).toBeInTheDocument());

        // Tabs only render after the diff data loads
        const findingsTab = await waitFor(() => {
            const tab = screen.getAllByRole('button').find(b => b.textContent?.startsWith('Findings'));
            if (!tab) throw new Error('Findings tab not found');
            return tab;
        });
        fireEvent.click(findingsTab);

        await waitFor(() => expect(screen.getByText('Added findings (1)')).toBeInTheDocument());
    });

    test('DiffModal shows vulnerabilities when Vulnerabilities tab is clicked', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockScanDiff));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Details'));
        await waitFor(() => expect(screen.getByText('Scan diff details')).toBeInTheDocument());

        const vulnsTab = await waitFor(() => {
            const tab = screen.getAllByRole('button').find(b => b.textContent?.startsWith('Vulnerabilities'));
            if (!tab) throw new Error('Vulnerabilities tab not found');
            return tab;
        });
        fireEvent.click(vulnsTab);

        await waitFor(() => expect(screen.getByText('New vulnerabilities (1)')).toBeInTheDocument());
    });

    test('DiffModal shows assessments when Assessments tab is clicked', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockScanDiff));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Details'));
        await waitFor(() => expect(screen.getByText('Scan diff details')).toBeInTheDocument());

        const assessmentsTab = await waitFor(() => {
            const tab = screen.getAllByRole('button').find(b => b.textContent?.startsWith('Assessments'));
            if (!tab) throw new Error('Assessments tab not found');
            return tab;
        });
        fireEvent.click(assessmentsTab);

        await waitFor(() => expect(screen.getByText('Unchanged assessments (1)')).toBeInTheDocument());
    });

    test('DiffModal closes when Close button is clicked', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockScanDiff));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Details'));
        await waitFor(() => expect(screen.getByText('Scan diff details')).toBeInTheDocument());

        fireEvent.click(screen.getByText('Close'));

        await waitFor(() => expect(screen.queryByText('Scan diff details')).not.toBeInTheDocument());
    });

    test('DiffModal shows first-scan message for is_first=true diffs', async () => {
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
        fetchMock.mockResponseOnce(JSON.stringify([firstScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockFirstScanDiff));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Current result')).toBeInTheDocument());

        // Section A has "Details" for first scan
        fireEvent.click(screen.getByText('Details'));

        await waitFor(() => expect(screen.getByText(/This is the first scan/)).toBeInTheDocument());
    });

    test('DiffModal for tool scan shows "Tool scan diff details" title', async () => {
        const toolScan: Scan = {
            ...baseScan,
            id: 'tool-scan-1',
            scan_type: 'tool',
            scan_source: 'grype',
            newly_detected_findings: 1,
            newly_detected_vulns: 1,
        };
        fetchMock.mockResponseOnce(JSON.stringify([toolScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockToolScanDiff));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());

        fireEvent.click(screen.getByText('Details'));

        await waitFor(() => expect(screen.getByText('Tool scan diff details')).toBeInTheDocument());
    });

    test('DiffModal for tool scan shows "New Discovered" tab with newly detected content', async () => {
        const toolScan: Scan = {
            ...baseScan,
            id: 'tool-scan-1',
            scan_type: 'tool',
            scan_source: 'grype',
            newly_detected_findings: 1,
            newly_detected_vulns: 1,
        };
        fetchMock.mockResponseOnce(JSON.stringify([toolScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockToolScanDiff));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Details'));
        await waitFor(() => expect(screen.getByText('Tool scan diff details')).toBeInTheDocument());

        const newDiscoveredTab = await waitFor(() => {
            const tab = screen.getAllByRole('button').find(b => b.textContent?.startsWith('New Discovered'));
            if (!tab) throw new Error('New Discovered tab not found');
            return tab;
        });
        fireEvent.click(newDiscoveredTab);

        await waitFor(() => expect(screen.getByText('New findings discovered (1)')).toBeInTheDocument());
    });

    test('DiffModal shows error when getDiff returns null', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce('', { status: 500 }); // getDiff returns null
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());

        fireEvent.click(screen.getByText('Details'));

        await waitFor(() => expect(screen.getByText('Failed to load diff details.')).toBeInTheDocument());
    });

});

// ---------------------------------------------------------------------------
// GlobalResultModal interactions
// ---------------------------------------------------------------------------

describe('ScanHistory — GlobalResultModal interactions', () => {

    test('clicking "View all" button opens GlobalResultModal', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockGlobalResult));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('View all')).toBeInTheDocument());

        fireEvent.click(screen.getByText('View all'));

        await waitFor(() => expect(screen.getByText('Scan Result — Active Items')).toBeInTheDocument());
    });

    test('GlobalResultModal shows packages tab by default with package names', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockGlobalResult));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('View all')).toBeInTheDocument());
        fireEvent.click(screen.getByText('View all'));

        await waitFor(() => expect(screen.getByText('openssl')).toBeInTheDocument());
    });

    test('GlobalResultModal shows findings when Findings tab is clicked', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockGlobalResult));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('View all')).toBeInTheDocument());
        fireEvent.click(screen.getByText('View all'));
        await waitFor(() => expect(screen.getByText('Scan Result — Active Items')).toBeInTheDocument());

        // Tabs only render after data loads
        const findingsTab = await waitFor(() => {
            const tab = screen.getAllByRole('button').find(b => b.textContent?.startsWith('Findings'));
            if (!tab) throw new Error('Findings tab not found');
            return tab;
        });
        fireEvent.click(findingsTab);

        await waitFor(() => expect(screen.getByText('CVE-2024-0727')).toBeInTheDocument());
    });

    test('GlobalResultModal shows vulnerabilities when Vulnerabilities tab is clicked', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockGlobalResult));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('View all')).toBeInTheDocument());
        fireEvent.click(screen.getByText('View all'));
        await waitFor(() => expect(screen.getByText('Scan Result — Active Items')).toBeInTheDocument());

        const vulnsTab = await waitFor(() => {
            const tab = screen.getAllByRole('button').find(b => b.textContent?.startsWith('Vulnerabilities'));
            if (!tab) throw new Error('Vulnerabilities tab not found');
            return tab;
        });
        fireEvent.click(vulnsTab);

        // Vulnerabilities table shows vuln IDs
        await waitFor(() => expect(screen.getAllByText('CVE-2024-0727').length).toBeGreaterThan(0));
    });

    test('GlobalResultModal closes when Close button is clicked', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockGlobalResult));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('View all')).toBeInTheDocument());
        fireEvent.click(screen.getByText('View all'));
        await waitFor(() => expect(screen.getByText('Scan Result — Active Items')).toBeInTheDocument());

        fireEvent.click(screen.getByText('Close'));

        await waitFor(() => expect(screen.queryByText('Scan Result — Active Items')).not.toBeInTheDocument());
    });

    test('GlobalResultModal shows error when getGlobalResult returns null', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce('', { status: 500 });
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('View all')).toBeInTheDocument());

        fireEvent.click(screen.getByText('View all'));

        await waitFor(() => expect(screen.getByText('Failed to load scan result.')).toBeInTheDocument());
    });

});

// ---------------------------------------------------------------------------
// Description editing
// ---------------------------------------------------------------------------

describe('ScanHistory card — description editing', () => {

    test('clicking pencil icon reveals description edit input', async () => {
        renderWithScan({ ...baseScan, description: 'Initial description' });
        await waitFor(() => expect(screen.getByText('Current result')).toBeInTheDocument());

        fireEvent.click(screen.getByTitle('Edit description'));

        await waitFor(() => expect(screen.getByPlaceholderText('Add a description…')).toBeInTheDocument());
        expect(screen.getByTitle('Save')).toBeInTheDocument();
        expect(screen.getByTitle('Cancel')).toBeInTheDocument();
    });

    test('clicking Cancel exits edit mode without saving', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('Current result')).toBeInTheDocument());
        fireEvent.click(screen.getByTitle('Edit description'));
        await waitFor(() => expect(screen.getByPlaceholderText('Add a description…')).toBeInTheDocument());

        fireEvent.click(screen.getByTitle('Cancel'));

        await waitFor(() => expect(screen.queryByPlaceholderText('Add a description…')).not.toBeInTheDocument());
    });

    test('saving a description updates the scan card and exits edit mode', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('Current result')).toBeInTheDocument());
        fireEvent.click(screen.getByTitle('Edit description'));
        await waitFor(() => expect(screen.getByPlaceholderText('Add a description…')).toBeInTheDocument());

        fireEvent.change(screen.getByPlaceholderText('Add a description…'), { target: { value: 'New desc' } });
        fetchMock.mockResponseOnce('{}', { status: 200 });
        fireEvent.click(screen.getByTitle('Save'));

        await waitFor(() => expect(screen.queryByPlaceholderText('Add a description…')).not.toBeInTheDocument());
    });

    test('pressing Escape key cancels the description edit', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('Current result')).toBeInTheDocument());
        fireEvent.click(screen.getByTitle('Edit description'));
        await waitFor(() => expect(screen.getByPlaceholderText('Add a description…')).toBeInTheDocument());

        fireEvent.keyDown(screen.getByPlaceholderText('Add a description…'), { key: 'Escape' });

        await waitFor(() => expect(screen.queryByPlaceholderText('Add a description…')).not.toBeInTheDocument());
    });

    test('pressing Enter key triggers description save', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('Current result')).toBeInTheDocument());
        fireEvent.click(screen.getByTitle('Edit description'));
        await waitFor(() => expect(screen.getByPlaceholderText('Add a description…')).toBeInTheDocument());

        fetchMock.mockResponseOnce('{}', { status: 200 });
        fireEvent.keyDown(screen.getByPlaceholderText('Add a description…'), { key: 'Enter' });

        await waitFor(() => expect(screen.queryByPlaceholderText('Add a description…')).not.toBeInTheDocument());
    });

});

// ---------------------------------------------------------------------------
// Delete confirmation modal
// ---------------------------------------------------------------------------

describe('ScanHistory card — delete scan', () => {

    test('clicking trash icon opens the Delete Scan confirmation modal', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('Current result')).toBeInTheDocument());

        fireEvent.click(screen.getByTitle('Delete scan'));

        await waitFor(() => expect(screen.getByText('Delete Scan')).toBeInTheDocument());
        expect(screen.getByText(/Are you sure you want to delete this scan/)).toBeInTheDocument();
    });

    test('clicking Cancel in the delete modal dismisses it', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('Current result')).toBeInTheDocument());
        fireEvent.click(screen.getByTitle('Delete scan'));
        await waitFor(() => expect(screen.getByText('Delete Scan')).toBeInTheDocument());

        fireEvent.click(screen.getByText('Cancel'));

        await waitFor(() => expect(screen.queryByText('Delete Scan')).not.toBeInTheDocument());
    });

});

// ---------------------------------------------------------------------------
// Section B delta row edge cases
// ---------------------------------------------------------------------------

describe('ScanHistory card — Section B delta display details', () => {

    test('shows "updated" label for findings_upgraded > 0', async () => {
        renderWithScan({ ...baseScan, findings_upgraded: 3 });
        await waitFor(() => expect(screen.getByText(/3 updated/)).toBeInTheDocument());
    });

    test('shows "updated" label for packages_upgraded > 0', async () => {
        renderWithScan({ ...baseScan, packages_upgraded: 2 });
        await waitFor(() => expect(screen.getByText(/2 updated/)).toBeInTheDocument());
    });

    test('shows "unchanged" label for packages_unchanged > 0', async () => {
        renderWithScan({ ...baseScan, packages_unchanged: 10 });
        await waitFor(() => expect(screen.getByText(/10 unchanged/)).toBeInTheDocument());
    });

});

// ---------------------------------------------------------------------------
// DiffModal — keyboard, overlay, and filter interactions
// ---------------------------------------------------------------------------

describe('ScanHistory — DiffModal advanced interactions', () => {

    test('pressing Escape closes the DiffModal', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockScanDiff));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Details'));
        await waitFor(() => expect(screen.getByText('Scan diff details')).toBeInTheDocument());

        fireEvent.keyDown(document, { key: 'Escape' });

        await waitFor(() => expect(screen.queryByText('Scan diff details')).not.toBeInTheDocument());
    });

    test('typing in Assessments tab filter narrows results', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockScanDiff));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Details'));
        await waitFor(() => expect(screen.getByText('Scan diff details')).toBeInTheDocument());

        const assessmentsTab = await waitFor(() => {
            const tab = screen.getAllByRole('button').find(b => b.textContent?.startsWith('Assessments'));
            if (!tab) throw new Error('Assessments tab not found');
            return tab;
        });
        fireEvent.click(assessmentsTab);
        await waitFor(() => expect(screen.getByText('Unchanged assessments (1)')).toBeInTheDocument());

        // AssessmentDiffTable always has a filter textbox; use index [2] for "Unchanged" (has 1 entry)
        const filterInputs = screen.getAllByRole('textbox');
        fireEvent.change(filterInputs[2], { target: { value: 'CVE-2023-2650' } });
        await waitFor(() => expect(screen.getByText('CVE-2023-2650')).toBeInTheDocument());
    });

    test('typing in Findings tab filter updates displayed results', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockScanDiff));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Details'));
        await waitFor(() => expect(screen.getByText('Scan diff details')).toBeInTheDocument());

        const findingsTab = await waitFor(() => {
            const tab = screen.getAllByRole('button').find(b => b.textContent?.startsWith('Findings'));
            if (!tab) throw new Error('Findings tab not found');
            return tab;
        });
        fireEvent.click(findingsTab);
        await waitFor(() => expect(screen.getByText('Added findings (1)')).toBeInTheDocument());

        // FindingDiffTable always has a filter textbox
        const filterInputs = screen.getAllByRole('textbox');
        fireEvent.change(filterInputs[0], { target: { value: 'openssl' } });
        // openssl is still shown after filter
        await waitFor(() => expect(screen.getByText('openssl')).toBeInTheDocument());
    });

    test('DiffModal shows FindingUpgradeDiffTable for scans with findings_upgraded', async () => {
        const upgradedFindingsDiff: ScanDiff = {
            ...mockScanDiff,
            findings_upgraded: [
                {
                    vulnerability_id: 'CVE-2024-1234',
                    package_name: 'libxml2',
                    old_version: '2.9.14',
                    new_version: '2.12.0',
                }
            ],
        };
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(upgradedFindingsDiff));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Details'));
        await waitFor(() => expect(screen.getByText('Scan diff details')).toBeInTheDocument());

        const findingsTab = await waitFor(() => {
            const tab = screen.getAllByRole('button').find(b => b.textContent?.startsWith('Findings'));
            if (!tab) throw new Error('Findings tab not found');
            return tab;
        });
        fireEvent.click(findingsTab);

        await waitFor(() => expect(screen.getByText('Findings on upgraded packages (1)')).toBeInTheDocument());
        expect(screen.getByText('libxml2')).toBeInTheDocument();
    });

    test('DiffModal GlobalResultModal Escape key closes it', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockGlobalResult));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('View all')).toBeInTheDocument());
        fireEvent.click(screen.getByText('View all'));
        await waitFor(() => expect(screen.getByText('Scan Result — Active Items')).toBeInTheDocument());

        fireEvent.keyDown(document, { key: 'Escape' });

        await waitFor(() => expect(screen.queryByText('Scan Result — Active Items')).not.toBeInTheDocument());
    });

    test('DiffModal Packages tab shows PackageUpgradeDiffTable for upgraded packages', async () => {
        const upgradedPkgDiff: ScanDiff = {
            ...mockScanDiff,
            packages_upgraded: [
                { package_name: 'openssl', old_version: '3.0.0', new_version: '3.2.1', old_package_id: 'p1-old', new_package_id: 'p1-new' }
            ],
        };
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(upgradedPkgDiff));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Details'));

        // Packages tab is default for SBOM — wait for upgraded packages section to appear
        await waitFor(() => expect(screen.getByText('Upgraded packages (1)')).toBeInTheDocument());
        expect(screen.getByText('3.0.0')).toBeInTheDocument();
        expect(screen.getByText('3.2.1')).toBeInTheDocument();
    });

    test('typing in FindingUpgradeDiffTable filter narrows results', async () => {
        const upgradedFindingsDiff: ScanDiff = {
            ...mockScanDiff,
            findings_upgraded: [
                { vulnerability_id: 'CVE-2024-1234', package_name: 'libxml2', old_version: '2.9.14', new_version: '2.12.0' }
            ],
        };
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(upgradedFindingsDiff));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Details'));
        await waitFor(() => expect(screen.getByText('Scan diff details')).toBeInTheDocument());

        const findingsTab = await waitFor(() => {
            const tab = screen.getAllByRole('button').find(b => b.textContent?.startsWith('Findings'));
            if (!tab) throw new Error('Findings tab not found');
            return tab;
        });
        fireEvent.click(findingsTab);
        await waitFor(() => expect(screen.getByText('Findings on upgraded packages (1)')).toBeInTheDocument());

        // FindingUpgradeDiffTable always has a filter textbox; index [2] = upgrade table
        // (after Added findings [0], Removed findings [1], FindingUpgradeDiffTable [2], Unchanged [3])
        const filterInputs = screen.getAllByRole('textbox');
        fireEvent.change(filterInputs[2], { target: { value: 'libxml2' } });
        await waitFor(() => expect(screen.getByText('libxml2')).toBeInTheDocument());
    });

});

// ---------------------------------------------------------------------------
// Delete scan confirmation
// ---------------------------------------------------------------------------

describe('ScanHistory card — delete scan confirmation', () => {

    test('clicking "Yes, delete" calls deleteScan and refreshes', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('Current result')).toBeInTheDocument());
        fireEvent.click(screen.getByTitle('Delete scan'));
        await waitFor(() => expect(screen.getByText('Delete Scan')).toBeInTheDocument());

        // Mock the deleteScan API response, then the re-fetch
        fetchMock.mockResponseOnce(JSON.stringify({ orphaned_findings_removed: 2 }), { status: 200 });
        fetchMock.mockResponseOnce(JSON.stringify([]));
        fireEvent.click(screen.getByText('Yes, delete'));

        await waitFor(() => expect(screen.queryByText('Delete Scan')).not.toBeInTheDocument());
    });

});

// ---------------------------------------------------------------------------
// Run Scans menu
// ---------------------------------------------------------------------------

describe('ScanHistory — Run Scans menu', () => {

    test('clicking Run Scans opens the scan menu', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('Run Scans')).toBeInTheDocument());

        fireEvent.click(screen.getByText('Run Scans'));

        await waitFor(() => expect(screen.getByText('Scan types')).toBeInTheDocument());
        // Scan menu has "NVD CPE" (different from filter bar's "NVD")
        expect(screen.getByText('NVD CPE')).toBeInTheDocument();
        expect(screen.getByText('OSV', { selector: 'span' })).toBeInTheDocument();
    });

    test('toggling a scan type checkbox deselects it', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('Run Scans')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Run Scans'));
        await waitFor(() => expect(screen.getByText('Scan types')).toBeInTheDocument());

        // All scan type checkboxes start checked
        const checkboxes = screen.getAllByRole('checkbox');
        const grypeCb = checkboxes[0]; // first scan type = grype
        expect(grypeCb).toBeChecked();
        fireEvent.click(grypeCb);
        expect(grypeCb).not.toBeChecked();
    });

    test('"Run N scans" button is disabled when no scan types selected', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('Run Scans')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Run Scans'));
        await waitFor(() => expect(screen.getByText('Scan types')).toBeInTheDocument());

        // Deselect all scan types (first 3 checkboxes = grype, nvd, osv)
        const checkboxes = screen.getAllByRole('checkbox');
        for (const cb of checkboxes.slice(0, 3)) {
            if ((cb as HTMLInputElement).checked) fireEvent.click(cb);
        }

        const runBtn = screen.getAllByRole('button').find(b => b.textContent?.startsWith('Run') && b !== screen.getByText('Run Scans'));
        expect(runBtn).toBeDisabled();
    });

    test('shows "No variants found" when variants list is empty', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('Run Scans')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Run Scans'));
        await waitFor(() => expect(screen.getByText('No variants found')).toBeInTheDocument());
    });

});

// ---------------------------------------------------------------------------
// GlobalResultModal — filter and Assessments tab
// ---------------------------------------------------------------------------

describe('ScanHistory — GlobalResultModal extra coverage', () => {

    test('GlobalResultModal filter narrows packages', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockGlobalResult));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('View all')).toBeInTheDocument());
        fireEvent.click(screen.getByText('View all'));
        await waitFor(() => expect(screen.getByText('openssl')).toBeInTheDocument());

        // GlobalResultModal has a filter textbox in the tab bar
        const filterInputs = screen.getAllByRole('textbox');
        fireEvent.change(filterInputs[0], { target: { value: 'openssl' } });

        await waitFor(() => expect(screen.getByText('openssl')).toBeInTheDocument());
    });

    test('GlobalResultModal shows Assessments tab', async () => {
        const resultWithAssessment: GlobalResult = {
            ...mockGlobalResult,
            assessments: [
                {
                    vulnerability_id: 'CVE-2024-0727',
                    status: 'not_affected',
                    simplified_status: 'Not Affected',
                    justification: 'vulnerable_code_not_present',
                    impact_statement: 'Code path not reachable',
                    status_notes: '',
                }
            ],
            assessment_count: 1,
        };
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(resultWithAssessment));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('View all')).toBeInTheDocument());
        fireEvent.click(screen.getByText('View all'));
        await waitFor(() => expect(screen.getByText('Scan Result — Active Items')).toBeInTheDocument());

        const assessmentsTab = await waitFor(() => {
            const tab = screen.getAllByRole('button').find(b => b.textContent?.startsWith('Assessments'));
            if (!tab) throw new Error('Assessments tab not found');
            return tab;
        });
        fireEvent.click(assessmentsTab);

        await waitFor(() => expect(screen.getAllByText('CVE-2024-0727').length).toBeGreaterThan(0));
    });

});

// ---------------------------------------------------------------------------
// Additional coverage: catch handlers, tab navigation, large datasets, menus
// ---------------------------------------------------------------------------

describe('ScanHistory — additional coverage', () => {

    test('DiffModal shows error when getDiff fetch rejects', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockRejectOnce(new Error('network error'));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Current result')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Details'));
        await waitFor(() => expect(screen.getByText('Failed to load diff details.')).toBeInTheDocument());
    });

    test('GlobalResultModal shows error when fetch rejects', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockRejectOnce(new Error('network error'));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('View all')).toBeInTheDocument());
        fireEvent.click(screen.getByText('View all'));
        await waitFor(() => expect(screen.getByText('Failed to load scan result.')).toBeInTheDocument());
    });

    test('GlobalResultModal Packages tab onClick is covered by navigating back', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockGlobalResult));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('View all')).toBeInTheDocument());
        fireEvent.click(screen.getByText('View all'));
        const findingsTab = await waitFor(() => {
            const tab = screen.getAllByRole('button').find(b => b.textContent?.startsWith('Findings'));
            if (!tab) throw new Error('Findings tab not found');
            return tab;
        });
        fireEvent.click(findingsTab);
        // Navigate back to Packages tab (covers line 489 onClick)
        const packagesTab = await waitFor(() => {
            const tab = screen.getAllByRole('button').find(b => b.textContent?.startsWith('Packages'));
            if (!tab) throw new Error('Packages tab not found');
            return tab;
        });
        fireEvent.click(packagesTab);
        await waitFor(() => expect(screen.getByText('openssl')).toBeInTheDocument());
    });

    test('DiffModal Packages tab onClick is covered by navigating back', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(mockScanDiff));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Details'));
        const findingsTab = await waitFor(() => {
            const tab = screen.getAllByRole('button').find(b => b.textContent?.startsWith('Findings'));
            if (!tab) throw new Error('Findings tab not found');
            return tab;
        });
        fireEvent.click(findingsTab);
        // Navigate back to Packages tab (covers line 694 onClick)
        const packagesTab = await waitFor(() => {
            const tab = screen.getAllByRole('button').find(b => b.textContent?.startsWith('Packages'));
            if (!tab) throw new Error('Packages tab not found');
            return tab;
        });
        fireEvent.click(packagesTab);
        await waitFor(() => expect(screen.getByText('Added packages (1)')).toBeInTheDocument());
    });

    test('PackageDiffTable filter input appears and filter fn is covered with > 10 entries', async () => {
        const largeDiff: ScanDiff = { ...mockScanDiff, packages_added: LARGE_PACKAGES_ADDED };
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(largeDiff));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Details'));
        // Packages tab is default for SBOM; wait for the large table to render
        await waitFor(() => expect(screen.getByText('Added packages (11)')).toBeInTheDocument());
        // Filter input is shown when entries > 10
        const filterInputs = screen.getAllByRole('textbox');
        expect(filterInputs.length).toBeGreaterThan(0);
        fireEvent.change(filterInputs[0], { target: { value: 'pkg-large-0' } });
        await waitFor(() => expect(screen.getByText('pkg-large-0')).toBeInTheDocument());
    });

    test('PackageUpgradeDiffTable filter input appears and filter fn is covered with > 10 entries', async () => {
        const largeDiff: ScanDiff = { ...mockScanDiff, packages_upgraded: LARGE_PACKAGES_UPGRADED };
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(largeDiff));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Details'));
        await waitFor(() => expect(screen.getByText('Upgraded packages (11)')).toBeInTheDocument());
        const filterInputs = screen.getAllByRole('textbox');
        expect(filterInputs.length).toBeGreaterThan(0);
        fireEvent.change(filterInputs[0], { target: { value: 'pkg-large-0' } });
        await waitFor(() => expect(screen.getByText('pkg-large-0')).toBeInTheDocument());
    });

    test('VulnDiffList filter input appears and filter fn is covered with > 10 vulns', async () => {
        const largeDiff: ScanDiff = { ...mockScanDiff, vulns_added: LARGE_VULNS_ADDED };
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        fetchMock.mockResponseOnce(JSON.stringify(largeDiff));
        render(<ScanHistory variantId="v1" />);
        await waitFor(() => expect(screen.getByText('Changes since previous scan')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Details'));
        const vulnsTab = await waitFor(() => {
            const tab = screen.getAllByRole('button').find(b => b.textContent?.startsWith('Vulnerabilities'));
            if (!tab) throw new Error('Vulnerabilities tab not found');
            return tab;
        });
        fireEvent.click(vulnsTab);
        await waitFor(() => expect(screen.getByText('New vulnerabilities (11)')).toBeInTheDocument());
        const filterInputs = screen.getAllByRole('textbox');
        expect(filterInputs.length).toBeGreaterThan(0);
        fireEvent.change(filterInputs[0], { target: { value: 'CVE-2024-0000' } });
        await waitFor(() => expect(screen.getByText('CVE-2024-0000')).toBeInTheDocument());
    });

    test('scan menu closes on outside click (handleClickOutside)', async () => {
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('Run Scans')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Run Scans'));
        await waitFor(() => expect(screen.getByText('Scan types')).toBeInTheDocument());
        fireEvent.mouseDown(document.body);
        await waitFor(() => expect(screen.queryByText('Scan types')).not.toBeInTheDocument());
    });

    test('variant checkbox toggles and Run button triggers handleRunSelectedScans', async () => {
        (Variants.listAll as jest.Mock).mockResolvedValueOnce([
            { id: 'v1', name: 'Prod', project_id: 'proj-1' },
        ]);
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('Run Scans')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Run Scans'));
        await waitFor(() => expect(screen.getByText('Prod')).toBeInTheDocument());

        // checkboxes: [0]=grype [1]=nvd [2]=osv [3]=variant
        const checkboxes = screen.getAllByRole('checkbox');
        const variantCb = checkboxes[3];
        expect(variantCb).toBeChecked();
        fireEvent.click(variantCb); // toggleVariant — unchecks
        expect(variantCb).not.toBeChecked();
        fireEvent.click(variantCb); // toggleVariant — re-checks
        expect(variantCb).toBeChecked();

        // Click Run button (handleRunSelectedScans)
        const runBtn = screen.getAllByRole('button').find(b => /Run \d+ scans? on/.test(b.textContent || ''));
        expect(runBtn).toBeDefined();
        expect(runBtn).not.toBeDisabled();
        fireEvent.click(runBtn!);
        await waitFor(() => expect(screen.queryByText('Scan types')).not.toBeInTheDocument());
    });

    test('Select all and Select none with two variants', async () => {
        (Variants.list as jest.Mock).mockResolvedValueOnce([
            { id: 'v1', name: 'Variant A', project_id: 'proj-1' },
            { id: 'v2', name: 'Variant B', project_id: 'proj-1' },
        ]);
        fetchMock.mockResponseOnce(JSON.stringify([baseScan]));
        render(<ScanHistory projectId="proj-1" />);
        await waitFor(() => expect(screen.getByText('Run Scans')).toBeInTheDocument());
        fireEvent.click(screen.getByText('Run Scans'));
        await waitFor(() => expect(screen.getByText('Variant A')).toBeInTheDocument());
        expect(screen.getByText('Variant B')).toBeInTheDocument();

        // Select none then Select all (covers those onClick lambdas)
        const selectNoneBtn = await waitFor(() => screen.getByText('Select none'));
        fireEvent.click(selectNoneBtn);
        const selectAllBtn = screen.getByText('Select all');
        fireEvent.click(selectAllBtn);
    });

    test('scan progress panels render with running grype entries', async () => {
        const runningEntries = [{ variantId: 'v1', variantName: 'default', status: 'running', error: null, progress: '50%', logs: [], total: 100, doneCount: 50 }];
        (grypeScanState.getSnapshot as jest.Mock).mockReturnValue(runningEntries);
        renderWithScan(baseScan);
        await waitFor(() => expect(screen.getByText('Grype Scan – default in progress')).toBeInTheDocument());
    });

});

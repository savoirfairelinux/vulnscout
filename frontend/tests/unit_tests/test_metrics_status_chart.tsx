/**
 * Tests for the "Vulnerabilities by Status" chart computation in Metrics.tsx.
 *
 * Each vulnerability must be counted at most once per status bucket
 * (Not affected, Fixed, Pending Assessment, Exploitable), based on whether it
 * has any variant in that status — not by summing the per-variant counts.
 */
import { render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
// @ts-expect-error TS6133
import React from 'react';

// ---------------------------------------------------------------------------
// Mocks — must be declared before component import
// ---------------------------------------------------------------------------

jest.mock('chart.js', () => ({
    Chart: {
        register: jest.fn(),
        overrides: { pie: { plugins: { legend: { onClick: jest.fn() } } } },
    },
    ArcElement: {},
    Tooltip: {},
    Legend: {},
    CategoryScale: {},
    LinearScale: {},
    PointElement: {},
    LineElement: {},
    BarElement: {},
    LogarithmicScale: {},
}));

// Expose each Pie's `data` prop as JSON so tests can read the computed dataset.
jest.mock('react-chartjs-2', () => ({
    Pie: ({ data }: any) => (
        <div data-testid="pie-chart" data-chart={JSON.stringify(data)} />
    ),
    Line: () => <div data-testid="line-chart" />,
    Bar:  () => <div data-testid="bar-chart" />,
}));

jest.mock('../../src/components/TableGeneric', () => ({
    __esModule: true,
    default: () => <table data-testid="mock-table" />,
}));

jest.mock('../../src/components/VulnModal', () => ({
    __esModule: true,
    default: () => <div data-testid="vuln-modal" />,
}));

jest.mock('../../src/components/SeverityTag', () => ({
    __esModule: true,
    default: ({ severity }: any) => <span>{severity}</span>,
}));

jest.mock('../../src/helpers/sourceNames', () => ({
    formatSourceName: (s: string) => s,
}));

jest.mock('../../src/handlers/iso8601duration', () => ({
    __esModule: true,
    default: class Iso8601Duration {
        raw: string;
        constructor(v: string) { this.raw = v; }
        toSeconds() { return 0; }
        toString() { return this.raw; }
    },
}));

jest.mock('../../src/handlers/variant', () => ({
    __esModule: true,
    default: { list: jest.fn().mockResolvedValue([]), listAll: jest.fn().mockResolvedValue([]) },
}));

import Metrics from '../../src/pages/Metrics';
import type { Vulnerability } from '../../src/handlers/vulnerabilities';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const STATUS_LABELS = ['Not affected', 'Fixed', 'Pending Assessment', 'Exploitable'];

const ACTIVE_STATUSES = new Set(['Exploitable', 'Pending Assessment']);

/** Build a vulnerability whose status_summary reflects per-variant `counts`. */
const makeVuln = (id: string, counts: Record<string, number>): Vulnerability => {
    const ordered = Object.entries(counts).map(([status, count]) => ({ status, count }));
    const dominant_status = ordered[0]?.status ?? 'unknown';
    const status_summary = {
        counts,
        ordered,
        total_assessments: ordered.reduce((acc, e) => acc + e.count, 0),
        dominant_status,
        has_active_status: ordered.some((e) => ACTIVE_STATUSES.has(e.status)),
    };
    return {
        id,
        aliases: [],
        related_vulnerabilities: [],
        namespace: 'nvd',
        found_by: ['nvd'],
        datasource: 'nvd',
        packages: ['pkg@1.0.0'],
        packages_current: ['pkg@1.0.0'],
        variants: ['default'],
        urls: [],
        texts: [],
        severity: { severity: 'HIGH', min_score: 7.5, max_score: 7.5, cvss: [] },
        epss: { score: undefined, percentile: undefined },
        effort: { optimistic: { raw: 'P0D' } as any, likely: { raw: 'P0D' } as any, pessimistic: { raw: 'P0D' } as any },
        fix: { state: 'unknown' },
        simplified_status: dominant_status,
        assessments: [],
        status_summary,
    };
};

const DEFAULT_PROPS = {
    packages: [],
    vulnerabilities: [] as Vulnerability[],
    goToVulnsTabWithFilter: jest.fn(),
    appendAssessment: jest.fn(),
    patchVuln: jest.fn(),
    setTab: jest.fn(),
    appendCVSS: jest.fn(),
    projectId: 'proj-1',
};

/** Read the dataset of the "Vulnerabilities by Status" pie chart from the DOM. */
const getStatusChartData = (): number[] => {
    const charts = screen.getAllByTestId('pie-chart');
    for (const el of charts) {
        const raw = el.getAttribute('data-chart');
        if (!raw) continue;
        const parsed = JSON.parse(raw);
        if (JSON.stringify(parsed.labels) === JSON.stringify(STATUS_LABELS)) {
            return parsed.datasets[0].data as number[];
        }
    }
    throw new Error('status chart not found');
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Metrics — Vulnerabilities by Status chart', () => {
    afterEach(() => { jest.clearAllMocks(); });

    test('counts a single-status vulnerability once', async () => {
        const vuln = makeVuln('CVE-1', { 'Exploitable': 1 });
        render(<Metrics {...DEFAULT_PROPS} vulnerabilities={[vuln]} />);
        await waitFor(() => expect(screen.getByText('Vulnerabilities by Status')).toBeInTheDocument());
        // [Not affected, Fixed, Pending Assessment, Exploitable]
        expect(getStatusChartData()).toEqual([0, 0, 0, 1]);
    });

    test('does not multiply a CVE present in several variants of the same status', async () => {
        // Same status across 3 variants must count once, not 3 times.
        const vuln = makeVuln('CVE-2', { 'Exploitable': 3 });
        render(<Metrics {...DEFAULT_PROPS} vulnerabilities={[vuln]} />);
        await waitFor(() => expect(screen.getByText('Vulnerabilities by Status')).toBeInTheDocument());
        expect(getStatusChartData()).toEqual([0, 0, 0, 1]);
    });

    test('counts a mixed-status CVE once in each bucket it has', async () => {
        // A CVE Exploitable in one variant and Pending in two others counts
        // once in Exploitable AND once in Pending Assessment.
        const vuln = makeVuln('CVE-3', { 'Exploitable': 1, 'Pending Assessment': 2 });
        render(<Metrics {...DEFAULT_PROPS} vulnerabilities={[vuln]} />);
        await waitFor(() => expect(screen.getByText('Vulnerabilities by Status')).toBeInTheDocument());
        expect(getStatusChartData()).toEqual([0, 0, 1, 1]);
    });

    test('aggregates distinct vulnerabilities across all status buckets', async () => {
        const vulns = [
            makeVuln('CVE-A', { 'Not affected': 5 }),
            makeVuln('CVE-B', { 'Fixed': 1 }),
            makeVuln('CVE-C', { 'Pending Assessment': 2 }),
            makeVuln('CVE-D', { 'Exploitable': 1, 'Fixed': 1 }),
        ];
        render(<Metrics {...DEFAULT_PROPS} vulnerabilities={vulns} />);
        await waitFor(() => expect(screen.getByText('Vulnerabilities by Status')).toBeInTheDocument());
        // Not affected: CVE-A → 1
        // Fixed: CVE-B + CVE-D → 2
        // Pending Assessment: CVE-C → 1
        // Exploitable: CVE-D → 1
        expect(getStatusChartData()).toEqual([1, 2, 1, 1]);
    });
});

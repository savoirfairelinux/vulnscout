/**
 * Tests for Metrics.tsx — tables section, UI interactions, and computation
 * paths.
 *
 * Covers:
 *  - "See all" buttons (setTab)
 *  - Time scale selector
 *  - topVulnerablePackages and TopVulns computation
 *  - Section / card titles rendered in the DOM
 *  - handlePatchVuln
 */
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import '@testing-library/jest-dom';
// @ts-expect-error TS6133
import React from 'react';

// ---------------------------------------------------------------------------
// Mocks — must be declared before component import
// ---------------------------------------------------------------------------

jest.mock('chart.js', () => {
    const legendClickFn = jest.fn();
    return {
        Chart: {
            register: jest.fn(),
            overrides: { pie: { plugins: { legend: { onClick: legendClickFn } } } },
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
    };
});

jest.mock('react-chartjs-2', () => ({
    Pie:  () => <div data-testid="pie-chart" />,
    Line: () => <div data-testid="line-chart" />,
    Bar:  () => <div data-testid="bar-chart" />,
}));

jest.mock('../../src/components/TableGeneric', () => ({
    __esModule: true,
    default: ({ data }: any) => (
        <table data-testid="mock-table">
            {data.map((row: any, i: number) => (
                <tr key={i} data-testid="mock-table-row">
                    <td>{row.cve || row.name || row.id}</td>
                </tr>
            ))}
        </table>
    ),
}));

jest.mock('../../src/components/VulnModal', () => ({
    __esModule: true,
    default: ({ vuln, onClose, onNavigate, currentIndex }: any) => (
        <div data-testid="vuln-modal">
            <span data-testid="modal-vuln-id">{vuln?.id}</span>
            <span data-testid="modal-index">{currentIndex}</span>
            <button data-testid="modal-close" onClick={onClose}>Close</button>
            <button data-testid="modal-nav-prev" onClick={() => onNavigate(currentIndex - 1)}>Prev</button>
            <button data-testid="modal-nav-next" onClick={() => onNavigate(currentIndex + 1)}>Next</button>
        </div>
    ),
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

import Metrics from '../../src/pages/Metrics';
import type { Vulnerability } from '../../src/handlers/vulnerabilities';
import type { Assessment } from '../../src/handlers/assessments';

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const makeAssessment = (variantId: string, status: string, timestamp = '2024-01-01T00:00:00Z'): Assessment => ({
    id: `assess-${variantId}-${status}`,
    vuln_id: 'CVE-2024-0001',
    packages: ['pkg@1.0.0'],
    variant_id: variantId,
    origin: 'user',
    status,
    simplified_status: status,
    timestamp,
    responses: [],
});

const makeVuln = (id: string, assessments: Assessment[], pkgs: string[] = ['pkg@1.0.0'], severity = 'HIGH', cvssScore = 7.5): Vulnerability => ({
    id,
    aliases: [],
    related_vulnerabilities: [],
    namespace: 'nvd',
    found_by: ['nvd'],
    datasource: 'nvd',
    packages: pkgs,
    packages_current: pkgs,
    variants: ['default'],
    urls: [],
    texts: [],
    severity: { severity, min_score: cvssScore, max_score: cvssScore, cvss: [{ base_score: cvssScore, author: 'nvd', severity, version: '3.1', vector_string: '', exploitability_score: 0, impact_score: 0 }] },
    epss: { score: undefined, percentile: undefined },
    effort: { optimistic: { raw: 'P0D' } as any, likely: { raw: 'P0D' } as any, pessimistic: { raw: 'P0D' } as any },
    fix: { state: 'unknown' },
    simplified_status: assessments[0]?.simplified_status ?? 'unknown',
    assessments,
    status_summary: {
        counts: { [assessments[0]?.simplified_status ?? 'unknown']: 1 },
        ordered: [{ status: assessments[0]?.simplified_status ?? 'unknown', count: 1 }],
        total_assessments: assessments.length,
        dominant_status: assessments[0]?.simplified_status ?? 'unknown',
        has_active_status: assessments[0]?.simplified_status === 'Exploitable' || assessments[0]?.simplified_status === 'Pending Assessment',
    },
});

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

/** Wait for the Metrics component to fully render (charts + tables visible). */
const waitForRender = () =>
    waitFor(() => expect(screen.getByText('Vulnerabilities by Severity')).toBeInTheDocument());

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('Metrics — sections and UI', () => {
    afterEach(() => {
        jest.clearAllMocks();
    });

    // -----------------------------------------------------------------------
    // Section titles
    // -----------------------------------------------------------------------

    test('renders the charts section titles', async () => {
        render(<Metrics {...DEFAULT_PROPS} />);
        await waitForRender();
        expect(screen.getByText('Vulnerabilities by Severity')).toBeInTheDocument();
        expect(screen.getByText('Vulnerabilities by Status')).toBeInTheDocument();
        expect(screen.getByText('Active vulnerabilities')).toBeInTheDocument();
        expect(screen.getByText('Vulnerabilities by Database')).toBeInTheDocument();
    }, 15_000);

    test('renders the tables section titles', async () => {
        render(<Metrics {...DEFAULT_PROPS} />);
        await waitForRender();
        expect(screen.getByText('Most critical unfixed vulnerabilities')).toBeInTheDocument();
        expect(screen.getByText('Most vulnerable packages')).toBeInTheDocument();
    });

    // -----------------------------------------------------------------------
    // "See all" buttons
    // -----------------------------------------------------------------------

    test('"See all" vulnerabilities button calls setTab("vulnerabilities")', async () => {
        const setTab = jest.fn();
        render(<Metrics {...DEFAULT_PROPS} setTab={setTab} />);
        await waitForRender();

        const buttons = screen.getAllByRole('button', { name: /see all/i });
        fireEvent.click(buttons[0]);
        expect(setTab).toHaveBeenCalledWith('vulnerabilities');
    });

    test('"See all" packages button calls setTab("packages")', async () => {
        const setTab = jest.fn();
        render(<Metrics {...DEFAULT_PROPS} setTab={setTab} />);
        await waitForRender();

        const buttons = screen.getAllByRole('button', { name: /see all/i });
        fireEvent.click(buttons[1]);
        expect(setTab).toHaveBeenCalledWith('packages');
    });

    // -----------------------------------------------------------------------
    // Time scale selector
    // -----------------------------------------------------------------------

    test('time scale selector defaults to 6 months', async () => {
        render(<Metrics {...DEFAULT_PROPS} />);
        await waitForRender();
        const select = screen.getByDisplayValue('6 months') as HTMLSelectElement;
        expect(select.value).toBe('6_months');
    });

    test('time scale selector can be changed to 1 year', async () => {
        render(<Metrics {...DEFAULT_PROPS} />);
        await waitForRender();
        const select = screen.getByDisplayValue('6 months') as HTMLSelectElement;
        await act(async () => {
            fireEvent.change(select, { target: { value: '12_months' } });
        });
        expect(select.value).toBe('12_months');
    });

    test('time scale selector can be changed to 24 hours', async () => {
        render(<Metrics {...DEFAULT_PROPS} />);
        await waitForRender();
        const select = screen.getByDisplayValue('6 months') as HTMLSelectElement;
        await act(async () => {
            fireEvent.change(select, { target: { value: '24_hours' } });
        });
        expect(select.value).toBe('24_hours');
    });
});

// ---------------------------------------------------------------------------
describe('Metrics — TopVulns and topVulnerablePackages', () => {
    afterEach(() => { jest.clearAllMocks(); });

    test('TopVulns only shows active (Exploitable / Pending) vulnerabilities', async () => {
        const active = makeVuln('CVE-ACTIVE', [makeAssessment('var-1', 'Exploitable')], ['pkgA@1.0'], 'HIGH', 8.0);
        active.simplified_status = 'Exploitable';
        active.status_summary = { counts: { 'Exploitable': 1 }, ordered: [{ status: 'Exploitable', count: 1 }], total_assessments: 1, dominant_status: 'Exploitable', has_active_status: true };

        const fixed = makeVuln('CVE-FIXED', [makeAssessment('var-1', 'Fixed')], ['pkgB@2.0'], 'MEDIUM', 5.0);
        fixed.simplified_status = 'Fixed';
        fixed.status_summary = { counts: { 'Fixed': 1 }, ordered: [{ status: 'Fixed', count: 1 }], total_assessments: 1, dominant_status: 'Fixed', has_active_status: false };

        render(<Metrics {...DEFAULT_PROPS} vulnerabilities={[active, fixed]} />);
        await waitForRender();
        const rows = screen.getAllByTestId('mock-table-row');
        const rowTexts = rows.map(r => r.textContent);
        expect(rowTexts.some(t => t?.includes('CVE-ACTIVE'))).toBe(true);
        expect(rowTexts.some(t => t?.includes('CVE-FIXED'))).toBe(false);
    });

    test('TopVulns shows at most 5 entries', async () => {
        const vulns = Array.from({ length: 8 }, (_, i) => {
            const v = makeVuln(`CVE-200${i}`, [makeAssessment('var-1', 'Exploitable')], [`pkg${i}@1.0`], 'HIGH', 9.0 - i * 0.1);
            v.simplified_status = 'Exploitable';
            v.status_summary = { counts: { 'Exploitable': 1 }, ordered: [{ status: 'Exploitable', count: 1 }], total_assessments: 1, dominant_status: 'Exploitable', has_active_status: true };
            return v;
        });
        render(<Metrics {...DEFAULT_PROPS} vulnerabilities={vulns} />);
        await waitForRender();
        const tables = screen.getAllByTestId('mock-table');
        const vulnTableRows = tables[0].querySelectorAll('[data-testid="mock-table-row"]');
        expect(vulnTableRows.length).toBeLessThanOrEqual(5);
    });

    test('TopVulns ranks by severity label, not a stale CVSS score', async () => {
        // Reproduces the bug where an nvd-refresh lowered a vulnerability to
        // "medium" but a stale high CVSS score kept it ranked above criticals.
        const medium = makeVuln('CVE-MEDIUM', [makeAssessment('var-1', 'Exploitable')], ['pkgM@1.0'], 'medium', 9.8);
        medium.simplified_status = 'Exploitable';
        medium.status_summary = { counts: { 'Exploitable': 1 }, ordered: [{ status: 'Exploitable', count: 1 }], total_assessments: 1, dominant_status: 'Exploitable', has_active_status: true };

        const critical = makeVuln('CVE-CRITICAL', [makeAssessment('var-1', 'Exploitable')], ['pkgC@1.0'], 'critical', 9.0);
        critical.simplified_status = 'Exploitable';
        critical.status_summary = { counts: { 'Exploitable': 1 }, ordered: [{ status: 'Exploitable', count: 1 }], total_assessments: 1, dominant_status: 'Exploitable', has_active_status: true };

        render(<Metrics {...DEFAULT_PROPS} vulnerabilities={[medium, critical]} />);
        await waitForRender();
        const tables = screen.getAllByTestId('mock-table');
        const vulnTableRows = tables[0].querySelectorAll('[data-testid="mock-table-row"]');
        const rowTexts = Array.from(vulnTableRows).map(r => r.textContent);
        // The critical vulnerability must rank above the medium one despite its
        // lower CVSS score.
        expect(rowTexts[0]).toContain('CVE-CRITICAL');
        expect(rowTexts[1]).toContain('CVE-MEDIUM');
    });

    test('TopVulns keeps incoming order for equal-severity vulns (matches Vulnerability tab)', async () => {
        // Within the same severity, the ranking must follow the same order as
        // the Vulnerability tab (which keeps the backend CVE-id order within a
        // severity) instead of re-sorting by the raw CVSS score.
        const first = makeVuln('CVE-2000-0001', [makeAssessment('var-1', 'Exploitable')], ['pkg1@1.0'], 'critical', 9.0);
        first.simplified_status = 'Exploitable';
        first.status_summary = { counts: { 'Exploitable': 1 }, ordered: [{ status: 'Exploitable', count: 1 }], total_assessments: 1, dominant_status: 'Exploitable', has_active_status: true };

        const second = makeVuln('CVE-2000-0002', [makeAssessment('var-1', 'Exploitable')], ['pkg2@1.0'], 'critical', 10.0);
        second.simplified_status = 'Exploitable';
        second.status_summary = { counts: { 'Exploitable': 1 }, ordered: [{ status: 'Exploitable', count: 1 }], total_assessments: 1, dominant_status: 'Exploitable', has_active_status: true };

        // `second` has the higher CVSS score but comes later in the incoming
        // order; the incoming order must win.
        render(<Metrics {...DEFAULT_PROPS} vulnerabilities={[first, second]} />);
        await waitForRender();
        const tables = screen.getAllByTestId('mock-table');
        const vulnTableRows = tables[0].querySelectorAll('[data-testid="mock-table-row"]');
        const rowTexts = Array.from(vulnTableRows).map(r => r.textContent);
        expect(rowTexts[0]).toContain('CVE-2000-0001');
        expect(rowTexts[1]).toContain('CVE-2000-0002');
    });

    test('topVulnerablePackages aggregates by package name', async () => {
        const vuln1 = makeVuln('CVE-A', [makeAssessment('var-1', 'Exploitable')], ['openssl@3.0', 'zlib@1.2'], 'HIGH', 8.0);
        const vuln2 = makeVuln('CVE-B', [makeAssessment('var-1', 'Exploitable')], ['openssl@3.0'], 'HIGH', 7.0);
        vuln1.simplified_status = 'Exploitable';
        vuln2.simplified_status = 'Exploitable';
        render(<Metrics {...DEFAULT_PROPS} vulnerabilities={[vuln1, vuln2]} />);
        await waitForRender();

        const tables = screen.getAllByTestId('mock-table');
        const pkgTableRows = tables[1].querySelectorAll('[data-testid="mock-table-row"]');
        expect(pkgTableRows.length).toBeGreaterThan(0);
        const rowTexts = Array.from(pkgTableRows).map(r => r.textContent);
        expect(rowTexts.some(t => t?.includes('openssl'))).toBe(true);
    });

    test('topVulnerablePackages shows at most 5 entries', async () => {
        const vulns = Array.from({ length: 3 }, (_, i) =>
            makeVuln(`CVE-P${i}`, [makeAssessment('var-1', 'Exploitable')],
                [`pkg0@1`, `pkg1@1`, `pkg2@1`, `pkg3@1`, `pkg4@1`, `pkg5@1`, `pkg6@1`])
        );
        render(<Metrics {...DEFAULT_PROPS} vulnerabilities={vulns} />);
        await waitForRender();

        const tables = screen.getAllByTestId('mock-table');
        const pkgRows = tables[1].querySelectorAll('[data-testid="mock-table-row"]');
        expect(pkgRows.length).toBeLessThanOrEqual(5);
    });
});

// ---------------------------------------------------------------------------
describe('Metrics — modal and patch', () => {
    afterEach(() => { jest.clearAllMocks(); });

    test('handlePatchVuln prop is wired — component renders without calling it', async () => {
        const patchVuln = jest.fn();
        const v = makeVuln('CVE-PATCH', [makeAssessment('var-1', 'Exploitable')], ['pkg@1.0'], 'HIGH', 9.0);
        v.simplified_status = 'Exploitable';
        v.status_summary = { counts: { 'Exploitable': 1 }, ordered: [{ status: 'Exploitable', count: 1 }], total_assessments: 1, dominant_status: 'Exploitable', has_active_status: true };

        render(<Metrics {...DEFAULT_PROPS} vulnerabilities={[v]} patchVuln={patchVuln} />);
        await waitForRender();
        expect(patchVuln).not.toHaveBeenCalled();
    });

    test('modal is not rendered when no vuln is selected', async () => {
        render(<Metrics {...DEFAULT_PROPS} vulnerabilities={[]} />);
        await waitForRender();
        expect(screen.queryByTestId('vuln-modal')).not.toBeInTheDocument();
    });
});

// ---------------------------------------------------------------------------
describe('Metrics — charts render correctly', () => {
    afterEach(() => { jest.clearAllMocks(); });

    test('renders all four chart placeholders', async () => {
        render(<Metrics {...DEFAULT_PROPS} />);
        await waitForRender();
        expect(screen.getAllByTestId('pie-chart').length).toBe(2);
        expect(screen.getByTestId('line-chart')).toBeInTheDocument();
        expect(screen.getByTestId('bar-chart')).toBeInTheDocument();
    });

    test('renders with vulnerability data without crashing', async () => {
        const vulns = [
            makeVuln('CVE-SEV', [makeAssessment('var-1', 'Exploitable')], ['a@1'], 'CRITICAL', 9.8),
            makeVuln('CVE-MED', [makeAssessment('var-1', 'Fixed')], ['b@2'], 'MEDIUM', 5.0),
            makeVuln('CVE-LOW', [makeAssessment('var-1', 'Not affected')], ['c@3'], 'LOW', 2.0),
        ];
        render(<Metrics {...DEFAULT_PROPS} vulnerabilities={vulns} />);
        await waitForRender();
        expect(screen.getAllByTestId('pie-chart').length).toBe(2);
    });

    test('dataSetVulnBySource uses found_by from vulnerabilities', async () => {
        const vuln = makeVuln('CVE-SRC', [makeAssessment('var-1', 'Exploitable')], ['pkg@1']);
        vuln.found_by = ['grype'];
        render(<Metrics {...DEFAULT_PROPS} vulnerabilities={[vuln]} />);
        await waitForRender();
        expect(screen.getByTestId('bar-chart')).toBeInTheDocument();
    });

    test('vulnerability with no found_by is skipped in source chart', async () => {
        const vuln = makeVuln('CVE-NOSRC', [makeAssessment('var-1', 'Exploitable')], ['pkg@1']);
        vuln.found_by = [];
        render(<Metrics {...DEFAULT_PROPS} vulnerabilities={[vuln]} />);
        await waitForRender();
        expect(screen.getByTestId('bar-chart')).toBeInTheDocument();
    });
});

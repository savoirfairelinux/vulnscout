import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

jest.mock('../../src/components/TableGeneric', () => ({
    __esModule: true,
    default: ({ data, columns, search }: any) => {
        const val = (row: any, col: any) => (col.accessorKey ? row[col.accessorKey] : undefined);
        return (
            <table data-testid="mock-table" data-search={search ?? ''}>
                <thead>
                    <tr>
                        {columns.map((col: any, ci: number) => (
                            <th key={ci}>{typeof col.header === 'function' ? col.header({ column: col }) : col.header}</th>
                        ))}
                    </tr>
                </thead>
                <tbody>
                    {data.map((row: any, i: number) => (
                        <tr key={i} data-testid="mock-table-row">
                            {columns.map((col: any, ci: number) => (
                                <td key={ci}>
                                    {col.cell ? col.cell({ row: { original: row }, getValue: () => val(row, col) }) : null}
                                </td>
                            ))}
                        </tr>
                    ))}
                </tbody>
            </table>
        );
    },
}));

// The vulnerability modal is not exercised here; keep it inert but observable,
// and expose its callbacks so we can test the dismiss and no-op handler paths.
jest.mock('../../src/components/VulnModal', () => ({
    __esModule: true,
    default: ({ onClose, appendAssessment, appendCVSS, patchVuln }: any) => (
        <div data-testid="vuln-modal">
            <button onClick={() => { appendAssessment(); appendCVSS(); patchVuln(); }}>
                invoke-vuln-modal-callbacks
            </button>
            <button onClick={onClose}>close-vuln-modal</button>
        </div>
    ),
}));

// Keep the real filename/timestamp helpers but stub the download so jsdom does
// not need URL.createObjectURL.
jest.mock('../../src/helpers/exportJson', () => ({
    __esModule: true,
    ...jest.requireActual('../../src/helpers/exportJson'),
    downloadJson: jest.fn(),
}));

import Review from '../../src/pages/Review';
import { downloadJson } from '../../src/helpers/exportJson';

const mockedDownloadJson = downloadJson as jest.MockedFunction<typeof downloadJson>;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const VARIANTS = [
    { id: 'v1', name: 'Variant Alpha', project_id: 'proj1' },
    { id: 'v2', name: 'Variant Beta', project_id: 'proj1' },
];

const PROJECTS = [{ id: 'proj1', name: 'Project One' }];

const RICH_PKG = 'pkgA@1.0.0::Organization: ACME Corp (info@acme.com)';

/** One custom assessment on a single package/variant. */
const makeAssessment = (id: string, variantId: string) => ({
    id,
    vuln_id: 'CVE-2020-1111',
    packages: ['pkgA@1.0.0'],
    variant_id: variantId,
    status: 'affected',
    status_notes: 'shared note',
    timestamp: '2024-01-01T00:00:00Z',
    origin: 'custom',
    responses: [],
});

/** A fully-populated assessment exercising every column's "value present" branch. */
const RICH_ASSESSMENT = {
    id: 'r1',
    vuln_id: 'CVE-2020-2222',
    packages: [RICH_PKG],
    variant_id: 'v1',
    status: 'not_affected',
    justification: 'code_not_reachable',
    impact_statement: 'no user impact',
    status_notes: 'reviewed carefully',
    workaround: 'apply upstream patch',
    timestamp: '2024-02-02T10:00:00Z',
    origin: 'custom',
    responses: [],
    vuln_texts: [{ title: 'description', content: 'a description' }],
};

/** An assessment with no packages/variant/details — exercises the "—" branches. */
const BARE_ASSESSMENT = {
    id: 'b1',
    vuln_id: 'CVE-2020-9999',
    packages: [],
    variant_id: undefined,
    status: 'affected',
    timestamp: '2024-03-03T00:00:00Z',
    origin: 'custom',
    responses: [],
};

const TIME_ESTIMATES = [
    {
        vuln_id: 'CVE-2020-3333', variant_id: 'v1',
        optimistic: 1, likely: 2, pessimistic: 4,
        optimistic_iso: 'PT1H', likely_iso: 'PT2H', pessimistic_iso: 'PT4H',
        vuln_texts: [{ title: 'description', content: 'te desc' }],
    },
    {
        vuln_id: 'CVE-2020-4444', variant_id: undefined,
        optimistic: 0, likely: 0, pessimistic: 0,
        optimistic_iso: 'PT0H', likely_iso: 'PT0H', pessimistic_iso: 'PT0H',
    },
];

const CUSTOM_CVSS = [
    { vuln_id: 'CVE-A', variant_id: 'v1', version: '3.1', vector_string: 'CVSS:3.1/AV:N', base_score: 9.5, author: 'alice', origin: 'custom', vuln_texts: [{ title: 'description', content: 'c' }] },
    { vuln_id: 'CVE-B', variant_id: undefined, version: '3.1', vector_string: 'CVSS:3.1/AV:L', base_score: 7.5, author: 'bob', origin: 'custom' },
    { vuln_id: 'CVE-C', variant_id: 'v1', version: '3.1', vector_string: 'CVSS:3.1/AV:A', base_score: 5.0, author: 'carol', origin: 'custom' },
    { vuln_id: 'CVE-D', variant_id: 'v1', version: '3.1', vector_string: 'CVSS:3.1/AV:P', base_score: 2.0, author: 'dan', origin: 'custom' },
    { vuln_id: 'CVE-E', variant_id: 'v1', version: '3.1', vector_string: 'CVSS:3.1/AV:N', base_score: 0, author: 'eve', origin: 'custom' },
    // Non-custom score is filtered out of the Custom CVSS tab.
    { vuln_id: 'CVE-F', variant_id: 'v1', version: '3.1', vector_string: 'x', base_score: 3, author: 'nvd', origin: 'nvd' },
];

type NetworkOpts = {
    te?: unknown[];
    cvss?: unknown[];
    variants?: unknown[];
    projects?: unknown[];
    packages?: unknown[];
    mutationOk?: boolean;
    exportOk?: boolean;
    importResult?: Record<string, unknown>;
    vulnDetail?: unknown;
    vulnOk?: boolean;
};

/**
 * Route every fetch the Review page makes. GET endpoints return the provided
 * review list / variants / projects; mutations (PUT / DELETE / POST) return a
 * 200 by default so the page treats them as successful.
 */
function mockNetwork(reviewList: unknown[] = [], opts: NetworkOpts = {}): void {
    const {
        te = [], cvss = [],
        variants = VARIANTS, projects = PROJECTS,
        // Every variant ships the shared package by default so the editor's
        // package/variant compatibility gate does not disable the checkboxes.
        packages = [{ name: 'pkgA', version: '1.0.0' }],
        mutationOk = true, exportOk = true,
        importResult = {
            status: 'success', assessments_imported: 2, assessments_skipped: 1,
            cvss_imported: 1, time_estimates_imported: 1, errors: [],
        },
        vulnDetail = { id: 'CVE-2020-1111', version: '4.0', base_score: 5 },
        vulnOk = true,
    } = opts;

    fetchMock.resetMocks();
    fetchMock.mockResponse(async (req) => {
        const url = req.url;
        const method = req.method;
        if (method === 'GET') {
            if (url.includes('/api/assessments/review/time-estimates')) return JSON.stringify(te);
            if (url.includes('/api/assessments/review/custom-cvss')) return JSON.stringify(cvss);
            if (url.includes('/api/assessments/review/export-custom-data')) {
                return exportOk
                    ? JSON.stringify({ version: 1, assessments: [] })
                    : { status: 500, body: JSON.stringify({}) };
            }
            if (url.includes('/api/assessments/review')) return JSON.stringify(reviewList);
            if (/\/api\/vulnerabilities\/[^/]+\/assessments/.test(url)) return JSON.stringify([]);
            if (/\/api\/vulnerabilities\/[^/]+\/variants/.test(url)) return JSON.stringify(variants);
            if (url.includes('/api/packages')) return JSON.stringify(packages);
            if (url.includes('/api/vulnerabilities/')) {
                return vulnOk
                    ? JSON.stringify(vulnDetail)
                    : { status: 500, body: JSON.stringify({}) };
            }
            if (url.includes('/api/variants')) return JSON.stringify(variants);
            if (url.includes('/api/projects')) return JSON.stringify(projects);
            if (url.includes('/api/version')) return JSON.stringify({ version: 'unknown' });
            return JSON.stringify([]);
        }
        // Mutations (PUT / DELETE / POST)
        if (url.includes('/api/assessments/review/import-custom-data')) return JSON.stringify(importResult);
        if (url.includes('/api/assessments/review/import')) return JSON.stringify({ status: 'success' });
        if (!mutationOk) return { status: 500, body: JSON.stringify({ status: 'error' }) };
        return JSON.stringify({ status: 'success' });
    });
}

const openEditor = async (user: ReturnType<typeof userEvent.setup>) => {
    const editBtn = await screen.findByTitle('Edit assessment');
    await user.click(editBtn);
    await screen.findByText('Apply to variants:');
};

const variantCheckbox = (name: string): HTMLInputElement =>
    screen.getByRole('checkbox', { name }) as HTMLInputElement;

const putCalls = () =>
    fetchMock.mock.calls.filter(c => (c[1] as any)?.method === 'PUT');
const deleteCalls = () =>
    fetchMock.mock.calls.filter(c => (c[1] as any)?.method === 'DELETE');
const postCalls = () =>
    fetchMock.mock.calls.filter(c => (c[1] as any)?.method === 'POST');

const fileInput = (): HTMLInputElement =>
    document.querySelector('input[type="file"]') as HTMLInputElement;

beforeEach(() => {
    mockedDownloadJson.mockClear();
});

describe('Review — editing "Apply to variants"', () => {
    test('checking a new variant creates an assessment for it (POST) and keeps the existing one (PUT)', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await openEditor(user);

        // Alpha is pre-selected (the row's current variant); Beta is not.
        expect(variantCheckbox('Variant Alpha').checked).toBe(true);
        expect(variantCheckbox('Variant Beta').checked).toBe(false);

        await user.click(variantCheckbox('Variant Beta'));
        await user.click(screen.getByText('Save Changes'));

        await waitFor(() => {
            expect(postCalls().length).toBeGreaterThan(0);
        });

        // Existing v1 assessment is updated in place.
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/assessments/a1'),
            expect.objectContaining({ method: 'PUT' })
        );

        // A new assessment is created for the newly-selected variant v2.
        const post = postCalls().find(c => String(c[0]).includes('/api/vulnerabilities/CVE-2020-1111/assessments'));
        expect(post).toBeDefined();
        const body = JSON.parse((post![1] as any).body);
        expect(body.variant_id).toBe('v2');
        expect(body.packages).toEqual(['pkgA@1.0.0']);

        // No assessments were removed.
        expect(deleteCalls()).toHaveLength(0);
    });

    test('unchecking a variant deletes its assessment (DELETE) and keeps the other (PUT)', async () => {
        // Two assessments with identical content are merged into one row.
        mockNetwork([makeAssessment('a1', 'v1'), makeAssessment('a2', 'v2')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await openEditor(user);

        // Both variants start selected.
        expect(variantCheckbox('Variant Alpha').checked).toBe(true);
        expect(variantCheckbox('Variant Beta').checked).toBe(true);

        await user.click(variantCheckbox('Variant Beta'));
        await user.click(screen.getByText('Save Changes'));

        await waitFor(() => {
            expect(deleteCalls().length).toBeGreaterThan(0);
        });

        // v2 assessment is deleted, v1 assessment is updated.
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/assessments/a2'),
            expect.objectContaining({ method: 'DELETE' })
        );
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/assessments/a1'),
            expect.objectContaining({ method: 'PUT' })
        );

        // Nothing new was created.
        expect(postCalls()).toHaveLength(0);
    });

    test('editing without changing the variant selection neither creates nor deletes assessments', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await openEditor(user);
        await user.click(screen.getByText('Save Changes'));

        await waitFor(() => {
            expect(putCalls().length).toBeGreaterThan(0);
        });

        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/assessments/a1'),
            expect.objectContaining({ method: 'PUT' })
        );
        expect(deleteCalls()).toHaveLength(0);
        expect(postCalls()).toHaveLength(0);
    });

    test('a successful edit reports success and notifies the parent', async () => {
        const onChanged = jest.fn();
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" onAssessmentChanged={onChanged} />);
        const user = userEvent.setup();

        await openEditor(user);
        await user.click(screen.getByText('Save Changes'));

        await screen.findByText('Assessment updated successfully!');
        expect(onChanged).toHaveBeenCalledWith(expect.objectContaining({ type: 'update', vulnId: 'CVE-2020-1111' }));
    });

    test('a failed edit reports an error', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { mutationOk: false });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await openEditor(user);
        await user.click(screen.getByText('Save Changes'));

        await screen.findByText('Failed to update assessment.');
    });

    test('pressing Escape closes the editor without saving', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await openEditor(user);
        fireEvent.keyDown(document, { key: 'Escape' });

        await waitFor(() => {
            expect(screen.queryByText('Apply to variants:')).not.toBeInTheDocument();
        });
    });

    test('clicking the modal backdrop closes the editor', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await openEditor(user);
        // The outermost editing overlay closes on click; the heading shows the vuln id.
        const heading = screen.getByRole('heading', { name: 'CVE-2020-1111' });
        const backdrop = heading.closest('.fixed');
        fireEvent.click(backdrop as Element);

        await waitFor(() => {
            expect(screen.queryByText('Apply to variants:')).not.toBeInTheDocument();
        });
    });
});

// ===========================================================================
// Loading & error states
// ===========================================================================

describe('Review — loading and error states', () => {
    test('shows a loading spinner before data resolves', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        expect(screen.getByText('Loading assessments...')).toBeInTheDocument();
        await screen.findByTitle('Edit assessment');
    });

    test('shows an error message when the review list fails to load', async () => {
        fetchMock.resetMocks();
        fetchMock.mockResponse(async (req) => {
            const url = req.url;
            if (url.includes('/api/assessments/review/time-estimates')) return JSON.stringify([]);
            if (url.includes('/api/assessments/review/custom-cvss')) return JSON.stringify([]);
            if (url.includes('/api/assessments/review')) return { status: 500, body: 'boom' };
            if (url.includes('/api/variants')) return JSON.stringify(VARIANTS);
            if (url.includes('/api/projects')) return JSON.stringify(PROJECTS);
            return JSON.stringify([]);
        });
        render(<Review projectId="proj1" />);
        await screen.findByText('Failed to load review data');
    });
});

// ===========================================================================
// Rendering columns & tabs
// ===========================================================================

describe('Review — rendering columns and tabs', () => {
    test('renders populated and empty assessment columns', async () => {
        mockNetwork([RICH_ASSESSMENT, BARE_ASSESSMENT]);
        render(<Review projectId="proj1" />);

        expect(await screen.findByText('pkgA@1.0.0')).toBeInTheDocument();
        expect(screen.getByText('ACME Corp')).toBeInTheDocument();
        expect(screen.getByText('Not affected')).toBeInTheDocument();
        expect(screen.getByText('code not reachable')).toBeInTheDocument();
        expect(screen.getByText('no user impact')).toBeInTheDocument();
        expect(screen.getByText('reviewed carefully')).toBeInTheDocument();
        expect(screen.getByText('apply upstream patch')).toBeInTheDocument();
        expect(screen.getAllByText('Variant Alpha').length).toBeGreaterThan(0);
        // Empty-value placeholders from the bare row
        expect(screen.getAllByText('—').length).toBeGreaterThan(0);
    });

    test('shows the assessments empty state when there are none', async () => {
        mockNetwork([]);
        render(<Review projectId="proj1" />);
        await screen.findByText('No handmade assessments found');
    });

    test('switches to the Time Estimates tab and renders its columns', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { te: TIME_ESTIMATES });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await screen.findByTitle('Edit assessment');
        await user.click(screen.getByText(/Time Estimates \(2\)/));

        expect(await screen.findByText('CVE-2020-3333')).toBeInTheDocument();
        expect(screen.getByText('1h')).toBeInTheDocument();
        expect(screen.getByText('2h')).toBeInTheDocument();
        expect(screen.getByText('4h')).toBeInTheDocument();
    });

    test('shows the time-estimates empty state', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { te: [] });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();
        await screen.findByTitle('Edit assessment');
        await user.click(screen.getByText('Time Estimates'));
        await screen.findByText('No time estimates found');
    });

    test('switches to the Custom CVSS tab and renders its score colors', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { cvss: CUSTOM_CVSS });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await screen.findByTitle('Edit assessment');
        // Only the 5 custom-origin scores are shown (the nvd one is filtered out).
        await user.click(screen.getByText(/Custom CVSS \(5\)/));

        expect(await screen.findByText('9.5')).toBeInTheDocument();
        expect(screen.getByText('7.5')).toBeInTheDocument();
        expect(screen.getByText('5.0')).toBeInTheDocument();
        expect(screen.getByText('2.0')).toBeInTheDocument();
        expect(screen.getByText('0.0')).toBeInTheDocument();
        expect(screen.getByText('alice')).toBeInTheDocument();
    });

    test('shows the custom-cvss empty state', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { cvss: [] });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();
        await screen.findByTitle('Edit assessment');
        await user.click(screen.getByText('Custom CVSS'));
        await screen.findByText('No custom CVSS scores found');
    });
});

// ===========================================================================
// Vulnerability modal
// ===========================================================================

describe('Review — vulnerability modal', () => {
    test('clicking a vulnerability id opens the modal', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        const idCell = (await screen.findAllByTitle('Click to view details'))[0];
        await user.click(idCell);

        await screen.findByTestId('vuln-modal');
    });

    test('the modal can be dismissed', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await user.click((await screen.findAllByTitle('Click to view details'))[0]);
        await user.click(await screen.findByText('close-vuln-modal'));

        await waitFor(() => {
            expect(screen.queryByTestId('vuln-modal')).not.toBeInTheDocument();
        });
    });

    test('the modal read-only callbacks are inert', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await user.click((await screen.findAllByTitle('Click to view details'))[0]);
        // Invoking the no-op append/patch callbacks must not throw or dismiss.
        await user.click(await screen.findByText('invoke-vuln-modal-callbacks'));
        expect(screen.getByTestId('vuln-modal')).toBeInTheDocument();
    });

    test('clicking a time-estimate vulnerability id opens the modal', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { te: TIME_ESTIMATES });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await screen.findByTitle('Edit assessment');
        await user.click(screen.getByText(/Time Estimates \(2\)/));
        const idCell = (await screen.findAllByTitle('Click to view details'))[0];
        await user.click(idCell);

        await screen.findByTestId('vuln-modal');
    });

    test('clicking a custom-cvss vulnerability id opens the modal', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { cvss: CUSTOM_CVSS });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await screen.findByTitle('Edit assessment');
        await user.click(screen.getByText(/Custom CVSS \(5\)/));
        const idCell = (await screen.findAllByTitle('Click to view details'))[0];
        await user.click(idCell);

        await screen.findByTestId('vuln-modal');
    });

    test('a failed vulnerability fetch does not open the modal', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { vulnOk: false });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await user.click((await screen.findAllByTitle('Click to view details'))[0]);
        await waitFor(() => {
            expect(fetchMock).toHaveBeenCalledWith(
                expect.stringContaining('/api/vulnerabilities/CVE-2020-1111'),
                expect.anything(),
            );
        });
        expect(screen.queryByTestId('vuln-modal')).not.toBeInTheDocument();
    });
});

// ===========================================================================
// Filters, search & keyboard
// ===========================================================================

describe('Review — filters, search and keyboard', () => {
    test('filtering by status hides non-matching rows', async () => {
        mockNetwork([RICH_ASSESSMENT, makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await screen.findByText('CVE-2020-2222');
        expect(screen.getByText('CVE-2020-1111')).toBeInTheDocument();

        await user.click(screen.getByRole('button', { name: /Status/ }));
        await user.click(screen.getByRole('checkbox', { name: 'Not affected' }));

        await waitFor(() => {
            expect(screen.queryByText('CVE-2020-1111')).not.toBeInTheDocument();
        });
        expect(screen.getByText('CVE-2020-2222')).toBeInTheDocument();
    });

    test('filtering by justification hides non-matching rows', async () => {
        mockNetwork([RICH_ASSESSMENT, makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await screen.findByText('CVE-2020-2222');
        await user.click(screen.getByRole('button', { name: /Justification/ }));
        await user.click(screen.getByRole('checkbox', { name: 'code not reachable' }));

        await waitFor(() => {
            expect(screen.queryByText('CVE-2020-1111')).not.toBeInTheDocument();
        });
    });

    test('filtering by supplier hides non-matching rows', async () => {
        mockNetwork([RICH_ASSESSMENT, makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await screen.findByText('CVE-2020-2222');
        await user.click(screen.getByRole('button', { name: /Supplier/ }));
        await user.click(screen.getByRole('checkbox', { name: 'ACME Corp' }));

        await waitFor(() => {
            expect(screen.queryByText('CVE-2020-1111')).not.toBeInTheDocument();
        });
    });

    test('reset filters restores every row', async () => {
        mockNetwork([RICH_ASSESSMENT, makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await screen.findByText('CVE-2020-2222');
        await user.click(screen.getByRole('button', { name: /Status/ }));
        await user.click(screen.getByRole('checkbox', { name: 'Not affected' }));
        await waitFor(() => {
            expect(screen.queryByText('CVE-2020-1111')).not.toBeInTheDocument();
        });

        await user.click(screen.getByText('Reset Filters'));
        await screen.findByText('CVE-2020-1111');
    });

    test('typing in the search box updates the table search term', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        await screen.findByTitle('Edit assessment');

        const input = screen.getByPlaceholderText(/Search by vulnerability/);
        fireEvent.input(input, { target: { value: 'pkg' } });
        await waitFor(() => {
            expect(screen.getByTestId('mock-table')).toHaveAttribute('data-search', 'pkg');
        });

        // Shrinking below 2 chars clears the search term first.
        fireEvent.input(input, { target: { value: 'p' } });
        await waitFor(() => {
            expect(screen.getByTestId('mock-table')).toHaveAttribute('data-search', 'p');
        });
    });

    test('the "/" shortcut focuses the search input', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        await screen.findByTitle('Edit assessment');

        const input = screen.getByPlaceholderText(/Search by vulnerability/);
        expect(input).not.toHaveFocus();
        fireEvent.keyDown(document, { key: '/' });
        expect(input).toHaveFocus();
    });

    test('the keyboard shortcut helper opens and closes on outside click', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();
        await screen.findByTitle('Edit assessment');

        await user.click(screen.getByLabelText('shortcut helper'));
        expect(await screen.findByText('Keyboard Shortcuts')).toBeInTheDocument();

        fireEvent.mouseDown(document.body);
        await waitFor(() => {
            expect(screen.queryByText('Keyboard Shortcuts')).not.toBeInTheDocument();
        });
    });

    test('the search syntax helper opens and closes on outside click', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();
        await screen.findByTitle('Edit assessment');

        await user.click(screen.getByLabelText('search syntax helper'));
        expect(await screen.findByText('Search Syntax')).toBeInTheDocument();

        fireEvent.mouseDown(document.body);
        await waitFor(() => {
            expect(screen.queryByText('Search Syntax')).not.toBeInTheDocument();
        });
    });
});

// ===========================================================================
// Delete flow
// ===========================================================================

describe('Review — deleting an assessment', () => {
    test('confirming the delete dialog removes the assessment', async () => {
        const onChanged = jest.fn();
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" onAssessmentChanged={onChanged} />);
        const user = userEvent.setup();

        await user.click(await screen.findByTitle('Delete assessment'));
        await user.click(await screen.findByText('Yes, delete'));

        await screen.findByText('Assessment deleted successfully!');
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/assessments/a1'),
            expect.objectContaining({ method: 'DELETE' })
        );
        expect(onChanged).toHaveBeenCalledWith(expect.objectContaining({ type: 'delete', vulnId: 'CVE-2020-1111' }));
    });

    test('reports an error when the delete request fails', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { mutationOk: false });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await user.click(await screen.findByTitle('Delete assessment'));
        await user.click(await screen.findByText('Yes, delete'));

        await screen.findByText('Failed to delete assessment.');
    });

    test('cancelling the delete dialog keeps the assessment', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await user.click(await screen.findByTitle('Delete assessment'));
        await user.click(await screen.findByText('Cancel'));

        await waitFor(() => {
            expect(deleteCalls()).toHaveLength(0);
        });
    });
});

// ===========================================================================
// Import / export
// ===========================================================================

describe('Review — import and export', () => {
    test('exporting custom data downloads a file', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();
        await screen.findByTitle('Edit assessment');

        await user.click(screen.getByText('Export Custom Data'));
        await waitFor(() => {
            expect(mockedDownloadJson).toHaveBeenCalled();
        });
    });

    test('exporting when scoped to a variant builds a variant-labelled filename', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review variantId="v1" />);
        const user = userEvent.setup();
        await screen.findByTitle('Edit assessment');

        await user.click(screen.getByText('Export Custom Data'));
        await waitFor(() => {
            expect(mockedDownloadJson).toHaveBeenCalled();
        });
        const filename = mockedDownloadJson.mock.calls[0][1] as string;
        expect(filename).toContain('Project_One');
        expect(filename).toContain('Variant_Alpha');
    });

    test('reports an error when export fails', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { exportOk: false });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();
        await screen.findByTitle('Edit assessment');

        await user.click(screen.getByText('Export Custom Data'));
        await screen.findByText('Failed to export custom data.');
        expect(mockedDownloadJson).not.toHaveBeenCalled();
    });

    test('the message banner can be dismissed', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { exportOk: false });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();
        await screen.findByTitle('Edit assessment');

        await user.click(screen.getByText('Export Custom Data'));
        await screen.findByText('Failed to export custom data.');

        await user.click(screen.getByRole('button', { name: 'Dismiss' }));
        await waitFor(() => {
            expect(screen.queryByText('Failed to export custom data.')).not.toBeInTheDocument();
        });
    });

    test('importing a custom-data JSON file reports a summary', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        await screen.findByTitle('Edit assessment');

        const file = new File(
            [JSON.stringify({ version: '1', assessments: [{ id: 'x' }] })],
            'custom.json',
            { type: 'application/json' },
        );
        fireEvent.change(fileInput(), { target: { files: [file] } });

        await screen.findByText(/Imported:/);
    });

    test('importing a legacy OpenVEX JSON file succeeds', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        await screen.findByTitle('Edit assessment');

        const file = new File(
            [JSON.stringify({ '@context': 'https://openvex.dev/ns/v0.2.0', statements: [] })],
            'openvex.json',
            { type: 'application/json' },
        );
        fireEvent.change(fileInput(), { target: { files: [file] } });

        await screen.findByText('Assessments imported successfully!');
    });

    test('importing a legacy tar.gz file uses the legacy endpoint', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        await screen.findByTitle('Edit assessment');

        const file = new File(['binary'], 'export.tar.gz', { type: 'application/gzip' });
        fireEvent.change(fileInput(), { target: { files: [file] } });

        await screen.findByText('Assessments imported successfully!');
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/assessments/review/import'),
            expect.objectContaining({ method: 'POST' })
        );
    });

    test('rejects a JSON file with an unrecognised format', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        await screen.findByTitle('Edit assessment');

        const file = new File([JSON.stringify({ foo: 'bar' })], 'unknown.json', { type: 'application/json' });
        fireEvent.change(fileInput(), { target: { files: [file] } });

        await screen.findByText('Invalid file format. Expected a VulnScout custom data export.');
    });

    test('reports a parse error for an invalid JSON file', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        await screen.findByTitle('Edit assessment');

        const file = new File(['not valid json {'], 'broken.json', { type: 'application/json' });
        fireEvent.change(fileInput(), { target: { files: [file] } });

        await screen.findByText('Import failed — invalid file');
    });
});

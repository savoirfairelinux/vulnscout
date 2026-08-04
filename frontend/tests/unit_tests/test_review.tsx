import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import { render, screen, waitFor, fireEvent, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

jest.mock('../../src/components/TableGeneric', () => {
    const ReactMock = require('react');
    return {
        __esModule: true,
        default: ({ data, columns, search, onFilteredDataChange, selected, updateSelected }: any) => {
            const val = (row: any, col: any) => (col.accessorKey ? row[col.accessorKey] : undefined);
            // Simulate TableGeneric emitting its filtered+sorted rows in display
            // order. The real component applies the text search internally; here
            // we approximate it with a substring match on vuln_id/id so tests can
            // assert that modal navigation follows the *displayed* rows, not the
            // pre-search `filteredAssessments` list.
            const displayedForNav = (typeof search === 'string' && search.length >= 1)
                ? data.filter((row: any) =>
                    String(row.vuln_id ?? row.id ?? '').toLowerCase().includes(search.toLowerCase()))
                : data;
            ReactMock.useEffect(() => {
                onFilteredDataChange?.(displayedForNav);
            }, [onFilteredDataChange, displayedForNav]);
            const selection = selected ?? {};
            const updateSelection = (next: Record<string, boolean>) => updateSelected?.(next);
            const isSelected = (row: any) => Boolean(selection[row.id]);
            const rowFor = (row: any) => ({
                original: row,
                getIsSelected: () => isSelected(row),
                getCanSelect: () => true,
                getToggleSelectedHandler: () => () => {
                    const next = { ...selection };
                    if (isSelected(row)) delete next[row.id];
                    else next[row.id] = true;
                    updateSelection(next);
                },
            });
            const selectedOnPage = displayedForNav.filter(isSelected);
            const allPageSelected = displayedForNav.length > 0 && selectedOnPage.length === displayedForNav.length;
            const table = {
                getIsAllPageRowsSelected: () => allPageSelected,
                getIsSomePageRowsSelected: () => selectedOnPage.length > 0 && !allPageSelected,
                getToggleAllPageRowsSelectedHandler: () => () => {
                    const next = { ...selection };
                    for (const row of displayedForNav) {
                        if (allPageSelected) delete next[row.id];
                        else next[row.id] = true;
                    }
                    updateSelection(next);
                },
            };
            return (
                <table data-testid="mock-table" data-search={search ?? ''}>
                    <thead>
                        <tr>
                            {columns.map((col: any, ci: number) => (
                                <th key={ci}>{typeof col.header === 'function' ? col.header({ column: col, table }) : col.header}</th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {data.map((row: any, i: number) => (
                            <tr key={i} data-testid="mock-table-row">
                                {columns.map((col: any, ci: number) => (
                                    <td key={ci}>
                                        {col.cell ? col.cell({ row: rowFor(row), getValue: () => val(row, col) }) : null}
                                    </td>
                                ))}
                            </tr>
                        ))}
                    </tbody>
                </table>
            );
        },
    };
});

// The vulnerability modal is not exercised here; keep it inert but observable,
// and expose its callbacks so we can test the dismiss and no-op handler paths.
// Also surface the Previous/Next navigation props (vulnerabilities/currentIndex/
// onNavigate) so tests can assert on Review's nav wiring without re-testing
// VulnModal's own navigation UI (covered in test_vuln_modal.tsx).
jest.mock('../../src/components/VulnModal', () => ({
    __esModule: true,
    default: ({ vuln, onClose, appendAssessment, appendCVSS, patchVuln, vulnerabilities, currentIndex, onNavigate }: any) => (
        <div data-testid="vuln-modal">
            <div data-testid="vuln-modal-vuln-id">{vuln?.id}</div>
            <button onClick={() => { appendAssessment(); appendCVSS(); patchVuln(); }}>
                invoke-vuln-modal-callbacks
            </button>
            <button onClick={onClose}>close-vuln-modal</button>
            {vulnerabilities !== undefined && currentIndex !== undefined && (
                <div data-testid="vuln-modal-nav-info">
                    {`nav ${currentIndex} of ${vulnerabilities.length}`}
                </div>
            )}
            {onNavigate && (
                <>
                    <button onClick={() => onNavigate((currentIndex ?? 0) - 1)}>nav-prev</button>
                    <button onClick={() => onNavigate((currentIndex ?? 0) + 1)}>nav-next</button>
                </>
            )}
        </div>
    ),
}));

// Keep the real filename/timestamp helpers but stub the download so jsdom does
// not need URL.createObjectURL.
jest.mock('../../src/helpers/exportJson', () => ({
    __esModule: true,
    ...jest.requireActual('../../src/helpers/exportJson'),
    downloadJson: jest.fn(),
    downloadBlob: jest.fn(),
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
        id: 'te-1',
        vuln_id: 'CVE-2020-3333', variant_id: 'v1',
        optimistic: 1, likely: 2, pessimistic: 4,
        optimistic_iso: 'PT1H', likely_iso: 'PT2H', pessimistic_iso: 'PT4H',
        vuln_texts: [{ title: 'description', content: 'te desc' }],
    },
    {
        id: 'te-2',
        vuln_id: 'CVE-2020-4444', variant_id: undefined,
        optimistic: 0, likely: 0, pessimistic: 0,
        optimistic_iso: 'PT0H', likely_iso: 'PT0H', pessimistic_iso: 'PT0H',
    },
];

const CUSTOM_CVSS = [
    { id: 'cvss-a', vuln_id: 'CVE-A', variant_id: 'v1', version: '3.1', vector_string: 'CVSS:3.1/AV:N', base_score: 9.5, author: 'alice', origin: 'custom', vuln_texts: [{ title: 'description', content: 'c' }] },
    { id: 'cvss-b', vuln_id: 'CVE-B', variant_id: undefined, version: '3.1', vector_string: 'CVSS:3.1/AV:L', base_score: 7.5, author: 'bob', origin: 'custom' },
    { id: 'cvss-c', vuln_id: 'CVE-C', variant_id: 'v1', version: '3.1', vector_string: 'CVSS:3.1/AV:A', base_score: 5.0, author: 'carol', origin: 'custom' },
    { id: 'cvss-d', vuln_id: 'CVE-D', variant_id: 'v1', version: '3.1', vector_string: 'CVSS:3.1/AV:P', base_score: 2.0, author: 'dan', origin: 'custom' },
    { id: 'cvss-e', vuln_id: 'CVE-E', variant_id: 'v1', version: '3.1', vector_string: 'CVSS:3.1/AV:N', base_score: 0, author: 'eve', origin: 'custom' },
    // Non-custom score is filtered out of the Custom CVSS tab.
    { id: 'cvss-f', vuln_id: 'CVE-F', variant_id: 'v1', version: '3.1', vector_string: 'x', base_score: 3, author: 'nvd', origin: 'nvd' },
];

type NetworkOpts = {
    te?: unknown[];
    cvss?: unknown[];
    aiReviewList?: unknown[];
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
        te = [], cvss = [], aiReviewList = [],
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
            if (url.includes('/api/assessments/review/export')) {
                return exportOk
                    ? JSON.stringify({ '@context': 'https://openvex.dev/ns/v0.2.0', statements: [] })
                    : { status: 500, body: JSON.stringify({}) };
            }
            if (url.includes('/api/assessments/review/ai')) return JSON.stringify(aiReviewList);
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

    test('shows outdated on the affected variant instead of the status', async () => {
        mockNetwork([
            {
                ...makeAssessment('a1', 'v1'),
                outdated: true,
                superseded_map: {'pkgA@1.0.0': ['pkgA@2.0.0']},
            },
            makeAssessment('a2', 'v2'),
        ]);
        render(<Review projectId="proj1" />);

        const outdatedBadges = await screen.findAllByText('Outdated');
        const outdated = outdatedBadges.find(element =>
            element.classList.contains('tracking-wide')
        );
        expect(outdated?.parentElement).toHaveTextContent(/Variant Alpha.*Outdated/);
        expect(screen.getByText('Variant Beta').closest('span')).not.toHaveTextContent('Outdated');
        expect(screen.getByText('Exploitable').closest('td')).not.toHaveTextContent('Outdated');
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
        await user.click(screen.getByText('Time Estimates'));

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
        await user.click(screen.getByText('Custom CVSS'));

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
// AI Assessments tab
// ===========================================================================

describe('Review — AI Assessments tab', () => {
    test('switches to the AI Assessments tab and renders pending rows with actions', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { aiReviewList: [makeAssessment('ai1', 'v1')] });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await screen.findByTitle('Edit assessment');
        await user.click(screen.getByText('AI Assessments'));

        expect(await screen.findByTitle('Approve AI suggestion')).toBeInTheDocument();
        expect(screen.getByTitle('Reject AI suggestion')).toBeInTheDocument();
    });

    test('shows the AI assessments empty state when there are none pending', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { aiReviewList: [] });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await screen.findByTitle('Edit assessment');
        await user.click(screen.getByText('AI Assessments'));

        await screen.findByText('No AI-generated assessments found');
    });

    test('approving a pending AI row calls approveAi with all grouped ids and refreshes the lists', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { aiReviewList: [makeAssessment('ai1', 'v1')] });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await screen.findByTitle('Edit assessment');
        await user.click(screen.getByText('AI Assessments'));
        await user.click(await screen.findByTitle('Approve AI suggestion'));

        await screen.findByText('AI assessment approved!');
        expect(postCalls().some(c => String(c[0]).includes('/api/assessments/ai1/approve'))).toBe(true);
    });

    test('rejecting a pending AI row calls rejectAi with all grouped ids and refreshes the lists', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { aiReviewList: [makeAssessment('ai1', 'v1')] });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await screen.findByTitle('Edit assessment');
        await user.click(screen.getByText('AI Assessments'));
        await user.click(await screen.findByTitle('Reject AI suggestion'));

        await screen.findByText('AI assessment rejected.');
        expect(postCalls().some(c => String(c[0]).includes('/api/assessments/ai1/reject'))).toBe(true);
    });

    test('reports an error when approving a pending AI row fails', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { aiReviewList: [makeAssessment('ai1', 'v1')], mutationOk: false });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await screen.findByTitle('Edit assessment');
        await user.click(screen.getByText('AI Assessments'));
        await user.click(await screen.findByTitle('Approve AI suggestion'));

        await screen.findByText(/Failed to approve AI assessment/);
    });

    test('reports an error when rejecting a pending AI row fails', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { aiReviewList: [makeAssessment('ai1', 'v1')], mutationOk: false });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await screen.findByTitle('Edit assessment');
        await user.click(screen.getByText('AI Assessments'));
        await user.click(await screen.findByTitle('Reject AI suggestion'));

        await screen.findByText(/Failed to reject AI assessment/);
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
        await user.click(screen.getByText('Time Estimates'));
        const idCell = (await screen.findAllByTitle('Click to view details'))[0];
        await user.click(idCell);

        await screen.findByTestId('vuln-modal');
    });

    test('clicking a custom-cvss vulnerability id opens the modal', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { cvss: CUSTOM_CVSS });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await screen.findByTitle('Edit assessment');
        await user.click(screen.getByText('Custom CVSS'));
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
// Assessments tab Previous/Next navigation (commit 144be635)
// ===========================================================================

// Two rows sharing the same vuln_id but differing in status/justification so
// groupAssessments keeps them as two distinct rows — exercising the vuln_id
// dedup in the display-order navigation list. A third row uses a different
// vuln_id entirely.
const NAV_DUP_A = {
    id: 'nav-a', vuln_id: 'CVE-NAV-1', packages: ['pkgA@1.0.0'], variant_id: 'v1',
    status: 'affected', status_notes: 'note-a', timestamp: '2024-01-01T00:00:00Z',
    origin: 'custom', responses: [],
};
const NAV_DUP_B = {
    id: 'nav-b', vuln_id: 'CVE-NAV-1', packages: ['pkgA@1.0.0'], variant_id: 'v2',
    status: 'not_affected', justification: 'code_not_reachable', status_notes: 'note-b',
    timestamp: '2024-01-02T00:00:00Z', origin: 'custom', responses: [],
};
const NAV_OTHER = {
    id: 'nav-c', vuln_id: 'CVE-NAV-2', packages: ['pkgA@1.0.0'], variant_id: 'v1',
    status: 'affected', status_notes: 'note-c', timestamp: '2024-01-03T00:00:00Z',
    origin: 'custom', responses: [],
};

/**
 * Same routing as mockNetwork, but resolves `/api/vulnerabilities/<id>` (and
 * its `/assessments` sibling) per requested id, so navigating between
 * distinct vulnerabilities can be observed via `vuln-modal-vuln-id`.
 */
function mockNetworkWithVulnById(
    reviewList: unknown[],
    opts: { te?: unknown[]; cvss?: unknown[] } = {},
): void {
    const { te = [], cvss = [] } = opts;
    fetchMock.resetMocks();
    fetchMock.mockResponse(async (req) => {
        const url = req.url;
        if (url.includes('/api/assessments/review/time-estimates')) return JSON.stringify(te);
        if (url.includes('/api/assessments/review/custom-cvss')) return JSON.stringify(cvss);
        if (url.includes('/api/assessments/review')) return JSON.stringify(reviewList);
        const assessMatch = url.match(/\/api\/vulnerabilities\/([^/]+)\/assessments/);
        if (assessMatch) return JSON.stringify([]);
        const variantsMatch = url.match(/\/api\/vulnerabilities\/([^/]+)\/variants/);
        if (variantsMatch) return JSON.stringify(VARIANTS);
        const vulnMatch = url.match(/\/api\/vulnerabilities\/([^/]+)$/);
        if (vulnMatch) {
            const id = decodeURIComponent(vulnMatch[1]);
            return JSON.stringify({ id, version: '4.0', base_score: 5 });
        }
        if (url.includes('/api/packages')) return JSON.stringify([{ name: 'pkgA', version: '1.0.0' }]);
        if (url.includes('/api/variants')) return JSON.stringify(VARIANTS);
        if (url.includes('/api/projects')) return JSON.stringify(PROJECTS);
        if (url.includes('/api/version')) return JSON.stringify({ version: 'unknown' });
        return JSON.stringify([]);
    });
}

const openAssessmentsModal = async (
    user: ReturnType<typeof userEvent.setup>,
    rowIndex: number,
) => {
    const idCell = (await screen.findAllByTitle('Click to view details'))[rowIndex];
    await user.click(idCell);
    await screen.findByTestId('vuln-modal');
};

/**
 * Like mockNetworkWithVulnById, but the single-vulnerability GET for any id in
 * `deferGates` blocks until its gate promise resolves. Lets tests hold a modal
 * navigation fetch pending while they close/reopen the modal, exercising the
 * request-generation guard against stale responses.
 */
function mockNetworkWithDeferredVuln(
    reviewList: unknown[],
    deferGates: Record<string, Promise<void>>,
): void {
    fetchMock.resetMocks();
    fetchMock.mockResponse(async (req) => {
        const url = req.url;
        if (url.includes('/api/assessments/review/time-estimates')) return JSON.stringify([]);
        if (url.includes('/api/assessments/review/custom-cvss')) return JSON.stringify([]);
        if (url.includes('/api/assessments/review')) return JSON.stringify(reviewList);
        const assessMatch = url.match(/\/api\/vulnerabilities\/([^/]+)\/assessments/);
        if (assessMatch) return JSON.stringify([]);
        const variantsMatch = url.match(/\/api\/vulnerabilities\/([^/]+)\/variants/);
        if (variantsMatch) return JSON.stringify(VARIANTS);
        const vulnMatch = url.match(/\/api\/vulnerabilities\/([^/]+)$/);
        if (vulnMatch) {
            const id = decodeURIComponent(vulnMatch[1]);
            if (id in deferGates) await deferGates[id];
            return JSON.stringify({ id, version: '4.0', base_score: 5 });
        }
        if (url.includes('/api/packages')) return JSON.stringify([{ name: 'pkgA', version: '1.0.0' }]);
        if (url.includes('/api/variants')) return JSON.stringify(VARIANTS);
        if (url.includes('/api/projects')) return JSON.stringify(PROJECTS);
        if (url.includes('/api/version')) return JSON.stringify({ version: 'unknown' });
        return JSON.stringify([]);
    });
}

const searchAssessments = (value: string) => {
    const input = screen.getByPlaceholderText(/Search by vulnerability/);
    fireEvent.change(input, { target: { value } });
    fireEvent.keyDown(input, { key: 'Enter' });
};

describe('Review — Assessments tab navigation', () => {
    test('dedupes repeated vuln_ids and computes index among distinct ids', async () => {
        mockNetworkWithVulnById([NAV_DUP_A, NAV_DUP_B, NAV_OTHER]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        // Row 1 is the second occurrence of CVE-NAV-1; its distinct index is
        // still 0 (not 1), and there are only 2 distinct vuln ids total.
        await openAssessmentsModal(user, 1);
        expect(await screen.findByTestId('vuln-modal-nav-info')).toHaveTextContent('nav 0 of 2');
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-NAV-1');

        await user.click(screen.getByText('close-vuln-modal'));
        await waitFor(() => expect(screen.queryByTestId('vuln-modal')).not.toBeInTheDocument());

        // Row 2 is the distinct second vuln id, so its index is 1.
        await openAssessmentsModal(user, 2);
        expect(await screen.findByTestId('vuln-modal-nav-info')).toHaveTextContent('nav 1 of 2');
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-NAV-2');
    });

    test('all three tabs (Assessments, Time Estimates, Custom CVSS) pass navigation props', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { te: TIME_ESTIMATES, cvss: CUSTOM_CVSS });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await openAssessmentsModal(user, 0);
        expect(await screen.findByTestId('vuln-modal-nav-info')).toBeInTheDocument();
        await user.click(screen.getByText('close-vuln-modal'));
        await waitFor(() => expect(screen.queryByTestId('vuln-modal')).not.toBeInTheDocument());

        await user.click(screen.getByText('Time Estimates'));
        const teIdCell = (await screen.findAllByTitle('Click to view details'))[0];
        await user.click(teIdCell);
        await screen.findByTestId('vuln-modal');
        expect(screen.getByTestId('vuln-modal-nav-info')).toBeInTheDocument();
        await user.click(screen.getByText('close-vuln-modal'));
        await waitFor(() => expect(screen.queryByTestId('vuln-modal')).not.toBeInTheDocument());

        await user.click(screen.getByText('Custom CVSS'));
        const cvssIdCell = (await screen.findAllByTitle('Click to view details'))[0];
        await user.click(cvssIdCell);
        await screen.findByTestId('vuln-modal');
        expect(screen.getByTestId('vuln-modal-nav-info')).toBeInTheDocument();
    });

    test('clicking Next fetches and displays the next distinct vulnerability', async () => {
        mockNetworkWithVulnById([NAV_DUP_A, NAV_DUP_B, NAV_OTHER]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await openAssessmentsModal(user, 0);
        expect(await screen.findByTestId('vuln-modal-nav-info')).toHaveTextContent('nav 0 of 2');
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-NAV-1');

        await user.click(screen.getByText('nav-next'));

        await waitFor(() => {
            expect(fetchMock).toHaveBeenCalledWith(
                expect.stringContaining('/api/vulnerabilities/CVE-NAV-2'),
                expect.anything(),
            );
        });
        expect(await screen.findByTestId('vuln-modal-nav-info')).toHaveTextContent('nav 1 of 2');
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-NAV-2');
    });

    test('navigating past the last vulnerability is a no-op', async () => {
        mockNetworkWithVulnById([NAV_DUP_A, NAV_OTHER]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await openAssessmentsModal(user, 1);
        expect(await screen.findByTestId('vuln-modal-nav-info')).toHaveTextContent('nav 1 of 2');
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-NAV-2');

        fetchMock.mockClear();
        await user.click(screen.getByText('nav-next'));

        // Out of bounds (index 2 >= length 2): no fetch, modal stays put.
        await waitFor(() => {
            expect(fetchMock.mock.calls.filter(c => String(c[0]).includes('/api/vulnerabilities/CVE-NAV'))).toHaveLength(0);
        });
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-NAV-2');
        expect(screen.getByTestId('vuln-modal-nav-info')).toHaveTextContent('nav 1 of 2');
    });

    test('navigating before the first vulnerability is a no-op', async () => {
        mockNetworkWithVulnById([NAV_DUP_A, NAV_OTHER]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await openAssessmentsModal(user, 0);
        expect(await screen.findByTestId('vuln-modal-nav-info')).toHaveTextContent('nav 0 of 2');
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-NAV-1');

        fetchMock.mockClear();
        await user.click(screen.getByText('nav-prev'));

        // Out of bounds (index -1 < 0): no fetch, modal stays on the first vuln.
        await waitFor(() => {
            expect(fetchMock.mock.calls.filter(c => String(c[0]).includes('/api/vulnerabilities/CVE-NAV'))).toHaveLength(0);
        });
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-NAV-1');
        expect(screen.getByTestId('vuln-modal-nav-info')).toHaveTextContent('nav 0 of 2');
    });

    test('filtering the Assessments tab narrows the navigation id list', async () => {
        mockNetworkWithVulnById([NAV_DUP_A, NAV_DUP_B, NAV_OTHER]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        // Filter down to "Not affected" rows only: this keeps NAV_DUP_B (CVE-NAV-1)
        // and drops NAV_DUP_A and NAV_OTHER, leaving a single distinct vuln id.
        await screen.findAllByTitle('Click to view details');
        await user.click(screen.getByRole('button', { name: /Status/ }));
        await user.click(screen.getByRole('checkbox', { name: 'Not affected' }));

        await openAssessmentsModal(user, 0);
        expect(await screen.findByTestId('vuln-modal-nav-info')).toHaveTextContent('nav 0 of 1');
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-NAV-1');
    });

    // Bug B: the navigation list must follow the table's displayed rows (which
    // include the text-search state), not the pre-search `filteredAssessments`.
    const SEARCH_A1 = { ...NAV_DUP_A, id: 'srch-a1', vuln_id: 'CVE-AAA-1' };
    const SEARCH_B2 = { ...NAV_OTHER, id: 'srch-b2', vuln_id: 'CVE-BBB-2' };
    const SEARCH_A3 = { ...NAV_OTHER, id: 'srch-a3', vuln_id: 'CVE-AAA-3' };

    test('search narrows the navigation list to the displayed rows', async () => {
        mockNetworkWithVulnById([SEARCH_A1, SEARCH_B2, SEARCH_A3]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await screen.findAllByTitle('Click to view details');
        // Search "AAA" hides CVE-BBB-2, leaving two distinct displayed ids.
        searchAssessments('AAA');
        await waitFor(() => {
            expect(screen.getByTestId('mock-table')).toHaveAttribute('data-search', 'AAA');
        });

        // Open the first displayed AAA row: nav context spans only the 2 visible
        // ids, not all 3 assessments.
        await openAssessmentsModal(user, 0);
        expect(await screen.findByTestId('vuln-modal-nav-info')).toHaveTextContent('nav 0 of 2');
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-AAA-1');
    });

    test('Next skips search-hidden vulnerabilities and follows display order', async () => {
        mockNetworkWithVulnById([SEARCH_A1, SEARCH_B2, SEARCH_A3]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await screen.findAllByTitle('Click to view details');
        searchAssessments('AAA');
        await waitFor(() => {
            expect(screen.getByTestId('mock-table')).toHaveAttribute('data-search', 'AAA');
        });

        await openAssessmentsModal(user, 0);
        expect(await screen.findByTestId('vuln-modal-nav-info')).toHaveTextContent('nav 0 of 2');

        // Next must jump to CVE-AAA-3 (the next *visible* row), skipping the
        // search-hidden CVE-BBB-2 that sits between them in the raw list.
        await user.click(screen.getByText('nav-next'));
        await waitFor(() => {
            expect(fetchMock).toHaveBeenCalledWith(
                expect.stringContaining('/api/vulnerabilities/CVE-AAA-3'),
                expect.anything(),
            );
        });
        expect(fetchMock).not.toHaveBeenCalledWith(
            expect.stringContaining('/api/vulnerabilities/CVE-BBB-2'),
            expect.anything(),
        );
        expect(await screen.findByTestId('vuln-modal-nav-info')).toHaveTextContent('nav 1 of 2');
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-AAA-3');
    });

    // Bug C: asynchronous navigation must not apply stale results. Closing the
    // modal (or starting a newer request) invalidates any in-flight fetch.
    test('closing the modal while a navigation fetch is pending does not reopen it', async () => {
        let release: () => void = () => {};
        const gate = new Promise<void>((res) => { release = res; });
        mockNetworkWithDeferredVuln([NAV_DUP_A, NAV_OTHER], { 'CVE-NAV-2': gate });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await openAssessmentsModal(user, 0);
        expect(await screen.findByTestId('vuln-modal-nav-info')).toHaveTextContent('nav 0 of 2');

        // Start navigating to CVE-NAV-2; its fetch is held pending.
        await user.click(screen.getByText('nav-next'));
        // Close before the fetch resolves.
        await user.click(screen.getByText('close-vuln-modal'));
        await waitFor(() => expect(screen.queryByTestId('vuln-modal')).not.toBeInTheDocument());

        // Releasing the stale fetch must not reopen the modal.
        release();
        await new Promise((r) => setTimeout(r, 0));
        await waitFor(() => expect(screen.queryByTestId('vuln-modal')).not.toBeInTheDocument());
    });

    test('a stale navigation response does not override a newer selection', async () => {
        let release: () => void = () => {};
        const gate = new Promise<void>((res) => { release = res; });
        mockNetworkWithDeferredVuln([NAV_DUP_A, NAV_OTHER], { 'CVE-NAV-2': gate });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await openAssessmentsModal(user, 0);
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-NAV-1');

        // Navigate to CVE-NAV-2 (held pending), then close and reopen CVE-NAV-1.
        await user.click(screen.getByText('nav-next'));
        await user.click(screen.getByText('close-vuln-modal'));
        await waitFor(() => expect(screen.queryByTestId('vuln-modal')).not.toBeInTheDocument());
        await openAssessmentsModal(user, 0);
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-NAV-1');

        // The late CVE-NAV-2 response must be discarded, leaving CVE-NAV-1 shown.
        release();
        await new Promise((r) => setTimeout(r, 0));
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-NAV-1');
    });

    test('a stale modal-open fetch is discarded when a newer vuln is opened', async () => {
        let release: () => void = () => {};
        const gate = new Promise<void>((res) => { release = res; });
        mockNetworkWithDeferredVuln([NAV_DUP_A, NAV_OTHER], { 'CVE-NAV-1': gate });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        // Click CVE-NAV-1 (row 0); its open fetch is held pending, so no modal yet.
        const cells = await screen.findAllByTitle('Click to view details');
        await user.click(cells[0]);
        expect(screen.queryByTestId('vuln-modal')).not.toBeInTheDocument();

        // Open CVE-NAV-2 (row 1, not gated); its newer generation supersedes the
        // still-pending CVE-NAV-1 open.
        await user.click(cells[1]);
        await screen.findByTestId('vuln-modal');
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-NAV-2');

        // Releasing the stale CVE-NAV-1 open must not replace the shown vuln.
        release();
        await new Promise((r) => setTimeout(r, 0));
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-NAV-2');
    });
});

describe('Review — Time Estimates & Custom CVSS tab navigation', () => {
    const TE_NAV = [
        { vuln_id: 'CVE-TE-1', variant_id: 'v1', optimistic: 1, likely: 2, pessimistic: 4 },
        { vuln_id: 'CVE-TE-1', variant_id: 'v2', optimistic: 1, likely: 2, pessimistic: 4 },
        { vuln_id: 'CVE-TE-2', variant_id: 'v1', optimistic: 1, likely: 2, pessimistic: 4 },
    ];
    const CVSS_NAV = [
        { vuln_id: 'CVE-CV-1', variant_id: 'v1', version: '3.1', vector_string: 'x', base_score: 5, author: 'alice', origin: 'custom' },
        { vuln_id: 'CVE-CV-1', variant_id: 'v2', version: '3.1', vector_string: 'x', base_score: 5, author: 'bob', origin: 'custom' },
        { vuln_id: 'CVE-CV-2', variant_id: 'v1', version: '3.1', vector_string: 'x', base_score: 5, author: 'carol', origin: 'custom' },
    ];

    test('Time Estimates tab: Next navigates across the distinct displayed vulns', async () => {
        mockNetworkWithVulnById([], { te: TE_NAV });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await user.click(await screen.findByText('Time Estimates'));
        const cells = await screen.findAllByTitle('Click to view details');
        await user.click(cells[0]);
        await screen.findByTestId('vuln-modal');
        expect(await screen.findByTestId('vuln-modal-nav-info')).toHaveTextContent('nav 0 of 2');
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-TE-1');

        await user.click(screen.getByText('nav-next'));
        expect(await screen.findByTestId('vuln-modal-nav-info')).toHaveTextContent('nav 1 of 2');
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-TE-2');
    });

    test('Time Estimates tab: duplicate vuln rows collapse to one nav entry', async () => {
        mockNetworkWithVulnById([], { te: TE_NAV });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await user.click(await screen.findByText('Time Estimates'));
        const cells = await screen.findAllByTitle('Click to view details');
        // Row 1 is the second occurrence of CVE-TE-1; its distinct index is still
        // 0 and only 2 distinct vuln ids exist.
        await user.click(cells[1]);
        await screen.findByTestId('vuln-modal');
        expect(await screen.findByTestId('vuln-modal-nav-info')).toHaveTextContent('nav 0 of 2');
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-TE-1');
    });

    test('Custom CVSS tab: Next navigates across the distinct displayed vulns', async () => {
        mockNetworkWithVulnById([], { cvss: CVSS_NAV });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await user.click(await screen.findByText('Custom CVSS'));
        const cells = await screen.findAllByTitle('Click to view details');
        await user.click(cells[0]);
        await screen.findByTestId('vuln-modal');
        expect(await screen.findByTestId('vuln-modal-nav-info')).toHaveTextContent('nav 0 of 2');
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-CV-1');

        await user.click(screen.getByText('nav-next'));
        expect(await screen.findByTestId('vuln-modal-nav-info')).toHaveTextContent('nav 1 of 2');
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-CV-2');
    });

    test('switching tabs and back rebuilds the navigation list for the active tab', async () => {
        mockNetworkWithVulnById([NAV_DUP_A, NAV_OTHER], { te: TE_NAV });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        // Start on the Assessments tab: nav spans the assessment vuln ids.
        await openAssessmentsModal(user, 0);
        expect(await screen.findByTestId('vuln-modal-nav-info')).toHaveTextContent('nav 0 of 2');
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-NAV-1');
        await user.click(screen.getByText('close-vuln-modal'));
        await waitFor(() => expect(screen.queryByTestId('vuln-modal')).not.toBeInTheDocument());

        // Move to Time Estimates: the shared ref now tracks the TE vuln ids.
        await user.click(await screen.findByText('Time Estimates'));
        let cells = await screen.findAllByTitle('Click to view details');
        await user.click(cells[0]);
        await screen.findByTestId('vuln-modal');
        expect(await screen.findByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-TE-1');
        await user.click(screen.getByText('close-vuln-modal'));
        await waitFor(() => expect(screen.queryByTestId('vuln-modal')).not.toBeInTheDocument());

        // Back to Assessments: nav must again span the assessment vuln ids.
        await user.click(screen.getByRole('button', { name: /^Assessments/ }));
        cells = await screen.findAllByTitle('Click to view details');
        await user.click(cells[0]);
        await screen.findByTestId('vuln-modal');
        expect(await screen.findByTestId('vuln-modal-nav-info')).toHaveTextContent('nav 0 of 2');
        expect(screen.getByTestId('vuln-modal-vuln-id')).toHaveTextContent('CVE-NAV-1');
    });
});

// ===========================================================================
// Filters, search & keyboard
// ===========================================================================

describe('Review — filters, search and keyboard', () => {
    test('does not provide a variants filter', async () => {
        mockNetwork([makeAssessment('a1', 'v1'), makeAssessment('a2', 'v2')]);
        render(<Review projectId="proj1" />);

        await screen.findByText('CVE-2020-1111');
        expect(screen.queryByRole('button', { name: /^variants$/i })).toBeNull();
    });

    test('the outdated toggle includes rows with mixed current and outdated assessments', async () => {
        const mixedOutdated = {
            ...makeAssessment('outdated', 'v1'),
            vuln_id: 'CVE-2020-MIXED',
            outdated: true,
            superseded_map: { 'pkgA@1.0.0': ['pkgA@2.0.0'] },
        };
        const mixedCurrent = {
            ...makeAssessment('current', 'v2'),
            vuln_id: 'CVE-2020-MIXED',
            packages: ['pkgB@1.0.0'],
        };
        mockNetwork([mixedOutdated, mixedCurrent, makeAssessment('current', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await screen.findByText('CVE-2020-MIXED');
        await user.click(screen.getByRole('button', { name: 'Show Outdated' }));

        await waitFor(() => {
            expect(screen.queryByText('CVE-2020-1111')).not.toBeInTheDocument();
        });
        expect(screen.getByText('CVE-2020-MIXED')).toBeInTheDocument();
    });

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

    test('search applies only with the button or Enter', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        await screen.findByTitle('Edit assessment');
        const user = userEvent.setup();

        const input = screen.getByPlaceholderText(/Search by vulnerability/);
        await user.type(input, 'pkg');
        expect(screen.getByTestId('mock-table')).toHaveAttribute('data-search', '');

        await user.click(screen.getByRole('button', {name: 'Search reviews'}));
        await waitFor(() => {
            expect(screen.getByTestId('mock-table')).toHaveAttribute('data-search', 'pkg');
        });

        await user.clear(input);
        await user.type(input, 'p');
        expect(screen.getByTestId('mock-table')).toHaveAttribute('data-search', 'pkg');

        await user.keyboard('{Enter}');
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
    const selectFirstTableRow = async (user: ReturnType<typeof userEvent.setup>) => {
        await user.click((await screen.findAllByTitle('Select'))[0]);
        await user.click(screen.getByText(/Delete selected \(1\)/));
        await user.click(screen.getByText('Yes, delete'));
    };

    test('bulk deletion removes selected handmade assessments', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await selectFirstTableRow(user);

        await waitFor(() => {
            expect(fetchMock).toHaveBeenCalledWith(
                expect.stringContaining('/api/assessments/a1'),
                expect.objectContaining({ method: 'DELETE' }),
            );
        });
    });

    test('bulk deletion rejects selected AI assessments', async () => {
        mockNetwork([], { aiReviewList: [makeAssessment('ai-1', 'v1')] });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await user.click(await screen.findByText('AI Assessments'));
        await selectFirstTableRow(user);

        await waitFor(() => {
            expect(fetchMock).toHaveBeenCalledWith(
                expect.stringContaining('/api/assessments/ai-1/reject'),
                expect.objectContaining({ method: 'POST' }),
            );
        });
    });

    test('bulk deletion removes selected time estimates', async () => {
        mockNetwork([], { te: TIME_ESTIMATES });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await user.click(await screen.findByText('Time Estimates'));
        await selectFirstTableRow(user);

        await waitFor(() => {
            expect(fetchMock).toHaveBeenCalledWith(
                expect.stringContaining('/api/assessments/review/time-estimates'),
                expect.objectContaining({ method: 'DELETE', body: JSON.stringify({ ids: ['te-1'] }) }),
            );
        });
    });

    test('bulk deletion removes selected custom CVSS scores', async () => {
        mockNetwork([], { cvss: CUSTOM_CVSS });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();

        await user.click(await screen.findByText('Custom CVSS'));
        await selectFirstTableRow(user);

        await waitFor(() => {
            expect(fetchMock).toHaveBeenCalledWith(
                expect.stringContaining('/api/assessments/review/custom-cvss'),
                expect.objectContaining({ method: 'DELETE', body: JSON.stringify({ ids: ['cvss-a'] }) }),
            );
        });
    });

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
    test('exports selected variants as VulnScout JSON', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();
        await screen.findByTitle('Edit assessment');

        await user.click(screen.getByText('Export'));
        const dialog = screen.getByRole('dialog');
        await user.click(within(dialog).getByRole('checkbox', { name: 'Variant Beta' }));
        await user.click(within(dialog).getByRole('button', { name: 'Export' }));
        await waitFor(() => {
            expect(mockedDownloadJson).toHaveBeenCalled();
        });
        const exportCall = fetchMock.mock.calls.find(call => String(call[0]).includes('/api/assessments/review/export-custom-data'));
        expect(String(exportCall?.[0])).toContain('variant_id=v1');
        expect(String(exportCall?.[0])).not.toContain('variant_id=v2');
        expect(mockedDownloadJson.mock.calls[0][1]).toContain('custom_data_Variant_Alpha_');
    });

    test('VulnScout JSON export defaults to the current variant', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review variantId="v1" />);
        const user = userEvent.setup();
        await screen.findByTitle('Edit assessment');

        await user.click(screen.getByText('Export'));
        await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Export' }));
        await waitFor(() => {
            expect(mockedDownloadJson).toHaveBeenCalled();
        });
        const exportCall = fetchMock.mock.calls.find(call => String(call[0]).includes('/api/assessments/review/export-custom-data'));
        expect(String(exportCall?.[0])).toContain('variant_id=v1');
    });

    test('exports one selected variant as an OpenVEX JSON document', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();
        await screen.findByTitle('Edit assessment');

        await user.click(screen.getByText('Export'));
        const dialog = screen.getByRole('dialog');
        await user.click(within(dialog).getByRole('radio', { name: /OpenVEX/ }));
        await user.click(within(dialog).getByRole('radio', { name: 'Variant Beta' }));
        await user.click(within(dialog).getByRole('button', { name: 'Export' }));

        await waitFor(() => expect(mockedDownloadJson).toHaveBeenCalled());
        const exportCall = fetchMock.mock.calls.find(call => String(call[0]).includes('/api/assessments/review/export?'));
        expect(String(exportCall?.[0])).toContain('variant_id=v2');
        expect(String(exportCall?.[0])).not.toContain('variant_id=v1');
        expect(mockedDownloadJson.mock.calls[0][1]).toContain('review_openvex_Variant_Beta_');
        expect(mockedDownloadJson.mock.calls[0][1]).toContain('.json');
    });

    test('reports an error when export fails', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { exportOk: false });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();
        await screen.findByTitle('Edit assessment');

        await user.click(screen.getByText('Export'));
        await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Export' }));
        await screen.findByText('Failed to export review data.');
        expect(mockedDownloadJson).not.toHaveBeenCalled();
    });

    test('the message banner can be dismissed', async () => {
        mockNetwork([makeAssessment('a1', 'v1')], { exportOk: false });
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();
        await screen.findByTitle('Edit assessment');

        await user.click(screen.getByText('Export'));
        await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Export' }));
        await screen.findByText('Failed to export review data.');

        await user.click(screen.getByRole('button', { name: 'Dismiss' }));
        await waitFor(() => {
            expect(screen.queryByText('Failed to export review data.')).not.toBeInTheDocument();
        });
    });

    test('importing VulnScout JSON has no variant selector and reports a summary', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();
        await screen.findByTitle('Edit assessment');

        await user.click(screen.getByText('Import'));
        const dialog = screen.getByRole('dialog');
        expect(within(dialog).queryByText('Variant')).not.toBeInTheDocument();
        expect(within(dialog).getByRole('radio', { name: /Use original timestamps from file/ })).toBeChecked();
        await user.click(within(dialog).getByRole('radio', { name: /Use current system time/ }));
        await user.click(within(dialog).getByRole('button', { name: 'Choose file' }));

        const file = new File(
            [JSON.stringify({ version: '1', assessments: [{ id: 'x' }] })],
            'custom.json',
            { type: 'application/json' },
        );
        fireEvent.change(fileInput(), { target: { files: [file] } });

        await screen.findByText(/Imported:/);
        const importCall = postCalls().find(call => String(call[0]).includes('/api/assessments/review/import-custom-data'));
        expect(JSON.parse(String((importCall?.[1] as RequestInit).body)).timestamp_policy).toBe('current');
    });

    test('imports OpenVEX into one selected variant without using the filename', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        const user = userEvent.setup();
        await screen.findByTitle('Edit assessment');

        await user.click(screen.getByText('Import'));
        const dialog = screen.getByRole('dialog');
        await user.click(within(dialog).getByRole('radio', { name: /OpenVEX/ }));
        await user.click(within(dialog).getByRole('radio', { name: 'Variant Beta' }));
        await user.click(within(dialog).getByRole('button', { name: 'Choose file' }));

        const file = new File(
            [JSON.stringify({ '@context': 'https://openvex.dev/ns/v0.2.0', statements: [] })],
            'does-not-match-a-variant.json',
            { type: 'application/json' },
        );
        fireEvent.change(fileInput(), { target: { files: [file] } });

        await screen.findByText('Assessments imported successfully!');
        const importCalls = postCalls().filter(call => String(call[0]).endsWith('/api/assessments/review/import'));
        expect(importCalls).toHaveLength(1);
        const targetedVariantIds = importCalls.map(call => ((call[1] as RequestInit).body as FormData).get('variant_id'));
        expect(targetedVariantIds).toEqual(['v2']);
        expect(((importCalls[0][1] as RequestInit).body as FormData).get('timestamp_policy')).toBe('original');
    });

    test('file selection accepts JSON only', async () => {
        mockNetwork([makeAssessment('a1', 'v1')]);
        render(<Review projectId="proj1" />);
        await screen.findByTitle('Edit assessment');

        expect(fileInput()).toHaveAttribute('accept', '.json,application/json');
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

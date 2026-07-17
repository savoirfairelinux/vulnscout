import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';

import type { Package } from '../../src/handlers/packages';
import type { Vulnerability } from '../../src/handlers/vulnerabilities';
import Vulnerabilities from '../../src/handlers/vulnerabilities';
import Iso8601Duration from '../../src/handlers/iso8601duration';
import TablePackages from '../../src/pages/TablePackages';

const packages: Package[] = [
    {
        id: 'alpha@1.0', name: 'alpha', version: '1.0', cpe: [], purl: [],
        vulnerabilities: { 'Pending Assessment': 1 }, maxSeverity: {}, source: [],
        variants: [], sbom_documents: [], supplier: '',
    },
    {
        id: 'beta@2.0', name: 'beta', version: '2.0', cpe: [], purl: [],
        vulnerabilities: { Fixed: 1 }, maxSeverity: {}, source: [],
        variants: [], sbom_documents: [], supplier: '',
    },
];

const duration = new Iso8601Duration('PT1H');
const vulnerabilities = [
    {
        id: 'CVE-HIGH', packages_current: ['alpha@1.0'], packages: ['alpha@1.0'],
        severity: {
            max_score: 9.8, min_score: 9.8, severity: 'critical',
            cvss: [],
        },
        epss: { score: 0.4, percentile: 0.7 }, effort: { likely: duration, optimistic: duration, pessimistic: duration },
        assessments: [],
    },
    {
        id: 'CVE-LOW', packages_current: ['beta@2.0'], packages: ['beta@2.0'],
        severity: { max_score: 3.1, min_score: 3.1, severity: 'low', cvss: [] },
        epss: { score: 0.1, percentile: 0.3 }, effort: { likely: duration, optimistic: duration, pessimistic: duration },
        assessments: [],
    },
] as unknown as Vulnerability[];

describe('SBOM match condition', () => {
    beforeAll(() => {
        Element.prototype.getBoundingClientRect = jest.fn(() => ({
            width: 800, height: 600, top: 0, left: 0, bottom: 600, right: 800,
            x: 0, y: 0, toJSON: () => ({}),
        }));
    });

    test('filters packages and carries matching vulnerability IDs into drill-down', async () => {
        const requests: RequestInit[] = [];
        global.fetch = jest.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
            requests.push(init ?? {});
            return {
                ok: true,
                json: async () => ({ matching_ids: requests.length === 1 ? ['CVE-HIGH'] : [] }),
            } as Response;
        });
        const onShowVulns = jest.fn();

        render(<TablePackages packages={packages} vulnerabilities={vulnerabilities} onShowVulns={onShowVulns} />);

        fireEvent.change(screen.getByLabelText('Match condition'), { target: { value: 'cvss >= 7 and pending' } });
        fireEvent.keyDown(screen.getByLabelText('Match condition'), { key: 'Enter' });

        await waitFor(() => expect(global.fetch).toHaveBeenCalledTimes(1));
        await waitFor(() => expect(screen.queryByText('beta')).not.toBeInTheDocument());
        expect(screen.getByText('alpha')).toBeInTheDocument();

        const body = JSON.parse(String(requests[0].body));
        expect(body.condition).toBe('cvss >= 7 and pending');
        expect(body.items[0].data).toMatchObject({ cvss: 9.8, cvss_min: 9.8, pending: true, new: true });

        fireEvent.click(screen.getByRole('button', { name: 'Show Vulnerabilities' }));
        expect(onShowVulns).toHaveBeenCalledWith('alpha@1.0', ['CVE-HIGH']);

        fireEvent.change(screen.getByLabelText('Match condition'), { target: { value: 'cvss > 11' } });
        fireEvent.keyDown(screen.getByLabelText('Match condition'), { key: 'Enter' });
        await waitFor(() => expect(screen.getByText('0-0 / 0')).toBeInTheDocument());
    });

    test('keeps search and match-condition help beside their respective inputs', () => {
        render(<TablePackages packages={packages} vulnerabilities={vulnerabilities} />);

        const searchInput = screen.getByPlaceholderText('Search by package name, version, ...');
        const searchHelp = screen.getByRole('button', { name: 'search syntax helper' });
        const matchConditionInput = screen.getByLabelText('Match condition');
        const matchConditionHelp = screen.getByRole('button', { name: 'match condition help' });

        expect(searchInput.nextElementSibling).toContainElement(searchHelp);
        expect(matchConditionInput.nextElementSibling).toContainElement(matchConditionHelp);
        expect(searchHelp.querySelector('[data-icon="circle-question"]')).toBeInTheDocument();
        expect(matchConditionHelp.querySelector('[data-icon="circle-info"]')).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Apply' })).not.toBeInTheDocument();

        fireEvent.click(searchHelp);
        expect(screen.getByRole('heading', { name: 'Search Syntax' })).toBeInTheDocument();

        fireEvent.click(matchConditionHelp);
        expect(screen.getByRole('heading', { name: 'Match condition' })).toBeInTheDocument();
        expect(screen.getByText('Filter packages by vulnerability facts. Press Enter to apply the condition.')).toBeInTheDocument();
        expect(screen.getByText('field operator value')).toBeInTheDocument();
        expect(screen.getByText('cvss >= 7 and pending')).toBeInTheDocument();
        expect(screen.getByText('epss >= 10% or fixed')).toBeInTheDocument();
    });

    test('shows match-condition failures in a dismissible error banner', async () => {
        global.fetch = jest.fn(async () => ({
            ok: false,
            json: async () => ({ error: 'Invalid match condition' }),
        }) as Response);

        render(<TablePackages packages={packages} vulnerabilities={vulnerabilities} />);

        fireEvent.change(screen.getByLabelText('Match condition'), { target: { value: 'cvss >=' } });
        fireEvent.keyDown(screen.getByLabelText('Match condition'), { key: 'Enter' });

        const banner = await screen.findByRole('alert');
        expect(banner).toHaveTextContent('Invalid match condition');

        fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    test('serializes every CI match-condition fact', async () => {
        const capturedBodies: unknown[] = [];
        global.fetch = jest.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
            capturedBodies.push(JSON.parse(String(init?.body)));
            return {
                ok: true,
                json: async () => ({ matching_ids: [] }),
            } as Response;
        });
        const assessment = (status: string, timestamp: string) => ({ status, timestamp });
        const makeVulnerability = (
            id: string,
            assessments: { status: string; timestamp: string }[],
        ) => ({
            id,
            severity: {
                max_score: 9.8,
                min_score: 7.5,
                cvss: [],
            },
            epss: { score: 0.42 },
            effort: {
                optimistic: new Iso8601Duration('PT30M'),
                likely: new Iso8601Duration('PT1H'),
                pessimistic: new Iso8601Duration('PT2H'),
            },
            assessments,
        }) as unknown as Vulnerability;
        const facts = [
            makeVulnerability('CVE-FIXED', [assessment('affected', '2026-01-01'), assessment('fixed', '2026-02-01')]),
            makeVulnerability('CVE-IGNORED', [assessment('not_affected', '2026-01-01')]),
            makeVulnerability('CVE-AFFECTED', [assessment('exploitable', '2026-01-01')]),
            makeVulnerability('CVE-PENDING', [assessment('in_triage', '2026-01-01')]),
            makeVulnerability('CVE-NEW', []),
        ];

        await Vulnerabilities.matchCondition('true', facts);

        const items = (capturedBodies[0] as { items: { id: string; data: Record<string, unknown> }[] }).items;
        expect(items[0].data).toEqual({
            id: 'CVE-FIXED', cvss: 9.8, cvss_min: 7.5, epss: 0.42,
            effort: 3600, effort_min: 1800, effort_max: 7200,
            fixed: true, ignored: false, affected: false, pending: false, new: false,
        });
        expect(items[1].data).toMatchObject({ fixed: false, ignored: true, affected: false, pending: false, new: false });
        expect(items[2].data).toMatchObject({ fixed: false, ignored: false, affected: true, pending: false, new: false });
        expect(items[3].data).toMatchObject({ fixed: false, ignored: false, affected: false, pending: true, new: false });
        expect(items[4].data).toMatchObject({ fixed: false, ignored: false, affected: false, pending: true, new: true });
    });

    test.each([
        ['fixed', 'fixed'],
        ['resolved', 'fixed'],
        ['resolved_with_pedigree', 'fixed'],
        ['not_affected', 'ignored'],
        ['false_positive', 'ignored'],
        ['affected', 'affected'],
        ['exploitable', 'affected'],
        ['under_investigation', 'pending'],
        ['in_triage', 'pending'],
    ])('maps %s assessments to the %s condition', async (status, expectedFlag) => {
        let requestBody: { items: { data: Record<string, unknown> }[] } | undefined;
        global.fetch = jest.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
            requestBody = JSON.parse(String(init?.body));
            return { ok: true, json: async () => ({ matching_ids: [] }) } as Response;
        });
        const vulnerability = {
            id: `CVE-${status}`,
            severity: { max_score: 5, min_score: 5, cvss: [] },
            epss: {},
            effort: {
                optimistic: new Iso8601Duration(undefined),
                likely: new Iso8601Duration(undefined),
                pessimistic: new Iso8601Duration(undefined),
            },
            assessments: [{ status, timestamp: '2026-01-01' }],
        } as unknown as Vulnerability;

        await Vulnerabilities.matchCondition(expectedFlag, [vulnerability]);

        expect(requestBody?.items[0].data[expectedFlag]).toBe(true);
    });
});

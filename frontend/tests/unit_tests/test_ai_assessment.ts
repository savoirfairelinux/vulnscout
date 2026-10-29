import fetchMock from 'jest-fetch-mock';
import { buildAiAssessmentMessages, loadAiAssessmentTargets } from '../../src/helpers/aiAssessment';
import type { Vulnerability } from '../../src/handlers/vulnerabilities';
import { AGENT_MESSAGE_MAX_LENGTH, type AgentContext } from '../../src/types/agent';

fetchMock.enableMocks();

const vulnerability = {
    id: 'CVE-2026-1234',
    packages: ['pkg@1::supplier', 'pkg@2', 'other@3', 'historical@1'],
    packages_current: ['pkg@1::supplier', 'pkg@2', 'other@3'],
} as Vulnerability;
const compatibility = [
    { variant_id: 'v1', findings: [
        { package: 'pkg@1::supplier', outdated: false },
        { package: 'pkg@1::supplier', outdated: false },
        { package: 'historical@1', outdated: true },
    ] },
    { variant_id: 'v2', findings: [{ package: 'pkg@2', outdated: false }] },
    { variant_id: 'v3', findings: [{ package: 'other@3', outdated: false }] },
];
const targets = (scope: Partial<AgentContext> = {}, vuln = vulnerability) =>
    loadAiAssessmentTargets(vuln, { page: 'vulnerabilities', ...scope }, new AbortController().signal);
const basePayload = {
    id: vulnerability.id, packages_current_by_variant: { v1: ['pkg@1::supplier'] },
};

beforeEach(() => fetchMock.resetMocks());

describe('AI assessment targets', () => {
    test('resolves exact pairs across project variants, excluding outdated findings and duplicates', async () => {
        fetchMock.mockResponseOnce(JSON.stringify(compatibility));
        expect(await targets({ projectId: 'project/one' })).toEqual([
            { variant_id: 'v1', package: 'pkg@1::supplier' },
            { variant_id: 'v2', package: 'pkg@2' },
            { variant_id: 'v3', package: 'other@3' },
        ]);
        const request = new URL(String(fetchMock.mock.calls[0][0]));
        expect(request.pathname).toContain(`/api/vulnerabilities/${vulnerability.id}/variant-active-packages`);
        expect(request.searchParams.get('project_id')).toBe('project/one');
    });

    test.each([
        [{ variantId: 'v1' }, ['v1']],
        [{ variantId: 'v2', baseVariantId: 'v1', compareOperation: 'difference' }, ['v2']],
        [{ variantId: 'v2', baseVariantId: 'v1', compareOperation: 'intersection' }, ['v1', 'v2']],
        [{ variantIds: ['v1', 'v3'], multiOperation: 'union' }, ['v1', 'v3']],
        [{ variantIds: ['v1', 'v3'], multiOperation: 'intersection' }, ['v1', 'v3']],
    ])('honors table scope %j', async (scope, expected) => {
        fetchMock.mockResponseOnce(JSON.stringify(compatibility));
        if ('compareOperation' in scope && scope.compareOperation === 'intersection') {
            fetchMock.mockResponseOnce(JSON.stringify(basePayload));
        }
        expect((await targets(scope)).map(target => target.variant_id)).toEqual(expected);
    });

    test('intersects findings with the table’s exact per-variant package scope', async () => {
        fetchMock.mockResponseOnce(JSON.stringify(compatibility));
        expect(await targets({}, {
            ...vulnerability, packages_current_by_variant: { v2: ['pkg@2'] },
        })).toEqual([{ variant_id: 'v2', package: 'pkg@2' }]);
    });

    test('resolves base packages independently of the compare-only table payload in intersection mode', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([
            { variant_id: 'v1', findings: [
                { package: 'pkg@1::supplier', outdated: false },
                // Still installed, but this CVE was only observed in an older scan.
                { package: 'historical@1', outdated: false },
            ] },
            ...compatibility.slice(1),
        ])).mockResponseOnce(JSON.stringify(basePayload));
        expect(await targets({
            variantId: 'v2', baseVariantId: 'v1', compareOperation: 'intersection',
        }, {
            ...vulnerability, packages: ['pkg@2'], packages_current: ['pkg@2'],
            packages_current_by_variant: { v2: ['pkg@2'] },
        })).toEqual([
            { variant_id: 'v1', package: 'pkg@1::supplier' },
            { variant_id: 'v2', package: 'pkg@2' },
        ]);
        const baseRequest = new URL(String(fetchMock.mock.calls[1][0]));
        expect(baseRequest.pathname).toBe(`/api/vulnerabilities/${vulnerability.id}`);
        expect(baseRequest.searchParams.get('variant_id')).toBe('v1');
        expect(baseRequest.searchParams.get('agent_scoped')).toBe('1');
        expect(fetchMock.mock.calls[1][1]?.signal).toBeInstanceOf(AbortSignal);
    });

    test.each([
        ['HTTP failure', 'failure', 503],
        ['inactive base finding', '{}', 404],
        ['invalid JSON', 'not JSON', 200],
        ['missing scoped packages', JSON.stringify({ id: vulnerability.id, packages_current: ['historical@1'] }), 200],
        ['invalid packages', JSON.stringify({ ...basePayload, packages_current_by_variant: { v1: [42] } }), 200],
        ['empty packages', JSON.stringify({ ...basePayload, packages_current_by_variant: { v1: [] } }), 200],
        ['wrong vulnerability', JSON.stringify({ ...basePayload, id: 'CVE-other' }), 200],
    ])('fails closed for %s in the active base payload', async (_name, body, status) => {
        fetchMock.mockResponseOnce(JSON.stringify(compatibility)).mockResponseOnce(body, { status });
        await expect(targets({
            variantId: 'v2', baseVariantId: 'v1', compareOperation: 'intersection',
        })).rejects.toThrow(`Unable to load active base-variant targets for ${vulnerability.id}`);
    });

    test('does not invent targets for active packages without a finding in that variant', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([
            { variant_id: 'v1', active_packages: ['pkg@2'], findings: [{ package: 'pkg@1::supplier', outdated: false }] },
        ]));
        expect(await targets()).toEqual([{ variant_id: 'v1', package: 'pkg@1::supplier' }]);
    });

    test.each([
        ['HTTP failure', 'failure', 503],
        ['invalid JSON', 'not JSON', 200],
        ['malformed response', '{}', 200],
        ['missing findings', '[{"variant_id":"v1","active_packages":["pkg@2"]}]', 200],
        ['invalid finding', '[{"variant_id":"v1","findings":[{"package":"pkg@2"}]}]', 200],
        ['no matching scope', '[]', 200],
    ])('fails closed for %s', async (_name, body, status) => {
        fetchMock.mockResponseOnce(body, { status });
        await expect(targets()).rejects.toThrow();
    });

    test('identifies the vulnerability when a target request loses its connection', async () => {
        fetchMock.mockRejectOnce(new TypeError('Failed to fetch'));
        await expect(targets()).rejects.toThrow(`Unable to load targets for ${vulnerability.id}. Check the connection and try again.`);
    });
});

describe('AI assessment prompts', () => {
    test('uses the modal workflow with exact identifiers and MCP instructions', () => {
        const messages = buildAiAssessmentMessages(vulnerability.id, [
            { variant_id: 'v1', package: 'pkg@1::supplier' },
            { variant_id: 'v2', package: 'pkg@2' },
        ], [{ id: 'v1', name: 'default', project_id: 'p1' }]);
        expect(messages).toHaveLength(1);
        expect(messages[0].text).toContain('Assess CVE-2026-1234 for exactly these targets');
        expect(messages[0].text).toContain('variant "default" (variant_id v1): pkg@1::supplier');
        expect(messages[0].text).toContain('variant variant_id v2: pkg@2');
        expect(messages[0].text).toContain("each variant's merged context with VulnScout MCP first");
        expect(messages[0].text).toContain('write_assessment for these targets only');
    });

    test('batches whole variants within the backend limit without dropping any target', () => {
        const selected = Array.from({ length: 160 }, (_, index) => ({
            variant_id: `v${Math.floor(index / 40)}`,
            package: `package-with-long-name-${index}-${'x'.repeat(45)}@1.0`,
        }));
        const messages = buildAiAssessmentMessages(vulnerability.id, selected);
        expect(messages.length).toBeGreaterThan(1);
        for (const message of messages) expect(message.text.length).toBeLessThanOrEqual(AGENT_MESSAGE_MAX_LENGTH);
        for (const target of selected) {
            expect(messages.filter(message => message.text.includes(target.package))).toHaveLength(1);
        }
        for (const variant of new Set(selected.map(target => target.variant_id))) {
            expect(messages.filter(message => message.text.includes(`variant_id ${variant}:`))).toHaveLength(1);
        }
    });

    test('rejects a single oversized variant and an empty target selection', () => {
        expect(() => buildAiAssessmentMessages(vulnerability.id, [
            { variant_id: 'v1', package: 'x'.repeat(AGENT_MESSAGE_MAX_LENGTH) },
        ])).toThrow('Too many packages selected');
        expect(() => buildAiAssessmentMessages(vulnerability.id, [])).toThrow('No active assessment targets');
    });
});

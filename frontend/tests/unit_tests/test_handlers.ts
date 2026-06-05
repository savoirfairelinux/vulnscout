import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import Packages from '../../src/handlers/packages';
import Vulnerabilities from '../../src/handlers/vulnerabilities';
import Assessments from '../../src/handlers/assessments';


const PACKAGES = [
    {
        name: 'aaabbbccc',
        version: '1.0.0',
        cpe: ['cpe:2.3:a:vendor:aaabbbccc:1.0.0:*:*:*:*:*:*:*:*'],
        purl: ['pkg:vendor/aaabbbccc@1.0.0']
    },
    {
        name: 'xxxyyyzzz',
        version: '2.0.0',
        cpe: ['cpe:2.3:a:vendor:xxxyyyzzz:2.0.0:*:*:*:*:*:*:*:*'],
        purl: ['pkg:vendor/xxxyyyzzz@2.0.0']
    }
];


const VULNERABILITIES = [
    {
        id: 'CVE-2010-1234',
        aliases: ['CVE-2008-3456'],
        related_vulnerabilities: [],
        namespace: 'nvd:cve',
        found_by: ['hardcoded'],
        datasource: 'https://nvd.nist.gov/vuln/detail/CVE-2010-1234',
        packages: ['aaabbbccc@1.0.0'],
        urls: ['https://security-tracker.debian.org/tracker/CVE-2010-1234'],
        texts: {},
        severity: {
            severity: 'high',
            min_score: 8,
            max_score: 8,
            cvss: []
        },
        epss: {
            score: 0.356789,
            percentile: 0.7546
        },
        effort: {
            optimistic: 'PT4H',
            likely: 'P1DT2H',
            pessimistic: 'P1W2D'
        },
        fix: {
            state: 'unknown'
        }
    },
    {
        id: 'CVE-2018-5678',
        aliases: ['CVE-2017-7890'],
        related_vulnerabilities: [],
        namespace: 'nvd:cve',
        found_by: ['cve-finder'],
        datasource: 'https://nvd.nist.gov/vuln/detail/CVE-2018-5678',
        packages: ['aaabbbccc@1.0.0', 'xxxyyyzzz@2.0.0'],
        urls: ['https://security-tracker.debian.org/tracker/CVE-2018-5678'],
        texts: { description: "Some description about a vulnerability" },
        severity: {
            severity: 'low',
            min_score: 3,
            max_score: 3,
            cvss: []
        },
        epss: {
            score: undefined,
            percentile: undefined
        },
        fix: {
            state: 'unknown'
        }
    }
];


const ASSESSMENTS = [
    {
        id: '123',
        vuln_id: 'CVE-2010-1234',
        packages: ['aaabbbccc@1.0.0'],
        status: 'fixed',
        timestamp: "2024-06-12T19:28:23.132683",
        responses: []
    },
    {
        id: '456',
        vuln_id: 'CVE-2018-5678',
        packages: ['aaabbbccc@1.0.0'],
        status: 'under_investigation',
        timestamp: "2024-06-10T19:28:23.132683",
        responses: []
    },
    {
        id: '789',
        vuln_id: 'CVE-2018-5678',
        packages: ['aaabbbccc@1.0.0', 'xxxyyyzzz@2.0.0'],
        status: 'affected',
        timestamp: "2024-06-12T13:45:18.846213",
        responses: []
    }
];


describe('Packages', () => {

    beforeEach(() => {
        fetchMock.resetMocks();
    });

    test('with empty list of packages', async () => {
        const thisFetch = fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                json: () => Promise.resolve([])
            } as Response)
        );

        const packages = await Packages.list();
        expect(packages).toEqual([]);
        expect(thisFetch).toHaveBeenCalledTimes(1);
    });

    test('enrich data with vulnerabilities', async () => {
        let thisFetch = fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                json: () => Promise.resolve(PACKAGES)
            } as Response)
        );

        const packages = await Packages.list();
        expect(packages.length).toEqual(2);
        expect(thisFetch).toHaveBeenCalledTimes(1);

        fetchMock.resetMocks();
        thisFetch = fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                json: () => Promise.resolve(VULNERABILITIES)
            } as Response)
        );

        const vulnerabilities = await Vulnerabilities.list();
        expect(vulnerabilities.length).toEqual(2);
        expect(thisFetch).toHaveBeenCalledTimes(1);

        vulnerabilities[0].simplified_status = 'Fixed';
        vulnerabilities[1].simplified_status = 'Exploitable';

        const enrichedPackages = Packages.enrich_with_vulns(packages, vulnerabilities);
        expect(enrichedPackages.length).toEqual(2);

        expect(enrichedPackages[0].vulnerabilities["Fixed"]).toEqual(1);
        expect(enrichedPackages[0].vulnerabilities["Exploitable"]).toEqual(1);
        expect(enrichedPackages[0].maxSeverity["Fixed"].label).toEqual('high');
        expect(enrichedPackages[0].maxSeverity["Exploitable"].label).toEqual('low');
        expect(enrichedPackages[0].source).toEqual(['hardcoded', 'cve-finder']);

        expect(enrichedPackages[1].vulnerabilities["Exploitable"]).toEqual(1);
        expect(enrichedPackages[1].maxSeverity["Exploitable"].label).toEqual('low');
        expect(enrichedPackages[1].source).toEqual(['cve-finder']);
    });

    test('asPackage parses supplier field', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                json: () => Promise.resolve([{
                    name: 'foo',
                    version: '1.0',
                    supplier: 'Organization: Acme Corp (x@a.com)',
                    cpe: [],
                    purl: [],
                }])
            } as Response)
        );
        const packages = await Packages.list();
        expect(packages[0].supplier).toBe('Organization: Acme Corp (x@a.com)');
    });

    test('asPackage defaults supplier to empty string when absent', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                json: () => Promise.resolve([{
                    name: 'foo',
                    version: '1.0',
                    cpe: [],
                    purl: [],
                }])
            } as Response)
        );
        const packages = await Packages.list();
        expect(packages[0].supplier).toBe('');
    });
});


describe('Vulnerabilities', () => {

    beforeEach(() => {
        fetchMock.resetMocks();
    });

    test('with empty list of vulnerabilities', async () => {
        const thisFetch = fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                json: () => Promise.resolve([])
            } as Response)
        );

        const vulns = await Vulnerabilities.list();
        expect(vulns).toEqual([]);
        expect(thisFetch).toHaveBeenCalledTimes(1);
    });

    test('enrich data with assessments', async () => {
        let thisFetch = fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                json: () => Promise.resolve(VULNERABILITIES)
            } as Response)
        );

        const vulnerabilities = await Vulnerabilities.list();
        expect(vulnerabilities.length).toEqual(2);
        expect(thisFetch).toHaveBeenCalledTimes(1);

        fetchMock.resetMocks();
        thisFetch = fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                json: () => Promise.resolve(ASSESSMENTS)
            } as Response)
        );

        const assessments = await Assessments.list();
        expect(assessments.length).toEqual(3);
        expect(thisFetch).toHaveBeenCalledTimes(1);

        const enrichedvuln = Vulnerabilities.enrich_with_assessments(vulnerabilities, assessments);
        expect(enrichedvuln.length).toEqual(2);

        expect(enrichedvuln[0].status).toEqual('fixed');
        expect(enrichedvuln[0].simplified_status).toEqual('Fixed');
        expect(enrichedvuln[0].assessments.length).toEqual(1);

        expect(enrichedvuln[1].status).toEqual('affected');
        expect(enrichedvuln[1].simplified_status).toEqual('Exploitable');
        expect(enrichedvuln[1].assessments.length).toEqual(2);
    });
});


describe('Assessments', () => {

    beforeEach(() => {
        fetchMock.resetMocks();
    });

    test('with empty list of assessments', async () => {
        const thisFetch = fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                json: () => Promise.resolve([])
            } as Response)
        );

        const assessments = await Assessments.list();
        expect(assessments).toEqual([]);
        expect(thisFetch).toHaveBeenCalledTimes(1);
    });
});

describe('Packages additional coverage', () => {
    beforeEach(() => {
        fetchMock.resetMocks();
    });

    test('asPackage parses variants, sources, and sbom_documents arrays', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                json: () => Promise.resolve([{
                    name: 'mypkg',
                    version: '3.0',
                    cpe: ['cpe:2.3:a:x:mypkg:3.0:*'],
                    purl: ['pkg:generic/mypkg@3.0'],
                    variants: ['variant-a', 42, 'variant-b'],
                    sources: ['scanner1', null, 'scanner2'],
                    sbom_documents: ['doc1.spdx', 'doc2.spdx'],
                }])
            } as Response)
        );
        const packages = await Packages.list();
        expect(packages[0].variants).toEqual(['variant-a', 'variant-b']);
        expect(packages[0].source).toEqual(['scanner1', 'scanner2']);
        expect(packages[0].sbom_documents).toEqual(['doc1.spdx', 'doc2.spdx']);
    });

    test('asPackage uses custom id when provided and non-empty', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                json: () => Promise.resolve([{
                    id: 'custom-id-123',
                    name: 'mypkg',
                    version: '1.0',
                    cpe: [],
                    purl: [],
                }])
            } as Response)
        );
        const packages = await Packages.list();
        expect(packages[0].id).toBe('custom-id-123');
    });

    test('asPackage falls back to name@version when id is empty string', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                json: () => Promise.resolve([{
                    id: '',
                    name: 'mypkg',
                    version: '2.0',
                    cpe: [],
                    purl: [],
                }])
            } as Response)
        );
        const packages = await Packages.list();
        expect(packages[0].id).toBe('mypkg@2.0');
    });

    test('list with compareVariantId and operation sets correct query params', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ json: () => Promise.resolve([]) } as Response)
        );
        await Packages.list('var-1', undefined, 'var-2', 'intersection');
        const url = new URL(fetchMock.mock.calls[0][0] as string);
        expect(url.searchParams.get('variant_id')).toBe('var-1');
        expect(url.searchParams.get('compare_variant_id')).toBe('var-2');
        expect(url.searchParams.get('operation')).toBe('intersection');
    });

    test('list with compareVariantId but no operation omits operation param', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ json: () => Promise.resolve([]) } as Response)
        );
        await Packages.list('var-1', undefined, 'var-2');
        const url = new URL(fetchMock.mock.calls[0][0] as string);
        expect(url.searchParams.get('variant_id')).toBe('var-1');
        expect(url.searchParams.get('compare_variant_id')).toBe('var-2');
        expect(url.searchParams.has('operation')).toBe(false);
    });

    test('list with projectId only sets project_id param', async () => {
        fetchMock.mockImplementationOnce(() =>
            Promise.resolve({ json: () => Promise.resolve([]) } as Response)
        );
        await Packages.list(undefined, 'proj-5');
        const url = new URL(fetchMock.mock.calls[0][0] as string);
        expect(url.searchParams.get('project_id')).toBe('proj-5');
        expect(url.searchParams.has('variant_id')).toBe(false);
    });

    test('enrich_with_vulns uses buildStatusSummary when pkg assessments exist', () => {
        const pkg = {
            id: 'mypkg@1.0',
            name: 'mypkg',
            version: '1.0',
            cpe: [],
            purl: [],
            vulnerabilities: {},
            maxSeverity: {},
            source: [],
            variants: [],
            sbom_documents: [],
            supplier: '',
        };

        const assessment = {
            id: 'a1',
            vuln_id: 'CVE-2024-1',
            packages: ['mypkg@1.0'],
            origin: 'sbom',
            status: 'fixed',
            simplified_status: 'Fixed',
            timestamp: '2024-01-01T00:00:00',
            responses: [],
        };

        const vuln = {
            id: 'CVE-2024-1',
            aliases: [],
            related_vulnerabilities: [],
            namespace: 'nvd:cve',
            found_by: ['scanner'],
            datasource: '',
            packages: ['mypkg@1.0'],
            packages_current: [],
            variants: [],
            urls: [],
            texts: [],
            severity: { severity: 'high', min_score: 7, max_score: 8, cvss: [] },
            epss: { score: undefined, percentile: undefined },
            effort: { optimistic: null, likely: null, pessimistic: null },
            fix: { state: 'unknown' },
            status: 'fixed',
            simplified_status: 'Fixed',
            assessments: [assessment],
        } as any;

        const result = Packages.enrich_with_vulns([pkg], [vuln]);
        expect(result[0].vulnerabilities['Fixed']).toBe(1);
        expect(result[0].maxSeverity['Fixed'].label).toBe('high');
    });
});


import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import Packages from '../../src/handlers/packages';
import Vulnerabilities from '../../src/handlers/vulnerabilities';
import Assessments from '../../src/handlers/assessments';
import PatchFinderLogic from '../../src/handlers/patch_finder';


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


const PATCH_FINDER = {
    "aaabbbccc": {
        "CVE-2021-37322 (nvd-cpe-match)": {
            "fix": [">=? 1.2.3"],
            "affected": ["< 1.2.3"]
        }
    }
};


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

        vulnerabilities[0].simplified_status = 'fixed';
        vulnerabilities[1].simplified_status = 'active';

        const enrichedPackages = Packages.enrich_with_vulns(packages, vulnerabilities);
        expect(enrichedPackages.length).toEqual(2);

        expect(enrichedPackages[0].vulnerabilities["fixed"]).toEqual(1);
        expect(enrichedPackages[0].vulnerabilities["active"]).toEqual(1);
        expect(enrichedPackages[0].maxSeverity["fixed"].label).toEqual('high');
        expect(enrichedPackages[0].maxSeverity["active"].label).toEqual('low');
        expect(enrichedPackages[0].source).toEqual(['hardcoded', 'cve-finder']);

        expect(enrichedPackages[1].vulnerabilities["active"]).toEqual(1);
        expect(enrichedPackages[1].maxSeverity["active"].label).toEqual('low');
        expect(enrichedPackages[1].source).toEqual(['cve-finder']);
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
        expect(enrichedvuln[0].simplified_status).toEqual('fixed');
        expect(enrichedvuln[0].assessments.length).toEqual(1);

        expect(enrichedvuln[1].status).toEqual('affected');
        expect(enrichedvuln[1].simplified_status).toEqual('active');
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


describe('PatchFinder', () => {

    beforeEach(() => {
        fetchMock.resetMocks();
    });

    test('with empty list of patch', async () => {
        const thisFetch = fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                json: () => Promise.resolve({})
            } as Response)
        );

        const patchs = await PatchFinderLogic.scan(["CVE-2021-37322", "CVE-0000-00000"]);
        expect(patchs).toEqual({});
        expect(thisFetch).toHaveBeenCalledTimes(1);
    });

    test('with some patchs found', async () => {
        let thisFetch = fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                json: () => Promise.resolve(PATCH_FINDER)
            } as Response)
        );

        const patchs = await PatchFinderLogic.scan(["CVE-2021-37322", "CVE-0000-00000"]);
        expect(thisFetch).toHaveBeenCalledTimes(1);

        const patchInfo = patchs?.["aaabbbccc"]?.["CVE-2021-37322"]?.["(nvd-cpe-match)"]
        expect(patchInfo).toBeDefined();
        expect(patchInfo.fix).toEqual([">=? 1.2.3"]);
        expect(patchInfo.affected).toEqual(["< 1.2.3"]);
        expect(patchInfo.solve_all).toEqual("1.2.3")
    });

    test('compute versions and patch', async () => {
        let thisFetch = fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                json: () => Promise.resolve(PATCH_FINDER)
            } as Response)
        );

        const patchs = await PatchFinderLogic.scan(["CVE-2021-37322", "CVE-0000-00000"]);
        expect(thisFetch).toHaveBeenCalledTimes(1);

        const computed = PatchFinderLogic.compute_versions_and_patch(
            patchs,
            {"aaabbbccc": "1.0.0"},
            undefined,
            ''
        );

        const patchsInfo = computed?.["aaabbbccc"]
        expect(patchsInfo).toBeDefined();
        expect(patchsInfo.nb_vulns).toEqual(1);
        expect(patchsInfo.latest.version).toEqual("1.2.3");
        expect(patchsInfo.latest.solve).toEqual(1);
        expect(patchsInfo.same_major.version).toEqual("1.2.3");
        expect(patchsInfo.same_major.solve).toEqual(1);
        expect(patchsInfo.same_minor.version).toEqual(undefined);
        expect(patchsInfo.same_minor.solve).toEqual(0);
    });

    test('compute vulns per versions', async () => {
        let thisFetch = fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                json: () => Promise.resolve(PATCH_FINDER)
            } as Response)
        );

        const patchs = await PatchFinderLogic.scan(["CVE-2021-37322", "CVE-0000-00000"]);
        expect(thisFetch).toHaveBeenCalledTimes(1);

        const computed = PatchFinderLogic.compute_vulns_per_versions(
            patchs,
            {"aaabbbccc": "1.0.0"},
            undefined,
            ''
        );

        const patchsInfo = computed?.["aaabbbccc"]?.["1.2.3"]
        expect(patchsInfo).toBeDefined();
        expect(patchsInfo[0]).toEqual("CVE-2021-37322");
    });
});

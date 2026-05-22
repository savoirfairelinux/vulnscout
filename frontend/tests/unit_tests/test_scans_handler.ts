/// <reference types="jest" />
import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import ScansHandler from '../../src/handlers/scans';

beforeEach(() => {
    fetchMock.resetMocks();
});

const VALID_SCAN = {
    id: 'scan-1',
    description: null,
    scan_type: 'sbom',
    scan_source: null,
    timestamp: '2026-01-01T00:00:00.000Z',
    variant_id: 'v1',
    variant_name: 'default',
    project_name: null,
    finding_count: 10,
    package_count: 5,
    vuln_count: 8,
    is_first: false,
    findings_added: null,
    findings_removed: null,
    findings_upgraded: null,
    packages_added: null,
    packages_removed: null,
    packages_upgraded: null,
    vulns_added: null,
    vulns_removed: null,
    vulns_unchanged: null,
    findings_unchanged: null,
    packages_unchanged: null,
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
    global_finding_count: null,
    global_vuln_count: null,
    global_package_count: null,
    global_assessment_count: null,
    formats: ['SPDX'],
};

// ---------------------------------------------------------------------------
// ScansHandler.list
// ---------------------------------------------------------------------------

describe('ScansHandler.list', () => {
    test('uses variant URL when variantId is provided', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([VALID_SCAN]));
        const scans = await ScansHandler.list('v1');
        expect(scans.length).toBe(1);
        expect(scans[0].id).toBe('scan-1');
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/variants/v1/scans'),
            expect.objectContaining({ mode: 'cors' })
        );
    });

    test('uses project URL when only projectId is given', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([VALID_SCAN]));
        const scans = await ScansHandler.list(undefined, 'proj-1');
        expect(scans.length).toBe(1);
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/projects/proj-1/scans'),
            expect.objectContaining({ mode: 'cors' })
        );
    });

    test('uses generic /api/scans URL when no IDs provided', async () => {
        fetchMock.mockResponseOnce(JSON.stringify([]));
        await ScansHandler.list();
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/scans'),
            expect.objectContaining({ mode: 'cors' })
        );
    });

    test('returns empty array on non-ok HTTP response', async () => {
        fetchMock.mockResponseOnce('', { status: 500 });
        const scans = await ScansHandler.list('v1');
        expect(scans).toEqual([]);
    });

    test('returns empty array when response is not an array', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ items: [] }));
        const scans = await ScansHandler.list('v1');
        expect(scans).toEqual([]);
    });

    test('filters out items missing required string/number fields', async () => {
        const data = [
            { ...VALID_SCAN, id: 123 },                // id not string
            { ...VALID_SCAN, timestamp: null },         // timestamp not string
            { ...VALID_SCAN, variant_id: undefined },   // variant_id missing
            { ...VALID_SCAN, finding_count: 'ten' },    // finding_count not number
            VALID_SCAN,                                  // valid
        ];
        fetchMock.mockResponseOnce(JSON.stringify(data));
        const scans = await ScansHandler.list('v1');
        expect(scans.length).toBe(1);
        expect(scans[0].id).toBe('scan-1');
    });
});

// ---------------------------------------------------------------------------
// ScansHandler.getDiff
// ---------------------------------------------------------------------------

describe('ScansHandler.getDiff', () => {
    test('returns diff data when API responds with valid scan_id', async () => {
        const mockDiff = { scan_id: 'scan-1', scan_type: 'sbom', is_first: false };
        fetchMock.mockResponseOnce(JSON.stringify(mockDiff));
        const diff = await ScansHandler.getDiff('scan-1');
        expect(diff).not.toBeNull();
        expect(diff?.scan_id).toBe('scan-1');
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/scans/scan-1/diff'),
            expect.objectContaining({ mode: 'cors' })
        );
    });

    test('returns null on non-ok HTTP response', async () => {
        fetchMock.mockResponseOnce('', { status: 404 });
        const diff = await ScansHandler.getDiff('scan-x');
        expect(diff).toBeNull();
    });

    test('returns null when scan_id field is not a string', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ scan_id: 999, scan_type: 'sbom' }));
        const diff = await ScansHandler.getDiff('scan-x');
        expect(diff).toBeNull();
    });
});

// ---------------------------------------------------------------------------
// ScansHandler.setDescription
// ---------------------------------------------------------------------------

describe('ScansHandler.setDescription', () => {
    test('returns true when PATCH succeeds', async () => {
        fetchMock.mockResponseOnce('{}', { status: 200 });
        const ok = await ScansHandler.setDescription('scan-1', 'My description');
        expect(ok).toBe(true);
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/scans/scan-1'),
            expect.objectContaining({ method: 'PATCH' })
        );
    });

    test('returns false when PATCH fails', async () => {
        fetchMock.mockResponseOnce('', { status: 400 });
        const ok = await ScansHandler.setDescription('scan-1', 'Bad');
        expect(ok).toBe(false);
    });
});

// ---------------------------------------------------------------------------
// ScansHandler.triggerGrypeScan
// ---------------------------------------------------------------------------

describe('ScansHandler.triggerGrypeScan', () => {
    test('returns ok=true on 200 success', async () => {
        fetchMock.mockResponseOnce('{}', { status: 200 });
        const result = await ScansHandler.triggerGrypeScan('v1');
        expect(result.ok).toBe(true);
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/variants/v1/grype-scan'),
            expect.objectContaining({ method: 'POST' })
        );
    });

    test('returns ok=true on 202 accepted', async () => {
        fetchMock.mockResponseOnce('{}', { status: 202 });
        const result = await ScansHandler.triggerGrypeScan('v1');
        expect(result.ok).toBe(true);
    });

    test('returns ok=false with error field from body on failure', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'scan already running' }), { status: 409 });
        const result = await ScansHandler.triggerGrypeScan('v1');
        expect(result.ok).toBe(false);
        expect(result.error).toBe('scan already running');
    });

    test('returns ok=false with HTTP status code when body is not JSON', async () => {
        fetchMock.mockResponseOnce('not json', { status: 500 });
        const result = await ScansHandler.triggerGrypeScan('v1');
        expect(result.ok).toBe(false);
        expect(result.error).toContain('500');
    });
});

// ---------------------------------------------------------------------------
// ScansHandler.getGlobalResult
// ---------------------------------------------------------------------------

describe('ScansHandler.getGlobalResult', () => {
    const mockResult = {
        scan_id: 'scan-1',
        scan_type: 'sbom',
        packages: [],
        findings: [],
        vulnerabilities: [],
        assessments: [],
        package_count: 0,
        finding_count: 0,
        vuln_count: 0,
        assessment_count: 0,
    };

    test('returns global result on success', async () => {
        fetchMock.mockResponseOnce(JSON.stringify(mockResult));
        const result = await ScansHandler.getGlobalResult('scan-1');
        expect(result).not.toBeNull();
        expect(result?.scan_id).toBe('scan-1');
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/scans/scan-1/global-result'),
            expect.objectContaining({ mode: 'cors' })
        );
    });

    test('returns null on non-ok response', async () => {
        fetchMock.mockResponseOnce('', { status: 404 });
        const result = await ScansHandler.getGlobalResult('scan-x');
        expect(result).toBeNull();
    });

    test('returns null when scan_id field is not a string', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ scan_id: 42 }));
        const result = await ScansHandler.getGlobalResult('scan-x');
        expect(result).toBeNull();
    });
});

// ---------------------------------------------------------------------------
// ScansHandler.getGrypeScanStatus
// ---------------------------------------------------------------------------

describe('ScansHandler.getGrypeScanStatus', () => {
    test('returns status data on success', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ status: 'running', progress: '50%' }));
        const status = await ScansHandler.getGrypeScanStatus('v1');
        expect(status.status).toBe('running');
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/variants/v1/grype-scan/status'),
            expect.objectContaining({ mode: 'cors' })
        );
    });

    test('returns { status: "unknown" } on non-ok response', async () => {
        fetchMock.mockResponseOnce('', { status: 500 });
        const status = await ScansHandler.getGrypeScanStatus('v1');
        expect(status.status).toBe('unknown');
    });
});

// ---------------------------------------------------------------------------
// ScansHandler.triggerNvdScan
// ---------------------------------------------------------------------------

describe('ScansHandler.triggerNvdScan', () => {
    test('returns ok=true on 200 success', async () => {
        fetchMock.mockResponseOnce('{}', { status: 200 });
        const result = await ScansHandler.triggerNvdScan('v1');
        expect(result.ok).toBe(true);
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/variants/v1/nvd-scan'),
            expect.objectContaining({ method: 'POST' })
        );
    });

    test('returns ok=true on 202', async () => {
        fetchMock.mockResponseOnce('{}', { status: 202 });
        const result = await ScansHandler.triggerNvdScan('v1');
        expect(result.ok).toBe(true);
    });

    test('returns ok=false with error on failure', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'NVD DB not found' }), { status: 400 });
        const result = await ScansHandler.triggerNvdScan('v1');
        expect(result.ok).toBe(false);
        expect(result.error).toBe('NVD DB not found');
    });

    test('returns ok=false with HTTP status when body is not JSON', async () => {
        fetchMock.mockResponseOnce('not json', { status: 503 });
        const result = await ScansHandler.triggerNvdScan('v1');
        expect(result.ok).toBe(false);
        expect(result.error).toContain('503');
    });
});

// ---------------------------------------------------------------------------
// ScansHandler.getNvdScanStatus
// ---------------------------------------------------------------------------

describe('ScansHandler.getNvdScanStatus', () => {
    test('returns status data on success', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ status: 'done', progress: '100%' }));
        const status = await ScansHandler.getNvdScanStatus('v1');
        expect(status.status).toBe('done');
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/variants/v1/nvd-scan/status'),
            expect.objectContaining({ mode: 'cors' })
        );
    });

    test('returns { status: "unknown" } on non-ok response', async () => {
        fetchMock.mockResponseOnce('', { status: 503 });
        const status = await ScansHandler.getNvdScanStatus('v1');
        expect(status.status).toBe('unknown');
    });
});

// ---------------------------------------------------------------------------
// ScansHandler.triggerOsvScan
// ---------------------------------------------------------------------------

describe('ScansHandler.triggerOsvScan', () => {
    test('returns ok=true on 200 success', async () => {
        fetchMock.mockResponseOnce('{}', { status: 200 });
        const result = await ScansHandler.triggerOsvScan('v1');
        expect(result.ok).toBe(true);
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/variants/v1/osv-scan'),
            expect.objectContaining({ method: 'POST' })
        );
    });

    test('returns ok=true on 202', async () => {
        fetchMock.mockResponseOnce('{}', { status: 202 });
        const result = await ScansHandler.triggerOsvScan('v1');
        expect(result.ok).toBe(true);
    });

    test('returns ok=false with error on failure', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'OSV unavailable' }), { status: 503 });
        const result = await ScansHandler.triggerOsvScan('v1');
        expect(result.ok).toBe(false);
        expect(result.error).toBe('OSV unavailable');
    });

    test('returns ok=false with HTTP status when body is not JSON', async () => {
        fetchMock.mockResponseOnce('not json', { status: 400 });
        const result = await ScansHandler.triggerOsvScan('v1');
        expect(result.ok).toBe(false);
        expect(result.error).toContain('400');
    });
});

// ---------------------------------------------------------------------------
// ScansHandler.getOsvScanStatus
// ---------------------------------------------------------------------------

describe('ScansHandler.getOsvScanStatus', () => {
    test('returns status data on success', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ status: 'queued' }));
        const status = await ScansHandler.getOsvScanStatus('v1');
        expect(status.status).toBe('queued');
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/variants/v1/osv-scan/status'),
            expect.objectContaining({ mode: 'cors' })
        );
    });

    test('returns { status: "unknown" } on non-ok response', async () => {
        fetchMock.mockResponseOnce('', { status: 404 });
        const status = await ScansHandler.getOsvScanStatus('v1');
        expect(status.status).toBe('unknown');
    });
});

// ---------------------------------------------------------------------------
// ScansHandler.deleteScan
// ---------------------------------------------------------------------------

describe('ScansHandler.deleteScan', () => {
    test('returns ok=true with orphaned_findings_removed count on success', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ orphaned_findings_removed: 42 }), { status: 200 });
        const result = await ScansHandler.deleteScan('scan-1');
        expect(result.ok).toBe(true);
        expect(result.orphaned_findings_removed).toBe(42);
        expect(fetchMock).toHaveBeenCalledWith(
            expect.stringContaining('/api/scans/scan-1'),
            expect.objectContaining({ method: 'DELETE' })
        );
    });

    test('returns ok=true with undefined orphaned count when field is absent', async () => {
        fetchMock.mockResponseOnce('{}', { status: 200 });
        const result = await ScansHandler.deleteScan('scan-1');
        expect(result.ok).toBe(true);
        expect(result.orphaned_findings_removed).toBeUndefined();
    });

    test('returns ok=false with error field from body on HTTP error', async () => {
        fetchMock.mockResponseOnce(JSON.stringify({ error: 'scan not found' }), { status: 404 });
        const result = await ScansHandler.deleteScan('scan-x');
        expect(result.ok).toBe(false);
        expect(result.error).toBe('scan not found');
    });

    test('returns ok=false with HTTP status code when body is not JSON', async () => {
        fetchMock.mockResponseOnce('not json', { status: 500 });
        const result = await ScansHandler.deleteScan('scan-x');
        expect(result.ok).toBe(false);
        expect(result.error).toContain('500');
    });
});

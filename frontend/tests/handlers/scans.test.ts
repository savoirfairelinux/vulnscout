import ScansHandler from "../../src/handlers/scans";

const fetchSpy = jest.fn();
global.fetch = fetchSpy as typeof fetch;

const response = (data: unknown = {}, ok = true, status = 200) => ({
  ok,
  status,
  json: async () => data,
}) as Response;

beforeEach(() => {
  fetchSpy.mockReset();
});

describe("ScansHandler request contracts", () => {
  test("lists scans for global, project, and variant scopes", async () => {
    const scan = { id: "scan-1", timestamp: "2026-08-07", variant_id: "variant-1", finding_count: 1 };
    fetchSpy.mockResolvedValueOnce(response([scan]));
    fetchSpy.mockResolvedValueOnce(response([scan]));
    fetchSpy.mockResolvedValueOnce(response([scan]));

    expect(await ScansHandler.list()).toEqual([scan]);
    expect(await ScansHandler.list(undefined, "project 1")).toEqual([scan]);
    expect(await ScansHandler.list("variant 1")).toEqual([scan]);
    expect(fetchSpy.mock.calls.map(([url]) => url)).toEqual(expect.arrayContaining([
      expect.stringContaining("/api/scans"),
      expect.stringContaining("/api/projects/project%201/scans"),
      expect.stringContaining("/api/variants/variant%201/scans"),
    ]));
  });

  test("gets scan details and updates descriptions", async () => {
    fetchSpy.mockResolvedValueOnce(response({ scan_id: "scan-1" }));
    fetchSpy.mockResolvedValueOnce(response());

    expect(await ScansHandler.getDiff("scan-1")).toEqual({ scan_id: "scan-1" });
    expect(await ScansHandler.setDescription("scan-1", "Nightly scan")).toBe(true);
    expect(fetchSpy.mock.calls[1][1]).toEqual(expect.objectContaining({ method: "PATCH" }));
  });

  test("triggers scanner engines and reads their statuses", async () => {
    fetchSpy.mockResolvedValueOnce(response({}, true, 202));
    fetchSpy.mockResolvedValueOnce(response({ status: "running" }));
    fetchSpy.mockResolvedValueOnce(response({}, true, 202));
    fetchSpy.mockResolvedValueOnce(response({ status: "done" }));
    fetchSpy.mockResolvedValueOnce(response({}, true, 202));
    fetchSpy.mockResolvedValueOnce(response({ status: "queued" }));
    fetchSpy.mockResolvedValueOnce(response({}, true, 202));
    fetchSpy.mockResolvedValueOnce(response({ status: "done" }));

    expect(await ScansHandler.triggerGrypeScan("variant-1", false)).toEqual({ ok: true });
    expect(await ScansHandler.getGrypeScanStatus("variant-1")).toEqual({ status: "running" });
    expect(await ScansHandler.triggerNvdScan("variant-1")).toEqual({ ok: true });
    expect(await ScansHandler.getNvdScanStatus("variant-1")).toEqual({ status: "done" });
    expect(await ScansHandler.triggerOsvScan("variant-1")).toEqual({ ok: true });
    expect(await ScansHandler.getOsvScanStatus("variant-1")).toEqual({ status: "queued" });
    expect(await ScansHandler.triggerSbomCveCheckScan("variant-1")).toEqual({ ok: true });
    expect(await ScansHandler.getSbomCveCheckScanStatus("variant-1")).toEqual({ status: "done" });
  });

  test("reads global scan results and active scanner queues", async () => {
    fetchSpy.mockResolvedValueOnce(response({ scan_id: "scan-1", packages: [] }));
    fetchSpy.mockResolvedValueOnce(response({ grype: [{ variant_id: "variant-1", status: "running" }] }));

    expect(await ScansHandler.getGlobalResult("scan-1")).toEqual({ scan_id: "scan-1", packages: [] });
    expect(await ScansHandler.getRunningScans()).toEqual({
      grype: [{ variant_id: "variant-1", status: "running" }],
      nvd: [],
      osv: [],
      "sbom-cve-check": [],
    });
  });

  test("deletes scans and all maintenance cleanup candidates", async () => {
    fetchSpy.mockResolvedValueOnce(response({ orphaned_findings_removed: 2 }));
    fetchSpy.mockResolvedValueOnce(response({ removed: 1 }));
    fetchSpy.mockResolvedValueOnce(response({ packages: [], assessments: [] }));
    fetchSpy.mockResolvedValueOnce(response({ scans_deleted: 1 }));
    fetchSpy.mockResolvedValueOnce(response({ scans: [] }));
    fetchSpy.mockResolvedValueOnce(response({ vulnerabilities_deleted: 2 }));
    fetchSpy.mockResolvedValueOnce(response({ vulnerabilities: [] }));

    expect(await ScansHandler.deleteScan("scan-1")).toEqual({ ok: true, orphaned_findings_removed: 2 });
    expect(await ScansHandler.deleteOutdatedData({ observations: [], assessments: [], package_pairs: [] })).toEqual({ ok: true, summary: { removed: 1 } });
    expect(await ScansHandler.getOutdatedDataPreview()).toEqual({ ok: true, preview: { packages: [], assessments: [] } });
    expect(await ScansHandler.deleteEmptyScans(["scan-1"])).toEqual({ ok: true, count: 1 });
    expect(await ScansHandler.getEmptyScansPreview()).toEqual({ ok: true, scans: [] });
    expect(await ScansHandler.deleteOrphanedVulnerabilities(["CVE-2026-0001"])).toEqual({ ok: true, count: 2 });
    expect(await ScansHandler.getOrphanedVulnerabilitiesPreview()).toEqual({ ok: true, vulnerabilities: [] });
  });

  test("normalizes unavailable scanner and cleanup responses", async () => {
    for (let index = 0; index < 11; index += 1) fetchSpy.mockResolvedValueOnce(response({}, false, 503));

    expect(await ScansHandler.getGrypeScanStatus("variant-1")).toEqual({ status: "unknown" });
    expect(await ScansHandler.getNvdScanStatus("variant-1")).toEqual({ status: "unknown" });
    expect(await ScansHandler.getOsvScanStatus("variant-1")).toEqual({ status: "unknown" });
    expect(await ScansHandler.getSbomCveCheckScanStatus("variant-1")).toEqual({ status: "unknown" });
    expect(await ScansHandler.getRunningScans()).toEqual({ grype: [], nvd: [], osv: [], "sbom-cve-check": [] });
    expect(await ScansHandler.deleteScan("scan-1")).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.getOutdatedDataPreview()).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.deleteEmptyScans(["scan-1"])).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.getEmptyScansPreview()).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.deleteOrphanedVulnerabilities(["CVE-2026-0001"])).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.getOrphanedVulnerabilitiesPreview()).toEqual({ ok: false, error: "HTTP 503" });
  });

  test("uses HTTP fallbacks when error responses have no JSON body", async () => {
    const invalidJsonResponse = { ok: false, status: 503, json: async () => { throw new Error("invalid JSON"); } } as unknown as Response;
    for (let index = 0; index < 12; index += 1) fetchSpy.mockResolvedValueOnce(invalidJsonResponse);

    expect(await ScansHandler.triggerGrypeScan("variant-1")).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.triggerNvdScan("variant-1")).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.triggerOsvScan("variant-1")).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.triggerSbomCveCheckScan("variant-1")).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.getRunningScans()).toEqual({ grype: [], nvd: [], osv: [], "sbom-cve-check": [] });
    expect(await ScansHandler.deleteScan("scan-1")).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.deleteOutdatedData({ observations: [], assessments: [], package_pairs: [] })).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.getOutdatedDataPreview()).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.getEmptyScansPreview()).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.deleteEmptyScans(["scan-1"])).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.getOrphanedVulnerabilitiesPreview()).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.deleteOrphanedVulnerabilities(["CVE-2026-0001"])).toEqual({ ok: false, error: "HTTP 503" });
  });
});
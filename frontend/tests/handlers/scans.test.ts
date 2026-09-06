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
  test("imports exported scan JSON and preserves API errors", async () => {
    const result = {
      scan_id: "scan-1",
      format: "diff",
      imported_count: 1,
      package_count: 2,
      finding_count: 3,
      vulnerability_count: 2,
      assessment_count: 1,
      is_first: false,
      scans: [{
        scan_id: "scan-1",
        source_scan_id: "source-1",
        format: "diff",
        project_name: "Proj",
        variant_name: "Var",
        package_count: 2,
        finding_count: 3,
        vulnerability_count: 2,
        assessment_count: 1,
        is_first: false,
      }],
    };
    fetchSpy.mockResolvedValueOnce(response(result, true, 201));
    fetchSpy.mockResolvedValueOnce(response({ error: "This scan has already been imported" }, false, 409));

    expect(await ScansHandler.importExport([{ scan_id: "scan-1" }])).toEqual({ ok: true, result });
    expect(fetchSpy.mock.calls[0]).toEqual([
      expect.stringContaining("/api/scans/import"),
      expect.objectContaining({
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify([{ scan_id: "scan-1" }]),
      }),
    ]);
    expect(await ScansHandler.importExport([{ scan_id: "scan-1" }])).toEqual({
      ok: false,
      error: "This scan has already been imported",
    });
  });

  test("reports a network failure instead of throwing", async () => {
    fetchSpy.mockRejectedValueOnce(new Error("Failed to fetch"));

    const result = await ScansHandler.importExport([{ scan_id: "scan-1" }]);

    expect(result.ok).toBe(false);
    expect(result.ok === false && result.error).toContain("could not reach the server");
  });

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

  test("reads global scan results", async () => {
    fetchSpy.mockResolvedValueOnce(response({ scan_id: "scan-1", packages: [] }));

    expect(await ScansHandler.getGlobalResult("scan-1")).toEqual({ scan_id: "scan-1", packages: [] });
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

  test("normalizes unavailable cleanup responses", async () => {
    for (let index = 0; index < 6; index += 1) fetchSpy.mockResolvedValueOnce(response({}, false, 503));

    expect(await ScansHandler.deleteScan("scan-1")).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.getOutdatedDataPreview()).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.deleteEmptyScans(["scan-1"])).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.getEmptyScansPreview()).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.deleteOrphanedVulnerabilities(["CVE-2026-0001"])).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.getOrphanedVulnerabilitiesPreview()).toEqual({ ok: false, error: "HTTP 503" });
  });

  test("uses HTTP fallbacks when error responses have no JSON body", async () => {
    const invalidJsonResponse = { ok: false, status: 503, json: async () => { throw new Error("invalid JSON"); } } as unknown as Response;
    for (let index = 0; index < 7; index += 1) fetchSpy.mockResolvedValueOnce(invalidJsonResponse);

    expect(await ScansHandler.deleteScan("scan-1")).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.deleteOutdatedData({ observations: [], assessments: [], package_pairs: [] })).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.getOutdatedDataPreview()).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.getEmptyScansPreview()).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.deleteEmptyScans(["scan-1"])).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.getOrphanedVulnerabilitiesPreview()).toEqual({ ok: false, error: "HTTP 503" });
    expect(await ScansHandler.deleteOrphanedVulnerabilities(["CVE-2026-0001"])).toEqual({ ok: false, error: "HTTP 503" });
  });
});
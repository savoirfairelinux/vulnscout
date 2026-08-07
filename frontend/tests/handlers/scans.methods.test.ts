import ScansHandler from "../../src/handlers/scans";

const mockFetch = jest.fn();
global.fetch = mockFetch as typeof fetch;

const ok = (json: unknown, status = 200) =>
    ({ ok: true, status, json: async () => json } as Response);
const fail = (json: unknown, status = 500) =>
    ({ ok: false, status, json: async () => json } as Response);

beforeEach(() => {
    mockFetch.mockReset();
});

describe("ScansHandler.list", () => {
    const validScan = {
        id: "s1",
        timestamp: "2026-01-01T00:00:00Z",
        variant_id: "v1",
        finding_count: 3,
    };

    it("builds a variant-scoped URL", async () => {
        mockFetch.mockResolvedValueOnce(ok([validScan]));
        const res = await ScansHandler.list("v1");
        expect(mockFetch.mock.calls[0][0]).toContain("/api/variants/v1/scans");
        expect(res).toHaveLength(1);
    });

    it("builds a project-scoped URL when only projectId is given", async () => {
        mockFetch.mockResolvedValueOnce(ok([]));
        await ScansHandler.list(undefined, "p1");
        expect(mockFetch.mock.calls[0][0]).toContain("/api/projects/p1/scans");
    });

    it("builds the global URL when no scope is given", async () => {
        mockFetch.mockResolvedValueOnce(ok([]));
        await ScansHandler.list();
        expect(mockFetch.mock.calls[0][0]).toContain("/api/scans");
    });

    it("returns [] when the response is not ok", async () => {
        mockFetch.mockResolvedValueOnce(fail({}));
        expect(await ScansHandler.list()).toEqual([]);
    });

    it("returns [] when the payload is not an array", async () => {
        mockFetch.mockResolvedValueOnce(ok({ nope: true }));
        expect(await ScansHandler.list()).toEqual([]);
    });

    it("filters out malformed rows", async () => {
        mockFetch.mockResolvedValueOnce(ok([validScan, { id: 123 }, {}]));
        const res = await ScansHandler.list();
        expect(res).toHaveLength(1);
    });
});

describe("ScansHandler.getDiff", () => {
    it("returns the diff on success", async () => {
        mockFetch.mockResolvedValueOnce(ok({ scan_id: "s1" }));
        const res = await ScansHandler.getDiff("s1");
        expect(res?.scan_id).toBe("s1");
    });

    it("returns null when not ok", async () => {
        mockFetch.mockResolvedValueOnce(fail({}));
        expect(await ScansHandler.getDiff("s1")).toBeNull();
    });

    it("returns null when scan_id is missing", async () => {
        mockFetch.mockResolvedValueOnce(ok({ foo: "bar" }));
        expect(await ScansHandler.getDiff("s1")).toBeNull();
    });
});

describe("ScansHandler.setDescription", () => {
    it("returns true on ok and sends a PATCH", async () => {
        mockFetch.mockResolvedValueOnce(ok({}));
        expect(await ScansHandler.setDescription("s1", "hello")).toBe(true);
        expect(mockFetch.mock.calls[0][1]?.method).toBe("PATCH");
    });

    it("returns false when not ok", async () => {
        mockFetch.mockResolvedValueOnce(fail({}));
        expect(await ScansHandler.setDescription("s1", "hello")).toBe(false);
    });
});

describe("ScansHandler.getGlobalResult", () => {
    it("returns the result on success", async () => {
        mockFetch.mockResolvedValueOnce(ok({ scan_id: "s1" }));
        expect((await ScansHandler.getGlobalResult("s1"))?.scan_id).toBe("s1");
    });

    it("returns null when not ok", async () => {
        mockFetch.mockResolvedValueOnce(fail({}));
        expect(await ScansHandler.getGlobalResult("s1")).toBeNull();
    });

    it("returns null when scan_id is missing", async () => {
        mockFetch.mockResolvedValueOnce(ok({}));
        expect(await ScansHandler.getGlobalResult("s1")).toBeNull();
    });
});

describe("scan triggers (grype/osv/sbom-cve-check)", () => {
    const cases: Array<[string, (v: string, e?: boolean) => Promise<{ ok: boolean; error?: string }>, string]> = [
        ["triggerGrypeScan", ScansHandler.triggerGrypeScan, "grype-scan"],
        ["triggerOsvScan", ScansHandler.triggerOsvScan, "osv-scan"],
        ["triggerSbomCveCheckScan", ScansHandler.triggerSbomCveCheckScan, "sbom-cve-check-scan"],
    ];

    it.each(cases)("%s returns ok:true on 202 and hits the right endpoint", async (_name, fn, path) => {
        mockFetch.mockResolvedValueOnce(ok({}, 202));
        const res = await fn("v1");
        expect(res.ok).toBe(true);
        expect(mockFetch.mock.calls[0][0]).toContain(`/api/variants/v1/${path}`);
    });

    it.each(cases)("%s returns ok:false with an error on failure", async (_name, fn) => {
        mockFetch.mockResolvedValueOnce(fail({ error: "boom" }, 409));
        const res = await fn("v1");
        expect(res.ok).toBe(false);
        expect(res.error).toContain("boom");
    });

    it.each(cases)("%s falls back to an HTTP error string", async (_name, fn) => {
        mockFetch.mockResolvedValueOnce(fail({}, 503));
        const res = await fn("v1", false);
        expect(res.error).toContain("503");
    });
});

describe("scan status getters (grype/nvd/osv/sbom-cve-check)", () => {
    const getters: Array<[string, (v: string) => Promise<{ status: string }>]> = [
        ["getGrypeScanStatus", ScansHandler.getGrypeScanStatus],
        ["getNvdScanStatus", ScansHandler.getNvdScanStatus],
        ["getOsvScanStatus", ScansHandler.getOsvScanStatus],
        ["getSbomCveCheckScanStatus", ScansHandler.getSbomCveCheckScanStatus],
    ];

    it.each(getters)("%s returns the parsed status on success", async (_name, fn) => {
        mockFetch.mockResolvedValueOnce(ok({ status: "running" }));
        expect((await fn("v1")).status).toBe("running");
    });

    it.each(getters)("%s returns unknown when not ok", async (_name, fn) => {
        mockFetch.mockResolvedValueOnce(fail({}));
        expect((await fn("v1")).status).toBe("unknown");
    });
});

describe("ScansHandler.getRunningScans", () => {
    it("normalises a well-formed payload", async () => {
        mockFetch.mockResolvedValueOnce(
            ok({ grype: [{ variant_id: "v1", status: "running" }], nvd: [], osv: [], "sbom-cve-check": [] })
        );
        const res = await ScansHandler.getRunningScans();
        expect(res.grype).toHaveLength(1);
        expect(res.nvd).toEqual([]);
    });

    it("returns empty structure when not ok", async () => {
        mockFetch.mockResolvedValueOnce(fail({}));
        const res = await ScansHandler.getRunningScans();
        expect(res).toEqual({ grype: [], nvd: [], osv: [], "sbom-cve-check": [] });
    });

    it("returns empty structure when payload is not an object", async () => {
        mockFetch.mockResolvedValueOnce(ok(null));
        const res = await ScansHandler.getRunningScans();
        expect(res.osv).toEqual([]);
    });

    it("coerces non-array members to []", async () => {
        mockFetch.mockResolvedValueOnce(ok({ grype: "nope" }));
        const res = await ScansHandler.getRunningScans();
        expect(res.grype).toEqual([]);
    });
});

describe("ScansHandler.deleteScan", () => {
    it("returns ok with the orphaned count on success", async () => {
        mockFetch.mockResolvedValueOnce(ok({ orphaned_findings_removed: 4 }));
        const res = await ScansHandler.deleteScan("s1");
        expect(res.ok).toBe(true);
        expect(res.orphaned_findings_removed).toBe(4);
    });

    it("returns ok:false with an error on failure", async () => {
        mockFetch.mockResolvedValueOnce(fail({ error: "nope" }, 404));
        const res = await ScansHandler.deleteScan("s1");
        expect(res.ok).toBe(false);
        expect(res.error).toContain("nope");
    });
});

describe("outdated-data endpoints", () => {
    it("getOutdatedDataPreview returns preview on success", async () => {
        mockFetch.mockResolvedValueOnce(ok({ packages: [], assessments: [] }));
        const res = await ScansHandler.getOutdatedDataPreview();
        expect(res.ok).toBe(true);
        expect(res.preview).toBeDefined();
    });

    it("getOutdatedDataPreview returns error when shape is wrong", async () => {
        mockFetch.mockResolvedValueOnce(ok({ packages: "x" }));
        const res = await ScansHandler.getOutdatedDataPreview();
        expect(res.ok).toBe(false);
    });

    it("deleteOutdatedData returns summary on success", async () => {
        mockFetch.mockResolvedValueOnce(ok({ removed: 2 }));
        const res = await ScansHandler.deleteOutdatedData({
            observations: [],
            assessments: [],
            package_pairs: [],
        });
        expect(res.ok).toBe(true);
        expect(res.summary).toEqual({ removed: 2 });
    });

    it("deleteOutdatedData returns error on failure", async () => {
        mockFetch.mockResolvedValueOnce(fail({ error: "bad" }, 400));
        const res = await ScansHandler.deleteOutdatedData({
            observations: [],
            assessments: [],
            package_pairs: [],
        });
        expect(res.ok).toBe(false);
        expect(res.error).toContain("bad");
    });
});

describe("empty-scans endpoints", () => {
    it("getEmptyScansPreview returns scans on success", async () => {
        mockFetch.mockResolvedValueOnce(ok({ scans: [{ id: "s1" }] }));
        const res = await ScansHandler.getEmptyScansPreview();
        expect(res.ok).toBe(true);
        expect(res.scans).toHaveLength(1);
    });

    it("getEmptyScansPreview returns error when shape is wrong", async () => {
        mockFetch.mockResolvedValueOnce(ok({ scans: "x" }));
        expect((await ScansHandler.getEmptyScansPreview()).ok).toBe(false);
    });

    it("deleteEmptyScans returns count on success", async () => {
        mockFetch.mockResolvedValueOnce(ok({ scans_deleted: 3 }));
        const res = await ScansHandler.deleteEmptyScans(["s1"]);
        expect(res.ok).toBe(true);
        expect(res.count).toBe(3);
    });

    it("deleteEmptyScans returns error on failure", async () => {
        mockFetch.mockResolvedValueOnce(fail({ error: "nope" }, 400));
        expect((await ScansHandler.deleteEmptyScans(["s1"])).ok).toBe(false);
    });
});

describe("orphaned-vulnerabilities endpoints", () => {
    it("getOrphanedVulnerabilitiesPreview returns rows on success", async () => {
        mockFetch.mockResolvedValueOnce(ok({ vulnerabilities: [{ id: "CVE-1", assessments: 0 }] }));
        const res = await ScansHandler.getOrphanedVulnerabilitiesPreview();
        expect(res.ok).toBe(true);
        expect(res.vulnerabilities).toHaveLength(1);
    });

    it("getOrphanedVulnerabilitiesPreview returns error when shape is wrong", async () => {
        mockFetch.mockResolvedValueOnce(ok({ vulnerabilities: 5 }));
        expect((await ScansHandler.getOrphanedVulnerabilitiesPreview()).ok).toBe(false);
    });

    it("deleteOrphanedVulnerabilities returns count on success", async () => {
        mockFetch.mockResolvedValueOnce(ok({ vulnerabilities_deleted: 7 }));
        const res = await ScansHandler.deleteOrphanedVulnerabilities(["CVE-1"]);
        expect(res.ok).toBe(true);
        expect(res.count).toBe(7);
    });

    it("deleteOrphanedVulnerabilities returns error on failure", async () => {
        mockFetch.mockResolvedValueOnce(fail({ error: "nope" }, 400));
        expect((await ScansHandler.deleteOrphanedVulnerabilities(["CVE-1"])).ok).toBe(false);
    });
});

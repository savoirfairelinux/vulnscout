import NvdRefreshHandler from "../../src/handlers/nvdRefresh";

const mockFetch = jest.fn();
global.fetch = mockFetch as typeof fetch;

beforeEach(() => {
    mockFetch.mockReset();
});

describe("NvdRefreshHandler.triggerBulkRefresh", () => {
    it("triggerBulkRefresh resolves on success", async () => {
        mockFetch.mockResolvedValueOnce({ ok: true, status: 204 });
        await expect(NvdRefreshHandler.triggerBulkRefresh("variant-uuid")).resolves.toBeUndefined();
    });

    it("POSTs to the correct URL", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 204,
        } as Response);

        await NvdRefreshHandler.triggerBulkRefresh("abc");
        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/variants/abc/nvd-refresh"),
            expect.objectContaining({ method: "POST" }),
        );
    });

    it("sends cve_ids in the body when provided", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 204,
        } as Response);

        await NvdRefreshHandler.triggerBulkRefresh("abc", ["CVE-2024-0001"]);
        const [, opts] = mockFetch.mock.calls[0];
        expect(JSON.parse(opts.body)).toEqual({ cve_ids: ["CVE-2024-0001"] });
    });
    it("throws on non-ok response", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 500,
            json: async () => ({ message: "internal error" }),
        } as Response);

        await expect(NvdRefreshHandler.triggerBulkRefresh("abc")).rejects.toThrow("internal error");
    });
});

describe("NvdRefreshHandler.getBulkRefreshStatus", () => {
    it("GETs the status endpoint", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({ status: "running", progress: "5/10", logs: [], total: 10, done_count: 5, error: null }),
        } as Response);

        const status = await NvdRefreshHandler.getBulkRefreshStatus("abc");
        expect(status.status).toBe("running");
        expect(status.total).toBe(10);
    });

    it("returns error status on non-ok response", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 503,
        } as Response);

        const status = await NvdRefreshHandler.getBulkRefreshStatus("abc");
        expect(status.status).toBe("error");
        expect(status.error).toContain("503");
    });
});

describe("NvdRefreshHandler.triggerSingleRefresh", () => {
    it("returns a Vulnerability object on 200", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({
                vulnerabilities: [{
                    id: "CVE-2024-0001",
                    found_by: [],
                    datasource: "nvd",
                    namespace: "nvd",
                    aliases: [],
                    related_vulnerabilities: [],
                    urls: [],
                    texts: {},
                    fix: {},
                    severity: { severity: "high", min_score: 8.1, max_score: 8.1, cvss: [] },
                    epss: {},
                    effort: {},
                    advisories: [],
                    packages: [],
                }]
            }),
        } as Response);

        const vuln = await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001");
        expect(vuln).not.toBeNull();
        expect(vuln!.id).toBe("CVE-2024-0001");
    });

    it("returns null on 503", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 503,
            text: async () => "NVD unavailable",
        } as Response);

        const result = await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001");
        expect(result).toBeNull();
    });
});

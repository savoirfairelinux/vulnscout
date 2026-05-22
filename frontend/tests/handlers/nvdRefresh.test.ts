import NvdRefreshHandler from "../../src/handlers/nvdRefresh";

const mockFetch = jest.fn();
global.fetch = mockFetch as typeof fetch;

beforeEach(() => {
    mockFetch.mockReset();
});

describe("NvdRefreshHandler.triggerBulkRefresh", () => {
    it("triggerBulkRefresh resolves with status on success", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 202,
            json: async () => ({ status: "started", variant_id: "variant-uuid" }),
        } as Response);
        const result = await NvdRefreshHandler.triggerBulkRefresh("variant-uuid");
        expect(result).toEqual({ status: "started", variant_id: "variant-uuid" });
    });

    it("POSTs to the correct URL", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 202,
            json: async () => ({ status: "started" }),
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
            status: 202,
            json: async () => ({ status: "started" }),
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

    it("includes changed_cves when present in response", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({
                status: "done",
                changed_cves: ["CVE-2024-0001", "CVE-2024-0002"],
                total: 5,
            }),
        } as Response);

        const status = await NvdRefreshHandler.getBulkRefreshStatus("abc");
        expect(status.status).toBe("done");
        expect(status.changed_cves).toEqual(["CVE-2024-0001", "CVE-2024-0002"]);
    });
});

describe("NvdRefreshHandler.triggerBulkRefresh — catch callback", () => {
    it("falls back to 'Unknown error' when response body cannot be parsed as JSON", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 500,
            json: async () => { throw new SyntaxError("Unexpected end of JSON input"); },
        } as unknown as Response);

        await expect(NvdRefreshHandler.triggerBulkRefresh("abc")).rejects.toThrow("Unknown error");
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

    it("returns null when response body cannot be parsed as JSON", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => { throw new SyntaxError("Unexpected end of JSON input"); },
        } as unknown as Response);

        const result = await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001");
        expect(result).toBeNull();
    });
});

describe("NvdRefreshHandler.triggerBulkRefreshForProject", () => {
    it("POSTs to the correct project URL", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 202,
            json: async () => ({ status: "started", project_id: "proj-uuid" }),
        } as Response);

        await NvdRefreshHandler.triggerBulkRefreshForProject("proj-uuid");
        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/projects/proj-uuid/nvd-refresh"),
            expect.objectContaining({ method: "POST" }),
        );
    });

    it("sends cve_ids in body when provided", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 202,
            json: async () => ({ status: "started" }),
        } as Response);

        await NvdRefreshHandler.triggerBulkRefreshForProject("proj-uuid", ["CVE-2024-0001"]);
        const [, opts] = mockFetch.mock.calls[0];
        expect(JSON.parse(opts.body)).toEqual({ cve_ids: ["CVE-2024-0001"] });
    });

    it("sends no body when cveIds is omitted", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 202,
            json: async () => ({ status: "started" }),
        } as Response);

        await NvdRefreshHandler.triggerBulkRefreshForProject("proj-uuid");
        const [, opts] = mockFetch.mock.calls[0];
        expect(opts.body).toBeUndefined();
    });

    it("throws on non-ok response", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 500,
            json: async () => ({ message: "internal error" }),
        } as Response);

        await expect(NvdRefreshHandler.triggerBulkRefreshForProject("proj-uuid")).rejects.toThrow("internal error");
    });
});

describe("NvdRefreshHandler.getBulkRefreshStatusForProject", () => {
    it("GETs the correct project status URL", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            json: async () => ({ status: "running", progress: "2/5", total: 5, error: null }),
        } as Response);

        const status = await NvdRefreshHandler.getBulkRefreshStatusForProject("proj-uuid");
        expect(status.status).toBe("running");
        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/projects/proj-uuid/nvd-refresh/status"),
            expect.objectContaining({ mode: "cors" }),
        );
    });

    it("returns error status on non-ok response", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 503,
        } as Response);

        const status = await NvdRefreshHandler.getBulkRefreshStatusForProject("proj-uuid");
        expect(status.status).toBe("error");
        expect(status.error).toContain("503");
    });
});

describe("NvdRefreshHandler.cancelBulkRefresh", () => {
    it("sends DELETE to the variant refresh URL", async () => {
        mockFetch.mockResolvedValueOnce({ ok: true } as Response);

        await NvdRefreshHandler.cancelBulkRefresh("variant-abc");

        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/variants/variant-abc/nvd-refresh"),
            expect.objectContaining({ method: "DELETE", mode: "cors" }),
        );
    });
});

describe("NvdRefreshHandler.cancelBulkRefreshForProject", () => {
    it("sends DELETE to the project refresh URL", async () => {
        mockFetch.mockResolvedValueOnce({ ok: true } as Response);

        await NvdRefreshHandler.cancelBulkRefreshForProject("proj-abc");

        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/projects/proj-abc/nvd-refresh"),
            expect.objectContaining({ method: "DELETE", mode: "cors" }),
        );
    });
});

import NvdRefreshHandler from "../../src/handlers/nvdRefresh";

const mockFetch = jest.fn();
global.fetch = mockFetch as typeof fetch;

beforeEach(() => {
    mockFetch.mockReset();
});

describe("NvdRefreshHandler.triggerSingleRefresh", () => {
    it("returns kind:success with Vulnerability on 200", async () => {
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

        const result = await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001");
        expect(result.kind).toBe("success");
        if (result.kind === "success") {
            expect(result.vuln.id).toBe("CVE-2024-0001");
        }
    });

    it("returns kind:error code:unavailable on 503", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 503,
            json: async () => ({ error: "NVD unavailable", error_code: "unavailable", api_key_configured: true }),
        } as Response);

        const result = await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001");
        expect(result.kind).toBe("error");
        if (result.kind === "error") {
            expect(result.code).toBe("unavailable");
            expect(result.apiKeyConfigured).toBe(true);
        }
    });

    it("returns kind:error code:rate_limited apiKeyConfigured:false on 429 without key", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 429,
            json: async () => ({ error: "rate limited", error_code: "rate_limited", api_key_configured: false }),
        } as Response);

        const result = await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001");
        expect(result.kind).toBe("error");
        if (result.kind === "error") {
            expect(result.code).toBe("rate_limited");
            expect(result.apiKeyConfigured).toBe(false);
        }
    });

    it("defaults apiKeyConfigured to true when body is missing", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 503,
            json: async () => { throw new Error("not json"); },
        } as unknown as Response);

        const result = await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001");
        expect(result.kind).toBe("error");
        if (result.kind === "error") {
            expect(result.apiKeyConfigured).toBe(true);
        }
    });

    it("returns kind:error code:unavailable when vulnerabilities array is empty", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({ vulnerabilities: [] }),
        } as Response);

        const result = await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001");
        expect(result.kind).toBe("error");
        if (result.kind === "error") {
            expect(result.code).toBe("unavailable");
            expect(result.apiKeyConfigured).toBe(true);
        }
    });

    it("returns kind:error code:unavailable when json() throws (malformed response)", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => { throw new Error("invalid json"); },
        } as unknown as Response);

        const result = await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001");
        expect(result.kind).toBe("error");
        if (result.kind === "error") {
            expect(result.code).toBe("unavailable");
            expect(result.apiKeyConfigured).toBe(true);
        }
    });
});

describe("NvdRefreshHandler.triggerSingleRefresh — mode parameter", () => {
    it("sends mode:local by default in the request body", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({
                vulnerabilities: [{
                    id: "CVE-2024-0001",
                    found_by: [], datasource: "nvd", namespace: "nvd",
                    aliases: [], related_vulnerabilities: [], urls: [],
                    texts: {}, fix: {},
                    severity: { severity: "high", min_score: 8.1, max_score: 8.1, cvss: [] },
                    epss: {}, effort: {}, advisories: [], packages: [],
                }]
            }),
        } as Response);

        await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001");

        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/vulnerabilities/CVE-2024-0001/nvd-refresh"),
            expect.objectContaining({
                method: "POST",
                body: JSON.stringify({ mode: "local" }),
            }),
        );
    });

    it("sends mode:api when explicitly passed", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({
                vulnerabilities: [{
                    id: "CVE-2024-0002",
                    found_by: [], datasource: "nvd", namespace: "nvd",
                    aliases: [], related_vulnerabilities: [], urls: [],
                    texts: {}, fix: {},
                    severity: { severity: "medium", min_score: 5.0, max_score: 5.0, cvss: [] },
                    epss: {}, effort: {}, advisories: [], packages: [],
                }]
            }),
        } as Response);

        await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0002", "api");

        const callArg = JSON.parse((mockFetch.mock.calls[0][1] as RequestInit).body as string);
        expect(callArg.mode).toBe("api");
    });

    it("returns kind:error code:rate_limited on 429 in api mode", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 429,
            json: async () => ({ error_code: "rate_limited", api_key_configured: true }),
        } as Response);

        const result = await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001", "api");
        expect(result.kind).toBe("error");
        if (result.kind === "error") {
            expect(result.code).toBe("rate_limited");
        }
    });

    it("returns kind:error code:unauthorized on 401 in api mode", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 401,
            json: async () => ({ error_code: "unauthorized", api_key_configured: true }),
        } as Response);

        const result = await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001", "api");
        expect(result.kind).toBe("error");
        if (result.kind === "error") {
            expect(result.code).toBe("unauthorized");
        }
    });

    it("returns kind:error code:unavailable on 503 in api mode", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 503,
            json: async () => ({ error_code: "unavailable", api_key_configured: false }),
        } as Response);

        const result = await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001", "api");
        expect(result.kind).toBe("error");
        if (result.kind === "error") {
            expect(result.code).toBe("unavailable");
            expect(result.apiKeyConfigured).toBe(false);
        }
    });

    it("returns kind:error code:unavailable on 503 in local mode", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 503,
            json: async () => ({ error_code: "unavailable" }),
        } as Response);

        const result = await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001", "local");
        expect(result.kind).toBe("error");
        if (result.kind === "error") {
            expect(result.code).toBe("unavailable");
        }
    });
});

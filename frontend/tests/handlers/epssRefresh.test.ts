import EpssRefreshHandler from "../../src/handlers/epssRefresh";

const mockFetch = jest.fn();
global.fetch = mockFetch as typeof fetch;

beforeEach(() => {
    mockFetch.mockReset();
});

const mockVulnResponse = {
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
    epss: { score: 0.75, percentile: 0.95 },
    effort: {},
    advisories: [],
    packages: [],
};

describe("EpssRefreshHandler.triggerSingleRefresh", () => {
    it("returns a Vulnerability object with updated epss on 200", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({ vulnerabilities: [mockVulnResponse] }),
        } as Response);

        const vuln = await EpssRefreshHandler.triggerSingleRefresh("CVE-2024-0001");
        expect(vuln).not.toBeNull();
        expect(vuln!.id).toBe("CVE-2024-0001");
        expect(vuln!.epss.score).toBe(0.75);
        expect(vuln!.epss.percentile).toBe(0.95);
    });

    it("returns null on 503 (API unavailable)", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 503,
            text: async () => "EPSS unavailable",
        } as Response);

        const result = await EpssRefreshHandler.triggerSingleRefresh("CVE-2024-0001");
        expect(result).toBeNull();
    });

    it("returns null on 404 (CVE not in DB)", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 404,
            text: async () => "not found",
        } as Response);

        const result = await EpssRefreshHandler.triggerSingleRefresh("CVE-9999-FAKE");
        expect(result).toBeNull();
    });

    it("calls the /epss-refresh endpoint (not /nvd-refresh)", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({ vulnerabilities: [mockVulnResponse] }),
        } as Response);

        await EpssRefreshHandler.triggerSingleRefresh("CVE-2024-0001");
        const calledUrl: string = mockFetch.mock.calls[0][0];
        expect(calledUrl).toContain("/epss-refresh");
        expect(calledUrl).not.toContain("/nvd-refresh");
    });

    it("returns null when response body is not valid JSON", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => {
                throw new Error("invalid json");
            },
        } as unknown as Response);

        const result = await EpssRefreshHandler.triggerSingleRefresh("CVE-2024-0001");
        expect(result).toBeNull();
    });
});

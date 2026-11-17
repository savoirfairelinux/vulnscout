import EuvdRefreshHandler from "../../src/handlers/euvdRefresh";

const fetchSpy = jest.fn();
global.fetch = fetchSpy as typeof fetch;

beforeEach(() => {
    fetchSpy.mockReset();
});

const vulnResponse = {
    id: "CVE-2024-0001",
    found_by: [],
    datasource: "nvd",
    namespace: "nvd",
    aliases: ["EUVD-2024-0001"],
    related_vulnerabilities: [],
    urls: [],
    texts: [],
    fix: {},
    severity: { severity: "high", min_score: 8.1, max_score: 8.1, cvss: [] },
    epss: { score: 0.75, percentile: 0.95 },
    effort: {},
    packages: [],
    euvd_fetched_at: "2026-11-11T10:00:00Z",
    euvd: {
        id: "EUVD-2024-0001",
        known_exploited: true,
        sources: ["CISA"],
        date_added: "2026-11-01",
        url: "https://euvd.enisa.europa.eu/vulnerability/EUVD-2024-0001",
    },
};

const okResponse = (body: unknown) => ({
    ok: true,
    status: 200,
    json: async () => body,
} as Response);

describe("EuvdRefreshHandler.triggerSingleRefresh", () => {
    it("POSTs to the euvd-refresh endpoint and returns the EUVD/KEV data", async () => {
        fetchSpy.mockResolvedValueOnce(okResponse({ vulnerabilities: [vulnResponse] }));

        const vuln = await EuvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001");

        expect(fetchSpy.mock.calls[0][0]).toContain("/api/vulnerabilities/CVE-2024-0001/euvd-refresh");
        expect(fetchSpy.mock.calls[0][1]).toEqual({ method: "POST", mode: "cors" });
        expect(vuln?.euvd).toEqual(vulnResponse.euvd);
        expect(vuln?.euvd_fetched_at).toBe("2026-11-11T10:00:00Z");
        expect(vuln?.aliases).toEqual(["EUVD-2024-0001"]);
    });

    it("returns null when the endpoint fails", async () => {
        fetchSpy.mockResolvedValueOnce({ ok: false, status: 503 } as Response);
        expect(await EuvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001")).toBeNull();
    });

    it("returns null for an unparseable or empty body", async () => {
        fetchSpy.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => { throw new Error("invalid json"); },
        } as unknown as Response);
        expect(await EuvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001")).toBeNull();

        fetchSpy.mockResolvedValueOnce(okResponse({ vulnerabilities: [] }));
        expect(await EuvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001")).toBeNull();
    });
});

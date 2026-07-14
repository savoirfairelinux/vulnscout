import ScansHandler from "../../src/handlers/scans";

const mockFetch = jest.fn();
global.fetch = mockFetch as typeof fetch;

beforeEach(() => {
    mockFetch.mockReset();
});

describe("ScansHandler.triggerNvdScan — mode parameter", () => {
    const variantId = "variant-uuid-1234";

    it("appends mode=local by default", async () => {
        mockFetch.mockResolvedValueOnce({ ok: true, status: 202, json: async () => ({}) } as Response);
        await ScansHandler.triggerNvdScan(variantId);
        const url: string = mockFetch.mock.calls[0][0];
        expect(url).toContain("mode=local");
    });

    it("appends mode=local when explicitly passed", async () => {
        mockFetch.mockResolvedValueOnce({ ok: true, status: 202, json: async () => ({}) } as Response);
        await ScansHandler.triggerNvdScan(variantId, true, "local");
        const url: string = mockFetch.mock.calls[0][0];
        expect(url).toContain("mode=local");
    });

    it("appends mode=api when api is passed", async () => {
        mockFetch.mockResolvedValueOnce({ ok: true, status: 202, json: async () => ({}) } as Response);
        await ScansHandler.triggerNvdScan(variantId, true, "api");
        const url: string = mockFetch.mock.calls[0][0];
        expect(url).toContain("mode=api");
    });

    it("also includes exclude_kernel in the URL", async () => {
        mockFetch.mockResolvedValueOnce({ ok: true, status: 202, json: async () => ({}) } as Response);
        await ScansHandler.triggerNvdScan(variantId, false, "api");
        const url: string = mockFetch.mock.calls[0][0];
        expect(url).toContain("exclude_kernel=false");
        expect(url).toContain("mode=api");
    });

    it("returns ok:true on 202", async () => {
        mockFetch.mockResolvedValueOnce({ ok: true, status: 202, json: async () => ({}) } as Response);
        const result = await ScansHandler.triggerNvdScan(variantId, true, "local");
        expect(result.ok).toBe(true);
    });

    it("returns ok:false on 409 with error message", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 409,
            json: async () => ({ error: "already in progress" }),
        } as Response);
        const result = await ScansHandler.triggerNvdScan(variantId, true, "api");
        expect(result.ok).toBe(false);
        expect(result.error).toContain("already in progress");
    });

    it("returns ok:false when fetch rejects", async () => {
        mockFetch.mockRejectedValueOnce(new Error("network down"));
        await expect(ScansHandler.triggerNvdScan(variantId)).rejects.toThrow("network down");
    });
});

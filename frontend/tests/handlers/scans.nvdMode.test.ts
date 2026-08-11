import ScansHandler from "../../src/handlers/scans";

const mockFetch = jest.fn();
global.fetch = mockFetch as typeof fetch;

beforeEach(() => {
    mockFetch.mockReset();
});

describe("ScansHandler.triggerNvdScan", () => {
    const variantId = "variant-uuid-1234";

    it("relies on the backend local data-source default", async () => {
        mockFetch.mockResolvedValueOnce({ ok: true, status: 202, json: async () => ({}) } as Response);
        await ScansHandler.triggerNvdScan(variantId);
        const url: string = mockFetch.mock.calls[0][0];
        expect(url).not.toContain("mode=");
    });

    it("also includes exclude_kernel in the URL", async () => {
        mockFetch.mockResolvedValueOnce({ ok: true, status: 202, json: async () => ({}) } as Response);
        await ScansHandler.triggerNvdScan(variantId, false);
        const url: string = mockFetch.mock.calls[0][0];
        expect(url).toContain("exclude_kernel=false");
    });

    it("returns ok:true on 202", async () => {
        mockFetch.mockResolvedValueOnce({ ok: true, status: 202, json: async () => ({}) } as Response);
        const result = await ScansHandler.triggerNvdScan(variantId);
        expect(result.ok).toBe(true);
    });

    it("returns ok:false on 409 with error message", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 409,
            json: async () => ({ error: "already in progress" }),
        } as Response);
        const result = await ScansHandler.triggerNvdScan(variantId);
        expect(result.ok).toBe(false);
        expect(result.error).toContain("already in progress");
    });

    it("returns ok:false when fetch rejects", async () => {
        mockFetch.mockRejectedValueOnce(new Error("network down"));
        await expect(ScansHandler.triggerNvdScan(variantId)).rejects.toThrow("network down");
    });
});

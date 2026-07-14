import NvdApiKey from "../../src/handlers/nvdApiKey";

const mockFetch = jest.fn();
global.fetch = mockFetch as typeof fetch;

beforeEach(() => {
    mockFetch.mockReset();
});

describe("NvdApiKey.get", () => {
    it("returns has_key:false and empty masked_key when server returns no key", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({ has_key: false, masked_key: "" }),
        } as Response);

        const result = await NvdApiKey.get();
        expect(result.has_key).toBe(false);
        expect(result.masked_key).toBe("");
    });

    it("returns has_key:true and masked key when server has a key", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({ has_key: true, masked_key: "abcd****mnop" }),
        } as Response);

        const result = await NvdApiKey.get();
        expect(result.has_key).toBe(true);
        expect(result.masked_key).toBe("abcd****mnop");
    });

    it("returns has_key:false on json() failure (fallback)", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 500,
            json: async () => { throw new Error("bad json"); },
        } as unknown as Response);

        const result = await NvdApiKey.get();
        expect(result.has_key).toBe(false);
        expect(result.masked_key).toBe("");
    });

    it("hits the correct URL", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({ has_key: false, masked_key: "" }),
        } as Response);

        await NvdApiKey.get();
        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/config/nvd-api-key"),
            expect.objectContaining({ mode: "cors" }),
        );
    });
});

describe("NvdApiKey.set", () => {
    it("returns ok:true, has_key:true and masked_key on success", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({ status: "ok", has_key: true, masked_key: "abcd****mnop" }),
        } as Response);

        const result = await NvdApiKey.set("abcdefghijklmnop");
        expect(result.ok).toBe(true);
        expect(result.has_key).toBe(true);
        expect(result.masked_key).toBe("abcd****mnop");
    });

    it("sends a PUT request with the api_key in the body", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({ status: "ok", has_key: true, masked_key: "abcd****" }),
        } as Response);

        await NvdApiKey.set("test-api-key");
        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/config/nvd-api-key"),
            expect.objectContaining({
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ api_key: "test-api-key" }),
            }),
        );
    });

    it("returns ok:false and error message on 400", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 400,
            json: async () => ({ error: "Invalid NVD API key" }),
        } as Response);

        const result = await NvdApiKey.set("bad-key");
        expect(result.ok).toBe(false);
        expect(result.error).toBe("Invalid NVD API key");
    });

    it("returns ok:false and no error on json() failure", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 500,
            json: async () => { throw new Error("server error"); },
        } as unknown as Response);

        const result = await NvdApiKey.set("some-key");
        expect(result.ok).toBe(false);
        expect(result.error).toBeUndefined();
    });

    it("returns warning when server includes one", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({
                status: "ok",
                has_key: true,
                masked_key: "abcd****",
                warning: "Probe returned HTTP 503, key saved anyway",
            }),
        } as Response);

        const result = await NvdApiKey.set("uncertain-key");
        expect(result.ok).toBe(true);
        expect(result.warning).toContain("503");
    });
});

describe("NvdApiKey.remove", () => {
    it("sends api_key:'' to remove the key", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({ status: "ok", has_key: false, masked_key: "" }),
        } as Response);

        const result = await NvdApiKey.remove();
        expect(result.ok).toBe(true);
        expect(result.has_key).toBe(false);
        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/config/nvd-api-key"),
            expect.objectContaining({
                method: "PUT",
                body: JSON.stringify({ api_key: "" }),
            }),
        );
    });
});

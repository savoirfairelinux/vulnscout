import Operations from "../../src/handlers/operations";

const fetchSpy = jest.fn();
global.fetch = fetchSpy as typeof fetch;

const enqueued = () => JSON.parse(fetchSpy.mock.calls[0][1].body);

beforeEach(() => {
    fetchSpy.mockReset();
});

describe("queueing an NVD scan", () => {
    const variantId = "variant-uuid-1234";

    it("uses the local data source unless another mode is asked for", async () => {
        fetchSpy.mockResolvedValueOnce({ status: 202, json: async () => ({ queue_id: "q-1", operations: [] }) } as Response);

        await Operations.enqueue([Operations.scanJob("nvd", [variantId])]);

        expect(enqueued().jobs[0].options.mode).toBe("local");
    });

    it("carries an explicit API data source through to the backend", async () => {
        fetchSpy.mockResolvedValueOnce({ status: 202, json: async () => ({ queue_id: "q-1", operations: [] }) } as Response);

        await Operations.enqueue([Operations.scanJob("nvd", [variantId], { mode: "api" })]);

        expect(enqueued().jobs[0].options.mode).toBe("api");
    });

    it("excludes kernel packages unless asked to include them", async () => {
        fetchSpy.mockResolvedValueOnce({ status: 202, json: async () => ({ queue_id: "q-1", operations: [] }) } as Response);

        await Operations.enqueue([
            Operations.scanJob("nvd", [variantId]),
        ]);
        expect(enqueued().jobs[0].options.exclude_kernel).toBe(true);

        fetchSpy.mockReset();
        fetchSpy.mockResolvedValueOnce({ status: 202, json: async () => ({ queue_id: "q-2", operations: [] }) } as Response);

        await Operations.enqueue([
            Operations.scanJob("nvd", [variantId], { excludeKernel: false }),
        ]);
        expect(enqueued().jobs[0].options.exclude_kernel).toBe(false);
    });

    it("scans every requested variant in one batch", async () => {
        fetchSpy.mockResolvedValueOnce({ status: 202, json: async () => ({ queue_id: "q-1", operations: [] }) } as Response);

        await Operations.enqueue([Operations.scanJob("nvd", [variantId, "variant-uuid-5678"])]);

        expect(enqueued().jobs[0].variant_ids).toEqual([variantId, "variant-uuid-5678"]);
    });

    it("accepts the batch when the backend queues it", async () => {
        fetchSpy.mockResolvedValueOnce({ status: 202, json: async () => ({ queue_id: "q-1", operations: [] }) } as Response);

        const result = await Operations.enqueue([Operations.scanJob("nvd", [variantId])]);

        expect(result.ok).toBe(true);
    });

    it("reports why the backend refused a batch already in progress", async () => {
        fetchSpy.mockResolvedValueOnce({
            status: 409,
            json: async () => ({ error: "already in progress" }),
        } as Response);

        const result = await Operations.enqueue([Operations.scanJob("nvd", [variantId])]);

        expect(result.ok).toBe(false);
        expect(result.ok === false && result.error).toContain("already in progress");
    });

    it("falls back to the HTTP status when the refusal has no message", async () => {
        fetchSpy.mockResolvedValueOnce({
            status: 503,
            json: async () => { throw new Error("invalid JSON"); },
        } as unknown as Response);

        const result = await Operations.enqueue([Operations.scanJob("nvd", [variantId])]);

        expect(result).toEqual({ ok: false, error: "HTTP 503", conflicts: undefined });
    });

    it("propagates a network failure to the caller", async () => {
        fetchSpy.mockRejectedValueOnce(new Error("network down"));

        await expect(Operations.enqueue([Operations.scanJob("nvd", [variantId])])).rejects.toThrow("network down");
    });
});

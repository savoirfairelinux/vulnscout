import { BulkNvdRefreshHandler, BulkEpssRefreshHandler, BulkNvdRefreshCancelHandler, BulkEpssRefreshCancelHandler, BulkGhsaRefreshHandler, BulkGhsaRefreshCancelHandler, BulkEuvdRefreshHandler, BulkEuvdRefreshCancelHandler } from "../../src/handlers/bulkRefresh";
import type { BulkRefreshResponse, CancelRefreshResponse } from "../../src/handlers/bulkRefresh";

const mockFetch = jest.fn();
global.fetch = mockFetch as typeof fetch;

beforeEach(() => {
    mockFetch.mockReset();
});

const makeOkResponse = (body: BulkRefreshResponse) => ({
    ok: true,
    status: 202,
    json: async () => body,
} as Response);

const makeErrorResponse = (status: number) => ({
    ok: false,
    status,
    json: async () => ({ error: "error" }),
} as Response);

describe("BulkNvdRefreshHandler.trigger", () => {
    it("returns BulkRefreshResponse on 202", async () => {
        mockFetch.mockResolvedValueOnce(makeOkResponse({ status: "started", total: 5 }));
        const result = await BulkNvdRefreshHandler.trigger(["CVE-2024-0001", "CVE-2024-0002"]);
        expect(result).not.toBeNull();
        expect(result!.status).toBe("started");
        expect(result!.total).toBe(5);
    });

    it("sends the correct request body", async () => {
        mockFetch.mockResolvedValueOnce(makeOkResponse({ status: "started", total: 1 }));
        const cveIds = ["CVE-2024-0001"];
        await BulkNvdRefreshHandler.trigger(cveIds);
        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/vulnerabilities/bulk-nvd-refresh"),
            expect.objectContaining({
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ cve_ids: cveIds }),
            }),
        );
    });

    it("returns null on 409 (already in progress)", async () => {
        mockFetch.mockResolvedValueOnce(makeErrorResponse(409));
        const result = await BulkNvdRefreshHandler.trigger(["CVE-2024-0001"]);
        expect(result).toBeNull();
    });

    it("returns null on 400 (bad request)", async () => {
        mockFetch.mockResolvedValueOnce(makeErrorResponse(400));
        const result = await BulkNvdRefreshHandler.trigger([]);
        expect(result).toBeNull();
    });

    it("returns null when fetch rejects", async () => {
        mockFetch.mockRejectedValueOnce(new Error("network error"));
        const result = await BulkNvdRefreshHandler.trigger(["CVE-2024-0001"]);
        expect(result).toBeNull();
    });

    it("returns null when json() throws (malformed 202 body)", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 202,
            json: async () => { throw new Error("bad json"); },
        } as unknown as Response);
        const result = await BulkNvdRefreshHandler.trigger(["CVE-2024-0001"]);
        expect(result).toBeNull();
    });
});

describe("BulkEpssRefreshHandler.trigger", () => {
    it("returns BulkRefreshResponse on 202", async () => {
        mockFetch.mockResolvedValueOnce(makeOkResponse({ status: "started", total: 10 }));
        const result = await BulkEpssRefreshHandler.trigger(["CVE-2024-0001"]);
        expect(result).not.toBeNull();
        expect(result!.total).toBe(10);
    });

    it("sends the correct request body", async () => {
        mockFetch.mockResolvedValueOnce(makeOkResponse({ status: "started", total: 1 }));
        const cveIds = ["CVE-2024-0001", "CVE-2024-0002"];
        await BulkEpssRefreshHandler.trigger(cveIds);
        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/vulnerabilities/bulk-epss-refresh"),
            expect.objectContaining({
                method: "POST",
                body: JSON.stringify({ cve_ids: cveIds }),
            }),
        );
    });

    it("returns null on 409", async () => {
        mockFetch.mockResolvedValueOnce(makeErrorResponse(409));
        const result = await BulkEpssRefreshHandler.trigger(["CVE-2024-0001"]);
        expect(result).toBeNull();
    });

    it("returns null on 400", async () => {
        mockFetch.mockResolvedValueOnce(makeErrorResponse(400));
        const result = await BulkEpssRefreshHandler.trigger([]);
        expect(result).toBeNull();
    });

    it("returns null when json() throws (malformed 202 body)", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 202,
            json: async () => { throw new Error("bad json"); },
        } as unknown as Response);
        const result = await BulkEpssRefreshHandler.trigger(["CVE-2024-0001"]);
        expect(result).toBeNull();
    });

    it("returns null when fetch rejects", async () => {
        mockFetch.mockRejectedValueOnce(new Error("network error"));
        const result = await BulkEpssRefreshHandler.trigger(["CVE-2024-0001"]);
        expect(result).toBeNull();
    });
});

const makeOkCancelResponse = (body: CancelRefreshResponse) => ({
    ok: true,
    status: 200,
    json: async () => body,
} as Response);

describe("BulkNvdRefreshCancelHandler.trigger", () => {
    it("returns CancelRefreshResponse on 200", async () => {
        mockFetch.mockResolvedValueOnce(makeOkCancelResponse({ status: "cancelling" }));
        const result = await BulkNvdRefreshCancelHandler.trigger();
        expect(result).not.toBeNull();
        expect(result!.status).toBe("cancelling");
    });

    it("sends POST to the correct cancel endpoint", async () => {
        mockFetch.mockResolvedValueOnce(makeOkCancelResponse({ status: "cancelling" }));
        await BulkNvdRefreshCancelHandler.trigger();
        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/vulnerabilities/cancel-nvd-refresh"),
            expect.objectContaining({ method: "POST" }),
        );
    });

    it("returns null on 409 (nothing in progress)", async () => {
        mockFetch.mockResolvedValueOnce(makeErrorResponse(409));
        const result = await BulkNvdRefreshCancelHandler.trigger();
        expect(result).toBeNull();
    });

    it("returns null when fetch rejects", async () => {
        mockFetch.mockRejectedValueOnce(new Error("network error"));
        const result = await BulkNvdRefreshCancelHandler.trigger();
        expect(result).toBeNull();
    });

    it("returns null when json() throws (malformed response body)", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => { throw new Error("bad json"); },
        } as unknown as Response);
        const result = await BulkNvdRefreshCancelHandler.trigger();
        expect(result).toBeNull();
    });
});

describe("BulkEpssRefreshCancelHandler.trigger", () => {
    it("returns CancelRefreshResponse on 200", async () => {
        mockFetch.mockResolvedValueOnce(makeOkCancelResponse({ status: "cancelling" }));
        const result = await BulkEpssRefreshCancelHandler.trigger();
        expect(result).not.toBeNull();
        expect(result!.status).toBe("cancelling");
    });

    it("sends POST to the correct cancel endpoint", async () => {
        mockFetch.mockResolvedValueOnce(makeOkCancelResponse({ status: "cancelling" }));
        await BulkEpssRefreshCancelHandler.trigger();
        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/vulnerabilities/cancel-epss-refresh"),
            expect.objectContaining({ method: "POST" }),
        );
    });

    it("returns null on 409 (nothing in progress)", async () => {
        mockFetch.mockResolvedValueOnce(makeErrorResponse(409));
        const result = await BulkEpssRefreshCancelHandler.trigger();
        expect(result).toBeNull();
    });

    it("returns null when fetch rejects", async () => {
        mockFetch.mockRejectedValueOnce(new Error("network error"));
        const result = await BulkEpssRefreshCancelHandler.trigger();
        expect(result).toBeNull();
    });

    it("returns null when json() throws (malformed response body)", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => { throw new Error("bad json"); },
        } as unknown as Response);
        const result = await BulkEpssRefreshCancelHandler.trigger();
        expect(result).toBeNull();
    });
});

describe("GHSAProgressHandler (smoke)", () => {
    it("parses a valid progress response", async () => {
        const { default: GHSAProgressHandler } = await import("../../src/handlers/ghsa_progress");
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({
                in_progress: true,
                phase: "bulk_ghsa_refresh",
                current: 3,
                total: 10,
                message: "GHSA refresh: 3/10",
            }),
        } as Response);
        const progress = await GHSAProgressHandler.getProgress();
        expect(progress.in_progress).toBe(true);
        expect(progress.current).toBe(3);
        expect(progress.total).toBe(10);
    });

    it("getProgressPercentage returns ratio when in progress", async () => {
        const { default: GHSAProgressHandler } = await import("../../src/handlers/ghsa_progress");
        const pct = GHSAProgressHandler.getProgressPercentage({ in_progress: true, phase: "bulk_ghsa_refresh", current: 5, total: 10, message: "" });
        expect(pct).toBeCloseTo(0.5);
    });

    it("getProgressPercentage returns 1 when completed", async () => {
        const { default: GHSAProgressHandler } = await import("../../src/handlers/ghsa_progress");
        const pct = GHSAProgressHandler.getProgressPercentage({ in_progress: false, phase: "completed", current: 10, total: 10, message: "" });
        expect(pct).toBe(1);
    });

    it("getProgressPercentage returns 0 when idle", async () => {
        const { default: GHSAProgressHandler } = await import("../../src/handlers/ghsa_progress");
        const pct = GHSAProgressHandler.getProgressPercentage({ in_progress: false, phase: "idle", current: 0, total: 0, message: "" });
        expect(pct).toBe(0);
    });

    it("getProgress applies ?? fallbacks when response fields are missing", async () => {
        const { default: GHSAProgressHandler } = await import("../../src/handlers/ghsa_progress");
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({}),
        } as Response);
        const progress = await GHSAProgressHandler.getProgress();
        expect(progress.in_progress).toBe(false);
        expect(progress.phase).toBe("idle");
        expect(progress.current).toBe(0);
        expect(progress.total).toBe(0);
        expect(progress.message).toBe("");
    });

    it("getProgress returns idleProgress when response is not ok (e.g. 404 on old backend)", async () => {
        const { default: GHSAProgressHandler } = await import("../../src/handlers/ghsa_progress");
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 404,
            json: async () => ({ error: "Not found" }),
        } as Response);
        const progress = await GHSAProgressHandler.getProgress();
        expect(progress.in_progress).toBe(false);
        expect(progress.phase).toBe("idle");
        expect(progress.current).toBe(0);
        expect(progress.total).toBe(0);
        expect(progress.message).toBe("");
        expect(progress.last_update).toBeUndefined();
        expect(progress.started_at).toBeUndefined();
    });
});

describe("BulkGhsaRefreshHandler.trigger", () => {
    it("returns BulkRefreshResponse on 202", async () => {
        mockFetch.mockResolvedValueOnce(makeOkResponse({ status: "started", total: 3 }));
        const result = await BulkGhsaRefreshHandler.trigger(["GHSA-R7JW-VC2X-4GBH"]);
        expect(result).not.toBeNull();
        expect(result!.status).toBe("started");
        expect(result!.total).toBe(3);
    });

    it("sends the correct request body", async () => {
        mockFetch.mockResolvedValueOnce(makeOkResponse({ status: "started", total: 1 }));
        const ghsaIds = ["GHSA-R7JW-VC2X-4GBH"];
        await BulkGhsaRefreshHandler.trigger(ghsaIds);
        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/vulnerabilities/bulk-ghsa-refresh"),
            expect.objectContaining({
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ ghsa_ids: ghsaIds }),
            }),
        );
    });

    it("returns null on 409 (already in progress)", async () => {
        mockFetch.mockResolvedValueOnce(makeErrorResponse(409));
        const result = await BulkGhsaRefreshHandler.trigger(["GHSA-R7JW-VC2X-4GBH"]);
        expect(result).toBeNull();
    });

    it("returns null on 400 (bad request)", async () => {
        mockFetch.mockResolvedValueOnce(makeErrorResponse(400));
        const result = await BulkGhsaRefreshHandler.trigger([]);
        expect(result).toBeNull();
    });

    it("returns null when fetch rejects", async () => {
        mockFetch.mockRejectedValueOnce(new Error("network error"));
        const result = await BulkGhsaRefreshHandler.trigger(["GHSA-R7JW-VC2X-4GBH"]);
        expect(result).toBeNull();
    });

    it("returns null when json() throws (malformed 202 body)", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 202,
            json: async () => { throw new Error("bad json"); },
        } as unknown as Response);
        const result = await BulkGhsaRefreshHandler.trigger(["GHSA-R7JW-VC2X-4GBH"]);
        expect(result).toBeNull();
    });
});

describe("BulkGhsaRefreshCancelHandler.trigger", () => {
    it("returns CancelRefreshResponse on 200", async () => {
        mockFetch.mockResolvedValueOnce(makeOkCancelResponse({ status: "cancelling" }));
        const result = await BulkGhsaRefreshCancelHandler.trigger();
        expect(result).not.toBeNull();
        expect(result!.status).toBe("cancelling");
    });

    it("sends POST to the correct cancel endpoint", async () => {
        mockFetch.mockResolvedValueOnce(makeOkCancelResponse({ status: "cancelling" }));
        await BulkGhsaRefreshCancelHandler.trigger();
        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/vulnerabilities/cancel-ghsa-refresh"),
            expect.objectContaining({ method: "POST" }),
        );
    });

    it("returns null on 409 (nothing in progress)", async () => {
        mockFetch.mockResolvedValueOnce(makeErrorResponse(409));
        const result = await BulkGhsaRefreshCancelHandler.trigger();
        expect(result).toBeNull();
    });

    it("returns null when fetch rejects", async () => {
        mockFetch.mockRejectedValueOnce(new Error("network error"));
        const result = await BulkGhsaRefreshCancelHandler.trigger();
        expect(result).toBeNull();
    });

    it("returns null when json() throws (malformed response body)", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => { throw new Error("bad json"); },
        } as unknown as Response);
        const result = await BulkGhsaRefreshCancelHandler.trigger();
        expect(result).toBeNull();
    });
});

describe("EUVDProgressHandler (smoke)", () => {
    it("parses a valid progress response", async () => {
        const { default: EUVDProgressHandler } = await import("../../src/handlers/euvd_progress");
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({
                in_progress: true,
                phase: "bulk_euvd_refresh",
                current: 4,
                total: 12,
                message: "EUVD refresh: 4/12",
            }),
        } as Response);
        const progress = await EUVDProgressHandler.getProgress();
        expect(progress.in_progress).toBe(true);
        expect(progress.current).toBe(4);
        expect(progress.total).toBe(12);
    });

    it("returns idle progress on a non-OK response (older backend)", async () => {
        const { default: EUVDProgressHandler } = await import("../../src/handlers/euvd_progress");
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 404,
            json: async () => ({ error: "not found" }),
        } as Response);
        const progress = await EUVDProgressHandler.getProgress();
        expect(progress.in_progress).toBe(false);
        expect(progress.phase).toBe("idle");
    });

    it("getProgressPercentage returns ratio when in progress", async () => {
        const { default: EUVDProgressHandler } = await import("../../src/handlers/euvd_progress");
        const pct = EUVDProgressHandler.getProgressPercentage({ in_progress: true, phase: "bulk_euvd_refresh", current: 5, total: 10, message: "" });
        expect(pct).toBeCloseTo(0.5);
    });

    it("getProgressPercentage returns 1 when completed", async () => {
        const { default: EUVDProgressHandler } = await import("../../src/handlers/euvd_progress");
        const pct = EUVDProgressHandler.getProgressPercentage({ in_progress: false, phase: "completed", current: 10, total: 10, message: "" });
        expect(pct).toBe(1);
    });

    it("getProgressPercentage returns 0 when idle", async () => {
        const { default: EUVDProgressHandler } = await import("../../src/handlers/euvd_progress");
        const pct = EUVDProgressHandler.getProgressPercentage({ in_progress: false, phase: "idle", current: 0, total: 0, message: "" });
        expect(pct).toBe(0);
    });

    it("getProgress applies ?? fallbacks when response fields are missing", async () => {
        const { default: EUVDProgressHandler } = await import("../../src/handlers/euvd_progress");
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({}),
        } as Response);
        const progress = await EUVDProgressHandler.getProgress();
        expect(progress.in_progress).toBe(false);
        expect(progress.phase).toBe("idle");
        expect(progress.current).toBe(0);
        expect(progress.total).toBe(0);
        expect(progress.message).toBe("");
    });
});

describe("BulkEuvdRefreshHandler.trigger", () => {
    it("returns BulkRefreshResponse on 202", async () => {
        mockFetch.mockResolvedValueOnce(makeOkResponse({ status: "started", total: 3 }));
        const result = await BulkEuvdRefreshHandler.trigger(["CVE-2021-44228"]);
        expect(result).not.toBeNull();
        expect(result!.status).toBe("started");
        expect(result!.total).toBe(3);
    });

    it("sends the correct request body", async () => {
        mockFetch.mockResolvedValueOnce(makeOkResponse({ status: "started", total: 1 }));
        const cveIds = ["CVE-2021-44228"];
        await BulkEuvdRefreshHandler.trigger(cveIds);
        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/vulnerabilities/bulk-euvd-refresh"),
            expect.objectContaining({
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ cve_ids: cveIds }),
            }),
        );
    });

    it("returns null on 409 (already in progress)", async () => {
        mockFetch.mockResolvedValueOnce(makeErrorResponse(409));
        const result = await BulkEuvdRefreshHandler.trigger(["CVE-2021-44228"]);
        expect(result).toBeNull();
    });

    it("returns null on 400 (bad request)", async () => {
        mockFetch.mockResolvedValueOnce(makeErrorResponse(400));
        const result = await BulkEuvdRefreshHandler.trigger([]);
        expect(result).toBeNull();
    });

    it("returns null when fetch rejects", async () => {
        mockFetch.mockRejectedValueOnce(new Error("network error"));
        const result = await BulkEuvdRefreshHandler.trigger(["CVE-2021-44228"]);
        expect(result).toBeNull();
    });

    it("returns null when json() throws (malformed 202 body)", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 202,
            json: async () => { throw new Error("bad json"); },
        } as unknown as Response);
        const result = await BulkEuvdRefreshHandler.trigger(["CVE-2021-44228"]);
        expect(result).toBeNull();
    });
});

describe("BulkEuvdRefreshCancelHandler.trigger", () => {
    it("returns CancelRefreshResponse on 200", async () => {
        mockFetch.mockResolvedValueOnce(makeOkCancelResponse({ status: "cancelling" }));
        const result = await BulkEuvdRefreshCancelHandler.trigger();
        expect(result).not.toBeNull();
        expect(result!.status).toBe("cancelling");
    });

    it("sends POST to the correct cancel endpoint", async () => {
        mockFetch.mockResolvedValueOnce(makeOkCancelResponse({ status: "cancelling" }));
        await BulkEuvdRefreshCancelHandler.trigger();
        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/vulnerabilities/cancel-euvd-refresh"),
            expect.objectContaining({ method: "POST" }),
        );
    });

    it("returns null on 409 (nothing in progress)", async () => {
        mockFetch.mockResolvedValueOnce(makeErrorResponse(409));
        const result = await BulkEuvdRefreshCancelHandler.trigger();
        expect(result).toBeNull();
    });

    it("returns null when fetch rejects", async () => {
        mockFetch.mockRejectedValueOnce(new Error("network error"));
        const result = await BulkEuvdRefreshCancelHandler.trigger();
        expect(result).toBeNull();
    });

    it("returns null when json() throws (malformed response body)", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => { throw new Error("bad json"); },
        } as unknown as Response);
        const result = await BulkEuvdRefreshCancelHandler.trigger();
        expect(result).toBeNull();
    });
});

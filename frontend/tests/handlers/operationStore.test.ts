/**
 * The single event stream that replaced every polling loop.
 *
 * Drives the store through a stand-in EventSource so frames can be delivered
 * deterministically.
 */

import Operations from "../../src/handlers/operations";
import {
    __reset,
    __setEventSourceFactory,
    getConnectionState,
    getOperation,
    getSnapshot,
    hasActive,
    hasActiveSource,
    refreshProgressOf,
    refreshProgressPercentage,
    selectByKind,
    selectByQueue,
    subscribe,
    waitForQueue,
} from "../../src/handlers/operationStore";
import type { RefreshProgressView } from "../../src/handlers/operationStore";
import type { Operation } from "../../src/types/operation";

class FakeEventSource {
    static instances: FakeEventSource[] = [];

    readonly url: string;
    closed = false;
    onerror: (() => void) | null = null;
    private readonly handlers = new Map<string, Array<(event: MessageEvent) => void>>();

    constructor(url: string) {
        this.url = url;
        FakeEventSource.instances.push(this);
    }

    addEventListener(type: string, handler: (event: MessageEvent) => void) {
        const existing = this.handlers.get(type) ?? [];
        existing.push(handler);
        this.handlers.set(type, existing);
    }

    close() {
        this.closed = true;
    }

    /** Deliver one SSE frame to the store. */
    send(type: string, data: unknown, id?: number) {
        const event = {
            data: JSON.stringify(data),
            lastEventId: id !== undefined ? String(id) : "",
        } as MessageEvent;
        (this.handlers.get(type) ?? []).forEach(handler => handler(event));
    }

    fail() {
        this.onerror?.();
    }

    static latest(): FakeEventSource {
        return FakeEventSource.instances[FakeEventSource.instances.length - 1];
    }
}

const operation = (overrides: Partial<Operation> & { op_id: string }): Operation => ({
    kind: "scan",
    source: "grype",
    label: "Grype",
    lane: "pipeline",
    scope: null,
    status: "queued",
    progress: { current: 0, total: 0, message: "Queued" },
    logs: [],
    error: null,
    queue_id: null,
    position: null,
    options: {},
    cancellable: true,
    created_at: "2026-08-19T10:00:00+00:00",
    started_at: null,
    finished_at: null,
    result: null,
    ...overrides,
});

let restoreFactory: () => void;

beforeEach(() => {
    FakeEventSource.instances = [];
    restoreFactory = __setEventSourceFactory(url => new FakeEventSource(url) as unknown as EventSource);
});

afterEach(() => {
    __reset();
    restoreFactory();
    jest.restoreAllMocks();
});

/** Subscribing is what opens the connection. */
function connect(): FakeEventSource {
    subscribe(() => {});
    return FakeEventSource.latest();
}

describe("connection", () => {
    it("opens exactly one stream no matter how many components subscribe", () => {
        subscribe(() => {});
        subscribe(() => {});
        subscribe(() => {});

        expect(FakeEventSource.instances).toHaveLength(1);
    });

    it("reports the connection as open once the first frame arrives", () => {
        const stream = connect();
        expect(getConnectionState()).toBe("connecting");

        stream.send("snapshot", { seq: 1, operations: [] });

        expect(getConnectionState()).toBe("open");
    });

    it("reconnects after the stream errors", () => {
        jest.useFakeTimers();
        const stream = connect();
        stream.send("snapshot", { seq: 1, operations: [] });

        stream.fail();
        expect(getConnectionState()).toBe("reconnecting");

        jest.advanceTimersByTime(500);
        expect(FakeEventSource.instances).toHaveLength(2);
        jest.useRealTimers();
    });

    it("reconnects when the server says goodbye", () => {
        jest.useFakeTimers();
        const stream = connect();
        stream.send("snapshot", { seq: 1, operations: [] });

        stream.send("bye", { reason: "server shutdown" });

        expect(stream.closed).toBe(true);
        jest.advanceTimersByTime(500);
        expect(FakeEventSource.instances).toHaveLength(2);
        jest.useRealTimers();
    });

    it("treats a heartbeat as proof the connection is alive", () => {
        const stream = connect();
        stream.send("heartbeat", { seq: 4 });

        expect(getConnectionState()).toBe("open");
    });

    it("closes the stream once the last subscriber leaves", () => {
        const unsubscribeFirst = subscribe(() => {});
        const unsubscribeSecond = subscribe(() => {});
        const stream = FakeEventSource.latest();

        unsubscribeFirst();
        expect(stream.closed).toBe(false);

        unsubscribeSecond();
        expect(stream.closed).toBe(true);
        expect(getConnectionState()).toBe("idle");
    });

    it("cancels a pending reconnect when the last subscriber leaves", () => {
        jest.useFakeTimers();
        const unsubscribe = subscribe(() => {});
        FakeEventSource.latest().fail();

        unsubscribe();
        jest.advanceTimersByTime(60000);

        expect(FakeEventSource.instances).toHaveLength(1);
        expect(getConnectionState()).toBe("idle");
        jest.useRealTimers();
    });

    it("resumes with the last seen event id so the server replays missed deltas", () => {
        jest.useFakeTimers();
        const stream = connect();
        stream.send("snapshot", { seq: 3, operations: [] });
        stream.send("operation", operation({ op_id: "scan:grype:v1" }), 7);

        stream.fail();
        jest.advanceTimersByTime(500);

        expect(FakeEventSource.latest().url).toContain("last_event_id=7");
        jest.useRealTimers();
    });
});

describe("state from the stream", () => {
    it("adopts the snapshot as the whole state", () => {
        const stream = connect();

        stream.send("snapshot", {
            seq: 7,
            operations: [
                operation({ op_id: "scan:grype:v1" }),
                operation({ op_id: "refresh:epss", kind: "refresh", source: "epss", label: "EPSS" }),
            ],
        });

        expect(getSnapshot().map(item => item.op_id)).toEqual(["refresh:epss", "scan:grype:v1"]);
    });

    it("restores queued operations, which per-variant status endpoints could never do", () => {
        const stream = connect();

        stream.send("snapshot", {
            seq: 1,
            operations: [operation({ op_id: "scan:osv:v9", status: "queued" })],
        });

        expect(getOperation("scan:osv:v9")?.status).toBe("queued");
    });

    it("applies deltas on top of the snapshot", () => {
        const stream = connect();
        stream.send("snapshot", { seq: 1, operations: [operation({ op_id: "scan:grype:v1" })] });

        stream.send("operation", operation({
            op_id: "scan:grype:v1",
            status: "running",
            progress: { current: 3, total: 10, message: "3/10 packages" },
        }));

        expect(getOperation("scan:grype:v1")?.progress).toEqual({
            current: 3, total: 10, message: "3/10 packages",
        });
    });

    it("forgets an operation the server removed", () => {
        const stream = connect();
        stream.send("snapshot", { seq: 1, operations: [operation({ op_id: "scan:grype:v1", status: "done" })] });

        stream.send("operation_removed", { op_id: "scan:grype:v1" });

        expect(getOperation("scan:grype:v1")).toBeUndefined();
        expect(getSnapshot()).toHaveLength(0);
    });

    it("keeps the remaining operations when one is removed", () => {
        const stream = connect();
        stream.send("snapshot", {
            seq: 1,
            operations: [
                operation({ op_id: "scan:grype:v1", status: "done" }),
                operation({ op_id: "scan:grype:v2", status: "running", created_at: "2026-08-19T10:00:01+00:00" }),
            ],
        });

        stream.send("operation_removed", { op_id: "scan:grype:v1" });

        expect(getSnapshot().map(item => item.op_id)).toEqual(["scan:grype:v2"]);
    });

    it("replaces state wholesale when a later snapshot arrives after a gap", () => {
        const stream = connect();
        stream.send("snapshot", { seq: 1, operations: [operation({ op_id: "scan:grype:v1" })] });

        stream.send("snapshot", { seq: 90, operations: [operation({ op_id: "refresh:nvd", kind: "refresh" })] });

        expect(getSnapshot().map(item => item.op_id)).toEqual(["refresh:nvd"]);
    });

    it("notifies subscribers when state changes", () => {
        const listener = jest.fn();
        subscribe(listener);
        const stream = FakeEventSource.latest();

        stream.send("snapshot", { seq: 1, operations: [operation({ op_id: "scan:grype:v1" })] });

        expect(listener).toHaveBeenCalled();
    });

    it("stops notifying a subscriber that unsubscribed", () => {
        const listener = jest.fn();
        const unsubscribe = subscribe(listener);
        const stream = FakeEventSource.latest();

        stream.send("snapshot", { seq: 1, operations: [operation({ op_id: "scan:grype:v1" })] });
        const callsWhileSubscribed = listener.mock.calls.length;
        unsubscribe();
        stream.send("operation", operation({ op_id: "scan:grype:v1", status: "running" }));

        expect(callsWhileSubscribed).toBeGreaterThan(0);
        expect(listener).toHaveBeenCalledTimes(callsWhileSubscribed);
    });

    it("keeps existing state when a frame payload cannot be parsed", () => {
        const stream = connect();
        stream.send("snapshot", { seq: 1, operations: [operation({ op_id: "scan:grype:v1" })] });

        stream.send("operation", undefined);

        expect(getSnapshot()).toHaveLength(1);
    });
});

describe("selectors", () => {
    const seed = (stream: FakeEventSource) => stream.send("snapshot", {
        seq: 1,
        operations: [
            operation({ op_id: "scan:grype:v1", queue_id: "q-1", status: "running" }),
            operation({ op_id: "scan:grype:v2", queue_id: "q-1", status: "queued" }),
            operation({
                op_id: "refresh:epss", kind: "refresh", source: "epss",
                label: "EPSS", queue_id: "q-2", status: "done",
            }),
        ],
    });

    it("filters by kind", () => {
        const stream = connect();
        seed(stream);

        expect(selectByKind("scan").map(item => item.op_id)).toEqual(["scan:grype:v1", "scan:grype:v2"]);
    });

    it("filters by batch", () => {
        const stream = connect();
        seed(stream);

        expect(selectByQueue("q-1")).toHaveLength(2);
    });

    it("reports active work overall and per source", () => {
        const stream = connect();
        seed(stream);

        expect(hasActive()).toBe(true);
        expect(hasActive("scan")).toBe(true);
        expect(hasActive("refresh")).toBe(false);
        expect(hasActiveSource("scan", "grype")).toBe(true);
        expect(hasActiveSource("refresh", "epss")).toBe(false);
    });
});

describe("waitForQueue", () => {
    it("resolves once every operation in the batch has settled", async () => {
        const stream = connect();
        stream.send("snapshot", {
            seq: 1,
            operations: [
                operation({ op_id: "scan:grype:v1", queue_id: "q-1", status: "running" }),
                operation({ op_id: "scan:nvd:v1", queue_id: "q-1", status: "queued", source: "nvd" }),
            ],
        });

        const pending = waitForQueue("q-1");

        stream.send("operation", operation({ op_id: "scan:grype:v1", queue_id: "q-1", status: "done" }));
        stream.send("operation", operation({
            op_id: "scan:nvd:v1", queue_id: "q-1", status: "done", source: "nvd",
        }));

        await expect(pending).resolves.toHaveLength(2);
    });

    it("resolves for a batch that had already finished", async () => {
        const stream = connect();
        stream.send("snapshot", {
            seq: 1,
            operations: [operation({ op_id: "scan:grype:v1", queue_id: "q-1", status: "done" })],
        });

        await expect(waitForQueue("q-1")).resolves.toHaveLength(1);
    });

    it("still resolves when the batch ends in failure", async () => {
        const stream = connect();
        stream.send("snapshot", {
            seq: 1,
            operations: [operation({ op_id: "scan:grype:v1", queue_id: "q-1", status: "running" })],
        });

        const pending = waitForQueue("q-1");
        stream.send("operation", operation({
            op_id: "scan:grype:v1", queue_id: "q-1", status: "error", error: "grype binary not found",
        }));

        await expect(pending).resolves.toHaveLength(1);
    });
});

describe("refresh progress adapter", () => {
    it("reports idle for a source that has never run", () => {
        connect();

        expect(refreshProgressOf("nvd")).toMatchObject({ in_progress: false, phase: "idle" });
    });

    it("derives the legacy progress shape from a running refresh", () => {
        const stream = connect();
        stream.send("snapshot", {
            seq: 1,
            operations: [operation({
                op_id: "refresh:epss",
                kind: "refresh",
                source: "epss",
                label: "EPSS",
                status: "running",
                started_at: "2026-08-19T10:01:00+00:00",
                progress: { current: 40, total: 100, message: "EPSS refresh: 40/100" },
            })],
        });

        expect(refreshProgressOf("epss")).toEqual({
            in_progress: true,
            phase: "running",
            current: 40,
            total: 100,
            message: "EPSS refresh: 40/100",
            started_at: "2026-08-19T10:01:00+00:00",
        });
    });

    it("maps a finished refresh to the completed phase", () => {
        const stream = connect();
        stream.send("snapshot", {
            seq: 1,
            operations: [operation({
                op_id: "refresh:ghsa", kind: "refresh", source: "ghsa", label: "GHSA", status: "done",
            })],
        });

        expect(refreshProgressOf("ghsa")).toMatchObject({ in_progress: false, phase: "completed" });
    });

    it("keeps a cancelled refresh distinct from a completed one", () => {
        const stream = connect();
        stream.send("snapshot", {
            seq: 1,
            operations: [operation({
                op_id: "refresh:nvd",
                kind: "refresh",
                source: "nvd",
                label: "NVD",
                status: "cancelled",
                progress: { current: 1, total: 2, message: "Cancelled" },
            })],
        });

        expect(refreshProgressOf("nvd")).toMatchObject({
            in_progress: false,
            phase: "cancelled",
            current: 1,
            total: 2,
        });
    });

    it("maps a failed refresh to the error phase", () => {
        const stream = connect();
        stream.send("snapshot", {
            seq: 1,
            operations: [operation({
                op_id: "refresh:euvd", kind: "refresh", source: "euvd", label: "EUVD",
                status: "error", error: "EUVD unreachable",
            })],
        });

        expect(refreshProgressOf("euvd")).toMatchObject({ in_progress: false, phase: "error" });
    });
});

describe("refresh progress percentage", () => {
    const view = (overrides: Partial<RefreshProgressView>): RefreshProgressView => ({
        in_progress: false,
        phase: "idle",
        current: 0,
        total: 0,
        message: "",
        ...overrides,
    });

    it("reports nothing done while idle", () => {
        expect(refreshProgressPercentage(view({ phase: "idle" }))).toBe(0);
    });

    it("reports everything done once the phase is completed", () => {
        expect(refreshProgressPercentage(view({ phase: "completed", current: 100, total: 100 }))).toBe(1);
    });

    it("reports nothing done while the total is still unknown", () => {
        expect(refreshProgressPercentage(view({ in_progress: true, phase: "running" }))).toBe(0);
    });

    it("reports the ratio of processed items", () => {
        expect(refreshProgressPercentage(view({ in_progress: true, phase: "running", current: 50, total: 100 }))).toBe(0.5);
        expect(refreshProgressPercentage(view({ in_progress: true, phase: "running", current: 25, total: 100 }))).toBe(0.25);
        expect(refreshProgressPercentage(view({ in_progress: true, phase: "running", current: 33, total: 100 }))).toBe(0.33);
    });

    it("never reports more than everything done", () => {
        expect(refreshProgressPercentage(view({ in_progress: true, phase: "running", current: 120, total: 100 }))).toBe(1);
        expect(refreshProgressPercentage(view({ in_progress: true, phase: "running", current: 100, total: 100 }))).toBe(1);
    });
});

describe("enqueueing work", () => {
    it("sends scans and refreshes as one batch", async () => {
        const fetchSpy = jest.spyOn(global, "fetch").mockResolvedValue({
            status: 202,
            json: async () => ({ queue_id: "q-9", operations: [] }),
        } as Response);

        const result = await Operations.enqueue([
            Operations.scanJob("grype", ["v1", "v2"], { excludeKernel: false }),
            Operations.refreshJob("epss", ["CVE-2024-1111"]),
        ]);

        expect(result).toEqual({ ok: true, queueId: "q-9", operations: [] });
        const body = JSON.parse((fetchSpy.mock.calls[0][1] as RequestInit).body as string);
        expect(body.jobs[0]).toEqual({
            kind: "scan",
            source: "grype",
            variant_ids: ["v1", "v2"],
            options: { exclude_kernel: false, mode: "local" },
        });
        expect(body.jobs[1]).toEqual({
            kind: "refresh",
            source: "epss",
            ids: ["CVE-2024-1111"],
            options: { mode: "local" },
        });
    });

    it("surfaces the conflicting operations when a batch is already running", async () => {
        jest.spyOn(global, "fetch").mockResolvedValue({
            status: 409,
            json: async () => ({ error: "already queued", operations: ["scan:grype:v1"] }),
        } as Response);

        const result = await Operations.enqueue([Operations.scanJob("grype", ["v1"])]);

        expect(result).toEqual({ ok: false, error: "already queued", conflicts: ["scan:grype:v1"] });
    });

    it("builds a deferred refresh target for an atomic scan batch", () => {
        expect(Operations.deferredRefreshJob(
            "epss", ["v1", "v2"], ["CVE-2024-1111"],
        )).toEqual({
            kind: "refresh",
            source: "epss",
            variant_ids: ["v1", "v2"],
            exclude_ids: ["CVE-2024-1111"],
            options: { mode: "local" },
        });
    });

    it("cancels a single operation", async () => {
        const fetchSpy = jest.spyOn(global, "fetch").mockResolvedValue({ ok: true } as Response);

        await Operations.cancel("scan:grype:v1");

        expect(fetchSpy.mock.calls[0][0]).toContain("/api/operations/scan%3Agrype%3Av1/cancel");
    });

    it("dismisses a finished operation for every client", async () => {
        const fetchSpy = jest.spyOn(global, "fetch").mockResolvedValue({ ok: true } as Response);

        await Operations.dismiss("scan:grype:v1");

        expect(fetchSpy.mock.calls[0][1]).toMatchObject({ method: "DELETE" });
    });
});

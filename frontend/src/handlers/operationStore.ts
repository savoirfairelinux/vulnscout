/**
 * Single source of truth for every long-running backend operation.
 *
 * One `EventSource` replaces the per-scan managers, the refresh queue, the
 * upload poll and the export poll. The backend owns sequencing, so this module
 * only mirrors what the stream reports and exposes it through the
 * `useSyncExternalStore` contract.
 */

import type { Operation, OperationKind } from "../types/operation";
import { isActive } from "../types/operation";

const STREAM_PATH = "/api/events/stream";

/** Backoff schedule for reconnects, in milliseconds. */
const RECONNECT_DELAYS_MS = [500, 1000, 2000, 5000, 10000];

export type ConnectionState = "idle" | "connecting" | "open" | "reconnecting";

type SnapshotFrame = { seq: number; operations: Operation[] };
type RemovedFrame = { op_id: string };

let operations = new Map<string, Operation>();
let snapshot: readonly Operation[] = [];
let connection: ConnectionState = "idle";

const listeners = new Set<() => void>();
let source: EventSource | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectAttempt = 0;
// Highest sequence seen, sent back on reconnect so the server replays the
// missed deltas instead of resending a full snapshot.
let lastEventId: number | null = null;

/** Swappable so tests can drive the store without a live server. */
let createEventSource: (url: string) => EventSource = url => new EventSource(url);

const streamUrl = (): string => {
    const base = import.meta.env.VITE_API_URL + STREAM_PATH;
    return lastEventId === null ? base : `${base}?last_event_id=${lastEventId}`;
};

function emit() {
    // Sorting by creation keeps the queue order stable across re-renders.
    snapshot = [...operations.values()].sort((a, b) => {
        if (a.created_at !== b.created_at) return a.created_at < b.created_at ? -1 : 1;
        return a.op_id < b.op_id ? -1 : 1;
    });
    listeners.forEach(listener => listener());
}

function setConnection(next: ConnectionState) {
    if (connection === next) return;
    connection = next;
    listeners.forEach(listener => listener());
}

function applySnapshot(frame: SnapshotFrame) {
    operations = new Map(frame.operations.map(operation => [operation.op_id, operation]));
    emit();
}

function applyOperation(operation: Operation) {
    operations.set(operation.op_id, operation);
    emit();
}

function applyRemoval(frame: RemovedFrame) {
    if (operations.delete(frame.op_id)) emit();
}

function parse<T>(event: MessageEvent): T | null {
    try {
        return JSON.parse(event.data) as T;
    } catch {
        return null;
    }
}

function trackEventId(event: MessageEvent) {
    const id = Number.parseInt(event.lastEventId, 10);
    if (!Number.isNaN(id)) lastEventId = id;
}

function scheduleReconnect() {
    if (reconnectTimer !== null) return;
    const delay = RECONNECT_DELAYS_MS[Math.min(reconnectAttempt, RECONNECT_DELAYS_MS.length - 1)];
    reconnectAttempt += 1;
    setConnection("reconnecting");
    reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        openStream();
    }, delay);
}

function openStream() {
    if (source !== null) return;
    setConnection(connection === "reconnecting" ? "reconnecting" : "connecting");

    const stream = createEventSource(streamUrl());
    source = stream;

    stream.addEventListener("snapshot", event => {
        reconnectAttempt = 0;
        setConnection("open");
        const frame = parse<SnapshotFrame>(event as MessageEvent);
        if (frame) {
            lastEventId = frame.seq;
            applySnapshot(frame);
        }
    });

    stream.addEventListener("operation", event => {
        setConnection("open");
        trackEventId(event as MessageEvent);
        const operation = parse<Operation>(event as MessageEvent);
        if (operation) applyOperation(operation);
    });

    stream.addEventListener("operation_removed", event => {
        trackEventId(event as MessageEvent);
        const frame = parse<RemovedFrame>(event as MessageEvent);
        if (frame) applyRemoval(frame);
    });

    stream.addEventListener("heartbeat", () => {
        reconnectAttempt = 0;
        setConnection("open");
    });

    // The server is going away; reconnecting picks up a fresh snapshot.
    stream.addEventListener("bye", () => {
        closeStream();
        scheduleReconnect();
    });

    stream.onerror = () => {
        closeStream();
        scheduleReconnect();
    };
}

function closeStream() {
    if (source === null) return;
    source.close();
    source = null;
}

/** Full teardown once nothing is listening: no stream, no pending reconnect. */
function teardown() {
    if (reconnectTimer !== null) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
    }
    closeStream();
    reconnectAttempt = 0;
    connection = "idle";
}

// ---- useSyncExternalStore API ----

export const subscribe = (listener: () => void): (() => void) => {
    listeners.add(listener);
    openStream();
    return () => {
        listeners.delete(listener);
        if (listeners.size === 0) teardown();
    };
};

export const getSnapshot = (): readonly Operation[] => snapshot;

export const subscribeToConnection = subscribe;

export const getConnectionState = (): ConnectionState => connection;

// ---- selectors ----

export const getOperation = (opId: string): Operation | undefined => operations.get(opId);

export const selectByKind = (kind: OperationKind): Operation[] =>
    snapshot.filter(operation => operation.kind === kind);

export const selectBySource = (kind: OperationKind, source_: string): Operation[] =>
    snapshot.filter(operation => operation.kind === kind && operation.source === source_);

export const selectByQueue = (queueId: string): Operation[] =>
    snapshot.filter(operation => operation.queue_id === queueId);

export const hasActive = (kind?: OperationKind): boolean =>
    snapshot.some(operation => isActive(operation) && (kind === undefined || operation.kind === kind));

export const hasActiveSource = (kind: OperationKind, source_: string): boolean =>
    snapshot.some(operation => isActive(operation) && operation.kind === kind && operation.source === source_);

/** Resolves once no operation of *queueId* is queued or running. */
export const waitForQueue = (queueId: string): Promise<Operation[]> =>
    new Promise(resolve => {
        const settled = () => {
            const batch = selectByQueue(queueId);
            // An empty batch means the snapshot has not caught up yet.
            return batch.length > 0 && !batch.some(isActive) ? batch : null;
        };

        const immediate = settled();
        if (immediate) {
            resolve(immediate);
            return;
        }

        const unsubscribe = subscribe(() => {
            const batch = settled();
            if (!batch) return;
            unsubscribe();
            resolve(batch);
        });
    });

// ---- refresh progress adapter ----

/**
 * The legacy per-source progress shape the vulnerability table renders.
 *
 * Derived from the stream rather than fetched, so the four `/progress`
 * endpoints are no longer needed.
 */
export type RefreshProgressView = {
    in_progress: boolean;
    phase: string;
    current: number;
    total: number;
    message: string;
    started_at?: string;
};

const IDLE_REFRESH: RefreshProgressView = {
    in_progress: false,
    phase: "idle",
    current: 0,
    total: 0,
    message: "No update in progress",
};

const PHASE_BY_STATUS: Record<string, string> = {
    queued: "queued",
    running: "running",
    done: "completed",
    error: "error",
    cancelled: "cancelled",
};

export const refreshProgressOf = (source: string): RefreshProgressView => {
    const operation = operations.get(`refresh:${source}`);
    if (!operation) return IDLE_REFRESH;
    return {
        in_progress: isActive(operation),
        phase: PHASE_BY_STATUS[operation.status] ?? operation.status,
        current: operation.progress.current,
        total: operation.progress.total,
        message: operation.progress.message,
        started_at: operation.started_at ?? undefined,
    };
};

export const refreshProgressPercentage = (progress: RefreshProgressView): number => {
    if (!progress.in_progress || progress.total === 0) {
        return progress.phase === "completed" ? 1 : 0;
    }
    return Math.min(progress.current / progress.total, 1);
};

// ---- test seams ----

/** Replaces the EventSource factory. Returns a function restoring the default. */
export const __setEventSourceFactory = (factory: (url: string) => EventSource): (() => void) => {
    const previous = createEventSource;
    createEventSource = factory;
    return () => {
        createEventSource = previous;
    };
};

export const __reset = () => {
    if (reconnectTimer !== null) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
    }
    closeStream();
    listeners.clear();
    operations = new Map();
    snapshot = [];
    connection = "idle";
    reconnectAttempt = 0;
    lastEventId = null;
};

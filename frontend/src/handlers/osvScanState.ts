/**
 * OSV PURL scan state — per-variant progress tracking.
 *
 * Thin wrapper around the generic ScanStateManager.
 * Lives at module scope so state survives component unmounts.
 */

import ScansHandler from "./scans";
import { ScanStateManager } from "./scanStateManager";
export type { ScanEntryState as OsvState, ScanManagerSnapshot } from "./scanStateManager";

const manager = new ScanStateManager(
    (vid, opts) => ScansHandler.triggerOsvScan(vid, opts.excludeKernel ?? true),
    (vid) => ScansHandler.getOsvScanStatus(vid),
    "OSV",
    true, // serial: scans share the global queue with the other scan types
);

export const subscribe = manager.subscribe;
export const getSnapshot = manager.getSnapshot;
export const setOnDone = manager.setOnDone;
export const triggerScan = manager.triggerScan;
export const waitForCompletion = manager.waitForCompletion;
export const queueScan = manager.queueScan;
export const startQueuedScan = manager.startQueuedScan;
export const dismiss = manager.dismiss;
export const dismissAll = manager.dismissAll;
export const restoreFromStatus = manager.restoreFromStatus;

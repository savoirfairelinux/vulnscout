/**
 * Grype scan state — per-variant progress tracking.
 *
 * Thin wrapper around the generic ScanStateManager.
 * Lives at module scope so state survives component unmounts.
 */

import ScansHandler from "./scans";
import { ScanStateManager } from "./scanStateManager";
export type { ScanEntryState as GrypeState, ScanManagerSnapshot } from "./scanStateManager";

const manager = new ScanStateManager(
    (vid, opts) => ScansHandler.triggerGrypeScan(vid, opts.excludeKernel ?? true),
    (vid) => ScansHandler.getGrypeScanStatus(vid),
    "Grype",
    true, // serial: run one variant at a time (flask process is global)
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

/**
 * sbom-cve-check scan state — per-variant progress tracking.
 *
 * Thin wrapper around the generic ScanStateManager.
 * Lives at module scope so state survives component unmounts.
 */

import ScansHandler from "./scans";
import { ScanStateManager } from "./scanStateManager";
export type { ScanEntryState as SccState, ScanManagerSnapshot } from "./scanStateManager";

const manager = new ScanStateManager(
    (vid, opts) => ScansHandler.triggerSbomCveCheckScan(vid, opts.excludeKernel ?? true),
    (vid) => ScansHandler.getSbomCveCheckScanStatus(vid),
    "sbom-cve-check",
);

export const subscribe = manager.subscribe;
export const getSnapshot = manager.getSnapshot;
export const setOnDone = manager.setOnDone;
export const triggerScan = manager.triggerScan;
export const dismiss = manager.dismiss;
export const dismissAll = manager.dismissAll;
export const restoreFromStatus = manager.restoreFromStatus;

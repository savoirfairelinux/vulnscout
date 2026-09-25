/**
 * Collapses the tool scans of each scan run into one scan-history entry.
 */

import type { Scan, ScanRunSummary } from "../handlers/scans";

export type ScanTimelineEntry =
    | { kind: "scan"; scan: Scan }
    | { kind: "run"; key: string; run: ScanRunSummary; steps: Scan[] };

/**
 * Keeps the order of *scans* (newest first), placing each run at its most
 * recent step. Steps are returned in launch order.
 */
export function groupScanRuns(scans: readonly Scan[]): ScanTimelineEntry[] {
    const runs = new Map<string, Scan[]>();
    const order: Array<Scan | string> = [];
    scans.forEach(scan => {
        if (!scan.run) {
            order.push(scan);
            return;
        }
        const key = `${scan.run.id}:${scan.variant_id}`;
        const steps = runs.get(key);
        if (steps === undefined) {
            runs.set(key, [scan]);
            order.push(key);
        } else {
            steps.push(scan);
        }
    });
    return order.map(entry => {
        if (typeof entry !== "string") return { kind: "scan", scan: entry };
        const steps = runs.get(entry)!.reverse();
        return { kind: "run", key: entry, run: steps[0].run!, steps };
    });
}

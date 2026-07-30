import { getSnapshot as getGrypeSnapshot, waitForCompletion as waitForGrypeCompletion } from "./grypeScanState";
import { getSnapshot as getNvdSnapshot, waitForCompletion as waitForNvdCompletion } from "./nvdScanState";
import { getSnapshot as getOsvSnapshot, waitForCompletion as waitForOsvCompletion } from "./osvScanState";
import { getSnapshot as getSccSnapshot, waitForCompletion as waitForSccCompletion } from "./sccScanState";

const isActive = (status: string) => status === "queued" || status === "running";

export async function waitForActiveScans(): Promise<boolean> {
    const scanQueues = [
        [getGrypeSnapshot, waitForGrypeCompletion],
        [getNvdSnapshot, waitForNvdCompletion],
        [getOsvSnapshot, waitForOsvCompletion],
        [getSccSnapshot, waitForSccCompletion],
    ] as const;
    const activeQueues = scanQueues.filter(([getSnapshot]) => getSnapshot().some(scan => isActive(scan.status)));
    if (activeQueues.length === 0) return false;

    await Promise.all(activeQueues.map(([, waitForCompletion]) => waitForCompletion()));
    return true;
}
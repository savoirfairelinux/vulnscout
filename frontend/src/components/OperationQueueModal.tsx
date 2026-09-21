import { useSyncExternalStore } from "react";
import { faBug, faShieldHalved, faLeaf, faCrosshairs, faArrowsRotate, faFileExport } from "@fortawesome/free-solid-svg-icons";
import OperationQueuePanel from "./OperationQueuePanel";
import ModalShell from "./ModalShell";
import { subscribe as grypeSubscribe, getSnapshot as grypeGetSnapshot, dismiss as grypeDismiss } from "../handlers/grypeScanState";
import { subscribe as nvdSubscribe, getSnapshot as nvdGetSnapshot, dismiss as nvdDismiss } from "../handlers/nvdScanState";
import { subscribe as osvSubscribe, getSnapshot as osvGetSnapshot, dismiss as osvDismiss } from "../handlers/osvScanState";
import { subscribe as sccSubscribe, getSnapshot as sccGetSnapshot, dismiss as sccDismiss } from "../handlers/sccScanState";
import { subscribeToRefreshQueue, getRefreshQueueSnapshot, dismissRefreshQueueEntry } from "../handlers/activeScanQueue";
import type { RefreshType } from "../handlers/activeScanQueue";
import { subscribe as exportSubscribe, getSnapshot as exportGetSnapshot, dismiss as exportDismiss } from "../handlers/exportQueue";

type Props = {
    isOpen: boolean;
    onClose: () => void;
};

const grypeColors = { border: "border-purple-700/60", headerBg: "bg-purple-900/40", iconText: "text-purple-400", titleText: "text-purple-200", subtitleText: "text-purple-300/80", bar: "bg-purple-500" };
const nvdColors = { border: "border-orange-700/60", headerBg: "bg-orange-900/40", iconText: "text-orange-400", titleText: "text-orange-200", subtitleText: "text-orange-300/80", bar: "bg-orange-500" };
const osvColors = { border: "border-green-700/60", headerBg: "bg-green-900/40", iconText: "text-green-400", titleText: "text-green-200", subtitleText: "text-green-300/80", bar: "bg-green-500" };
const sccColors = { border: "border-sky-700/60", headerBg: "bg-sky-900/40", iconText: "text-sky-400", titleText: "text-sky-200", subtitleText: "text-sky-300/80", bar: "bg-sky-500" };
const refreshColors = { border: "border-cyan-700/60", headerBg: "bg-cyan-900/40", iconText: "text-cyan-400", titleText: "text-cyan-200", subtitleText: "text-cyan-300/80", bar: "bg-cyan-500" };
const exportColors = { border: "border-teal-700/60", headerBg: "bg-teal-900/40", iconText: "text-teal-400", titleText: "text-teal-200", subtitleText: "text-teal-300/80", bar: "bg-teal-500" };

function OperationQueueModal({ isOpen, onClose }: Readonly<Props>) {
    const grypeEntries = useSyncExternalStore(grypeSubscribe, grypeGetSnapshot);
    const nvdEntries = useSyncExternalStore(nvdSubscribe, nvdGetSnapshot);
    const osvEntries = useSyncExternalStore(osvSubscribe, osvGetSnapshot);
    const sccEntries = useSyncExternalStore(sccSubscribe, sccGetSnapshot);
    const refreshEntries = useSyncExternalStore(subscribeToRefreshQueue, getRefreshQueueSnapshot);
    const exportEntries = useSyncExternalStore(exportSubscribe, exportGetSnapshot);

    if (!isOpen) return null;

    const hasEntries = grypeEntries.length + nvdEntries.length + osvEntries.length + sccEntries.length + refreshEntries.length + exportEntries.length > 0;

    return (
        <ModalShell
            isOpen={isOpen}
            title="Operation queue"
            subtitle="This window can be safely closed. Track the operation queue in the navigation bar."
            titleId="operation-queue-title"
            onClose={onClose}
            closeLabel="Close operation queue"
            size="large"
            contentClassName="overflow-y-auto"
        >
            {hasEntries ? (
                <div className="overflow-hidden rounded-lg border border-neutral-700 divide-y divide-neutral-700">
                    {grypeEntries.map(entry => (
                        <OperationQueuePanel key={`grype-${entry.variantId}`} entry={entry} label="Grype Scan" icon={faBug} colors={grypeColors} onDismiss={() => grypeDismiss(entry.variantId)} />
                    ))}
                    {nvdEntries.map(entry => (
                        <OperationQueuePanel key={`nvd-${entry.variantId}`} entry={entry} label="NVD Scan" icon={faShieldHalved} colors={nvdColors} onDismiss={() => nvdDismiss(entry.variantId)} />
                    ))}
                    {osvEntries.map(entry => (
                        <OperationQueuePanel key={`osv-${entry.variantId}`} entry={entry} label="OSV Scan" icon={faLeaf} colors={osvColors} onDismiss={() => osvDismiss(entry.variantId)} />
                    ))}
                    {sccEntries.map(entry => (
                        <OperationQueuePanel key={`scc-${entry.variantId}`} entry={entry} label="sbom-cve-check Scan" icon={faCrosshairs} colors={sccColors} onDismiss={() => sccDismiss(entry.variantId)} />
                    ))}
                    {refreshEntries.map(entry => (
                        <OperationQueuePanel key={entry.variantId} entry={entry} label="Vulnerability Data Refresh" icon={faArrowsRotate} colors={refreshColors} onDismiss={() => dismissRefreshQueueEntry(entry.variantId as RefreshType)} />
                    ))}
                    {exportEntries.map(entry => (
                        <OperationQueuePanel key={entry.variantId} entry={entry} label="Export" icon={faFileExport} colors={exportColors} onDismiss={() => exportDismiss(entry.variantId)} />
                    ))}
                </div>
            ) : (
                <p className="py-8 text-center text-sm text-neutral-400">No operations to display.</p>
            )}
        </ModalShell>
    );
}

export default OperationQueueModal;
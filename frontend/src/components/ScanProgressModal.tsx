import { useEffect, useRef, useSyncExternalStore } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faBug, faShieldHalved, faLeaf, faCrosshairs, faXmark } from "@fortawesome/free-solid-svg-icons";
import ScanProgressPanel from "./ScanProgressPanel";
import { subscribe as grypeSubscribe, getSnapshot as grypeGetSnapshot, dismiss as grypeDismiss } from "../handlers/grypeScanState";
import { subscribe as nvdSubscribe, getSnapshot as nvdGetSnapshot, dismiss as nvdDismiss } from "../handlers/nvdScanState";
import { subscribe as osvSubscribe, getSnapshot as osvGetSnapshot, dismiss as osvDismiss } from "../handlers/osvScanState";
import { subscribe as sccSubscribe, getSnapshot as sccGetSnapshot, dismiss as sccDismiss } from "../handlers/sccScanState";

type Props = {
    isOpen: boolean;
    onClose: () => void;
};

const grypeColors = { border: "border-purple-700/60", headerBg: "bg-purple-900/40", iconText: "text-purple-400", titleText: "text-purple-200", subtitleText: "text-purple-300/80", bar: "bg-purple-500" };
const nvdColors = { border: "border-orange-700/60", headerBg: "bg-orange-900/40", iconText: "text-orange-400", titleText: "text-orange-200", subtitleText: "text-orange-300/80", bar: "bg-orange-500" };
const osvColors = { border: "border-green-700/60", headerBg: "bg-green-900/40", iconText: "text-green-400", titleText: "text-green-200", subtitleText: "text-green-300/80", bar: "bg-green-500" };
const sccColors = { border: "border-sky-700/60", headerBg: "bg-sky-900/40", iconText: "text-sky-400", titleText: "text-sky-200", subtitleText: "text-sky-300/80", bar: "bg-sky-500" };

function ScanProgressModal({ isOpen, onClose }: Readonly<Props>) {
    const overlayRef = useRef<HTMLDivElement>(null);
    const grypeEntries = useSyncExternalStore(grypeSubscribe, grypeGetSnapshot);
    const nvdEntries = useSyncExternalStore(nvdSubscribe, nvdGetSnapshot);
    const osvEntries = useSyncExternalStore(osvSubscribe, osvGetSnapshot);
    const sccEntries = useSyncExternalStore(sccSubscribe, sccGetSnapshot);

    useEffect(() => {
        if (!isOpen) return;

        const handleKeyDown = (event: KeyboardEvent) => {
            if (event.key === "Escape") onClose();
        };
        document.addEventListener("keydown", handleKeyDown);
        return () => document.removeEventListener("keydown", handleKeyDown);
    }, [isOpen, onClose]);

    if (!isOpen) return null;

    const hasEntries = grypeEntries.length + nvdEntries.length + osvEntries.length + sccEntries.length > 0;

    return (
        <div
            ref={overlayRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="scan-progress-title"
            className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 p-4"
            onMouseDown={event => {
                if (event.target === overlayRef.current) onClose();
            }}
        >
            <div className="flex max-h-[min(42rem,calc(100vh-2rem))] w-full max-w-3xl flex-col overflow-hidden rounded-lg bg-neutral-900 shadow-xl">
                <div className="flex items-center justify-between border-b border-neutral-700 px-4 py-3">
                    <div>
                        <h2 id="scan-progress-title" className="text-lg font-semibold text-white">Scan progress</h2>
                        <p className="text-sm text-neutral-400">This window can be safely closed. Track scan progress in the navigation bar.</p>
                    </div>
                    <button
                        type="button"
                        onClick={onClose}
                        aria-label="Close scan progress"
                        className="inline-flex h-8 w-8 items-center justify-center rounded text-neutral-400 transition-colors hover:bg-neutral-700 hover:text-white"
                    >
                        <FontAwesomeIcon icon={faXmark} />
                    </button>
                </div>
                <div className="overflow-y-auto p-4">
                    {hasEntries ? (
                        <div className="overflow-hidden rounded-lg border border-neutral-700 divide-y divide-neutral-700">
                            {grypeEntries.map(entry => (
                                <ScanProgressPanel key={`grype-${entry.variantId}`} entry={entry} label="Grype Scan" icon={faBug} colors={grypeColors} onDismiss={() => grypeDismiss(entry.variantId)} />
                            ))}
                            {nvdEntries.map(entry => (
                                <ScanProgressPanel key={`nvd-${entry.variantId}`} entry={entry} label="NVD Scan" icon={faShieldHalved} colors={nvdColors} onDismiss={() => nvdDismiss(entry.variantId)} />
                            ))}
                            {osvEntries.map(entry => (
                                <ScanProgressPanel key={`osv-${entry.variantId}`} entry={entry} label="OSV Scan" icon={faLeaf} colors={osvColors} onDismiss={() => osvDismiss(entry.variantId)} />
                            ))}
                            {sccEntries.map(entry => (
                                <ScanProgressPanel key={`scc-${entry.variantId}`} entry={entry} label="sbom-cve-check Scan" icon={faCrosshairs} colors={sccColors} onDismiss={() => sccDismiss(entry.variantId)} />
                            ))}
                        </div>
                    ) : (
                        <p className="py-8 text-center text-sm text-neutral-400">No scan progress to display.</p>
                    )}
                </div>
            </div>
        </div>
    );
}

export default ScanProgressModal;
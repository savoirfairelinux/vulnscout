import { useEffect } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faRotate, faTimes } from "@fortawesome/free-solid-svg-icons";

type Props = {
    changedCves: string[];
    onClose: () => void;
};

/**
 * Non-blocking toast shown after a bulk NVD refresh completes.
 * Auto-dismisses after 15 seconds; can also be closed manually.
 */
function RefreshToast({ changedCves, onClose }: Readonly<Props>) {
    useEffect(() => {
        const timer = setTimeout(onClose, 15000);
        return () => clearTimeout(timer);
    }, [onClose]);

    return (
        <div className="fixed bottom-5 right-5 z-50 w-80 rounded-lg border border-sky-600 bg-sky-950 text-neutral-50 shadow-xl p-4">
            <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                    <FontAwesomeIcon icon={faRotate} className="text-sky-400 shrink-0" />
                    <p className="text-sm font-semibold text-sky-300">NVD Refresh Complete</p>
                </div>
                <button
                    onClick={onClose}
                    className="text-neutral-400 hover:text-white transition-colors"
                    aria-label="Dismiss"
                >
                    <FontAwesomeIcon icon={faTimes} className="w-3.5 h-3.5" />
                </button>
            </div>

            {changedCves.length === 0 ? (
                <p className="mt-2 text-xs text-neutral-300">No CVEs were updated.</p>
            ) : (
                <>
                    <p className="mt-2 text-xs text-neutral-300">
                        {changedCves.length} CVE{changedCves.length !== 1 ? "s" : ""} updated with fresh NVD data:
                    </p>
                    <ul className="mt-1 max-h-32 overflow-y-auto space-y-0.5">
                        {changedCves.map(id => (
                            <li key={id} className="text-xs font-mono text-sky-200 truncate">{id}</li>
                        ))}
                    </ul>
                </>
            )}
        </div>
    );
}

export default RefreshToast;

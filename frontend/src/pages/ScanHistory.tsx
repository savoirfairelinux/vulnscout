import { useEffect, useRef, useState, useCallback, useSyncExternalStore } from "react";
import ScansHandler from "../handlers/scans";
import type { Scan, ScanDiff, FindingDiffEntry, FindingUpgradeEntry, PackageDiffEntry, PackageUpgradeEntry, AssessmentDiffEntry, GlobalResult } from "../handlers/scans";
import { subscribe, getSnapshot, setOnDone, triggerScan, dismiss as grypeDismiss } from "../handlers/grypeScanState";
import {
    subscribe as nvdSubscribe,
    getSnapshot as nvdGetSnapshot,
    setOnDone as nvdSetOnDone,
    triggerScan as nvdTriggerScan,
    dismiss as nvdDismiss,
} from "../handlers/nvdScanState";
import {
    subscribe as osvSubscribe,
    getSnapshot as osvGetSnapshot,
    setOnDone as osvSetOnDone,
    triggerScan as osvTriggerScan,
    dismiss as osvDismiss,
} from "../handlers/osvScanState";
import type { ScanManagerSnapshot } from "../handlers/scanStateManager";
import ScanProgressPanel from "../components/ScanProgressPanel";
import { useDocUrl } from "../helpers/useDocUrl";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faPencil, faCheck, faXmark, faBug, faFilter, faShieldHalved, faLeaf, faFile, faCrosshairs, faTrash, faPlay, faBook } from "@fortawesome/free-solid-svg-icons";
import ConfirmationModal from "../components/ConfirmationModal";
import Variants from "../handlers/variant";
import type { Variant } from "../handlers/variant";

type Props = {
    variantId?: string;
    projectId?: string;
    onScanComplete?: () => void;
};

function formatDate(iso: string): string {
    const d = new Date(iso);
    return d.toLocaleDateString(undefined, {
        year: 'numeric',
        month: 'short',
        day: '2-digit',
    }) + ' ' + d.toLocaleTimeString(undefined, {
        hour: '2-digit',
        minute: '2-digit',
        timeZoneName: 'short',
    });
}

// ---------------------------------------------------------------------------
// Diff detail modal
// ---------------------------------------------------------------------------

function FindingDiffTable({ entries, label, colorClass }: {
    entries: FindingDiffEntry[];
    label: string;
    colorClass: string;
}) {
    const [filter, setFilter] = useState('');
    const hasOrigin = entries.some(e => e.origin);
    const filtered = filter
        ? entries.filter(e =>
            e.package_name.toLowerCase().includes(filter.toLowerCase()) ||
            e.package_version.toLowerCase().includes(filter.toLowerCase()) ||
            e.vulnerability_id.toLowerCase().includes(filter.toLowerCase()) ||
            (e.origin || '').toLowerCase().includes(filter.toLowerCase())
        )
        : entries;

    return (
        <div className="mb-6">
            <div className="flex items-center justify-between mb-2 gap-3">
                <h3 className={["font-bold text-base", colorClass].join(' ')}>
                    {label} ({entries.length})
                </h3>
                <input
                    type="text"
                    placeholder="Filter\u2026"
                    value={filter}
                    onChange={e => setFilter(e.target.value)}
                    className="text-xs px-2 py-1 rounded border border-gray-600 bg-gray-800 text-gray-200 w-48"
                />
            </div>
            {entries.length === 0 ? (
                <p className="text-sm text-gray-400 italic">None</p>
            ) : (
                <div className="overflow-auto max-h-48 rounded border border-gray-600">
                    <table className="w-full text-xs text-left">
                        <thead className="sticky top-0 bg-gray-800 text-gray-300 uppercase">
                            <tr>
                                <th className="px-3 py-2">Package</th>
                                <th className="px-3 py-2">Version</th>
                                <th className="px-3 py-2">Vulnerability</th>
                                {hasOrigin && <th className="px-3 py-2">Origin</th>}
                            </tr>
                        </thead>
                        <tbody>
                            {filtered.map((e) => (
                                <tr key={e.finding_id} className="border-t border-gray-600 hover:bg-gray-600/40">
                                    <td className="px-3 py-1.5 font-mono">{e.package_name}</td>
                                    <td className="px-3 py-1.5 font-mono text-gray-400">{e.package_version}</td>
                                    <td className="px-3 py-1.5 font-mono">{e.vulnerability_id}</td>
                                    {hasOrigin && <td className="px-3 py-1.5 text-gray-400">{e.origin ?? ''}</td>}
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}

function FindingUpgradeDiffTable({ entries, label, colorClass }: {
    entries: FindingUpgradeEntry[];
    label: string;
    colorClass: string;
}) {
    const [filter, setFilter] = useState('');
    const hasOrigin = entries.some(e => !!e.origin);
    const filtered = filter
        ? entries.filter(e =>
            e.package_name.toLowerCase().includes(filter.toLowerCase()) ||
            e.vulnerability_id.toLowerCase().includes(filter.toLowerCase()) ||
            e.old_version.toLowerCase().includes(filter.toLowerCase()) ||
            e.new_version.toLowerCase().includes(filter.toLowerCase()) ||
            (e.origin || '').toLowerCase().includes(filter.toLowerCase())
        )
        : entries;

    return (
        <div className="mb-6">
            <div className="flex items-center justify-between mb-2 gap-3">
                <h3 className={["font-bold text-base", colorClass].join(' ')}>
                    {label} ({entries.length})
                </h3>
                <input
                    type="text"
                    placeholder="Filter&#x2026;"
                    value={filter}
                    onChange={e => setFilter(e.target.value)}
                    className="text-xs px-2 py-1 rounded border border-gray-600 bg-gray-800 text-gray-200 w-48"
                />
            </div>
            {entries.length === 0 ? (
                <p className="text-sm text-gray-400 italic">None</p>
            ) : (
                <div className="overflow-auto max-h-48 rounded border border-gray-600">
                    <table className="w-full text-xs text-left">
                        <thead className="sticky top-0 bg-gray-800 text-gray-300 uppercase">
                            <tr>
                                <th className="px-3 py-2">Package</th>
                                <th className="px-3 py-2">Old Version</th>
                                <th className="px-3 py-2">New Version</th>
                                <th className="px-3 py-2">Vulnerability</th>
                                {hasOrigin && <th className="px-3 py-2">Origin</th>}
                            </tr>
                        </thead>
                        <tbody>
                            {filtered.map((e, i) => (
                                <tr key={e.vulnerability_id + e.package_name + i} className="border-t border-gray-600 hover:bg-gray-600/40">
                                    <td className="px-3 py-1.5 font-mono">{e.package_name}</td>
                                    <td className="px-3 py-1.5 font-mono text-red-400">{e.old_version}</td>
                                    <td className="px-3 py-1.5 font-mono text-green-400">{e.new_version}</td>
                                    <td className="px-3 py-1.5 font-mono">{e.vulnerability_id}</td>
                                    {hasOrigin && <td className="px-3 py-1.5 text-gray-400">{e.origin ?? ''}</td>}
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}

function PackageDiffTable({ entries, label, colorClass }: {
    entries: PackageDiffEntry[];
    label: string;
    colorClass: string;
}) {
    const [filter, setFilter] = useState('');
    const filtered = filter
        ? entries.filter(e =>
            e.package_name.toLowerCase().includes(filter.toLowerCase()) ||
            e.package_version.toLowerCase().includes(filter.toLowerCase())
        )
        : entries;

    return (
        <div className="mb-6">
            <div className="flex items-center justify-between mb-2 gap-3">
                <h3 className={["font-bold text-base", colorClass].join(' ')}>
                    {label} ({entries.length})
                </h3>
                {entries.length > 10 && (
                    <input
                        type="text"
                        placeholder="Filter…"
                        value={filter}
                        onChange={e => setFilter(e.target.value)}
                        className="text-xs px-2 py-1 rounded border border-gray-600 bg-gray-800 text-gray-200 w-48"
                    />
                )}
            </div>
            {entries.length === 0 ? (
                <p className="text-sm text-gray-400 italic">None</p>
            ) : (
                <div className="overflow-auto max-h-48 rounded border border-gray-600">
                    <table className="w-full text-xs text-left">
                        <thead className="sticky top-0 bg-gray-800 text-gray-300 uppercase">
                            <tr>
                                <th className="px-3 py-2">Package</th>
                                <th className="px-3 py-2">Version</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filtered.map((e) => (
                                <tr key={e.package_id} className="border-t border-gray-600 hover:bg-gray-600/40">
                                    <td className="px-3 py-1.5 font-mono">{e.package_name}</td>
                                    <td className="px-3 py-1.5 font-mono text-gray-400">{e.package_version}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}

function PackageUpgradeDiffTable({ entries, label, colorClass }: {
    entries: PackageUpgradeEntry[];
    label: string;
    colorClass: string;
}) {
    const [filter, setFilter] = useState('');
    const filtered = filter
        ? entries.filter(e =>
            e.package_name.toLowerCase().includes(filter.toLowerCase()) ||
            e.old_version.toLowerCase().includes(filter.toLowerCase()) ||
            e.new_version.toLowerCase().includes(filter.toLowerCase())
        )
        : entries;

    return (
        <div className="mb-6">
            <div className="flex items-center justify-between mb-2 gap-3">
                <h3 className={["font-bold text-base", colorClass].join(' ')}>
                    {label} ({entries.length})
                </h3>
                {entries.length > 10 && (
                    <input
                        type="text"
                        placeholder="Filter…"
                        value={filter}
                        onChange={e => setFilter(e.target.value)}
                        className="text-xs px-2 py-1 rounded border border-gray-600 bg-gray-800 text-gray-200 w-48"
                    />
                )}
            </div>
            {entries.length === 0 ? (
                <p className="text-sm text-gray-400 italic">None</p>
            ) : (
                <div className="overflow-auto max-h-48 rounded border border-gray-600">
                    <table className="w-full text-xs text-left">
                        <thead className="sticky top-0 bg-gray-800 text-gray-300 uppercase">
                            <tr>
                                <th className="px-3 py-2">Package</th>
                                <th className="px-3 py-2">Old Version</th>
                                <th className="px-3 py-2">New Version</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filtered.map((e) => (
                                <tr key={e.old_package_id + e.new_package_id} className="border-t border-gray-600 hover:bg-gray-600/40">
                                    <td className="px-3 py-1.5 font-mono">{e.package_name}</td>
                                    <td className="px-3 py-1.5 font-mono text-red-400">{e.old_version}</td>
                                    <td className="px-3 py-1.5 font-mono text-green-400">{e.new_version}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}

function AssessmentDiffTable({ entries, label, colorClass }: {
    entries: AssessmentDiffEntry[];
    label: string;
    colorClass: string;
}) {
    const [filter, setFilter] = useState('');
    const filtered = filter
        ? entries.filter(e =>
            e.vulnerability_id.toLowerCase().includes(filter.toLowerCase()) ||
            e.status.toLowerCase().includes(filter.toLowerCase()) ||
            e.simplified_status.toLowerCase().includes(filter.toLowerCase()) ||
            e.justification.toLowerCase().includes(filter.toLowerCase()) ||
            e.impact_statement.toLowerCase().includes(filter.toLowerCase()) ||
            e.status_notes.toLowerCase().includes(filter.toLowerCase())
        )
        : entries;

    return (
        <div className="mb-6">
            <div className="flex items-center justify-between mb-2 gap-3">
                <h3 className={["font-bold text-base", colorClass].join(' ')}>
                    {label} ({entries.length})
                </h3>
                <input
                    type="text"
                    placeholder="Filter&#x2026;"
                    value={filter}
                    onChange={e => setFilter(e.target.value)}
                    className="text-xs px-2 py-1 rounded border border-gray-600 bg-gray-800 text-gray-200 w-48"
                />
            </div>
            {entries.length === 0 ? (
                <p className="text-sm text-gray-400 italic">None</p>
            ) : (
                <div className="overflow-auto max-h-64 rounded border border-gray-600">
                    <table className="w-full text-xs text-left">
                        <thead className="sticky top-0 bg-gray-800 text-gray-300 uppercase">
                            <tr>
                                <th className="px-3 py-2">Vulnerability</th>
                                <th className="px-3 py-2">Status</th>
                                <th className="px-3 py-2">Justification</th>
                                <th className="px-3 py-2">Impact</th>
                                <th className="px-3 py-2">Notes</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filtered.map((e, i) => (
                                <tr key={e.vulnerability_id + i} className="border-t border-gray-600 hover:bg-gray-600/40">
                                    <td className="px-3 py-1.5 font-mono">{e.vulnerability_id}</td>
                                    <td className="px-3 py-1.5">{e.simplified_status}</td>
                                    <td className="px-3 py-1.5 text-gray-400">{e.justification || '—'}</td>
                                    <td className="px-3 py-1.5 text-gray-400 max-w-xs truncate" title={e.impact_statement}>{e.impact_statement || '—'}</td>
                                    <td className="px-3 py-1.5 text-gray-400 max-w-xs truncate" title={e.status_notes}>{e.status_notes || '—'}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}

function VulnDiffList({ vulns, label, colorClass, originMap }: {
    vulns: string[];
    label: string;
    colorClass: string;
    originMap?: Record<string, string[]>;
}) {
    const [filter, setFilter] = useState('');
    const hasOrigin = !!originMap && Object.keys(originMap).length > 0;
    const filtered = filter
        ? vulns.filter(v =>
            v.toLowerCase().includes(filter.toLowerCase()) ||
            (originMap?.[v] || []).some(o => o.toLowerCase().includes(filter.toLowerCase()))
        )
        : vulns;

    return (
        <div className="mb-6">
            <div className="flex items-center justify-between mb-2 gap-3">
                <h3 className={["font-bold text-base", colorClass].join(' ')}>
                    {label} ({vulns.length})
                </h3>
                {vulns.length > 10 && (
                    <input
                        type="text"
                        placeholder="Filter…"
                        value={filter}
                        onChange={e => setFilter(e.target.value)}
                        className="text-xs px-2 py-1 rounded border border-gray-600 bg-gray-800 text-gray-200 w-48"
                    />
                )}
            </div>
            {vulns.length === 0 ? (
                <p className="text-sm text-gray-400 italic">None</p>
            ) : (
                <div className="overflow-auto max-h-64 rounded border border-gray-600">
                    <table className="w-full text-xs text-left">
                        <thead className="sticky top-0 bg-gray-800 text-gray-300 uppercase">
                            <tr>
                                <th className="px-3 py-2">CVE / Vulnerability ID</th>
                                {hasOrigin && <th className="px-3 py-2">Origin</th>}
                            </tr>
                        </thead>
                        <tbody>
                            {filtered.map((v) => (
                                <tr key={v} className="border-t border-gray-600 hover:bg-gray-600/40">
                                    <td className="px-3 py-1.5 font-mono">{v}</td>
                                    {hasOrigin && <td className="px-3 py-1.5 text-gray-400">{(originMap?.[v] || []).join(', ')}</td>}
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}

type Section = 'packages' | 'findings' | 'vulnerabilities' | 'assessments' | 'newly_detected';
type GlobalSection = 'packages' | 'findings' | 'vulnerabilities' | 'assessments';

// ---------------------------------------------------------------------------
// Scan Result modal — shows active items (SBOM ∪ Tool scan) with source
// ---------------------------------------------------------------------------

function GlobalResultModal({ scanId, onClose }: { scanId: string; onClose: () => void }) {
    const [data, setData] = useState<GlobalResult | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [section, setSection] = useState<GlobalSection>('packages');
    const [filter, setFilter] = useState('');
    const overlayRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const handleKeyDown = (e: KeyboardEvent) => {
            if (e.key === 'Escape') { e.preventDefault(); onClose(); }
        };
        document.addEventListener('keydown', handleKeyDown);
        return () => document.removeEventListener('keydown', handleKeyDown);
    }, [onClose]);

    useEffect(() => {
        ScansHandler.getGlobalResult(scanId)
            .then(d => {
                if (d) setData(d);
                else setError("Failed to load scan result.");
                setLoading(false);
            })
            .catch(() => { setError("Failed to load scan result."); setLoading(false); });
    }, [scanId]);

    const tabCls = (s: GlobalSection) =>
        ["px-4 py-2 text-sm font-semibold border-b-2 transition-colors",
         section === s ? "border-cyan-500 text-cyan-400" : "border-transparent text-gray-400 hover:text-gray-200",
        ].join(' ');

    const lc = filter.toLowerCase();
    const filteredPkgs = data ? (lc ? data.packages.filter(p => p.package_name.toLowerCase().includes(lc) || p.package_version.toLowerCase().includes(lc) || p.sources.some(s => s.toLowerCase().includes(lc))) : data.packages) : [];
    const filteredFindings = data ? (lc ? data.findings.filter(f => f.package_name.toLowerCase().includes(lc) || f.vulnerability_id.toLowerCase().includes(lc) || f.sources.some(s => s.toLowerCase().includes(lc))) : data.findings) : [];
    const filteredVulns = data ? (lc ? data.vulnerabilities.filter(v => v.vulnerability_id.toLowerCase().includes(lc) || v.sources.some(s => s.toLowerCase().includes(lc))) : data.vulnerabilities) : [];
    const filteredAssessments = data ? (lc ? (data.assessments || []).filter(a => a.vulnerability_id.toLowerCase().includes(lc) || a.status.toLowerCase().includes(lc) || a.justification.toLowerCase().includes(lc) || a.impact_statement.toLowerCase().includes(lc) || a.status_notes.toLowerCase().includes(lc)) : (data.assessments || [])) : [];

    return (
        <div
            className="overflow-x-hidden fixed top-0 right-0 left-0 z-50 flex items-center justify-center w-full md:inset-0 h-full max-h-full bg-gray-900/90"
            onClick={e => { if (e.target === overlayRef.current) onClose(); }}
            ref={overlayRef}
        >
            <div className="relative p-16 h-full w-full">
                <div className="relative rounded-lg shadow bg-gray-700 h-full overflow-y-auto flex flex-col">

                    {/* Header */}
                    <div className="flex items-center justify-between p-4 md:p-5 border-b rounded-t dark:border-gray-600">
                        <h3 className="text-xl font-semibold text-white">
                            Scan Result — Active Items
                        </h3>
                        <button onClick={onClose} type="button" className="text-white bg-transparent border border-gray-600 hover:bg-gray-600 hover:border-gray-500 rounded-lg text-sm w-8 h-8 ms-auto inline-flex justify-center items-center transition-colors">
                            <svg className="w-3 h-3" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 14 14">
                                <path stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="m1 1 6 6m0 0 6 6M7 7l6-6M7 7l-6 6"/>
                            </svg>
                            <span className="sr-only">Close modal</span>
                        </button>
                    </div>

                    {/* Tab bar */}
                    {data && (
                        <div className="flex border-b dark:border-gray-600 px-4 flex-wrap items-center">
                            <button className={tabCls('packages')} onClick={() => setSection('packages')}>
                                Packages
                                <span className="ml-2 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold bg-cyan-900/40 text-cyan-300">
                                    {data.package_count.toLocaleString()}
                                </span>
                            </button>
                            <button className={tabCls('findings')} onClick={() => setSection('findings')}>
                                Findings
                                <span className="ml-2 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold bg-cyan-900/40 text-cyan-300">
                                    {data.finding_count.toLocaleString()}
                                </span>
                            </button>
                            <button className={tabCls('vulnerabilities')} onClick={() => setSection('vulnerabilities')}>
                                Vulnerabilities
                                <span className="ml-2 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold bg-cyan-900/40 text-cyan-300">
                                    {data.vuln_count.toLocaleString()}
                                </span>
                            </button>
                            <button className={tabCls('assessments')} onClick={() => setSection('assessments')}>
                                Assessments
                                <span className="ml-2 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold bg-cyan-900/40 text-cyan-300">
                                    {(data.assessment_count ?? 0).toLocaleString()}
                                </span>
                            </button>
                            <div className="ml-auto">
                                <input
                                    type="text"
                                    placeholder="Filter…"
                                    value={filter}
                                    onChange={e => setFilter(e.target.value)}
                                    className="text-xs px-2 py-1 rounded border border-gray-600 bg-gray-800 text-gray-200 w-48"
                                />
                            </div>
                        </div>
                    )}

                    {/* Body */}
                    <div className="p-4 md:p-5 space-y-4 text-gray-300 flex-1 overflow-auto">
                        {loading && <p className="text-gray-400">Loading…</p>}
                        {error && <p className="text-red-400">{error}</p>}

                        {data && section === 'packages' && (
                            <div className="overflow-auto max-h-[70vh] rounded border border-gray-600">
                                <table className="w-full text-xs text-left">
                                    <thead className="sticky top-0 bg-gray-800 text-gray-300 uppercase">
                                        <tr>
                                            <th className="px-3 py-2">Package</th>
                                            <th className="px-3 py-2">Version</th>
                                            <th className="px-3 py-2">Source</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {filteredPkgs.map(p => (
                                            <tr key={p.package_id} className="border-t border-gray-600 hover:bg-gray-600/40">
                                                <td className="px-3 py-1.5 font-mono">{p.package_name}</td>
                                                <td className="px-3 py-1.5 font-mono text-gray-400">{p.package_version}</td>
                                                <td className="px-3 py-1.5 text-gray-400">{p.sources.join(', ')}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}

                        {data && section === 'findings' && (
                            <div className="overflow-auto max-h-[70vh] rounded border border-gray-600">
                                <table className="w-full text-xs text-left">
                                    <thead className="sticky top-0 bg-gray-800 text-gray-300 uppercase">
                                        <tr>
                                            <th className="px-3 py-2">Package</th>
                                            <th className="px-3 py-2">Version</th>
                                            <th className="px-3 py-2">Vulnerability</th>
                                            <th className="px-3 py-2">Source</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {filteredFindings.map(f => (
                                            <tr key={f.finding_id} className="border-t border-gray-600 hover:bg-gray-600/40">
                                                <td className="px-3 py-1.5 font-mono">{f.package_name}</td>
                                                <td className="px-3 py-1.5 font-mono text-gray-400">{f.package_version}</td>
                                                <td className="px-3 py-1.5 font-mono">{f.vulnerability_id}</td>
                                                <td className="px-3 py-1.5 text-gray-400">{f.sources.join(', ')}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}

                        {data && section === 'vulnerabilities' && (
                            <div className="overflow-auto max-h-[70vh] rounded border border-gray-600">
                                <table className="w-full text-xs text-left">
                                    <thead className="sticky top-0 bg-gray-800 text-gray-300 uppercase">
                                        <tr>
                                            <th className="px-3 py-2">Vulnerability</th>
                                            <th className="px-3 py-2">Source</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {filteredVulns.map(v => (
                                            <tr key={v.vulnerability_id} className="border-t border-gray-600 hover:bg-gray-600/40">
                                                <td className="px-3 py-1.5 font-mono">{v.vulnerability_id}</td>
                                                <td className="px-3 py-1.5 text-gray-400">{v.sources.join(', ')}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}

                        {data && section === 'assessments' && (
                            <div className="overflow-auto max-h-[70vh] rounded border border-gray-600">
                                <table className="w-full text-xs text-left">
                                    <thead className="sticky top-0 bg-gray-800 text-gray-300 uppercase">
                                        <tr>
                                            <th className="px-3 py-2">Vulnerability</th>
                                            <th className="px-3 py-2">Status</th>
                                            <th className="px-3 py-2">Justification</th>
                                            <th className="px-3 py-2">Impact</th>
                                            <th className="px-3 py-2">Notes</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {filteredAssessments.map((a, i) => (
                                            <tr key={`${a.vulnerability_id}-${i}`} className="border-t border-gray-600 hover:bg-gray-600/40">
                                                <td className="px-3 py-1.5 font-mono">{a.vulnerability_id}</td>
                                                <td className="px-3 py-1.5">
                                                    <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-gray-600 text-gray-200">
                                                        {a.simplified_status}
                                                    </span>
                                                </td>
                                                <td className="px-3 py-1.5 text-gray-400">{a.justification}</td>
                                                <td className="px-3 py-1.5 text-gray-400">{a.impact_statement}</td>
                                                <td className="px-3 py-1.5 text-gray-400">{a.status_notes}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>

                    {/* Footer */}
                    <div className="flex items-center justify-end p-4 md:p-5 border-t border-gray-200 rounded-b dark:border-gray-600">
                        <button onClick={onClose} type="button" className="py-2.5 px-5 text-sm font-medium text-gray-400 focus:outline-none rounded-lg border border-gray-600 hover:bg-gray-600 hover:text-white focus:z-10 focus:ring-4 focus:ring-blue-500 bg-gray-800">
                            Close
                        </button>
                    </div>

                </div>
            </div>
        </div>
    );
}

function DiffModal({ scanId, scanType, onClose }: { scanId: string; scanType: string; onClose: () => void }) {
    const [diff, setDiff] = useState<ScanDiff | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const isToolScan = scanType === 'tool';
    const [section, setSection] = useState<Section>(isToolScan ? 'findings' : 'packages');
    const overlayRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const handleKeyDown = (e: KeyboardEvent) => {
            if (e.key === 'Escape') {
                e.preventDefault();
                onClose();
            }
        };
        document.addEventListener('keydown', handleKeyDown);
        return () => document.removeEventListener('keydown', handleKeyDown);
    }, [onClose]);

    useEffect(() => {
        ScansHandler.getDiff(scanId)
            .then(data => {
                if (data) setDiff(data);
                else setError("Failed to load diff details.");
                setLoading(false);
            })
            .catch(() => {
                setError("Failed to load diff details.");
                setLoading(false);
            });
    }, [scanId]);

    const tabCls = (s: Section) =>
        [
            "px-4 py-2 text-sm font-semibold border-b-2 transition-colors",
            section === s
                ? "border-blue-500 text-blue-400"
                : "border-transparent text-gray-400 hover:text-gray-200",
        ].join(' ');

    return (
        <div
            className="overflow-x-hidden fixed top-0 right-0 left-0 z-50 flex items-center justify-center w-full md:inset-0 h-full max-h-full bg-gray-900/90"
            onClick={e => { if (e.target === overlayRef.current) onClose(); }}
            ref={overlayRef}
        >
            <div className="relative p-16 h-full w-full">
                <div className="relative rounded-lg shadow bg-gray-700 h-full overflow-y-auto flex flex-col">

                    {/* Header */}
                    <div className="flex items-center justify-between p-4 md:p-5 border-b rounded-t dark:border-gray-600">
                        <h3 className="text-xl font-semibold text-gray-900 dark:text-white">
                            {isToolScan ? 'Tool scan diff details' : 'Scan diff details'}
                        </h3>
                        <button
                            onClick={onClose}
                            type="button"
                            className="text-white bg-transparent border border-gray-600 hover:bg-gray-600 hover:border-gray-500 rounded-lg text-sm w-8 h-8 ms-auto inline-flex justify-center items-center transition-colors"
                        >
                            <svg className="w-3 h-3" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 14 14">
                                <path stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="m1 1 6 6m0 0 6 6M7 7l6-6M7 7l-6 6"/>
                            </svg>
                            <span className="sr-only">Close modal</span>
                        </button>
                    </div>

                    {/* Tab bar */}
                    {diff && (
                        <div className="flex border-b dark:border-gray-600 px-4 flex-wrap">
                            {!isToolScan && (
                            <button className={tabCls('packages')} onClick={() => setSection('packages')}>
                                Packages
                                {diff.is_first ? (
                                    <span className="ml-2 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold bg-blue-900/40 text-blue-300">
                                        {diff.package_count.toLocaleString()}
                                    </span>
                                ) : (
                                    <>
                                        <span className={`ml-2 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold ${diff.packages_added.length > 0 ? 'bg-green-900/40 text-green-300' : 'bg-gray-600 text-gray-400'}`}>
                                            +{diff.packages_added.length.toLocaleString()}
                                        </span>
                                        <span className={`ml-1 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold ${diff.packages_removed.length > 0 ? 'bg-red-900/40 text-red-300' : 'bg-gray-600 text-gray-400'}`}>
                                            −{diff.packages_removed.length.toLocaleString()}
                                        </span>
                                        <span className={`ml-1 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold ${diff.packages_upgraded.length > 0 ? 'bg-yellow-900/40 text-yellow-300' : 'bg-gray-600 text-gray-400'}`}>
                                            ↑{diff.packages_upgraded.length.toLocaleString()}
                                        </span>
                                        <span className="ml-1 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold bg-gray-600 text-gray-400">
                                            ={diff.packages_unchanged.length.toLocaleString()}
                                        </span>
                                    </>
                                )}
                            </button>
                            )}
                            <button className={tabCls('findings')} onClick={() => setSection('findings')}>
                                Findings
                                {(diff.is_first || isToolScan) ? (
                                    <span className="ml-2 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold bg-blue-900/40 text-blue-300">
                                        {diff.finding_count.toLocaleString()}
                                    </span>
                                ) : (
                                    <>
                                        <span className={`ml-2 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold ${diff.findings_added.length > 0 ? 'bg-green-900/40 text-green-300' : 'bg-gray-600 text-gray-400'}`}>
                                            +{diff.findings_added.length.toLocaleString()}
                                        </span>
                                        <span className={`ml-1 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold ${diff.findings_removed.length > 0 ? 'bg-red-900/40 text-red-300' : 'bg-gray-600 text-gray-400'}`}>
                                            −{diff.findings_removed.length.toLocaleString()}
                                        </span>
                                        <span className={`ml-1 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold ${diff.findings_upgraded.length > 0 ? 'bg-yellow-900/40 text-yellow-300' : 'bg-gray-600 text-gray-400'}`}>
                                            ↑{diff.findings_upgraded.length.toLocaleString()}
                                        </span>
                                        <span className="ml-1 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold bg-gray-600 text-gray-400">
                                            ={diff.findings_unchanged.length.toLocaleString()}
                                        </span>
                                    </>
                                )}
                            </button>
                            <button className={tabCls('vulnerabilities')} onClick={() => setSection('vulnerabilities')}>
                                Vulnerabilities
                                {(diff.is_first || isToolScan) ? (
                                    <span className="ml-2 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold bg-blue-900/40 text-blue-300">
                                        {diff.vuln_count.toLocaleString()}
                                    </span>
                                ) : (
                                    <>
                                        <span className={`ml-2 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold ${diff.vulns_added.length > 0 ? 'bg-green-900/40 text-green-300' : 'bg-gray-600 text-gray-400'}`}>
                                            +{diff.vulns_added.length.toLocaleString()}
                                        </span>
                                        <span className={`ml-1 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold ${diff.vulns_removed.length > 0 ? 'bg-red-900/40 text-red-300' : 'bg-gray-600 text-gray-400'}`}>
                                            −{diff.vulns_removed.length.toLocaleString()}
                                        </span>
                                        <span className="ml-1 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold bg-gray-600 text-gray-400">
                                            ={diff.vulns_unchanged.length.toLocaleString()}
                                        </span>
                                    </>
                                )}
                            </button>
                            <button className={tabCls('assessments')} onClick={() => setSection('assessments')}>
                                Assessments
                                {diff.is_first ? (
                                    <span className="ml-2 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold bg-blue-900/40 text-blue-300">
                                        {(diff.assessment_count ?? 0).toLocaleString()}
                                    </span>
                                ) : (
                                    <>
                                        <span className={`ml-2 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold ${(Array.isArray(diff.assessments_added) ? diff.assessments_added.length : 0) > 0 ? 'bg-green-900/40 text-green-300' : 'bg-gray-600 text-gray-400'}`}>
                                            +{(Array.isArray(diff.assessments_added) ? diff.assessments_added.length : 0).toLocaleString()}
                                        </span>
                                        <span className={`ml-1 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold ${(Array.isArray(diff.assessments_removed) ? diff.assessments_removed.length : 0) > 0 ? 'bg-red-900/40 text-red-300' : 'bg-gray-600 text-gray-400'}`}>
                                            −{(Array.isArray(diff.assessments_removed) ? diff.assessments_removed.length : 0).toLocaleString()}
                                        </span>
                                        <span className="ml-1 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold bg-gray-600 text-gray-400">
                                            ={(Array.isArray(diff.assessments_unchanged) ? diff.assessments_unchanged.length : 0).toLocaleString()}
                                        </span>
                                    </>
                                )}
                            </button>
                            {isToolScan && diff.newly_detected_findings != null && (
                            <button className={tabCls('newly_detected')} onClick={() => setSection('newly_detected')}>
                                New Discovered
                                <span className="ml-2 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold bg-green-900/40 text-green-300">
                                    {(diff.newly_detected_findings ?? 0).toLocaleString()} findings
                                </span>
                                <span className="ml-1 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold bg-green-900/40 text-green-300">
                                    {(diff.newly_detected_vulns ?? 0).toLocaleString()} vulns
                                </span>
                                <span className="ml-1 inline-flex items-center px-1.5 py-0.5 rounded-full text-xs font-bold bg-green-900/40 text-green-300">
                                    {(diff.newly_detected_assessments_list ?? []).length.toLocaleString()} assessments
                                </span>
                            </button>
                            )}
                        </div>
                    )}

                    {/* Body */}
                    <div className="p-4 md:p-5 space-y-4 text-gray-300 flex-1 overflow-auto">
                        {loading && <p className="text-gray-400">Loading…</p>}
                        {error && <p className="text-red-400">{error}</p>}
                        {diff && section === 'packages' && (
                            <>
                                {diff.is_first && (
                                    <p className="text-sm text-gray-400 mb-4 italic">
                                        This is the first scan — all {diff.package_count.toLocaleString()} packages are new.
                                    </p>
                                )}
                                <PackageDiffTable
                                    entries={diff.packages_added}
                                    label={diff.is_first ? "All packages" : "Added packages"}
                                    colorClass={diff.is_first ? "text-cyan-400" : "text-green-400"}
                                />
                                {!diff.is_first && (
                                    <PackageDiffTable
                                        entries={diff.packages_removed}
                                        label="Removed packages"
                                        colorClass="text-red-400"
                                    />
                                )}
                                {!diff.is_first && (
                                    <PackageUpgradeDiffTable
                                        entries={diff.packages_upgraded}
                                        label="Upgraded packages"
                                        colorClass="text-yellow-400"
                                    />
                                )}
                                {!diff.is_first && (
                                    <PackageDiffTable
                                        entries={diff.packages_unchanged}
                                        label="Unchanged packages"
                                        colorClass="text-gray-400"
                                    />
                                )}
                            </>
                        )}
                        {diff && section === 'findings' && (
                            <>
                                {(diff.is_first || isToolScan) ? (
                                    <>
                                        <p className="text-sm text-gray-400 mb-4 italic">
                                            {diff.is_first
                                                ? `This is the first scan — all ${diff.finding_count.toLocaleString()} findings are listed below.`
                                                : `All ${diff.finding_count.toLocaleString()} findings detected by this scan.`}
                                        </p>
                                        <FindingDiffTable
                                            entries={diff.all_findings ?? diff.findings_added}
                                            label="All findings"
                                            colorClass="text-cyan-400"
                                        />
                                    </>
                                ) : (
                                    <>
                                        <FindingDiffTable
                                            entries={diff.findings_added}
                                            label="Added findings"
                                            colorClass="text-green-400"
                                        />
                                        <FindingDiffTable
                                            entries={diff.findings_removed}
                                            label="Removed findings"
                                            colorClass="text-red-400"
                                        />
                                        {diff.findings_upgraded.length > 0 && (
                                            <FindingUpgradeDiffTable
                                                entries={diff.findings_upgraded}
                                                label="Findings on upgraded packages"
                                                colorClass="text-yellow-400"
                                            />
                                        )}
                                        <FindingDiffTable
                                            entries={diff.findings_unchanged}
                                            label="Unchanged findings"
                                            colorClass="text-gray-400"
                                        />
                                    </>
                                )}
                            </>
                        )}
                        {diff && section === 'vulnerabilities' && (
                            <>
                                {(diff.is_first || isToolScan) ? (
                                    <>
                                        <p className="text-sm text-gray-400 mb-4 italic">
                                            {diff.is_first
                                                ? `This is the first scan — all ${diff.vuln_count.toLocaleString()} vulnerabilities are listed below.`
                                                : `All ${diff.vuln_count.toLocaleString()} vulnerabilities detected by this scan.`}
                                        </p>
                                        <VulnDiffList
                                            vulns={diff.all_vulns ?? diff.vulns_added}
                                            label="All vulnerabilities"
                                            colorClass="text-cyan-400"
                                        />
                                    </>
                                ) : (
                                    <>
                                        <VulnDiffList
                                            vulns={diff.vulns_added}
                                            label="New vulnerabilities"
                                            colorClass="text-green-400"
                                        />
                                        {(() => {
                                            const originMap: Record<string, string[]> = {};
                                            for (const f of diff.findings_removed) {
                                                if (f.origin) {
                                                    const origins = originMap[f.vulnerability_id] || [];
                                                    if (!origins.includes(f.origin)) origins.push(f.origin);
                                                    originMap[f.vulnerability_id] = origins;
                                                }
                                            }
                                            return (
                                                <VulnDiffList
                                                    vulns={diff.vulns_removed}
                                                    label="Removed vulnerabilities"
                                                    colorClass="text-red-400"
                                                    originMap={originMap}
                                                />
                                            );
                                        })()}
                                        <VulnDiffList
                                            vulns={diff.vulns_unchanged}
                                            label="Unchanged vulnerabilities"
                                            colorClass="text-gray-400"
                                        />
                                    </>
                                )}
                            </>
                        )}
                        {diff && section === 'assessments' && (
                            <>
                                <p className="text-sm text-gray-400 mb-4 italic">
                                    {diff.is_first
                                        ? `This is the first scan — all ${(diff.assessment_count ?? 0).toLocaleString()} assessments were created during this import.`
                                        : `${(Array.isArray(diff.assessments_added) ? diff.assessments_added.length : 0).toLocaleString()} new, ${(Array.isArray(diff.assessments_removed) ? diff.assessments_removed.length : 0).toLocaleString()} removed, ${(Array.isArray(diff.assessments_unchanged) ? diff.assessments_unchanged.length : 0).toLocaleString()} unchanged assessment(s).`
                                    }
                                </p>
                                <AssessmentDiffTable
                                    entries={Array.isArray(diff.assessments_added) ? diff.assessments_added : []}
                                    label={diff.is_first ? "All assessments" : "New assessments"}
                                    colorClass={diff.is_first ? "text-cyan-400" : "text-green-400"}
                                />
                                {!diff.is_first && (
                                    <AssessmentDiffTable
                                        entries={Array.isArray(diff.assessments_removed) ? diff.assessments_removed : []}
                                        label="Removed assessments"
                                        colorClass="text-red-400"
                                    />
                                )}
                                {!diff.is_first && (
                                    <AssessmentDiffTable
                                        entries={Array.isArray(diff.assessments_unchanged) ? diff.assessments_unchanged : []}
                                        label="Unchanged assessments"
                                        colorClass="text-gray-400"
                                    />
                                )}
                            </>
                        )}
                        {diff && section === 'newly_detected' && isToolScan && (
                            <>
                                <p className="text-sm text-gray-400 mb-4 italic">
                                    Findings and vulnerabilities discovered by the tool scan that were <strong className="text-purple-300">not previously known</strong> — they are new items not found in the SBOM or any earlier tool scan.
                                </p>
                                {diff.newly_detected_findings_list && diff.newly_detected_findings_list.length > 0 ? (
                                    <FindingDiffTable
                                        entries={diff.newly_detected_findings_list}
                                        label="New findings discovered"
                                        colorClass="text-green-400"
                                    />
                                ) : (
                                    <p className="text-sm text-gray-400 italic mb-4">No new findings discovered.</p>
                                )}
                                {diff.newly_detected_vulns_list && diff.newly_detected_vulns_list.length > 0 ? (
                                    <VulnDiffList
                                        vulns={diff.newly_detected_vulns_list}
                                        label="New vulnerabilities discovered"
                                        colorClass="text-green-400"
                                    />
                                ) : (
                                    <p className="text-sm text-gray-400 italic">No new vulnerabilities discovered.</p>
                                )}
                                {diff.newly_detected_assessments_list && diff.newly_detected_assessments_list.length > 0 ? (
                                    <AssessmentDiffTable
                                        entries={diff.newly_detected_assessments_list}
                                        label="New assessments discovered"
                                        colorClass="text-green-400"
                                    />
                                ) : (
                                    <p className="text-sm text-gray-400 italic">No new assessments discovered.</p>
                                )}
                            </>
                        )}
                    </div>

                    {/* Footer */}
                    <div className="flex items-center justify-end p-4 md:p-5 border-t border-gray-200 rounded-b dark:border-gray-600">
                        <button
                            onClick={onClose}
                            type="button"
                            className="py-2.5 px-5 text-sm font-medium text-gray-400 focus:outline-none rounded-lg border border-gray-600 hover:bg-gray-600 hover:text-white focus:z-10 focus:ring-4 focus:ring-blue-500 bg-gray-800"
                        >
                            Close
                        </button>
                    </div>

                </div>
            </div>
        </div>
    );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

function ScanHistory({ variantId, projectId, onScanComplete }: Readonly<Props>) {
    const docUrl = useDocUrl("interactive-mode.html#scan-history");
    const [scans, setScans] = useState<Scan[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [openDiffId, setOpenDiffId] = useState<string | null>(null);
    const [openDiffType, setOpenDiffType] = useState<string>('sbom');
    const [openGlobalId, setOpenGlobalId] = useState<string | null>(null);
    const [editingDescId, setEditingDescId] = useState<string | null>(null);
    const [editingDescValue, setEditingDescValue] = useState<string>('');
    const [deletingId, setDeletingId] = useState<string | null>(null);
    const [hideEmptyScans, setHideEmptyScans] = useState(false);
    const [showGrype, setShowGrype] = useState(true);
    const [showOsv, setShowOsv] = useState(true);
    const [showNvd, setShowNvd] = useState(true);

    // Scan menu state
    const [scanMenuOpen, setScanMenuOpen] = useState(false);
    const [allVariants, setAllVariants] = useState<Variant[]>([]);
    const [selectedVariantIds, setSelectedVariantIds] = useState<Set<string>>(new Set());
    const [selectedScanTypes, setSelectedScanTypes] = useState<Set<string>>(new Set(['grype', 'nvd', 'osv']));
    const scanMenuRef = useRef<HTMLDivElement>(null);

    // Global Grype scan state — survives tab switches (per-variant)
    const grypeEntries: ScanManagerSnapshot = useSyncExternalStore(subscribe, getSnapshot);
    const grypeRunning = grypeEntries.some(e => e.status === "running" || e.status === "queued");

    // Global NVD scan state — survives tab switches (per-variant)
    const nvdEntries: ScanManagerSnapshot = useSyncExternalStore(nvdSubscribe, nvdGetSnapshot);
    const nvdRunning = nvdEntries.some(e => e.status === "running");

    // Global OSV scan state — survives tab switches (per-variant)
    const osvEntries: ScanManagerSnapshot = useSyncExternalStore(osvSubscribe, osvGetSnapshot);
    const osvRunning = osvEntries.some(e => e.status === "running");

    const refreshScans = useCallback(() => {
        ScansHandler.list(variantId, projectId)
            .then((data) => {
                setScans([...data].reverse());
            })
            .catch(() => {});
    }, [variantId, projectId]);

    async function saveDescription(scanId: string) {
        const ok = await ScansHandler.setDescription(scanId, editingDescValue);
        if (ok) {
            setScans(prev => prev.map(s => s.id === scanId ? { ...s, description: editingDescValue } : s));
            setEditingDescId(null);
        }
    }

    async function handleDeleteScan(scanId: string) {
        const result = await ScansHandler.deleteScan(scanId);
        if (result.ok) {
            setDeletingId(null);
            refreshScans();
            onScanComplete?.();
        }
    }

    // Derive the effective variant IDs to scan: explicit prop or unique IDs from loaded scans
    const effectiveVariantIds: string[] = variantId
        ? [variantId]
        : [...new Set(scans.map(s => s.variant_id))];

    // Register the refresh callback so the global store can trigger it on completion
    useEffect(() => {
        setOnDone(() => { refreshScans(); onScanComplete?.(); });
        return () => setOnDone(null);
    }, [refreshScans, onScanComplete]);

    useEffect(() => {
        nvdSetOnDone(() => { refreshScans(); onScanComplete?.(); });
        return () => nvdSetOnDone(null);
    }, [refreshScans, onScanComplete]);

    useEffect(() => {
        osvSetOnDone(() => { refreshScans(); onScanComplete?.(); });
        return () => osvSetOnDone(null);
    }, [refreshScans, onScanComplete]);

    // If a scan finished while we were away, refresh the list on mount
    useEffect(() => {
        if (grypeEntries.some(e => e.status === 'done')) refreshScans();
        if (nvdEntries.some(e => e.status === 'done')) refreshScans();
        if (osvEntries.some(e => e.status === 'done')) refreshScans();
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    // Fetch variants scoped to the current view for the scan menu
    useEffect(() => {
        const fetchVariants = variantId
            // Single variant selected → fetch all and filter to just that one
            ? Variants.listAll().then(vs => vs.filter(v => v.id === variantId))
            : projectId
                // Project selected → only that project's variants
                ? Variants.list(projectId)
                // No scope → all variants
                : Variants.listAll();

        fetchVariants.then(vs => {
            setAllVariants(vs);
            setSelectedVariantIds(new Set(vs.map(v => v.id)));
        });
    }, [variantId, projectId]);

    // Close scan menu on outside click
    useEffect(() => {
        function handleClickOutside(e: MouseEvent) {
            if (scanMenuRef.current && !scanMenuRef.current.contains(e.target as Node)) {
                setScanMenuOpen(false);
            }
        }
        if (scanMenuOpen) {
            document.addEventListener('mousedown', handleClickOutside);
            return () => document.removeEventListener('mousedown', handleClickOutside);
        }
    }, [scanMenuOpen]);

    function toggleVariant(vid: string) {
        setSelectedVariantIds(prev => {
            const next = new Set(prev);
            if (next.has(vid)) next.delete(vid); else next.add(vid);
            return next;
        });
    }

    function toggleScanType(t: string) {
        setSelectedScanTypes(prev => {
            const next = new Set(prev);
            if (next.has(t)) next.delete(t); else next.add(t);
            return next;
        });
    }

    async function handleRunSelectedScans() {
        const variants = allVariants
            .filter(v => selectedVariantIds.has(v.id))
            .map(v => ({ id: v.id, name: v.name }));
        if (variants.length === 0 || selectedScanTypes.size === 0) return;
        setScanMenuOpen(false);
        const promises: Promise<void>[] = [];
        if (selectedScanTypes.has('grype')) promises.push(triggerScan(variants));
        if (selectedScanTypes.has('nvd')) promises.push(nvdTriggerScan(variants));
        if (selectedScanTypes.has('osv')) promises.push(osvTriggerScan(variants));
        await Promise.all(promises);
    }

    useEffect(() => {
        setLoading(true);
        setError(null);
        ScansHandler.list(variantId, projectId)
            .then((data) => {
                setScans([...data].reverse()); // most recent first
                setLoading(false);
            })
            .catch(() => {
                setError("Failed to load scan history.");
                setLoading(false);
            });
    }, [variantId, projectId, refreshScans]);

    // Build the scan-trigger button (always visible when there are variant(s) to scan)
    const canTriggerScan = effectiveVariantIds.length > 0 || variantId;
    const allRunning = grypeRunning || nvdRunning || osvRunning;

    // Filter out "empty" scans (no changes) when toggle is active
    const displayedScans = hideEmptyScans
        ? scans.filter(s => {
            if (s.is_first) return true; // first scans always shown
            const hasChanges =
                (s.findings_added ?? 0) !== 0 ||
                (s.findings_removed ?? 0) !== 0 ||
                (s.findings_upgraded ?? 0) !== 0 ||
                (s.packages_added ?? 0) !== 0 ||
                (s.packages_removed ?? 0) !== 0 ||
                (s.packages_upgraded ?? 0) !== 0 ||
                (s.vulns_added ?? 0) !== 0 ||
                (s.vulns_removed ?? 0) !== 0 ||
                (s.newly_detected_findings ?? 0) !== 0 ||
                (s.newly_detected_vulns ?? 0) !== 0;
            return hasChanges;
        })
        : scans;

    // Apply scan-source visibility filters
    const filteredScans = displayedScans.filter((s) => {
        if ((s.scan_type || 'sbom') !== 'tool') return true; // always show SBOM
        const src = s.scan_source || 'grype';
        if (src === 'grype' && !showGrype) return false;
        if (src === 'osv' && !showOsv) return false;
        if (src === 'nvd' && !showNvd) return false;
        return true;
    });

    // -----------------------------------------------------------------------
    // Linear timeline — source-to-color mapping for tool scan squares
    // -----------------------------------------------------------------------
    const sourceSquareColor: Record<string, string> = {
        grype: "bg-purple-400",
        osv: "bg-green-400",
        nvd: "bg-orange-400",
    };

    // Column sizing — single lane
    const LANE_W = 36;            // px – timeline column
    const mainCX = LANE_W / 2;    // center-x of the lane

    const menuBar = (
        <div className="rounded-md mb-4 p-2 bg-sky-800 text-white w-full flex flex-row items-center gap-2 flex-wrap">
            <h1 className="text-lg font-bold">Scan History</h1>

            {/* Hide empty scans toggle */}
            <button
                onClick={() => setHideEmptyScans(h => !h)}
                className={[
                    "py-1 px-2 rounded flex items-center gap-1 text-sm font-semibold transition-colors",
                    hideEmptyScans
                        ? "bg-sky-950 text-white"
                        : "bg-sky-900 hover:bg-sky-950 text-white",
                ].join(' ')}
                title={hideEmptyScans ? "Showing only scans with changes" : "Showing all scans"}
            >
                <FontAwesomeIcon icon={faFilter} />
                Hide empty scans
                {hideEmptyScans && <span className="ml-1 bg-sky-700 px-1 rounded text-xs">✓</span>}
            </button>

            {/* Scan source visibility toggles */}
            <span className="text-xs text-sky-300 ml-2">Show:</span>
            <button
                onClick={() => setShowGrype(v => !v)}
                className={[
                    "py-1 px-2 rounded flex items-center gap-1 text-xs font-semibold transition-colors",
                    showGrype ? "bg-purple-700 text-white" : "bg-sky-900/60 text-sky-400 line-through",
                ].join(' ')}
                title={showGrype ? "Grype scans visible" : "Grype scans hidden"}
            >
                <FontAwesomeIcon icon={faBug} />
                Grype
            </button>
            <button
                onClick={() => setShowOsv(v => !v)}
                className={[
                    "py-1 px-2 rounded flex items-center gap-1 text-xs font-semibold transition-colors",
                    showOsv ? "bg-green-700 text-white" : "bg-sky-900/60 text-sky-400 line-through",
                ].join(' ')}
                title={showOsv ? "OSV scans visible" : "OSV scans hidden"}
            >
                <FontAwesomeIcon icon={faLeaf} />
                OSV
            </button>
            <button
                onClick={() => setShowNvd(v => !v)}
                className={[
                    "py-1 px-2 rounded flex items-center gap-1 text-xs font-semibold transition-colors",
                    showNvd ? "bg-orange-700 text-white" : "bg-sky-900/60 text-sky-400 line-through",
                ].join(' ')}
                title={showNvd ? "NVD scans visible" : "NVD scans hidden"}
            >
                <FontAwesomeIcon icon={faShieldHalved} />
                NVD
            </button>

            {/* Right side: doc link + scan menu */}
            <div className="ml-auto flex items-center gap-3">
                <a
                    href={docUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label="documentation"
                    title="Open documentation"
                    className="text-white hover:text-blue-300 transition-colors"
                >
                    <FontAwesomeIcon icon={faBook} />
                </a>
                {/* Run Scans dropdown */}
                {canTriggerScan && (
                    <div className="relative" ref={scanMenuRef}>
                        <button
                            onClick={() => setScanMenuOpen(o => !o)}
                            disabled={allRunning || loading}
                            className={[
                                "inline-flex items-center gap-2 px-3 py-1.5 rounded text-sm font-semibold transition-colors",
                                allRunning
                                    ? "bg-cyan-800/50 text-cyan-300 cursor-wait"
                                    : "bg-cyan-700 hover:bg-cyan-600 text-white",
                            ].join(' ')}
                        >
                            <FontAwesomeIcon icon={faPlay} />
                            {allRunning ? 'Scanning…' : 'Run Scans'}
                        </button>

                        {scanMenuOpen && (
                            <div className="absolute right-0 top-full mt-1 z-50 w-72 rounded-lg border border-sky-700/60 bg-neutral-900 shadow-xl p-3">

                                {/* Scan types */}
                                <div className="mb-3">
                                    <div className="text-xs font-semibold text-sky-300 mb-1.5">Scan types</div>
                                    {([
                                        { key: 'grype', label: 'Grype', icon: faBug, color: 'purple' },
                                        { key: 'nvd', label: 'NVD CPE', icon: faShieldHalved, color: 'orange' },
                                        { key: 'osv', label: 'OSV', icon: faLeaf, color: 'green' },
                                    ] as const).map(({ key, label, icon, color }) => (
                                        <label
                                            key={key}
                                            className="flex items-center gap-2 py-1 px-1 rounded hover:bg-sky-900/40 cursor-pointer text-sm"
                                        >
                                            <input
                                                type="checkbox"
                                                checked={selectedScanTypes.has(key)}
                                                onChange={() => toggleScanType(key)}
                                                className="rounded accent-cyan-500"
                                            />
                                            <FontAwesomeIcon icon={icon} className={`text-${color}-400 w-4`} />
                                            <span className="text-neutral-200">{label}</span>
                                        </label>
                                    ))}
                                </div>

                                {/* Variants */}
                                <div className="mb-3">
                                    <div className="text-xs font-semibold text-sky-300 mb-1.5">Variants</div>
                                    <div className="max-h-40 overflow-y-auto">
                                        {allVariants.length === 0 && (
                                            <span className="text-xs text-neutral-500 italic">No variants found</span>
                                        )}
                                        {allVariants.map(v => (
                                            <label
                                                key={v.id}
                                                className="flex items-center gap-2 py-1 px-1 rounded hover:bg-sky-900/40 cursor-pointer text-sm"
                                            >
                                                <input
                                                    type="checkbox"
                                                    checked={selectedVariantIds.has(v.id)}
                                                    onChange={() => toggleVariant(v.id)}
                                                    className="rounded accent-cyan-500"
                                                />
                                                <span className="text-neutral-200 truncate">{v.name}</span>
                                            </label>
                                        ))}
                                    </div>
                                    {allVariants.length > 1 && (
                                        <div className="flex gap-2 mt-1">
                                            <button
                                                onClick={() => setSelectedVariantIds(new Set(allVariants.map(v => v.id)))}
                                                className="text-xs text-sky-400 hover:text-sky-300"
                                            >Select all</button>
                                            <button
                                                onClick={() => setSelectedVariantIds(new Set())}
                                                className="text-xs text-sky-400 hover:text-sky-300"
                                            >Select none</button>
                                        </div>
                                    )}
                                </div>

                                {/* Run button */}
                                <button
                                    onClick={handleRunSelectedScans}
                                    disabled={selectedVariantIds.size === 0 || selectedScanTypes.size === 0}
                                    className={[
                                        "w-full py-1.5 rounded text-sm font-semibold transition-colors",
                                        selectedVariantIds.size === 0 || selectedScanTypes.size === 0
                                            ? "bg-neutral-700 text-neutral-500 cursor-not-allowed"
                                            : "bg-cyan-700 hover:bg-cyan-600 text-white",
                                    ].join(' ')}
                                >
                                    <FontAwesomeIcon icon={faPlay} className="mr-1" />
                                    Run {selectedScanTypes.size} scan{selectedScanTypes.size !== 1 ? 's' : ''} on {selectedVariantIds.size} variant{selectedVariantIds.size !== 1 ? 's' : ''}
                                </button>
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );

    // ---- Per-variant progress panels ----
    const grypeColors = { border: "border-purple-700/60", headerBg: "bg-purple-900/40", iconText: "text-purple-400", titleText: "text-purple-200", subtitleText: "text-purple-300/80", bar: "bg-purple-500" };
    const nvdColors = { border: "border-orange-700/60", headerBg: "bg-orange-900/40", iconText: "text-orange-400", titleText: "text-orange-200", subtitleText: "text-orange-300/80", bar: "bg-orange-500" };
    const osvColors = { border: "border-green-700/60", headerBg: "bg-green-900/40", iconText: "text-green-400", titleText: "text-green-200", subtitleText: "text-green-300/80", bar: "bg-green-500" };

    const progressPanels = (
        <>
            {grypeEntries
                .filter(e => e.status === "queued" || e.status === "running" || e.status === "done" || (e.status === "error" && e.logs.length > 0))
                .map(entry => (
                    <ScanProgressPanel key={`grype-${entry.variantId}`} entry={entry} label="Grype Scan" icon={faBug} colors={grypeColors} onDismiss={() => grypeDismiss(entry.variantId)} />
                ))
            }
            {nvdEntries
                .filter(e => e.status === "running" || e.status === "done" || (e.status === "error" && e.logs.length > 0))
                .map(entry => (
                    <ScanProgressPanel key={`nvd-${entry.variantId}`} entry={entry} label="NVD Scan" icon={faShieldHalved} colors={nvdColors} onDismiss={() => nvdDismiss(entry.variantId)} />
                ))
            }
            {osvEntries
                .filter(e => e.status === "running" || e.status === "done" || (e.status === "error" && e.logs.length > 0))
                .map(entry => (
                    <ScanProgressPanel key={`osv-${entry.variantId}`} entry={entry} label="OSV Scan" icon={faLeaf} colors={osvColors} onDismiss={() => osvDismiss(entry.variantId)} />
                ))
            }
        </>
    );

    if (loading) {
        return (
            <div className="w-full px-6 py-6">
                {menuBar}
                {progressPanels}
                <div className="flex items-center justify-center h-32 text-gray-400">
                    Loading scan history…
                </div>
            </div>
        );
    }
    if (error) {
        return (
            <div className="w-full px-6 py-6">
                {menuBar}
                {progressPanels}
                <div className="flex items-center justify-center h-32 text-red-400">
                    {error}
                </div>
            </div>
        );
    }
    if (scans.length === 0) {
        return (
            <div className="w-full px-6 py-6">
                {menuBar}
                {progressPanels}
                <div className="flex items-center justify-center h-32 text-gray-400 dark:text-neutral-400">
                    No scans found.
                </div>
            </div>
        );
    }

    return (
        <>
            {openDiffId && (
                <DiffModal scanId={openDiffId} scanType={openDiffType} onClose={() => setOpenDiffId(null)} />
            )}
            {openGlobalId && (
                <GlobalResultModal scanId={openGlobalId} onClose={() => setOpenGlobalId(null)} />
            )}
            <ConfirmationModal
                isOpen={deletingId !== null}
                title="Delete Scan"
                message="Are you sure you want to delete this scan? Associated observations and orphaned findings will be removed. This action cannot be undone."
                confirmText="Yes, delete"
                cancelText="Cancel"
                showTitleIcon={true}
                onConfirm={() => { if (deletingId) handleDeleteScan(deletingId); }}
                onCancel={() => setDeletingId(null)}
            />

            <div className="w-full px-6 py-6">
                {menuBar}
                {progressPanels}

                {/* Timeline rows */}
                <div className="relative">
                    {filteredScans.map((scan, index) => {
                        const isTool = (scan.scan_type || "sbom") === "tool";
                        const isFirst = index === 0;
                        const isLast = index === filteredScans.length - 1;

                        return (
                        <div key={scan.id} className="flex items-stretch mb-0">
                            {/* Lane indicator — single linear column */}
                            <div className="flex-shrink-0 relative" style={{ width: LANE_W, minHeight: 80 }}>
                                {/* Vertical line */}
                                <div
                                    className="absolute border-l-2 border-cyan-700 dark:border-cyan-600"
                                    style={{ left: mainCX, top: isFirst ? "50%" : 0, bottom: isLast ? "50%" : 0 }}
                                />

                                {/* Dot: circle for SBOM, colored square for tool scans */}
                                {!isTool ? (
                                    <span
                                        className={[
                                            "absolute flex items-center justify-center",
                                            "w-5 h-5 rounded-full ring-[3px]",
                                            "ring-gray-200 dark:ring-neutral-800",
                                            isFirst ? "bg-cyan-500" : "bg-cyan-700",
                                        ].join(" ")}
                                        style={{ left: mainCX, top: "50%", transform: "translate(-50%, -50%)" }}
                                    />
                                ) : (
                                    <span
                                        className={[
                                            "absolute flex items-center justify-center",
                                            "w-3 h-3 rounded-sm ring-2",
                                            "ring-gray-200 dark:ring-neutral-800",
                                            sourceSquareColor[scan.scan_source ?? ""] ?? "bg-neutral-400",
                                        ].join(" ")}
                                        style={{ left: mainCX, top: "50%", transform: "translate(-50%, -50%)" }}
                                    />
                                )}
                            </div>

                            {/* Scan card */}
                            <div className="flex-1 min-w-0 py-2 pl-3">
                            <div className="group/card relative p-4 bg-white dark:bg-neutral-700 rounded-lg shadow-sm border border-gray-100 dark:border-neutral-600">
                                {/* Delete button — top-right corner */}
                                <button
                                    onClick={() => setDeletingId(scan.id)}
                                    title="Delete scan"
                                    className="absolute top-2 right-2 z-10 opacity-0 group-hover/card:opacity-100 text-neutral-400 hover:text-red-400 transition-all p-1"
                                >
                                    <FontAwesomeIcon icon={faTrash} className="text-sm" />
                                </button>
                                {/* Row 1: timestamp + scan type badge */}
                                <div className="flex items-center gap-2 mb-1">
                                    <time className="text-sm font-semibold text-gray-500 dark:text-neutral-400">
                                        {formatDate(scan.timestamp)}
                                    </time>
                                    {(scan.scan_type || 'sbom') === 'tool' && scan.scan_source === 'osv' ? (
                                        <>
                                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold bg-gray-200 text-gray-700 dark:bg-gray-700 dark:text-gray-300">
                                            <FontAwesomeIcon icon={faCrosshairs} className="mr-1" />
                                            Vulnerability Scan
                                        </span>
                                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300">
                                            <FontAwesomeIcon icon={faLeaf} className="mr-1" />
                                            OSV Scan
                                        </span>
                                        </>
                                    ) : (scan.scan_type || 'sbom') === 'tool' && scan.scan_source === 'nvd' ? (
                                        <>
                                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold bg-gray-200 text-gray-700 dark:bg-gray-700 dark:text-gray-300">
                                            <FontAwesomeIcon icon={faCrosshairs} className="mr-1" />
                                            Vulnerability Scan
                                        </span>
                                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300">
                                            <FontAwesomeIcon icon={faShieldHalved} className="mr-1" />
                                            NVD CPE Scan
                                        </span>
                                        </>
                                    ) : (scan.scan_type || 'sbom') === 'tool' ? (
                                        <>
                                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold bg-gray-200 text-gray-700 dark:bg-gray-700 dark:text-gray-300">
                                            <FontAwesomeIcon icon={faCrosshairs} className="mr-1" />
                                            Vulnerability Scan
                                        </span>
                                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300">
                                            <FontAwesomeIcon icon={faBug} className="mr-1" />
                                            Grype Scan
                                        </span>
                                        </>
                                    ) : (
                                        <>
                                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300">
                                            <FontAwesomeIcon icon={faFile} className="mr-1" />
                                            Import SBOM
                                        </span>
                                        {(scan.formats || []).map((fmt: string) => (
                                            <span key={fmt} className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-cyan-50 text-cyan-600 dark:bg-cyan-900/20 dark:text-cyan-400">
                                                {fmt}
                                            </span>
                                        ))}
                                        </>
                                    )}
                                </div>

                                {/* Project / Variant */}
                                <p className="text-sm font-medium text-gray-800 dark:text-neutral-100 mb-1">
                                    {scan.project_name
                                        ? <><span className="text-neutral-500 dark:text-neutral-400">{scan.project_name}</span><span className="mx-1 text-neutral-400">/</span><span>{scan.variant_name ?? scan.variant_id}</span></>
                                        : <span>{scan.variant_name ?? scan.variant_id}</span>
                                    }
                                </p>

                                {/* Row 2: badges + details button */}
                                {(scan.scan_type || 'sbom') === 'tool' && (
                                <>
                                {/* Update Vulnerabilities row */}
                                <div className="flex items-center gap-2 flex-wrap mb-1">
                                    <span className="text-xs font-bold text-neutral-400 dark:text-neutral-400 uppercase tracking-wide">Update Vulnerabilities:</span>
                                    {scan.is_first ? (
                                        <>
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.vuln_count ?? 0) > 0 ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {(scan.vuln_count ?? 0).toLocaleString()} vulnerabilities detected
                                            </span>
                                            {scan.newly_detected_vulns != null && (
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${scan.newly_detected_vulns > 0 ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {scan.newly_detected_vulns.toLocaleString()} new vulnerabilities discovered
                                            </span>
                                            )}
                                        </>
                                    ) : (
                                        <>
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.vuln_count ?? 0) > 0 ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {(scan.vuln_count ?? 0).toLocaleString()} vulnerabilities detected
                                            </span>
                                            {scan.newly_detected_vulns != null && (
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${scan.newly_detected_vulns > 0 ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {scan.newly_detected_vulns.toLocaleString()} new vulnerabilities discovered
                                            </span>
                                            )}
                                        </>
                                    )}
                                </div>
                                {/* Update Findings row */}
                                <div className="flex items-center gap-2 flex-wrap mb-1">
                                    <span className="text-xs font-bold text-neutral-400 dark:text-neutral-400 uppercase tracking-wide">Update Findings:</span>
                                    {scan.is_first ? (
                                        <>
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.finding_count ?? 0) > 0 ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {(scan.finding_count ?? 0).toLocaleString()} findings detected
                                            </span>
                                            {scan.newly_detected_findings != null && (
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${scan.newly_detected_findings > 0 ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {scan.newly_detected_findings.toLocaleString()} new findings discovered
                                            </span>
                                            )}
                                        </>
                                    ) : (
                                        <>
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.finding_count ?? 0) > 0 ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {(scan.finding_count ?? 0).toLocaleString()} findings detected
                                            </span>
                                            {scan.newly_detected_findings != null && (
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${scan.newly_detected_findings > 0 ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {scan.newly_detected_findings.toLocaleString()} new findings discovered
                                            </span>
                                            )}
                                        </>
                                    )}

                                </div>
                                {/* Update Assessments row */}
                                <div className="flex items-center gap-2 flex-wrap mb-1">
                                    <span className="text-xs font-bold text-neutral-400 dark:text-neutral-400 uppercase tracking-wide">Update Assessments:</span>
                                    {scan.is_first ? (
                                        <>
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.assessment_count ?? 0) > 0 ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {(scan.assessment_count ?? 0).toLocaleString()} assessments detected
                                            </span>
                                            {scan.newly_detected_assessments != null && (
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.newly_detected_assessments ?? 0) > 0 ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {(scan.newly_detected_assessments ?? 0).toLocaleString()} new assessments discovered
                                            </span>
                                            )}
                                        </>
                                    ) : (
                                        <>
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.assessment_count ?? 0) > 0 ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {(scan.assessment_count ?? 0).toLocaleString()} assessments detected
                                            </span>
                                            {scan.newly_detected_assessments != null && (
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.newly_detected_assessments ?? 0) > 0 ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {(scan.newly_detected_assessments ?? 0).toLocaleString()} new assessments discovered
                                            </span>
                                            )}
                                        </>
                                    )}
                                    {/* Details button */}
                                    <button
                                        onClick={() => { setOpenDiffId(scan.id); setOpenDiffType(scan.scan_type || 'sbom'); }}
                                        className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-neutral-200 dark:bg-neutral-600 hover:bg-neutral-300 dark:hover:bg-neutral-500 text-neutral-700 dark:text-neutral-200 transition-colors"
                                    >
                                        Details
                                    </button>
                                </div>
                                </>
                                )}
                                {(scan.scan_type || 'sbom') !== 'tool' && (
                                <>
                                {/* Vulnerabilities row */}
                                <div className="flex items-center gap-2 flex-wrap mb-1">
                                    <span className="text-xs font-bold text-neutral-400 dark:text-neutral-400 uppercase tracking-wide">Vulnerabilities:</span>
                                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.vuln_count ?? 0) > 0 ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                        {(scan.vuln_count ?? 0).toLocaleString()} vulnerabilities detected
                                    </span>
                                    {!scan.is_first && (
                                        <>
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.vulns_added ?? 0) > 0 ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {(scan.vulns_added ?? 0).toLocaleString()} new vulnerabilities
                                            </span>
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.vulns_removed ?? 0) > 0 ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {(scan.vulns_removed ?? 0).toLocaleString()} vulnerabilities removed
                                            </span>
                                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400">
                                                {(scan.vulns_unchanged ?? 0).toLocaleString()} vulnerabilities unchanged
                                            </span>
                                        </>
                                    )}
                                </div>
                                {/* Findings row */}
                                <div className="flex items-center gap-2 flex-wrap mb-1">
                                    <span className="text-xs font-bold text-neutral-400 dark:text-neutral-400 uppercase tracking-wide">Findings:</span>
                                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.finding_count ?? 0) > 0 ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                        {(scan.finding_count ?? 0).toLocaleString()} findings detected
                                    </span>
                                    {!scan.is_first && (
                                        <>
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.findings_added ?? 0) > 0 ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {(scan.findings_added ?? 0).toLocaleString()} new findings
                                            </span>
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.findings_removed ?? 0) > 0 ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {(scan.findings_removed ?? 0).toLocaleString()} findings removed
                                            </span>
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.findings_upgraded ?? 0) > 0 ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {(scan.findings_upgraded ?? 0).toLocaleString()} findings upgraded
                                            </span>
                                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400">
                                                {(scan.findings_unchanged ?? 0).toLocaleString()} findings unchanged
                                            </span>
                                        </>
                                    )}
                                </div>
                                {/* Packages row */}
                                <div className="flex items-center gap-2 flex-wrap mb-1">
                                    <span className="text-xs font-bold text-neutral-400 dark:text-neutral-400 uppercase tracking-wide">Packages:</span>
                                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.package_count ?? 0) > 0 ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                        {(scan.package_count ?? 0).toLocaleString()} packages detected
                                    </span>
                                    {!scan.is_first && (
                                        <>
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.packages_added ?? 0) > 0 ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {(scan.packages_added ?? 0).toLocaleString()} new packages
                                            </span>
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.packages_removed ?? 0) > 0 ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {(scan.packages_removed ?? 0).toLocaleString()} packages removed
                                            </span>
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.packages_upgraded ?? 0) > 0 ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {(scan.packages_upgraded ?? 0).toLocaleString()} packages upgraded
                                            </span>
                                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400">
                                                {(scan.packages_unchanged ?? 0).toLocaleString()} packages unchanged
                                            </span>
                                        </>
                                    )}
                                </div>
                                {/* Assessments row */}
                                <div className="flex items-center gap-2 flex-wrap mb-1">
                                    <span className="text-xs font-bold text-neutral-400 dark:text-neutral-400 uppercase tracking-wide">Assessments:</span>
                                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.assessment_count ?? 0) > 0 ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                        {(scan.assessment_count ?? 0).toLocaleString()} assessments detected
                                    </span>
                                    {!scan.is_first && (scan.assessment_count ?? 0) > 0 && (
                                        <>
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.assessments_added ?? 0) > 0 ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {(scan.assessments_added ?? 0).toLocaleString()} new assessments
                                            </span>
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.assessments_removed ?? 0) > 0 ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                {(scan.assessments_removed ?? 0).toLocaleString()} assessments removed
                                            </span>
                                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400">
                                                {(scan.assessments_unchanged ?? 0).toLocaleString()} assessments unchanged
                                            </span>
                                        </>
                                    )}
                                    {/* Details button */}
                                    <button
                                        onClick={() => { setOpenDiffId(scan.id); setOpenDiffType(scan.scan_type || 'sbom'); }}
                                        className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-neutral-200 dark:bg-neutral-600 hover:bg-neutral-300 dark:hover:bg-neutral-500 text-neutral-700 dark:text-neutral-200 transition-colors"
                                    >
                                        Details
                                    </button>
                                </div>

                                {/* Scan Result row — uses global counts when tool scans exist, else SBOM-only */}
                                <div className="flex items-center gap-2 flex-wrap mb-1 mt-2 pt-2 border-t border-neutral-300 dark:border-neutral-600">
                                    <span className="text-xs font-bold text-neutral-400 dark:text-neutral-400 uppercase tracking-wide">Scan Result:</span>
                                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${((scan.global_package_count ?? scan.package_count ?? 0)) > 0 ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                        {(scan.global_package_count ?? scan.package_count ?? 0).toLocaleString()} packages
                                    </span>
                                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${((scan.global_finding_count ?? scan.finding_count ?? 0)) > 0 ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                        {(scan.global_finding_count ?? scan.finding_count ?? 0).toLocaleString()} findings
                                    </span>
                                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${((scan.global_vuln_count ?? scan.vuln_count ?? 0)) > 0 ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                        {(scan.global_vuln_count ?? scan.vuln_count ?? 0).toLocaleString()} vulnerabilities
                                    </span>
                                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.global_assessment_count ?? scan.assessment_count ?? 0) > 0 ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                        {(scan.global_assessment_count ?? scan.assessment_count ?? 0).toLocaleString()} assessments
                                    </span>
                                    <button
                                        onClick={() => setOpenGlobalId(scan.id)}
                                        className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-neutral-200 dark:bg-neutral-600 hover:bg-neutral-300 dark:hover:bg-neutral-500 text-neutral-700 dark:text-neutral-200 transition-colors"
                                    >
                                        Details
                                    </button>
                                </div>
                                </>
                                )}

                                {/* Scan Result (tool scans only) — SBOM ∪ all sources */}
                                {(scan.scan_type || 'sbom') === 'tool' && scan.global_finding_count != null && (
                                    <div className="flex items-center gap-2 flex-wrap mb-1 mt-2 pt-2 border-t border-neutral-300 dark:border-neutral-600">
                                        <span className="text-xs font-bold text-neutral-400 dark:text-neutral-400 uppercase tracking-wide">Scan Result:</span>
                                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.global_package_count ?? 0) > 0 ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                            {(scan.global_package_count ?? 0).toLocaleString()} packages
                                        </span>
                                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.global_finding_count ?? 0) > 0 ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                            {(scan.global_finding_count ?? 0).toLocaleString()} findings
                                        </span>
                                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.global_vuln_count ?? 0) > 0 ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                            {(scan.global_vuln_count ?? 0).toLocaleString()} vulnerabilities
                                        </span>
                                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.global_assessment_count ?? 0) > 0 ? 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                            {(scan.global_assessment_count ?? 0).toLocaleString()} assessments
                                        </span>
                                        <button
                                            onClick={() => setOpenGlobalId(scan.id)}
                                            className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-neutral-200 dark:bg-neutral-600 hover:bg-neutral-300 dark:hover:bg-neutral-500 text-neutral-700 dark:text-neutral-200 transition-colors"
                                        >
                                            Details
                                        </button>
                                    </div>
                                )}

                                {/* Description row */}
                                {editingDescId === scan.id ? (
                                    <div className="mt-2 flex items-center gap-2">
                                        <input
                                            autoFocus
                                            type="text"
                                            value={editingDescValue}
                                            onChange={e => setEditingDescValue(e.target.value)}
                                            onKeyDown={e => {
                                                if (e.key === 'Enter') saveDescription(scan.id);
                                                if (e.key === 'Escape') setEditingDescId(null);
                                            }}
                                            placeholder="Add a description…"
                                            className="flex-1 text-sm px-2 py-1 rounded border border-neutral-500 bg-neutral-800 text-neutral-100 placeholder-neutral-500 focus:outline-none focus:border-cyan-500"
                                        />
                                        <button
                                            onClick={() => saveDescription(scan.id)}
                                            title="Save"
                                            className="text-green-400 hover:text-green-300 transition-colors"
                                        >
                                            <FontAwesomeIcon icon={faCheck} />
                                        </button>
                                        <button
                                            onClick={() => setEditingDescId(null)}
                                            title="Cancel"
                                            className="text-neutral-400 hover:text-neutral-200 transition-colors"
                                        >
                                            <FontAwesomeIcon icon={faXmark} />
                                        </button>
                                    </div>
                                ) : (
                                    <div className="mt-1.5 flex items-center gap-2 group/desc">
                                        <span className="text-sm text-neutral-400 dark:text-neutral-400 italic flex-1">
                                            {scan.description ?? ''}
                                        </span>
                                        <button
                                            onClick={() => { setEditingDescId(scan.id); setEditingDescValue(scan.description ?? ''); }}
                                            title="Edit description"
                                            className="opacity-0 group-hover/desc:opacity-100 text-neutral-400 hover:text-cyan-400 transition-all"
                                        >
                                            <FontAwesomeIcon icon={faPencil} className="text-xs" />
                                        </button>
                                    </div>
                                )}
                            </div>
                            </div>
                        </div>
                        );
                    })}
                </div>
            </div>
        </>
    );
}

export default ScanHistory;

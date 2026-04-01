import { useEffect, useRef, useState } from "react";
import ScansHandler from "../handlers/scans";
import type { Scan, ScanDiff, FindingDiffEntry, FindingUpgradeEntry, PackageDiffEntry, PackageUpgradeEntry } from "../handlers/scans";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faPencil, faCheck, faXmark } from "@fortawesome/free-solid-svg-icons";

type Props = {
    variantId?: string;
    projectId?: string;
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
    const filtered = filter
        ? entries.filter(e =>
            e.package_name.toLowerCase().includes(filter.toLowerCase()) ||
            e.package_version.toLowerCase().includes(filter.toLowerCase()) ||
            e.vulnerability_id.toLowerCase().includes(filter.toLowerCase())
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
                            </tr>
                        </thead>
                        <tbody>
                            {filtered.map((e) => (
                                <tr key={e.finding_id} className="border-t border-gray-600 hover:bg-gray-600/40">
                                    <td className="px-3 py-1.5 font-mono">{e.package_name}</td>
                                    <td className="px-3 py-1.5 font-mono text-gray-400">{e.package_version}</td>
                                    <td className="px-3 py-1.5 font-mono">{e.vulnerability_id}</td>
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
    const filtered = filter
        ? entries.filter(e =>
            e.package_name.toLowerCase().includes(filter.toLowerCase()) ||
            e.vulnerability_id.toLowerCase().includes(filter.toLowerCase()) ||
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
                            </tr>
                        </thead>
                        <tbody>
                            {filtered.map((e, i) => (
                                <tr key={e.vulnerability_id + e.package_name + i} className="border-t border-gray-600 hover:bg-gray-600/40">
                                    <td className="px-3 py-1.5 font-mono">{e.package_name}</td>
                                    <td className="px-3 py-1.5 font-mono text-red-400">{e.old_version}</td>
                                    <td className="px-3 py-1.5 font-mono text-green-400">{e.new_version}</td>
                                    <td className="px-3 py-1.5 font-mono">{e.vulnerability_id}</td>
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

function VulnDiffList({ vulns, label, colorClass }: {
    vulns: string[];
    label: string;
    colorClass: string;
}) {
    const [filter, setFilter] = useState('');
    const filtered = filter
        ? vulns.filter(v => v.toLowerCase().includes(filter.toLowerCase()))
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
                            </tr>
                        </thead>
                        <tbody>
                            {filtered.map((v) => (
                                <tr key={v} className="border-t border-gray-600 hover:bg-gray-600/40">
                                    <td className="px-3 py-1.5 font-mono">{v}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}

type Section = 'packages' | 'findings' | 'vulnerabilities';

function DiffModal({ scanId, onClose }: { scanId: string; onClose: () => void }) {
    const [diff, setDiff] = useState<ScanDiff | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [section, setSection] = useState<Section>('packages');
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
                            Scan diff details
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
                                    </>
                                )}
                            </button>
                            <button className={tabCls('findings')} onClick={() => setSection('findings')}>
                                Findings
                                {diff.is_first ? (
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
                                    </>
                                )}
                            </button>
                            <button className={tabCls('vulnerabilities')} onClick={() => setSection('vulnerabilities')}>
                                Vulnerabilities
                                {diff.is_first ? (
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
                                    </>
                                )}
                            </button>
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
                                    colorClass="text-green-400"
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
                            </>
                        )}
                        {diff && section === 'findings' && (
                            <>
                                {diff.is_first && (
                                    <p className="text-sm text-gray-400 mb-4 italic">
                                        This is the first scan — all {diff.finding_count.toLocaleString()} findings are listed below.
                                    </p>
                                )}
                                <FindingDiffTable
                                    entries={diff.findings_added}
                                    label={diff.is_first ? "All findings" : "Added findings"}
                                    colorClass="text-green-400"
                                />
                                {!diff.is_first && (
                                    <FindingDiffTable
                                        entries={diff.findings_removed}
                                        label="Removed findings"
                                        colorClass="text-red-400"
                                    />
                                )}
                                {!diff.is_first && diff.findings_upgraded.length > 0 && (
                                    <FindingUpgradeDiffTable
                                        entries={diff.findings_upgraded}
                                        label="Findings on upgraded packages"
                                        colorClass="text-yellow-400"
                                    />
                                )}
                            </>
                        )}
                        {diff && section === 'vulnerabilities' && (
                            <>
                                {diff.is_first && (
                                    <p className="text-sm text-gray-400 mb-4 italic">
                                        This is the first scan — all {diff.vuln_count.toLocaleString()} vulnerabilities are listed below.
                                    </p>
                                )}
                                <VulnDiffList
                                    vulns={diff.vulns_added}
                                    label={diff.is_first ? "All vulnerabilities" : "New vulnerabilities"}
                                    colorClass="text-green-400"
                                />
                                {!diff.is_first && (
                                    <VulnDiffList
                                        vulns={diff.vulns_removed}
                                        label="Removed vulnerabilities"
                                        colorClass="text-red-400"
                                    />
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

function ScanHistory({ variantId, projectId }: Readonly<Props>) {
    const [scans, setScans] = useState<Scan[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [openDiffId, setOpenDiffId] = useState<string | null>(null);
    const [editingDescId, setEditingDescId] = useState<string | null>(null);
    const [editingDescValue, setEditingDescValue] = useState<string>('');

    async function saveDescription(scanId: string) {
        const ok = await ScansHandler.setDescription(scanId, editingDescValue);
        if (ok) {
            setScans(prev => prev.map(s => s.id === scanId ? { ...s, description: editingDescValue } : s));
            setEditingDescId(null);
        }
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
    }, [variantId, projectId]);

    if (loading) {
        return (
            <div className="flex items-center justify-center h-32 text-gray-400">
                Loading scan history…
            </div>
        );
    }
    if (error) {
        return (
            <div className="flex items-center justify-center h-32 text-red-400">
                {error}
            </div>
        );
    }
    if (scans.length === 0) {
        return (
            <div className="flex items-center justify-center h-32 text-gray-400 dark:text-neutral-400">
                No scans found.
            </div>
        );
    }

    return (
        <>
            {openDiffId && (
                <DiffModal scanId={openDiffId} onClose={() => setOpenDiffId(null)} />
            )}

            <div className="max-w-7xl mx-auto py-6">
                <h1 className="text-2xl font-bold mb-6 text-gray-800 dark:text-neutral-100">
                    Scan History
                </h1>

                <ol className="relative border-l-2 border-cyan-700 dark:border-cyan-600">
                    {scans.map((scan, index) => (
                        <li key={scan.id} className="mb-8 ml-6">
                            {/* Connector dot */}
                            <span className={[
                                "absolute -left-3 flex items-center justify-center",
                                "w-6 h-6 rounded-full ring-4",
                                "ring-gray-200 dark:ring-neutral-800",
                                index === 0
                                    ? "bg-cyan-600"
                                    : "bg-neutral-400 dark:bg-neutral-600",
                            ].join(' ')} />

                            <div className="p-4 bg-white dark:bg-neutral-700 rounded-lg shadow-sm border border-gray-100 dark:border-neutral-600">
                                {/* Row 1: timestamp */}
                                <time className="block text-sm font-semibold text-gray-500 dark:text-neutral-400 mb-1">
                                    {formatDate(scan.timestamp)}
                                </time>

                                {/* Row 2: badges + details button */}
                                <div className="flex items-center gap-2 flex-wrap mb-1">
                                        {scan.is_first ? (
                                            /* First scan: total counts */
                                            <>
                                                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300">
                                                    {(scan.package_count ?? 0).toLocaleString()} packages
                                                </span>
                                                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300">
                                                    {(scan.finding_count ?? 0).toLocaleString()} findings
                                                </span>
                                                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-300">
                                                    {(scan.vuln_count ?? 0).toLocaleString()} vulnerabilities
                                                </span>
                                            </>
                                        ) : (
                                            /* Subsequent scans: diff badges */
                                            <>
                                                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.packages_added ?? 0) > 0 ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                    +{(scan.packages_added ?? 0).toLocaleString()} packages
                                                </span>
                                                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.packages_removed ?? 0) > 0 ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                    −{(scan.packages_removed ?? 0).toLocaleString()} packages
                                                </span>
                                                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.packages_upgraded ?? 0) > 0 ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                    ↑{(scan.packages_upgraded ?? 0).toLocaleString()} packages upgraded
                                                </span>
                                                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.findings_added ?? 0) > 0 ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                    +{(scan.findings_added ?? 0).toLocaleString()} findings
                                                </span>
                                                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.findings_removed ?? 0) > 0 ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                    −{(scan.findings_removed ?? 0).toLocaleString()} findings
                                                </span>
                                                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.findings_upgraded ?? 0) > 0 ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                    ↑{(scan.findings_upgraded ?? 0).toLocaleString()} findings upgraded
                                                </span>
                                                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.vulns_added ?? 0) > 0 ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                    +{(scan.vulns_added ?? 0).toLocaleString()} vulnerabilities
                                                </span>
                                                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${(scan.vulns_removed ?? 0) > 0 ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300' : 'bg-neutral-100 text-neutral-500 dark:bg-neutral-700 dark:text-neutral-400'}`}>
                                                    −{(scan.vulns_removed ?? 0).toLocaleString()} vulnerabilities
                                                </span>
                                            </>
                                        )}

                                        {/* Details button */}
                                        <button
                                            onClick={() => setOpenDiffId(scan.id)}
                                            className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-neutral-200 dark:bg-neutral-600 hover:bg-neutral-300 dark:hover:bg-neutral-500 text-neutral-700 dark:text-neutral-200 transition-colors"
                                        >
                                            Details
                                        </button>
                                    </div>

                                {/* Project / Variant */}
                                <p className="text-base font-medium text-gray-800 dark:text-neutral-100">
                                    {scan.project_name
                                        ? <><span className="text-neutral-500 dark:text-neutral-400">{scan.project_name}</span><span className="mx-1 text-neutral-400">/</span><span>{scan.variant_name ?? scan.variant_id}</span></>
                                        : <span>{scan.variant_name ?? scan.variant_id}</span>
                                    }
                                </p>

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
                        </li>
                    ))}
                </ol>
            </div>
        </>
    );
}

export default ScanHistory;

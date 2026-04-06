import { useCallback, useEffect, useMemo, useState } from "react";
import type { CVSS } from "../handlers/vulnerabilities";
import { SEVERITY_ORDER } from "../handlers/vulnerabilities";
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, BarElement, LogarithmicScale, ChartEvent, LegendItem, LegendElement } from 'chart.js';
import { Pie, Line, Bar } from 'react-chartjs-2';
import TableGeneric from "../components/TableGeneric";
import SeverityTag from "../components/SeverityTag";
import VulnModal from "../components/VulnModal";
import type { Assessment } from "../handlers/assessments";
import MetricsHandler from "../handlers/metrics";
import type { MetricsData } from "../handlers/metrics";

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, BarElement, LogarithmicScale);

type Props = {
    variantId?: string;
    projectId?: string;
    goToVulnsTabWithFilter: (filterType: "Source" | "Severity" | "Status", value: string) => void;
    appendAssessment: (added: Assessment) => void;
    patchVuln: (vulnId: string, data: any) => void;
    setTab: (tab: string) => void;
    appendCVSS: (vulnId: string, vector: string) => CVSS | null;
};

const pieOptions = {
    maintainAspectRatio: true,
    plugins: {
        legend: {
            position: 'bottom' as const,
            labels: { color: '#ccc' }
        }
    }
};

const LineOptions = {
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    elements: {
        point: { radius: 6 },
        line: { borderWidth: 3, borderColor: '#aaa' }
    },
    scales: {
        x: { ticks: { color: 'white' } },
        y: { beginAtZero: true, ticks: { color: 'white' } }
    }
};

const BarOptions = {
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
        x: { ticks: { color: 'white' } },
        y: { ticks: { color: 'white' } }
    }
};

function Metrics({ variantId, projectId, goToVulnsTabWithFilter, appendAssessment, appendCVSS, patchVuln, setTab }: Readonly<Props>) {
    const defaultPieHandler = ChartJS.overrides.pie.plugins.legend.onClick;

    const [timeScale, setTimeScale] = useState<string>("6_months");
    const [metricsData, setMetricsData] = useState<MetricsData | null>(null);
    const [loadError, setLoadError] = useState<string | null>(null);
    const [modalVulnIndex, setModalVulnIndex] = useState<number | undefined>(undefined);
    const [isEditing, setIsEditing] = useState<boolean>(false);

    const fetchMetrics = useCallback(() => {
        MetricsHandler.fetch(variantId, projectId, timeScale)
            .then(data => { setMetricsData(data); setLoadError(null); })
            .catch(err => { console.error("Failed to load metrics:", err); setLoadError("Failed to load metrics data."); });
    }, [variantId, projectId, timeScale]);

    useEffect(() => { fetchMetrics(); }, [fetchMetrics]);

    const modalVuln = metricsData && modalVulnIndex !== undefined
        ? metricsData.top_vulns[modalVulnIndex]?.original
        : undefined;

    const handleAppendAssessment = useCallback((added: Assessment) => {
        appendAssessment(added);
        fetchMetrics();
    }, [appendAssessment, fetchMetrics]);

    const handlePatchVuln = useCallback((vulnId: string, data: any) => {
        patchVuln(vulnId, data);
        fetchMetrics();
    }, [patchVuln, fetchMetrics]);

    const handleModalNavigation = (newIndex: number) => {
        if (metricsData && newIndex >= 0 && newIndex < metricsData.top_vulns.length) {
            setModalVulnIndex(newIndex);
        }
    };

    // Chart datasets

    const dataSetVulnBySeverity = useMemo(() => ({
        labels: ['Unknown', 'Low', 'Medium', 'High', 'Critical'],
        datasets: [{
            label: '# of Vulnerabilities',
            data: metricsData?.vuln_by_severity ?? [0, 0, 0, 0, 0],
            backgroundColor: ['rgba(180, 180, 180)', 'rgba(0, 150, 150)', '#F8DE22', '#F94C10', '#FC2947'],
            hoverOffset: 4
        }]
    }), [metricsData]);

    const dataSetVulnByStatus = useMemo(() => ({
        labels: ['Not affected', 'Fixed', 'Pending Assessment', 'Exploitable'],
        datasets: [{
            label: '# of Vulnerabilities',
            data: metricsData?.vuln_by_status ?? [0, 0, 0, 0],
            backgroundColor: ['rgba(0, 150, 150)', '#009900', 'rgba(255, 128, 0)', '#F94C10'],
            hoverOffset: 4
        }]
    }), [metricsData]);

    const vulnEvolutionTime = useMemo(() => ({
        labels: metricsData?.vuln_evolution.labels ?? [],
        datasets: [{
            label: '# of Vulnerabilities',
            data: metricsData?.vuln_evolution.data ?? [],
            backgroundColor: 'rgba(0, 150, 150, 0.7)',
            hoverOffset: 4
        }]
    }), [metricsData]);

    const dataSetVulnBySource = useMemo(() => ({
        labels: metricsData?.vuln_by_source.labels ?? [],
        datasets: [{
            label: '# of Vulnerabilities',
            data: metricsData?.vuln_by_source.data ?? [],
            backgroundColor: 'rgba(0, 150, 150, 0.7)',
            hoverOffset: 4
        }]
    }), [metricsData]);

    // Column definitions

    const vulnColumns = useMemo(() => [
        {
            accessorKey: "rank",
            header: () => <div className="flex items-center justify-center h-full">#</div>,
            cell: (info: any) => <div className="flex items-center justify-center h-full text-center">{info.getValue()}</div>,
            size: 30, enableSorting: false,
        },
        {
            accessorKey: "cve",
            header: () => <div className="flex items-center justify-center h-full">CVE</div>,
            cell: (info: any) => <div className="flex items-center justify-center h-full text-center">{info.getValue()}</div>,
            size: 200, enableSorting: false,
        },
        {
            accessorKey: "package",
            header: () => <div className="flex items-center justify-center h-full">Package</div>,
            cell: (info: any) => <div className="flex items-center justify-center h-full text-center">{info.getValue()}</div>,
            size: 200, enableSorting: false,
        },
        {
            accessorKey: "severity",
            header: () => <div className="flex items-center justify-center h-full">Severity</div>,
            cell: (info: any) => (
                <div className="flex items-center justify-center h-full text-center">
                    <SeverityTag severity={info.getValue()} className="!py-0" />
                </div>
            ),
            size: 100, enableSorting: false,
        },
        {
            accessorKey: "edit",
            header: () => <div className="flex items-center justify-center h-full">Actions</div>,
            cell: (info: any) => (
                <div className="flex items-center justify-center h-full text-center">
                    <button
                        className="bg-slate-800 hover:bg-slate-700 px-2 rounded-lg"
                        onClick={() => { setModalVulnIndex(info.row.index); setIsEditing(true); }}
                    >
                        Edit
                    </button>
                </div>
            ),
            size: 50, enableSorting: false,
        },
    ], []);

    const packageColumns = [
        { accessorKey: "id", header: () => <div className="flex items-center justify-center h-full">#</div>, cell: (info: any) => <div className="flex items-center justify-center py-1 h-full text-center">{info.getValue()}</div>, size: 30, enableSorting: false },
        { accessorKey: "name", size: 350, header: () => <div className="flex items-center justify-center h-full">Name</div>, cell: (info: any) => <div className="flex items-center justify-center h-full text-center">{info.getValue()}</div>, enableSorting: false },
        { accessorKey: "version", size: 100, header: () => <div className="flex items-center justify-center h-full">Version</div>, cell: (info: any) => <div className="flex items-center justify-center h-full text-center"><span className="truncate max-w-full block" title={info.getValue()}>{info.getValue()}</span></div>, enableSorting: false },
        { accessorKey: "count", size: 100, header: () => <div className="flex items-center justify-center h-full">Vulnerabilities</div>, cell: (info: any) => <div className="flex items-center justify-center h-full text-center">{info.getValue()}</div>, enableSorting: false },
    ];

    // Pie click options

    const vulnBySeverityOptions = {
        ...pieOptions,
        plugins: {
            ...pieOptions.plugins,
            legend: {
                ...pieOptions.plugins.legend,
                onClick: function (this: LegendElement<"pie">, e: ChartEvent, legendItem: LegendItem, legend: LegendElement<"pie">) {
                    defaultPieHandler.call(this, e, legendItem, legend);
                }
            }
        },
        onClick: (_e: ChartEvent, elements: any[]) => {
            if (!elements.length) return;
            const severityOrder = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
            const targetSeverity = severityOrder[elements[0].index];
            if (targetSeverity) {
                goToVulnsTabWithFilter("Severity", targetSeverity.charAt(0) + targetSeverity.slice(1).toLowerCase());
            }
        }
    };

    const vulnByStatusOptions = {
        ...pieOptions,
        plugins: {
            ...pieOptions.plugins,
            legend: {
                ...pieOptions.plugins.legend,
                onClick: function (this: LegendElement<"pie">, e: ChartEvent, legendItem: LegendItem, legend: LegendElement<"pie">) {
                    defaultPieHandler.call(this, e, legendItem, legend);
                }
            }
        },
        onClick: (_e: ChartEvent, elements: any[]) => {
            if (!elements.length) return;
            const statusOrder = ['Not affected', 'Fixed', 'Pending Assessment', 'Exploitable'];
            const targetStatus = statusOrder[elements[0].index];
            if (targetStatus) goToVulnsTabWithFilter("Status", targetStatus);
        }
    };

    if (loadError) {
        return <div className="w-full flex flex-col items-center justify-center py-16 text-red-400"><p>{loadError}</p></div>;
    }

    return (
        <div className="w-full flex flex-col gap-4 pb-8">

            {/* TOP CHART GRID */}
            <div className="w-full grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">

                <div className="p-4">
                    <div className="bg-zinc-700 p-2 text-center text-xl text-white whitespace-nowrap rounded-t-md">Vulnerabilities by Severity</div>
                    <div className="bg-zinc-700 p-4 w-full aspect-square rounded-b-md">
                        <div className="h-full"><Pie data={dataSetVulnBySeverity} options={{ ...vulnBySeverityOptions, maintainAspectRatio: false }} /></div>
                    </div>
                </div>

                <div className="p-4">
                    <div className="bg-zinc-700 p-2 text-center text-xl text-white whitespace-nowrap rounded-t-md">Vulnerabilities by Status</div>
                    <div className="bg-zinc-700 p-4 w-full aspect-square rounded-b-md">
                        <div className="h-full"><Pie data={dataSetVulnByStatus} options={{ ...vulnByStatusOptions, maintainAspectRatio: false }} /></div>
                    </div>
                </div>

                <div className="p-4">
                    <div className="bg-zinc-700 p-2 flex items-center justify-center gap-2 rounded-t-md">
                        <div className="text-xl text-white whitespace-nowrap" title="Active vulnerabilities is the sum of exploitable and Pending Assessment vulnerabilities.">
                            Active vulnerabilities
                        </div>
                        <select className="bg-zinc-800 p-1 text-white rounded w-36" value={timeScale} onChange={(event) => setTimeScale(event.target.value)}>
                            <option value="12_months">1 year</option>
                            <option value="6_months">6 months</option>
                            <option value="12_weeks">12 weeks</option>
                            <option value="6_weeks">6 weeks</option>
                            <option value="31_days">1 month</option>
                            <option value="7_days">1 week</option>
                            <option value="24_hours">24 hours</option>
                        </select>
                    </div>
                    <div className="bg-zinc-700 p-4 w-full aspect-square rounded-b-md">
                        <div className="h-full"><Line data={vulnEvolutionTime} options={{ ...LineOptions, maintainAspectRatio: false }} /></div>
                    </div>
                </div>

                <div className="p-4">
                    <div className="bg-zinc-700 p-2 text-center text-xl text-white whitespace-nowrap rounded-t-md">Vulnerabilities by Database</div>
                    <div className="bg-zinc-700 p-4 w-full aspect-square rounded-b-md">
                        <div className="h-full"><Bar data={dataSetVulnBySource} options={{ ...BarOptions, maintainAspectRatio: false }} /></div>
                    </div>
                </div>

            </div>

            {/* TABLES SECTION */}
            <div className="w-full grid grid-cols-1 lg:grid-cols-2">

                <div className="p-4">
                    <div className="bg-zinc-700 px-4 py-2 flex items-center justify-between rounded-t-md">
                        <h3 className="text-2xl font-bold text-white whitespace-nowrap">Most critical unfixed vulnerabilities</h3>
                        <button className="bg-cyan-800 hover:bg-cyan-700 focus:ring-4 focus:outline-none focus:ring-blue-800 font-medium rounded-lg px-4 py-2 text-center text-white" onClick={() => setTab('vulnerabilities')}>See all</button>
                    </div>
                    <div className="bg-zinc-700 p-4 rounded-b-md">
                        <TableGeneric columns={vulnColumns} data={metricsData?.top_vulns ?? []} hasPagination={false} tableHeight="auto" />
                    </div>
                </div>

                <div className="p-4">
                    <div className="bg-zinc-700 px-4 py-2 flex items-center justify-between rounded-t-md">
                        <h3 className="text-2xl font-bold text-white whitespace-nowrap">Most vulnerable packages</h3>
                        <button className="bg-cyan-800 hover:bg-cyan-700 focus:ring-4 focus:outline-none focus:ring-blue-800 font-medium rounded-lg px-4 py-2 text-center text-white" onClick={() => setTab('packages')}>See all</button>
                    </div>
                    <div className="bg-zinc-700 p-4 rounded-b-md">
                        <div className="w-full h-full overflow-y-auto">
                            <TableGeneric columns={packageColumns} data={metricsData?.top_packages ?? []} hasPagination={false} tableHeight="auto" />
                        </div>
                    </div>
                </div>

            </div>

            {/* MODAL */}
            {modalVuln && metricsData && (
                <VulnModal
                    vuln={modalVuln}
                    isEditing={isEditing}
                    onClose={() => { setModalVulnIndex(undefined); setIsEditing(false); }}
                    appendAssessment={handleAppendAssessment}
                    appendCVSS={appendCVSS}
                    patchVuln={handlePatchVuln}
                    vulnerabilities={metricsData.top_vulns.map(item => item.original)}
                    currentIndex={modalVulnIndex}
                    onNavigate={handleModalNavigation}
                />
            )}
        </div>
    );
}

export { SEVERITY_ORDER };
export default Metrics;

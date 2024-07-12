import { useMemo, useState } from "react";
import type { Package } from "../handlers/packages";
import type { Vulnerability } from "../handlers/vulnerabilities";
import { SEVERITY_ORDER } from "../handlers/vulnerabilities";
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, BarElement, LogarithmicScale, ChartEvent, LegendItem, LegendElement } from 'chart.js';
import { Pie, Line, Bar } from 'react-chartjs-2';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, BarElement, LogarithmicScale);

type Props = {
    packages: Package[];
    vulnerabilities: Vulnerability[];
};


const pieOptions = {
    maintainAspectRatio: true,
    plugins: {
        legend: {
            position: 'bottom' as const,
            labels: {
                color: '#ccc'
            }
        }
    }
}

const LineOptions = {
    maintainAspectRatio: false,
    plugins: {
        legend: {
            display: false
        }
    },
    elements: {
        point: {
            radius: 6
        },
        line: {
            borderWidth: 3,
            borderColor: '#aaa'
        }
    },
    scales: {
        y: {
            beginAtZero: true
        }
    }
}

const BarOptions = {
    maintainAspectRatio: false,
    plugins: {
        legend: {
            display: false
        }
    }
};

function Metrics ({ vulnerabilities }: Props) {
    const defaultPieHandler = ChartJS.overrides.pie.plugins.legend.onClick

    const [hideSeverity, setHideSeverity] = useState<{[key: string] : boolean}>({});
    const [hideStatus, setHideStatus] = useState<{[key: string] : boolean}>({});

    const dataSetVulnBySeverity = useMemo(() => {
        return {
            labels: ['Unknown', 'Low', 'Medium', 'High', 'Critical'],
            datasets: [{
                label: '# of Vulnerabilities',
                data: vulnerabilities.reduce((acc, vuln) => {
                    if (hideStatus[vuln.simplified_status]) return acc;
                    const severity = vuln.severity.severity.toUpperCase();
                    const index = Math.max(SEVERITY_ORDER.indexOf(severity) - 1, 0)
                    acc[index]++;
                    return acc;
                }, [0, 0, 0, 0, 0]),
                backgroundColor: [
                    'rgba(180, 180, 180)',
                    'rgba(0, 150, 150)',
                    '#F8DE22',
                    '#F94C10',
                    '#FC2947',
                ],
                hoverOffset: 4
            }]
        }
    }, [vulnerabilities, hideStatus]);

    const dataSetVulnByStatus = useMemo(() => {
        return {
            labels: ['Pending analysis', 'Fixed', 'Not Affected', 'Active'],
            datasets: [{
                label: '# of Vulnerabilities',
                data: vulnerabilities.reduce((acc, vuln) => {
                    if (hideSeverity[vuln.severity.severity]) return acc;
                    const status = vuln.simplified_status;
                    const index = status == 'pending analysis' ? 0 : status == 'fixed' ? 1 : status == 'not affected' ? 2 : 3;
                    acc[index]++;
                    return acc;
                }, [0, 0, 0, 0]),
                backgroundColor: [
                    'rgba(180, 180, 180)',
                    '#40A578',
                    'rgba(0, 150, 150)',
                    '#F94C10',
                ],
                hoverOffset: 4
            }]
        }
    }, [vulnerabilities, hideSeverity]);

    const vulnEvolutionTime = {
        labels: ['feb 24', 'march 24', 'april 24', 'may 24', 'june 24'],
        datasets: [{
            label: '# of Vulnerabilities',
            data: [512, 483, 430, 380, 440],
            backgroundColor: [
                '#C63D2F',
                '#E25E3E',
                '#FF9B50',
                '#FFBB5C',
                '#FFDB5A',
            ],
            hoverOffset: 4
        }]
    }

    const dataSetVulnBySource = useMemo(() => {
        return {
            labels: ['Unknown', 'Grype', 'Yocto', 'OSV'],
            datasets: [{
                label: '# of Vulnerabilities',
                data: vulnerabilities.reduce((acc, vuln) => {
                    if (hideStatus[vuln.simplified_status]) return acc;
                    if (hideSeverity[vuln.severity.severity]) return acc;
                    let added = false;
                    if (vuln.found_by.includes('grype')) acc[1]++; added = true;
                    if (vuln.found_by.includes('yocto')) acc[2]++; added = true;
                    if (vuln.found_by.includes('osv')) acc[3]++; added = true;
                    if (!added) acc[0]++;
                    return acc;
                }, [0, 0, 0, 0]),
                backgroundColor: [
                    'rgba(180, 180, 180)',
                    'rgba(0, 150, 150)',
                    '#F8DE22',
                    '#F94C10',
                    '#FC2947',
                ],
                hoverOffset: 4
            }]
        }
    }, [vulnerabilities, hideSeverity, hideStatus]);


    const vulnBySeverityOptions = {
        ...pieOptions,
        plugins: {
            ...pieOptions.plugins,
            legend: {
                ...pieOptions.plugins.legend,
                onClick: function (this: LegendElement<"pie">, e: ChartEvent, legendItem: LegendItem, legend: LegendElement<"pie">) {
                    setHideSeverity({...hideSeverity, [legendItem.text.toLowerCase()]: !legendItem.hidden});
                    defaultPieHandler.call(this, e, legendItem, legend);
                }
            }
        }
    }

    const vulnByStatusOptions = {
        ...pieOptions,
        plugins: {
            ...pieOptions.plugins,
            legend: {
                ...pieOptions.plugins.legend,
                onClick: function (this: LegendElement<"pie">, e: ChartEvent, legendItem: LegendItem, legend: LegendElement<"pie">) {
                    setHideStatus({...hideStatus, [legendItem.text.toLowerCase()]: !legendItem.hidden});
                    defaultPieHandler.call(this, e, legendItem, legend);
                }
            }
        }
    }

    return (
        <div className="w-full flex flex-wrap">

            <div className="w-1/3 lg:w-1/4 p-4">
                <div className="bg-zinc-700 p-2 text-center text-xl">Vulnerabilities by Severity</div>
                <div className="bg-zinc-700 p-4 w-full aspect-square">
                    <Pie data={dataSetVulnBySeverity} options={vulnBySeverityOptions} />
                </div>
            </div>

            <div className="w-1/3 lg:w-1/4 p-4">
                <div className="bg-zinc-700 p-2 text-center text-xl">Vulnerabilities by Status</div>
                <div className="bg-zinc-700 p-4 w-full aspect-square">
                    <Pie data={dataSetVulnByStatus} options={vulnByStatusOptions} />
                </div>
            </div>

            <div className="w-1/3 lg:w-1/4 p-4">
                <div className="bg-zinc-700 p-2 text-center text-xl">Active vulnerabilities <i>[fake data]</i></div>
                <div className="bg-zinc-700 p-4 w-full aspect-square">
                    <Line data={vulnEvolutionTime} options={LineOptions} />
                </div>
            </div>

            <div className="w-1/3 lg:w-1/4 p-4">
                <div className="bg-zinc-700 p-2 text-center text-xl">Vulnerabilities by Source</div>
                <div className="bg-zinc-700 p-4 w-full aspect-square">
                    <Bar data={dataSetVulnBySource} options={BarOptions} />
                </div>
            </div>

        </div>
    );
}

export default Metrics;

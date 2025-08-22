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
            setVulns: (vulns: Vulnerability[]) => void;
            goToVulnsTabWithFilter: (vulns: Vulnerability[]) => void;
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


        function zeroise_date (date: Date, unit: string) {
            if (unit.startsWith('month')) date.setDate(1);

            if (unit.startsWith('hour')) {
                date.setMinutes(0, 0, 0);
            } else {
                date.setHours(0, 0, 0, 0);
            }
        }


        function previous_date (date: Date, unit: string): Date {
            if (unit.startsWith('week')) {
                date = new Date(date.getTime() - (7 * 86400000));
            } else if (unit.startsWith('hour')) {
                date = new Date(date.getTime() - 3600000);
            } else {
                date = new Date(date.getTime() - 86400000);
            }
            return date;
        }

        function filterVulnerabilities(vulns: Vulnerability[], severity?: string, status?: string): Vulnerability[] {
            return vulns.filter(vuln => {
                const matchesSeverity = severity
                    ? vuln.severity?.severity?.toLowerCase() === severity.toLowerCase()
                    : true;

                const matchesStatus = status
                    ? vuln.simplified_status?.toLowerCase() === status.toLowerCase()
                    : true;

                return matchesSeverity && matchesStatus;
            });
        }

        function Metrics ({ vulnerabilities, goToVulnsTabWithFilter }: Readonly<Props>) {
            const defaultPieHandler = ChartJS.overrides.pie.plugins.legend.onClick

            const [hideSeverity, setHideSeverity] = useState<{[key: string] : boolean}>({});
            const [hideStatus, setHideStatus] = useState<{[key: string] : boolean}>({});
            const [timeScale, setTimeScale] = useState<string>("6_months")

            const time_scales = useMemo(() => {
                const scale = Number(timeScale.split('_')[0]);
                const unit = timeScale.split('_')[1];
                if (isNaN(scale) || scale < 2 || !unit || unit == ''){
                    console.error("Invalid time scale, must be <number>_<unit>. eg: 6_months")
                    return [];
                }
                let refs: Date[] = [];
                let date = new Date();
                do {
                    // clean date and insert it
                    zeroise_date(date, unit)
                    refs.splice(0, 0, date);

                    // generate previous date for use in next iteration
                    date = previous_date(date, unit)
                } while (refs.length < scale);

                return refs;
            }, [timeScale]);

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
                    labels: ['Not Affected', 'Fixed', 'Community Analysis Pending', 'Exploitable'],
                    datasets: [{
                        label: '# of Vulnerabilities',
                        data: vulnerabilities.reduce((acc, vuln) => {
                            if (hideSeverity[vuln.severity.severity]) return acc;
                            const status = vuln.simplified_status;
                            const index = status == 'not affected' ? 0 : status == 'fixed' ? 1 : status == 'Community Analysis Pending' ? 2 : 3;
                            acc[index]++;
                            return acc;
                        }, [0, 0, 0, 0]),
                        backgroundColor: [
                            'rgba(0, 150, 150)',
                            '#009900',
                            'rgba(255, 128, 0)',
                            '#F94C10',
                        ],
                        hoverOffset: 4
                    }]
                }
            }, [vulnerabilities, hideSeverity]);

            const nb_points = Number(timeScale.split('_')[0])
            const vulnEvolutionTime = {
                labels: time_scales.map(date => date.toLocaleString(undefined, {
                    day: timeScale.includes('_month') ? undefined : 'numeric',
                    month: 'short',
                    year: timeScale.includes('_hour') ? undefined : '2-digit',
                    hour: timeScale.includes('_hour') ? 'numeric' : undefined,
                    minute: undefined,
                    second: undefined,
                    timeZone: undefined,
                    hour12: false
                })),
                datasets: [{
                    label: '# of Vulnerabilities',
                    data: vulnerabilities.reduce((acc, vuln) => {
                        let is_active = false
                        let date_index = 0
                        let was_active = new Array(nb_points).fill(false)

                        vuln.assessments.forEach(assess => {
                            const dt = new Date(assess.timestamp);

                            // forward time index if needed
                            while (dt.getTime() > time_scales[date_index+1]?.getTime() && date_index < (nb_points - 1)) {
                                if (is_active) was_active[date_index] = true;
                                date_index++;
                            }

                            const should_be_active = (assess.simplified_status != 'not affected' && assess.simplified_status != 'fixed');
                            if (is_active != should_be_active) {
                                if (should_be_active && dt.getTime() >= time_scales[date_index]?.getTime()) {
                                    // if vulnerability was active at least one time in the month, then classify as active for while month
                                    was_active[date_index] = true
                                }
                                is_active = should_be_active;
                            }
                        })

                        while (date_index < nb_points) {
                            if (is_active) was_active[date_index] = true;
                            date_index++;
                        }
                        was_active.forEach((v, i) => acc[i] += v ? 1 : 0);
                        return acc;
                    }, new Array(nb_points).fill(0)),
                    backgroundColor: new Array(nb_points).fill(0).map((_, ind) => `hsl(${Math.round((60 / nb_points) * (ind+1))} 100% 50%)`),
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
                            if (vuln.found_by.includes('grype')) { acc[1]++; added = true; }
                            if (vuln.found_by.includes('yocto')) { acc[2]++; added = true; }
                            if (vuln.found_by.includes('osv')) { acc[3]++; added = true; }
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
                },
                onClick: (_e: ChartEvent, elements: any[]) => {
                    if (!elements.length) return;
                    const index = elements[0].index;
                    const label = dataSetVulnBySeverity.labels[index];
                    const vuls = filterVulnerabilities(vulnerabilities, label as string, undefined);
                    goToVulnsTabWithFilter(vuls);                }
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
                },
                onClick: (_e: ChartEvent, elements: any[]) => {
                    if (!elements.length) return;
                    const index = elements[0].index;
                    const label = dataSetVulnByStatus.labels[index];
                    const vuls = filterVulnerabilities(vulnerabilities, undefined, label as string);
                    goToVulnsTabWithFilter(vuls);
                }
            }

            return (
                <div className="w-full flex flex-wrap">

                    <div className="w-1/3 lg:w-1/4 p-4">
                        <div className="bg-zinc-700 p-2 text-center text-xl text-white">Vulnerabilities by Severity</div>
                        <div className="bg-zinc-700 p-4 w-full aspect-square">
                            <Pie data={dataSetVulnBySeverity} options={vulnBySeverityOptions} />
                        </div>
                    </div>

                    <div className="w-1/3 lg:w-1/4 p-4">
                        <div className="bg-zinc-700 p-2 text-center text-xl text-white">Vulnerabilities by Status</div>
                        <div className="bg-zinc-700 p-4 w-full aspect-square">
                            <Pie data={dataSetVulnByStatus} options={vulnByStatusOptions} />
                        </div>
                    </div>

                    <div className="w-1/3 lg:w-1/4 p-4">
                        <div className="bg-zinc-700 p-1 flex flex-row flex-wrap items-center justify-center">
                            <div className="text-xl p-1 text-white">Exploitable vulnerabilities</div>
                            <select className="bg-zinc-800 ml-2 p-1 text-white" value={timeScale} onChange={(event) => setTimeScale(event.target.value)}>
                                <option value="12_months">1 year</option>
                                <option value="6_months">6 months</option>
                                <option value="12_weeks">12 weeks</option>
                                <option value="6_weeks">6 weeks</option>
                                <option value="31_days">1 month</option>
                                <option value="7_days">1 week</option>
                                <option value="24_hours">24 hours</option>
                            </select>
                        </div>
                        <div className="bg-zinc-700 p-4 w-full aspect-square">
                            <Line data={vulnEvolutionTime} options={LineOptions} />
                        </div>
                    </div>

                    <div className="w-1/3 lg:w-1/4 p-4">
                        <div className="bg-zinc-700 p-2 text-center text-xl text-white">Vulnerabilities by Source</div>
                        <div className="bg-zinc-700 p-4 w-full aspect-square">
                            <Bar data={dataSetVulnBySource} options={BarOptions} />
                        </div>
                    </div>

                </div>
            );

        }

        export default Metrics;

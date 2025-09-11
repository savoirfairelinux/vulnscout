        import { useMemo, useState } from "react";
        import type { Package } from "../handlers/packages";
        import type { CVSS } from "../handlers/vulnerabilities";
        import type { Vulnerability } from "../handlers/vulnerabilities";
        import { SEVERITY_ORDER } from "../handlers/vulnerabilities";
        import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, BarElement, LogarithmicScale, ChartEvent, LegendItem, LegendElement } from 'chart.js';
        import { Pie, Line, Bar } from 'react-chartjs-2';
        import TableGeneric from "../components/TableGeneric";
        import SeverityTag from "../components/SeverityTag";
        import VulnModal from "../components/VulnModal";
        import type { Assessment } from "../handlers/assessments";

        ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, BarElement, LogarithmicScale);

        type Props = {
            packages: Package[];
            vulnerabilities: Vulnerability[];
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



function Metrics({ vulnerabilities, goToVulnsTabWithFilter, appendAssessment, appendCVSS, patchVuln, setTab }: Readonly<Props>) {
            const defaultPieHandler = ChartJS.overrides.pie.plugins.legend.onClick

            const [timeScale, setTimeScale] = useState<string>("6_months")
            const [modalVuln, setModalVuln] = useState<Vulnerability | undefined>(undefined);

  const vulnColumns = useMemo(
    () => [
      { accessorKey: "rank", header: "#", size: 40, cell: (info: any) => info.getValue(), enableSorting: false },
      { accessorKey: "cve", header: "CVE", size: 150, cell: (info: any) => info.getValue(), enableSorting: false },
      { accessorKey: "package", header: "Package", size: 200, cell: (info: any) => info.getValue(), enableSorting: false },
      { accessorKey: "severity", header: "Severity", size: 120, cell: (info: any) => <SeverityTag severity={info.getValue()} />, enableSorting: false },
      {
        accessorKey: "edit",
        header: "Actions",
        size: 80,
        cell: (info: any) => {
          const vuln = info.row.original.original;
          return (
            <button
              className="bg-slate-800 hover:bg-slate-700 px-2 py-1 rounded-lg"
              onClick={() => setModalVuln(vuln)}
            >
              Edit
            </button>
          );
        },
        enableSorting: false
      },
    ],
    []
  );

  const packageColumns = [
  { accessorKey: "id", header: "#", size: 50, cell: (info: any) => info.getValue(), enableSorting: false },
  { accessorKey: "name", header: "Name", cell: (info: any) => info.getValue(), enableSorting: false },
  { accessorKey: "version", header: "Version", cell: (info: any) => info.getValue(), enableSorting: false },
  { accessorKey: "count", header: "Vulnerabilities", cell: (info: any) => info.getValue(), enableSorting: false },
];

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
            }, [vulnerabilities]);

            const dataSetVulnByStatus = useMemo(() => {
                return {
                    labels: ['Not Affected', 'Fixed', 'Community Analysis Pending', 'Exploitable'],
                    datasets: [{
                        label: '# of Vulnerabilities',
                        data: vulnerabilities.reduce((acc, vuln) => {
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
            }, [vulnerabilities]);

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
            
  const topVulnerablePackages = useMemo(() => {
    const counts: Record<string, { count: number; version?: string }> = {};
    vulnerabilities.forEach((vuln) => {
      vuln.packages.forEach((pkg) => {
        const [pkgName, pkgVersion] = pkg.split("@");
        if (!counts[pkgName]) {
          counts[pkgName] = { count: 0, version: pkgVersion };
        }
        counts[pkgName].count += 1;
      });
    });
    return Object.entries(counts)
      .sort(([, a], [, b]) => b.count - a.count)
      .slice(0, 5)
      .map(([name, { count, version }], index) => ({
        id: index + 1,
        name,
        version: version ?? "-",
        count,
        licences: "",
        vulnerabilities: { exploitable: count },
        maxSeverity: { label: "UNKNOWN", index: 0 },
        source: [],
      }));
  }, [vulnerabilities]);

  const TopVulns = useMemo(() => {
    return [...vulnerabilities]
      .map((vuln, index) => {
        const maxCvss = vuln.severity.cvss?.length
          ? Math.max(...vuln.severity.cvss.map((cvss) => cvss.base_score || 0))
          : 0;
        return {
          id: index + 1,
          rank: 0,
          cve: vuln.id,
          package: vuln.packages.join(", "),
          severity: vuln.severity.severity,
          maxCvss,
          texts: vuln.texts,
          original: vuln,
        };
      })
      .sort((a, b) => b.maxCvss - a.maxCvss)
      .slice(0, 5)
      .map((vuln, idx) => ({
        ...vuln,
        rank: idx + 1,
        }));
    }, [vulnerabilities]);
  
              const dataSetVulnBySource = useMemo(() => {
                return {
                    labels: ['Unknown', 'Grype', 'Yocto', 'OSV'],
                    datasets: [{
                        label: '# of Vulnerabilities',
                        data: vulnerabilities.reduce((acc, vuln) => {
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
            }, [vulnerabilities]);


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
                    const index = elements[0].index;
                    const severityOrder = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
                    const targetSeverity = severityOrder[index];
                    
                    const matchingSeverity = vulnerabilities.find(v => 
                        v.severity.severity.toUpperCase() === targetSeverity
                    )?.severity.severity;
                    
                    if (matchingSeverity) {
                        goToVulnsTabWithFilter("Severity", matchingSeverity);
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
                            defaultPieHandler.call(this, e, legendItem, legend);
                        }
                    }
                },
                onClick: (_e: ChartEvent, elements: any[]) => {
                    if (!elements.length) return;
                    const index = elements[0].index;
                    const statusOrder = ['not affected', 'fixed', 'Community Analysis Pending', 'Exploitable'];
                    const targetStatus = statusOrder[index];
                    
                    const matchingStatus = vulnerabilities.find(v => 
                        v.simplified_status === targetStatus
                    )?.simplified_status;
                    
                    if (matchingStatus) {
                        goToVulnsTabWithFilter("Status", matchingStatus);
                    }
                }
            }

            return (
    <div className="w-full">
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

      <div className="w-full flex flex-wrap">
        <div className="w-1/2 lg:w-1/2 p-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-2xl font-bold">Most critical unfixed vulnerabilities</h3>
            <button
              className="bg-blue-600 hover:bg-blue-700 focus:ring-4 focus:outline-none focus:ring-blue-800 font-medium rounded-lg px-4 py-2 text-center"
              onClick={() => setTab('vulnerabilities')}
            >
              See all
            </button>
          </div>
          <div>
            <TableGeneric
              columns={vulnColumns}
              data={TopVulns}
              hoverField="texts"
              hasPagination={false}
              tableHeight="auto"
            />
          </div>
                    </div>

        <div className="w-1/2 lg:w-1/2 p-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-2xl font-bold">Most vulnerable packages</h3>
            <button
              className="bg-blue-600 hover:bg-blue-700 focus:ring-4 focus:outline-none focus:ring-blue-800 font-medium rounded-lg px-4 py-2 text-center"
              onClick={() => setTab("packages")}
            >
              See all
            </button>
          </div>
          <div>
            <TableGeneric
              columns={packageColumns}
              data={topVulnerablePackages}
              hasPagination={false}
              tableHeight="auto"
            />
          </div>
        </div>
                </div>

      {modalVuln && (
        <VulnModal
          vuln={modalVuln}
          onClose={() => setModalVuln(undefined)}
          appendAssessment={appendAssessment}
          appendCVSS={appendCVSS}
          patchVuln={patchVuln}
        />
      )}
    </div>
            );
            
        }

        export default Metrics;

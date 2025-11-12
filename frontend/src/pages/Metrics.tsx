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
              x: {
                ticks: {
                  color: 'white'
                }
              },
              y: {
                beginAtZero: true,
                ticks: {
                  color: 'white'
                }
              }
            }
        }

        const BarOptions = {
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                      x: {
                        ticks: {
                          color: 'white'
                        }
                      },
                      y: {
                        ticks: {
                          color: 'white'
                        }
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
            const [modalVulnIndex, setModalVulnIndex] = useState<number | undefined>(undefined);
            const [isEditing, setIsEditing] = useState<boolean>(false);

const vulnColumns = useMemo(
  () => [
    {
      accessorKey: "rank",
      header: () => <div className="flex items-center justify-center h-full">#</div>,
      cell: (info: any) => <div className="flex items-center justify-center h-full text-center">{info.getValue()}</div>,
      size: 30,
      enableSorting: false,
    },
    {
      accessorKey: "cve",
      header: () => (
        <div className="flex items-center justify-center h-full">CVE</div>
      ),
      cell: (info: any) => (
        <div className="flex items-center justify-center h-full text-center">{info.getValue()}</div>
      ),
      size: 200,
      enableSorting: false,
    },
    {
      accessorKey: "package",
      header: () => (
        <div className="flex items-center justify-center h-full">Package</div>
      ),
      cell: (info: any) => (
        <div className="flex items-center justify-center h-full text-center">{info.getValue()}</div>
      ),
      size: 200,
      enableSorting: false,
    },
    {
      accessorKey: "severity",
      header: () => <div className="flex items-center justify-center h-full">Severity</div>,
      cell: (info: any) => (
        <div className="flex items-center justify-center h-full text-center">
          <SeverityTag severity={info.getValue()} />
        </div>
      ),
      size: 100,
      enableSorting: false,
    },
    {
      accessorKey: "edit",
      header: () => <div className="flex items-center justify-center h-full">Actions</div>,
      cell: (info: any) => {
        const vuln = info.row.original.original;
        return (
          <div className="flex items-center justify-center h-full text-center">
            <button
              className="bg-slate-800 hover:bg-slate-700 px-2 py-1 rounded-lg"
              onClick={() => {
                // Get the current TopVulns list and find the index
                const currentTopVulns = [...vulnerabilities]
                  .map((v, index) => {
                    const maxCvss = v.severity.cvss?.length
                      ? Math.max(...v.severity.cvss.map((cvss) => cvss.base_score || 0))
                      : 0;
                    return {
                      id: index + 1,
                      rank: 0,
                      cve: v.id,
                      package: v.packages.join(", "),
                      severity: v.severity.severity,
                      maxCvss,
                      texts: v.texts,
                      original: v,
                    };
                  })
                  .sort((a, b) => b.maxCvss - a.maxCvss)
                  .slice(0, 5)
                  .map((v, idx) => ({
                    ...v,
                    rank: idx + 1,
                  }));
                  
                const index = currentTopVulns.findIndex(item => item.original.id === vuln.id);
                setModalVuln(vuln);
                setModalVulnIndex(index >= 0 ? index : undefined);
                setIsEditing(true);
              }}
            >
              Edit
            </button>
          </div>
        );
      },
      size: 50,
      enableSorting: false,
    },
  ],
  [vulnerabilities]
);

const packageColumns = [
  {
    accessorKey: "id",
    header: () => (
      <div className="flex items-center justify-center h-full">
        #
      </div>
    ),
    cell: (info: any) => (
      <div className="flex items-center justify-center py-1 h-full text-center">
        {info.getValue()}
      </div>
    ),
    size: 30,
    enableSorting: false,
  },
  {
    accessorKey: "name",
    size: 350,
    header: () => (
      <div className="flex items-center justify-center h-full">
        Name
      </div>
    ),
    cell: (info: any) => (
      <div className="flex items-center justify-center h-full text-center">
        {info.getValue()}
      </div>
    ),
    enableSorting: false,
  },
  {
    accessorKey: "version",
    size: 100,
    header: () => (
      <div className="flex items-center justify-center h-full">
        Version
      </div>
    ),
    cell: (info: any) => (
      <div className="flex items-center justify-center h-full text-center">
        {info.getValue()}
      </div>
    ),
    enableSorting: false,
  },
  {
    accessorKey: "count",
    size: 100,
    header: () => (
      <div className="flex items-center justify-center h-full">
        Vulnerabilities
      </div>
    ),
    cell: (info: any) => (
      <div className="flex items-center justify-center h-full text-center">
        {info.getValue()}
      </div>
    ),
    enableSorting: false,
  },
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
                    labels: ['Not affected', 'Fixed', 'Community analysis pending', 'Exploitable'],
                    datasets: [{
                        label: '# of Vulnerabilities',
                        data: vulnerabilities.reduce((acc, vuln) => {
                            const status = vuln.simplified_status;
                            const index = status == 'Not affected' ? 0 : status == 'Fixed' ? 1 : status == 'Community analysis pending' ? 2 : 3;
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

                            const should_be_active = (assess.simplified_status != 'Not affected' && assess.simplified_status != 'Fixed');
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
      .filter((vuln) => vuln.simplified_status !== 'Fixed' && vuln.simplified_status !== 'Not affected')
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

    const handleModalNavigation = (newIndex: number) => {
        if (newIndex >= 0 && newIndex < TopVulns.length) {
            setModalVuln(TopVulns[newIndex].original);
            setModalVulnIndex(newIndex);
        }
    };

              const dataSetVulnBySource = useMemo(() => {
                const uniqueSources = Array.from(
                    new Set(vulnerabilities.flatMap(vuln => vuln.found_by))
                ).sort((a, b) =>
                    vulnerabilities.filter(vuln => vuln.found_by.includes(b)).length -
                    vulnerabilities.filter(vuln => vuln.found_by.includes(a)).length
                );
                return {
                    labels: uniqueSources,
                    datasets: [{
                        label: '# of Vulnerabilities',
                        data: uniqueSources.map(source =>
                            vulnerabilities.filter(vuln => vuln.found_by.includes(source)).length
                        ),
                        backgroundColor: 'rgba(0, 150, 150, 0.7)',
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
                    const statusOrder = ['Not affected', 'Fixed', 'Community analysis pending', 'Exploitable'];
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

          {/* === TOP CHART GRID === */}
          <div className="w-full grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">

            {/* Vulnerabilities by Severity */}
            <div className="p-4">
              <div className="bg-zinc-700 p-2 text-center text-xl text-white whitespace-nowrap rounded-t-md">
                Vulnerabilities by Severity
              </div>
              <div className="bg-zinc-700 p-4 w-full aspect-square rounded-b-md">
                <div className="h-full">
                  <Pie
                    data={dataSetVulnBySeverity}
                    options={{ ...vulnBySeverityOptions, maintainAspectRatio: false }}
                  />
                </div>
              </div>
            </div>

            {/* Vulnerabilities by Status */}
            <div className="p-4">
              <div className="bg-zinc-700 p-2 text-center text-xl text-white whitespace-nowrap rounded-t-md">
                Vulnerabilities by Status
              </div>
              <div className="bg-zinc-700 p-4 w-full aspect-square rounded-b-md">
                <div className="h-full">
                  <Pie
                    data={dataSetVulnByStatus}
                    options={{ ...vulnByStatusOptions, maintainAspectRatio: false }}
                  />
                </div>
              </div>
            </div>

            {/* Exploitable Vulnerabilities */}
            <div className="p-4">
              <div className="bg-zinc-700 p-2 flex items-center justify-center gap-2 rounded-t-md">
                <div 
                  className="text-xl text-white whitespace-nowrap" 
                  title="Active vulnerabilities is the sum of exploitable and community analysis pending vulnerabilities."
                >
                  Active vulnerabilities
                </div>
                <select
                  className="bg-zinc-800 p-1 text-white rounded w-36"
                  value={timeScale}
                  onChange={(event) => setTimeScale(event.target.value)}
                >
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
                <div className="h-full">
                  <Line
                    data={vulnEvolutionTime}
                    options={{ ...LineOptions, maintainAspectRatio: false }}
                  />
                </div>
              </div>
            </div>

            {/* Vulnerabilities by Source */}
            <div className="p-4">
              <div className="bg-zinc-700 p-2 text-center text-xl text-white whitespace-nowrap rounded-t-md">
                Vulnerabilities by Source
              </div>
              <div className="bg-zinc-700 p-4 w-full aspect-square rounded-b-md">
                <div className="h-full">
                  <Bar
                    data={dataSetVulnBySource}
                    options={{ ...BarOptions, maintainAspectRatio: false }}
                  />
                </div>
              </div>
            </div>

          </div>

        {/* === TABLES SECTION === */}
        <div className="w-full grid grid-cols-1 lg:grid-cols-2 gap-4">

          {/* Most Critical Unfixed Vulnerabilities */}
          <div className="p-4">
            {/* Table Header */}
            <div className="bg-zinc-700 px-4 py-2 flex items-center justify-between rounded-t-md">
              <h3 className="text-2xl font-bold text-white whitespace-nowrap">
                Most critical unfixed vulnerabilities
              </h3>
              <button
                className="bg-cyan-800 hover:bg-cyan-700 focus:ring-4 focus:outline-none focus:ring-blue-800 font-medium rounded-lg px-4 py-2 text-center text-white"
                onClick={() => setTab('vulnerabilities')}
              >
                See all
              </button>
            </div>

            {/* Table Body */}
            <div className="bg-zinc-700 p-4 rounded-b-md">
              <TableGeneric
                columns={vulnColumns}
                data={TopVulns}
                hoverField="texts"
                hasPagination={false}
                tableHeight="auto"
              />
            </div>
          </div>

          {/* Most Vulnerable Packages */}
          <div className="p-4">
            {/* Table Header */}
            <div className="bg-zinc-700 px-4 py-2 flex items-center justify-between rounded-t-md">
              <h3 className="text-2xl font-bold text-white whitespace-nowrap">
                Most vulnerable packages
              </h3>
              <button
                className="bg-cyan-800 hover:bg-cyan-700 focus:ring-4 focus:outline-none focus:ring-blue-800 font-medium rounded-lg px-4 py-2 text-center text-white"
                onClick={() => setTab('packages')}
              >
                See all
              </button>
            </div>

            {/* Table Body */}
            <div className="bg-zinc-700 p-4 rounded-b-md">
              <TableGeneric
                columns={packageColumns}
                data={topVulnerablePackages}
                hasPagination={false}
                tableHeight="auto"
              />
            </div>
          </div>

        </div>

        {/* === MODAL === */}
        {modalVuln && (
          <VulnModal
            vuln={modalVuln}
            isEditing={isEditing}
            onClose={() => {
              setModalVuln(undefined);
              setModalVulnIndex(undefined);
              setIsEditing(false);
            }}
            appendAssessment={appendAssessment}
            appendCVSS={appendCVSS}
            patchVuln={patchVuln}
            vulnerabilities={TopVulns.map(item => item.original)}
            currentIndex={modalVulnIndex}
            onNavigate={handleModalNavigation}
          />
        )}
        </div>
      );

        }

        export default Metrics;

import { useMemo, useState, useCallback, useEffect } from "react";
  import type { AgentViewContext } from "../types/agent";
        import type { Package } from "../handlers/packages";
        import type { CVSS } from "../handlers/vulnerabilities";
        import type { Vulnerability, VulnerabilityPatch } from "../handlers/vulnerabilities";
        import Vulnerabilities, { SEVERITY_ORDER, getVulnerabilityStatusSummary, isVulnerabilityActive } from "../handlers/vulnerabilities";
        import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, BarElement, LogarithmicScale, ChartEvent, LegendItem, LegendElement } from 'chart.js';
        import { Pie, Line, Bar } from 'react-chartjs-2';
        import TableGeneric from "../components/TableGeneric";
        import SeverityTag from "../components/SeverityTag";
        import VulnModal from "../components/VulnModal";
        import { formatSourceName } from "../helpers/sourceNames";
        import type { Assessment } from "../handlers/assessments";

        ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, BarElement, LogarithmicScale);

        // Rank active vulnerabilities for the "Most critical unfixed" table.
        // Sort by the displayed severity label first (so the ranking always
        // matches the Severity column even after an nvd-refresh changes a
        // vulnerability's severity), then preserve the incoming order as a
        // tiebreaker so vulnerabilities of equal severity keep the same order
        // as the Vulnerability tab (which sorts by severity label and leaves
        // the backend CVE-id order within each severity).
        function rankTopVulns(vulnerabilities: Vulnerability[], includeOutdated: boolean) {
            return [...vulnerabilities]
                .filter((vuln) => isVulnerabilityActive(vuln))
                .map((vuln, index) => {
                    return {
                        id: index + 1,
                        rank: 0,
                        cve: vuln.id,
                        package: (includeOutdated ? vuln.packages : vuln.packages_current).join(", "),
                        severity: vuln.severity.severity,
                        texts: vuln.texts,
                        original: vuln,
                    };
                })
                .sort((a, b) => {
                    const severityDiff =
                        SEVERITY_ORDER.indexOf(b.severity.toUpperCase())
                        - SEVERITY_ORDER.indexOf(a.severity.toUpperCase());
                    if (severityDiff !== 0) return severityDiff;
                    return a.id - b.id;
                })
                .slice(0, 5)
                .map((vuln, idx) => ({
                    ...vuln,
                    rank: idx + 1,
                }));
        }

        type Props = {
            packages: Package[];
            vulnerabilities: Vulnerability[];
            goToVulnsTabWithFilter: (filterType: "Source" | "Severity" | "Status", value: string) => void;
            appendAssessment: (added: Assessment) => void;
            patchVuln: (vulnId: string, patch: VulnerabilityPatch) => void;
            setTab: (tab: string) => void;
            appendCVSS: (vulnId: string, vector: string) => CVSS | null;
            projectId?: string;
            variantId?: string;
            baseVariantId?: string;
            compareOperation?: string;
            variantIds?: string[];
            multiOperation?: string;
            includeOutdated?: boolean;
            onAgentContextChange?: (context: AgentViewContext) => void;
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

        function activeTrendBuckets(assessments: Assessment[], dates: Date[], count: number): boolean[] {
            const active = new Array<boolean>(count).fill(false);
            let isActive = false;
            let index = 0;
            for (const assessment of assessments) {
                const timestamp = new Date(assessment.timestamp).getTime();
                while (timestamp > dates[index + 1]?.getTime() && index < count - 1) {
                    if (isActive) active[index] = true;
                    index++;
                }
                const nextActive = assessment.simplified_status !== 'Not affected' && assessment.simplified_status !== 'Fixed';
                if (!isActive && nextActive && timestamp >= dates[index]?.getTime()) active[index] = true;
                isActive = nextActive;
            }
            if (isActive) active.fill(true, index);
            return active;
        }

        function historicalTrendBuckets(
            vulnerabilities: Vulnerability[], assessments: Assessment[], dates: Date[], count: number,
        ): number[] {
            const visible = new Map(vulnerabilities.map(vuln => [vuln.id, vuln.packages_status_by_variant]));
            const histories = new Map<string, Map<string, Assessment[]>>();
            for (const assessment of assessments) {
                const packagesByVariant = visible.get(assessment.vuln_id);
                if (!packagesByVariant) continue;
                const byTarget = histories.get(assessment.vuln_id) ?? new Map<string, Assessment[]>();
                histories.set(assessment.vuln_id, byTarget);
                for (const target of assessment.targets ?? []) {
                    if (!target.variant_id || !packagesByVariant[target.variant_id]?.includes(target.package)) continue;
                    const key = JSON.stringify([target.variant_id, target.package]);
                    const timeline = byTarget.get(key) ?? [];
                    timeline.push(assessment);
                    byTarget.set(key, timeline);
                }
            }
            const total = new Array<number>(count).fill(0);
            for (const byTarget of histories.values()) {
                // Each CVE counts once per bucket, even with multiple active targets.
                const active = new Array<boolean>(count).fill(false);
                for (const timeline of byTarget.values()) {
                    activeTrendBuckets(timeline, dates, count).forEach((value, i) => { active[i] ||= value; });
                }
                active.forEach((value, i) => { if (value) total[i]++; });
            }
            return total;
        }

function Metrics({ vulnerabilities, goToVulnsTabWithFilter, appendAssessment, appendCVSS, patchVuln, setTab,
    projectId, variantId, baseVariantId, compareOperation, variantIds, multiOperation, includeOutdated = false,
    onAgentContextChange }: Readonly<Props>) {
            const defaultPieHandler = ChartJS.overrides.pie.plugins.legend.onClick

            const [timeScale, setTimeScale] = useState<string>("6_months")
            const [modalVuln, setModalVuln] = useState<Vulnerability | undefined>(undefined);
            const [modalVulnIndex, setModalVulnIndex] = useState<number | undefined>(undefined);
            const [isEditing, setIsEditing] = useState<boolean>(false);
            const [detailsError, setDetailsError] = useState(false);
            const comparisonScope = useMemo(() => ({
                baseVariantId, operation: compareOperation, variantIds, multiOperation,
            }), [baseVariantId, compareOperation, variantIds, multiOperation]);
            const [historicalTrend, setHistoricalTrend] = useState<Assessment[] | null>(null);
            const [trendError, setTrendError] = useState(false);

            useEffect(() => {
                setHistoricalTrend(null);
                setTrendError(false);
                if (!includeOutdated) return;
                const controller = new AbortController();
                Vulnerabilities.historicalAssessmentTrend(variantId, projectId, comparisonScope, controller.signal)
                    .then(rows => { if (!controller.signal.aborted) setHistoricalTrend(rows); })
                    .catch(() => { if (!controller.signal.aborted) setTrendError(true); });
                return () => controller.abort();
            }, [includeOutdated, variantId, projectId, comparisonScope, vulnerabilities]);

            useEffect(() => {
                setDetailsError(false);
                if (!modalVuln || modalVuln.details_loaded !== false) return;
                const controller = new AbortController();
                Vulnerabilities.getDetails(modalVuln.id, variantId, projectId, controller.signal, comparisonScope, includeOutdated)
                    .then(details => {
                        if (!details || controller.signal.aborted) return;
                        setModalVuln(current => current?.id === details.id ? {
                            ...current, texts: details.texts, urls: details.urls, cpes: details.cpes,
                            severity: { ...current.severity, cvss: details.severity.cvss }, details_loaded: true,
                        } : current);
                    })
                    .catch(() => { if (!controller.signal.aborted) setDetailsError(true); });
                return () => controller.abort();
            }, [modalVuln, variantId, projectId, comparisonScope, includeOutdated]);

            const handlePatchVuln = useCallback((vulnId: string, patch: VulnerabilityPatch) => {
                patchVuln(vulnId, patch);
                setModalVuln(prev => prev?.id === vulnId ? (typeof patch === 'function' ? patch(prev) : patch) : prev);
            }, [patchVuln]);

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
        <div className="flex items-center justify-center h-full text-center min-w-0 w-full overflow-hidden">
          <span className="truncate block w-full" title={info.getValue()}>{info.getValue()}</span>
        </div>
      ),
      size: 200,
      enableSorting: false,
    },
    {
      accessorKey: "severity",
      header: () => <div className="flex items-center justify-center h-full">Severity</div>,
      cell: (info: any) => (
        <div className="flex items-center justify-center h-full text-center">
          <SeverityTag severity={info.getValue()} className="!py-0" />
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
              className="bg-slate-800 hover:bg-slate-700 px-2 rounded-lg"
              onClick={() => {
                // Get the current TopVulns list and find the index
                const currentTopVulns = rankTopVulns(vulnerabilities, includeOutdated);

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
  [vulnerabilities, includeOutdated]
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
        <span className="truncate max-w-full block" title={info.getValue()}>
          {info.getValue()}
        </span>
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
                    labels: ['Not affected', 'Fixed', 'Pending Assessment', 'Exploitable'],
                    datasets: [{
                        label: '# of Vulnerabilities',
                        data: vulnerabilities.reduce((acc, vuln) => {
                          const summary = getVulnerabilityStatusSummary(vuln);
                          // Count each vulnerability once per status it has (not once per variant).
                          // A CVE may appear in both "Exploitable" and "Pending Assessment" across
                          // different variants, but must never be counted more than once per status.
                          if ((summary.counts['Not affected'] ?? 0) > 0) acc[0] += 1;
                          if ((summary.counts['Fixed'] ?? 0) > 0) acc[1] += 1;
                          if ((summary.counts['Pending Assessment'] ?? 0) > 0) acc[2] += 1;
                          if ((summary.counts['Exploitable'] ?? 0) > 0) acc[3] += 1;
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
                    data: includeOutdated
                        ? historicalTrendBuckets(vulnerabilities, historicalTrend ?? [], time_scales, nb_points)
                        : vulnerabilities.reduce((acc, vuln) => {
                            activeTrendBuckets(vuln.assessments, time_scales, nb_points)
                                .forEach((active, i) => { if (active) acc[i]++; });
                            return acc;
                        }, new Array<number>(nb_points).fill(0)),
                    backgroundColor: 'rgba(0, 150, 150, 0.7)',
                    hoverOffset: 4
                }]
            }

  const topVulnerablePackages = useMemo(() => {
    const counts: Record<string, { count: number; version?: string }> = {};
    vulnerabilities.forEach((vuln) => {
      (includeOutdated ? vuln.packages : vuln.packages_current).forEach((pkg) => {
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
        vulnerabilities: { exploitable: count },
        maxSeverity: { label: "UNKNOWN", index: 0 },
        source: [],
      }));
  }, [vulnerabilities, includeOutdated]);

  const TopVulns = useMemo(() => {
    return rankTopVulns(vulnerabilities, includeOutdated);
    }, [vulnerabilities, includeOutdated]);

    useEffect(() => {
      onAgentContextChange?.({
        section: 'most critical unfixed',
        visibleVulnerabilityIds: TopVulns.map(item => item.cve),
        openVulnerabilityId: modalVuln?.id,
      });
    }, [TopVulns, modalVuln?.id, onAgentContextChange]);

    const handleModalNavigation = (newIndex: number) => {
        if (newIndex >= 0 && newIndex < TopVulns.length) {
            setModalVuln(TopVulns[newIndex].original);
            setModalVulnIndex(newIndex);
        }
    };

              const dataSetVulnBySource = useMemo(() => {
                // Each vulnerability is attributed to exactly ONE primary source
                // so that the sum of all bars equals the total vulnerability count.
                const SOURCE_PRIORITY: Record<string, number> = {
                    grype: 1,
                    yocto_cve_check: 2,
                    yocto: 2,
                    nvd_cpe: 3,
                    osv: 4,
                    cyclonedx: 5,
                    spdx3: 6,
                    openvex: 7,
                    local_user_data: 8,
                };

                const countBySource: Record<string, number> = {};
                vulnerabilities.forEach(vuln => {
                    if (!vuln.found_by.length) return;
                    // Pick the highest-priority (lowest number) source
                    const primary = vuln.found_by.reduce((best, src) => {
                        const bestPri = SOURCE_PRIORITY[best] ?? 99;
                        const srcPri = SOURCE_PRIORITY[src] ?? 99;
                        return srcPri < bestPri ? src : best;
                    });
                    countBySource[primary] = (countBySource[primary] || 0) + 1;
                });

                const sources = Object.keys(countBySource).sort(
                    (a, b) => countBySource[b] - countBySource[a]
                );

                return {
                    labels: sources.map(formatSourceName),
                    datasets: [{
                        label: '# of Vulnerabilities',
                        data: sources.map(source => countBySource[source]),
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
                    const statusOrder = ['Not affected', 'Fixed', 'Pending Assessment', 'Exploitable'];
                    const targetStatus = statusOrder[index];

                    const matchingStatus = vulnerabilities.find(v =>
                      (getVulnerabilityStatusSummary(v).counts[targetStatus] ?? 0) > 0
                    );

                    if (matchingStatus) {
                      goToVulnsTabWithFilter("Status", targetStatus);
                    }
                }
            }

      return (
        <div className="w-full flex flex-col gap-4 pb-8">

          {/* === CHARTS SECTION === */}
          <div className="w-full grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">

            {/* Vulnerabilities by Severity */}
            <div className="p-3">
              <div className="bg-zinc-700 p-2 text-center text-xl text-white rounded-t-md">
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
            <div className="p-3">
              <div className="bg-zinc-700 p-2 text-center text-xl text-white rounded-t-md">
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

            <div className="p-3">
              <div className="bg-zinc-700 p-2 flex items-center justify-center gap-2 rounded-t-md">
                <div
                  className="text-xl text-white"
                  title={includeOutdated ? undefined : "Based on assessments for today's findings; not historical scan membership or exposure."}
                >
                  {includeOutdated ? 'Assessment trend for ever-observed findings' : 'Assessment trend for current findings'}
                </div>
                <select
                  aria-label="Assessment trend interval"
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
                  {includeOutdated && !historicalTrend ? (
                    trendError
                      ? <p role="alert">Could not load assessment history.</p>
                      : <p role="status">Loading assessment history…</p>
                  ) : <Line
                    data={vulnEvolutionTime}
                    options={{ ...LineOptions, maintainAspectRatio: false }}
                  />}
                </div>
              </div>
            </div>

            {/* Vulnerabilities by Database */}
            <div className="p-3">
              <div className="bg-zinc-700 p-2 text-center text-xl text-white rounded-t-md">
                Vulnerabilities by Database
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

          </div>{/* end charts section */}

        {/* === TABLES SECTION === */}
        <div className="w-full grid grid-cols-1 lg:grid-cols-2">

            {/* Most Critical Unfixed Vulnerabilities */}
            <div className="p-3 min-w-0">
              <div className="bg-zinc-700 px-4 py-2 flex items-center justify-between rounded-t-md flex-wrap gap-2">
                <h3 className="text-xl font-bold text-white">
                  {includeOutdated ? 'Most critical unfixed vulnerabilities ever observed' : 'Most critical unfixed vulnerabilities'}
                </h3>
                <button
                  className="bg-cyan-800 hover:bg-cyan-700 focus:ring-4 focus:outline-none focus:ring-blue-800 font-medium rounded-lg px-4 py-2 text-center text-white"
                  onClick={() => setTab('vulnerabilities')}
                >
                  See all
                </button>
              </div>
              <div className="bg-zinc-700 p-4 rounded-b-md overflow-x-auto">
                <TableGeneric
                  columns={vulnColumns}
                  data={TopVulns}
                  hasPagination={false}
                  tableHeight="auto"
                />
              </div>
            </div>

            {/* Most Vulnerable Packages */}
            <div className="p-3 min-w-0">
              <div className="bg-zinc-700 px-4 py-2 flex items-center justify-between rounded-t-md flex-wrap gap-2">
                <h3 className="text-xl font-bold text-white">
                  Most vulnerable packages
                </h3>
                <button
                  className="bg-cyan-800 hover:bg-cyan-700 focus:ring-4 focus:outline-none focus:ring-blue-800 font-medium rounded-lg px-4 py-2 text-center text-white"
                  onClick={() => setTab('packages')}
                >
                  See all
                </button>
              </div>
              <div className="bg-zinc-700 p-4 rounded-b-md overflow-x-auto">
                <TableGeneric
                  columns={packageColumns}
                  data={topVulnerablePackages}
                  hasPagination={false}
                  tableHeight="auto"
                />
              </div>
            </div>

        </div>{/* end tables section */}

        {/* === MODAL === */}
        {modalVuln && (
          <VulnModal
            vuln={modalVuln}
            detailsLoading={modalVuln.details_loaded === false && !detailsError}
            detailsError={detailsError}
            isEditing={isEditing}
            onClose={() => {
              setModalVuln(undefined);
              setModalVulnIndex(undefined);
              setIsEditing(false);
            }}
            appendAssessment={appendAssessment}
            appendCVSS={appendCVSS}
            patchVuln={handlePatchVuln}
            vulnerabilities={TopVulns.map(item => item.original)}
            currentIndex={modalVulnIndex}
            onNavigate={handleModalNavigation}
            projectId={projectId}
            variantId={variantId}
            comparisonScope={comparisonScope}
            includeOutdated={includeOutdated}
          />
        )}
        </div>
      );

        }

        export default Metrics;

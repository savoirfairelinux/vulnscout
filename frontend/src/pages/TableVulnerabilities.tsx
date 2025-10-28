import type { Vulnerability } from "../handlers/vulnerabilities";
import type { CVSS } from "../handlers/vulnerabilities";
import type { Assessment } from "../handlers/assessments";
import { createColumnHelper, SortingFn, RowSelectionState, Row, Table } from '@tanstack/react-table'
import { useMemo, useState, useEffect } from "react";
import SeverityTag from "../components/SeverityTag";
import { SEVERITY_ORDER } from "../handlers/vulnerabilities";
import TableGeneric from "../components/TableGeneric";
import VulnModal from "../components/VulnModal";
import MultiEditBar from "../components/MultiEditBar";
import debounce from 'lodash-es/debounce';
import FilterOption from "../components/FilterOption";
import ToggleSwitch from "../components/ToggleSwitch";
import MessageBanner from "../components/MessageBanner";

type Props = {
    vulnerabilities: Vulnerability[];
    appendAssessment: (added: Assessment) => void;
    appendCVSS: (vulnId: string, vector: string) => CVSS | null;
    patchVuln: (vulnId: string, replace_vuln: Vulnerability) => void;
    filterLabel?: "Source" | "Severity" | "Status" | "Package";
    filterValue?: string;
};

const dt_options: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: 'numeric',
    minute: 'numeric',
    timeZoneName: 'shortOffset'
};

const sortSeverityFn: SortingFn<Vulnerability> = (rowA, rowB) => {
    const vulnsA = rowA.original.severity.severity.toUpperCase()
    const vulnsB = rowB.original.severity.severity.toUpperCase()
    return SEVERITY_ORDER.indexOf(vulnsA) - SEVERITY_ORDER.indexOf(vulnsB)
}

const sortStatusFn: SortingFn<Vulnerability> = (rowA, rowB) => {
    const indexA = ['unknown', 'Community analysis pending', 'Exploitable', 'Not affected', 'Fixed'].indexOf(rowA.original.simplified_status)
    const indexB = ['unknown', 'Community analysis pending', 'Exploitable', 'Not affected', 'Fixed'].indexOf(rowB.original.simplified_status)
    return indexA - indexB
}

const sortAttackVectorFn: SortingFn<Vulnerability> = (rowA, rowB) => {
    const av_A = [...(new Set(
        rowA.original.severity.cvss.map(cvss => cvss.attack_vector)
    ))]
    const av_B = [...(new Set(
        rowB.original.severity.cvss.map(cvss => cvss.attack_vector)
    ))]
    const priorities = [undefined, 'PHYSICAL', 'LOCAL', 'ADJACENT', 'NETWORK']
    const indexA = Math.max(...av_A.map(a => priorities.indexOf(a)))
    const indexB = Math.max(...av_B.map(b => priorities.indexOf(b)))
    return indexA - indexB
}

const fuseKeys = ['id', 'aliases', 'related_vulnerabilities', 'packages', 'simplified_status', 'status', 'texts.content']

function TableVulnerabilities ({ vulnerabilities, filterLabel, filterValue, appendAssessment, appendCVSS, patchVuln }: Readonly<Props>) {

    const [modalVuln, setModalVuln] = useState<Vulnerability|undefined>(undefined);
    const [search, setSearch] = useState<string>('');
    const [selectedSeverities, setSelectedSeverities] = useState<string[]>([]);
    const [selectedStatuses, setSelectedStatuses] = useState<string[]>([]);
    const [selectedSources, setSelectedSources] = useState<string[]>([]);
    const [selectedPackages, setSelectedPackages] = useState<string[]>([]);
    const [selectedRows, setSelectedRows] = useState<RowSelectionState>({});
    const [hideFixed, setHideFixed] = useState<boolean>(false);
    const [bannerMessage, setBannerMessage] = useState<string>('');
    const [bannerType, setBannerType] = useState<'error' | 'success'>('success');
    const [bannerVisible, setBannerVisible] = useState<boolean>(false);

    useEffect(() => {
        if (!filterLabel || !filterValue) return;
        if (filterLabel === "Source") setSelectedSources([filterValue]);
        if (filterLabel === "Severity") setSelectedSeverities([filterValue]);
        if (filterLabel === "Status") setSelectedStatuses([filterValue]);
        if (filterLabel === "Package") setSelectedPackages([filterValue]);
    }, [filterLabel, filterValue]);

    const triggerBanner = (message: string, type: 'error' | 'success') => {
        setBannerMessage(message);
        setBannerType(type);
        setBannerVisible(true);
    };

    const closeBanner = () => {
        setBannerVisible(false);
    };

    const updateSearch = debounce((event: React.ChangeEvent<HTMLInputElement>) => {
        if (event.target.value.length < 2) {
            if (search != '') setSearch('');
        }
        setSearch(event.target.value);
    }, 750, { maxWait: 5000 });

    const sources_list = useMemo(() => vulnerabilities.reduce((acc: string[], vuln) => {
        vuln.found_by.forEach(source => {
            if (!acc.includes(source) && source != '')
                acc.push(source)
        });
        return acc;
    }, []), [vulnerabilities])

    const columns = useMemo(() => {
        const columnHelper = createColumnHelper<Vulnerability>()
        return [
            {
            id: 'select-checkbox',
                cell: ({ row }: { row: Row<Vulnerability> }) => (
                    <div className="flex items-center justify-center h-full">
                    <input
                        type="checkbox"
                        title={row.getIsSelected() ? "Unselect" : "Select"}
                        checked={row.getIsSelected()}
                        disabled={!row.getCanSelect()}
                        onChange={row.getToggleSelectedHandler()}
                    />
                    </div>
                ),
                header: ({ table }: { table: Table<Vulnerability> }) => (
                    <div className="flex items-center justify-center h-full">
                    <input
                        type="checkbox"
                        title={table.getIsAllRowsSelected() ? "Unselect all" : "Select all"}
                        checked={table.getIsAllRowsSelected()}
                        onChange={table.getToggleAllRowsSelectedHandler()}
                    />
                    </div>
                ),
                footer: ({ table }: { table: Table<Vulnerability> }) => (
                    <div className="flex items-center justify-center h-full">
                    {table.getSelectedRowModel().rows.length || ''}
                    </div>
                ),
                minSize: 10,
                size: 10,
                maxSize: 40
            },
            columnHelper.accessor('id', {
                header: () => <div className="flex items-center justify-center">ID</div>,
                cell: info => <div className="flex items-center justify-center h-full text-center">{info.getValue()}</div>,
                sortDescFirst: true,
                footer: (info) => <div className="flex items-center justify-center">{`Total: ${info.table.getRowCount()}`}</div>,
                size: 145
            }),
            columnHelper.accessor('severity.severity', {
            header: () => (
                <div className="flex items-center justify-center">
                Severity
                </div>
            ),
            cell: info => (
                <div className="flex items-center justify-center h-full text-center">
                <SeverityTag severity={info.getValue()} />
                </div>
            ),
            sortingFn: sortSeverityFn,
            size: 40,
            }),
            columnHelper.accessor('epss', {
            header: () => <div className="flex items-center justify-center">EPSS Score</div>,
            cell: info => {
                const epss = info.getValue();
                return (
                <div className="flex flex-col items-center justify-center h-full text-center">
                    {epss.score !== undefined && epss.score !== 0 &&  <>
                    {(epss.score * 100).toFixed(2)}%
                    </>}
                </div>
                );
            },
            sortingFn: (rowA, rowB) => (rowA.original.epss?.score || 0.0) - (rowB.original.epss?.score || 0.0),
            size: 125,
            }),
            columnHelper.accessor('packages', {
            header: () => <div className="flex items-center justify-center">Packages Affected</div>,
            cell: info => <div className="flex items-center justify-center h-full text-center">{info.getValue().map(p => p.split('+git')[0]).join(', ')}</div>,
            enableSorting: false,
            size: 205
            }),
            columnHelper.accessor('severity', {
            header: () => <div className="flex items-center justify-center">Attack Vector</div>,
            cell: info => <div className="flex items-center justify-center h-full text-center">
                {[...(new Set(info.getValue().cvss.map(cvss => cvss.attack_vector).filter(av => av != undefined)))]?.join(', ')}
            </div>,
            enableSorting: true,
            sortingFn: sortAttackVectorFn,
            size: 100
            }),
            columnHelper.accessor('simplified_status', {
            header: () => <div className="flex items-center justify-center">Status</div>,
            cell: info => <div className="flex items-center justify-center h-full text-center"><code>{info.renderValue()}</code></div>,
            sortingFn: sortStatusFn,
            size: 130
            }),
            columnHelper.accessor('effort.likely', {
            header: () => <div className="flex items-center justify-center">Estimated Effort</div>,
            cell: info => <div className="flex items-center justify-center h-full text-center">{info.getValue().formatHumanShort()}</div>,
            enableSorting: true,
            sortingFn: (rowA, rowB) => rowA.original.effort.likely.total_seconds - rowB.original.effort.likely.total_seconds,
            size: 100
            }),
            columnHelper.accessor('assessments', {
            header: () => <div className="flex items-center justify-center">Last Updated</div>,
            cell: info => {
                const assessments = info.getValue();
                if (!assessments || assessments.length === 0) {
                    return <div className="flex items-center justify-center h-full text-center text-gray-400">No assessment</div>;
                }
                
                // Find the most recent update time across all assessments
                const mostRecentTime = assessments.reduce((latest, assessment) => {
                    const assessmentTime = new Date(assessment.last_update || assessment.timestamp);
                    return assessmentTime > latest ? assessmentTime : latest;
                }, new Date(0));
                
                // Format the date using the same format as VulnModal
                const formattedDate = mostRecentTime.getTime() > 0 ? 
                    mostRecentTime.toLocaleString(undefined, dt_options) : 'No assessment';
                
                return (
                    <div className="flex items-center justify-center h-full text-center text-sm">
                        {formattedDate}
                    </div>
                );
            },
            enableSorting: true,
            sortingFn: (rowA, rowB) => {
                const getLatestAssessmentTime = (assessments: Assessment[]) => {
                    if (!assessments || assessments.length === 0) return 0;
                    return assessments.reduce((latest, assessment) => {
                        const assessmentTime = new Date(assessment.last_update || assessment.timestamp).getTime();
                        return assessmentTime > latest ? assessmentTime : latest;
                    }, 0);
                };
                
                return getLatestAssessmentTime(rowA.original.assessments) - getLatestAssessmentTime(rowB.original.assessments);
            },
            size: 140
            }),
            columnHelper.accessor('found_by', {
            header: () => <div className="flex items-center justify-center">Sources</div>,
            cell: info => (
                <div className="flex items-center justify-center h-full text-center">
                    {info.renderValue()?.join(', ')}
                </div>
            ),
            enableSorting: false
            }),
            columnHelper.accessor(row => row, {
                header: 'Actions',
                cell: info => (
                    <div className="flex items-center justify-center h-full">
                    <button
                        className="bg-slate-800 hover:bg-slate-700 px-2 py-1 rounded-lg"
                        onClick={() => setModalVuln(info.getValue())}
                    >
                        Edit
                    </button>
                    </div>
                ),
                enableSorting: false,
                minSize: 20,
                size: 20
            })
        ]
    }, []);

    const dataToDisplay = useMemo(() => {
        return vulnerabilities.filter((el) => {
            if (selectedSeverities.length && !selectedSeverities.includes(el.severity.severity)) return false;
            if (selectedStatuses.length && !selectedStatuses.includes(el.simplified_status)) return false;
            if (selectedSources.length && !selectedSources.some(src => el.found_by.includes(src))) return false;
            if (selectedPackages.length && !selectedPackages.some(pkg => el.packages.includes(pkg))) return false;
            return true;
        });
    }, [vulnerabilities, selectedSeverities, selectedStatuses, selectedSources, selectedPackages]);

    const selectedVulns = useMemo(() => {
        return Object.entries(selectedRows).flatMap(([id, selected]) => selected ? [id] : [])
    }, [selectedRows])

    function resetFilters() {
        setSearch('');
        setSelectedSources([]);
        setSelectedSeverities([]);
        setSelectedStatuses([]);
        setSelectedPackages([]);
        setSelectedRows({});
        setHideFixed(false);
    }

    const handleHideFixedToggle = (enabled: boolean) => {
        setHideFixed(enabled);
        if (enabled) {
            const allStatuses = Array.from(new Set(vulnerabilities.map(v => v.simplified_status)));
            const statusesExceptFixed = allStatuses.filter(status => status !== 'Fixed');
            setSelectedStatuses(statusesExceptFixed);
        } else {
            setSelectedStatuses([]);
        }
    };

    const handleStatusChange = (newStatuses: string[]) => {
        setSelectedStatuses(newStatuses);
        if (newStatuses.includes('Fixed') && hideFixed) {
            setHideFixed(false);
        }
    };

    return (<>
        {bannerVisible && (
            <MessageBanner
                type={bannerType}
                message={bannerMessage}
                isVisible={bannerVisible}
                onClose={closeBanner}
            />
        )}

        <div className="rounded-md mb-4 p-2 bg-sky-800 text-white w-full flex flex-row items-center gap-2">
            <div>Search</div>
            <input onInput={updateSearch} type="search" className="py-1 px-2 bg-sky-900 focus:bg-sky-950 min-w-[250px] grow max-w-[800px]" placeholder="Search by ID, packages, description, ..." />

            <FilterOption
                label="Source"
                options={sources_list}
                selected={selectedSources}
                setSelected={setSelectedSources}
            />

            <FilterOption
                label="Severity"
                options={Array.from(new Set(vulnerabilities.map(v => v.severity.severity))).sort((a, b) =>
                    SEVERITY_ORDER.map(s => s.toLowerCase()).indexOf(b.toLowerCase()) - SEVERITY_ORDER.map(s => s.toLowerCase()).indexOf(a.toLowerCase())
                )}
                selected={selectedSeverities}
                setSelected={setSelectedSeverities}
            />

            <FilterOption
                label="Status"
                options={Array.from(new Set(vulnerabilities.map(v => v.simplified_status)))}
                selected={selectedStatuses}
                setSelected={handleStatusChange}
            />

            <ToggleSwitch
                enabled={hideFixed}
                setEnabled={handleHideFixedToggle}
                label="Hide Fixed"
            />

            <button
                onClick={resetFilters}
                className="ml-auto bg-sky-900 hover:bg-sky-950 px-3 py-1 rounded text-white border border-sky-700"
            >
                Reset Filters
            </button>
        </div>


        <MultiEditBar
            vulnerabilities={vulnerabilities}
            selectedVulns={selectedVulns}
            resetVulns={() => setSelectedRows({})}
            appendAssessment={appendAssessment}
            patchVuln={patchVuln}
            triggerBanner={triggerBanner}
            hideBanner={closeBanner}
        />

        <TableGeneric
            fuseKeys={fuseKeys}
            hoverField="texts"
            search={search}
            columns={columns}
            tableHeight={
                selectedVulns.length >= 1 ?
                (bannerVisible ?
                    'calc(100vh - 44px - 64px - 48px - 16px - 48px - 16px - 8px - 64px)' :
                    'calc(100vh - 44px - 64px - 48px - 16px - 48px - 16px - 8px)') :
                (bannerVisible ?
                    'calc(100vh - 44px - 64px - 48px - 16px - 8px - 64px)' :
                    'calc(100vh - 44px - 64px - 48px - 16px - 8px)')
            }
            data={dataToDisplay}
            estimateRowHeight={66}
            selected={selectedRows}
            updateSelected={setSelectedRows}
        />

        {modalVuln != undefined && <VulnModal
            vuln={modalVuln}
            onClose={() => setModalVuln(undefined)}
            appendAssessment={appendAssessment}
            appendCVSS={appendCVSS}
            patchVuln={patchVuln}
        ></VulnModal>}
    </>)
}

export default TableVulnerabilities;
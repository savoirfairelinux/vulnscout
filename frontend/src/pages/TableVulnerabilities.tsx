import type { Vulnerability } from "../handlers/vulnerabilities";
import type { Assessment } from "../handlers/assessments";
import { createColumnHelper, SortingFn, RowSelectionState, Row, Table } from '@tanstack/react-table'
import { useMemo, useState } from "react";
import SeverityTag from "../components/SeverityTag";
import { SEVERITY_ORDER } from "../handlers/vulnerabilities";
import TableGeneric from "../components/TableGeneric";
import VulnModal from "../components/VulnModal";
import MultiEditBar from "../components/MultiEditBar";
import debounce from 'lodash-es/debounce';
import { escape } from "lodash-es";

type Props = {
    vulnerabilities: Vulnerability[];
    filteredVulns?: Vulnerability[];
    appendAssessment: (added: Assessment) => void;
    patchVuln: (vulnId: string, replace_vuln: Vulnerability) => void;
};

const sortSeverityFn: SortingFn<Vulnerability> = (rowA, rowB) => {
    const vulnsA = rowA.original.severity.severity.toUpperCase()
    const vulnsB = rowB.original.severity.severity.toUpperCase()
    return SEVERITY_ORDER.indexOf(vulnsA) - SEVERITY_ORDER.indexOf(vulnsB)
}

const sortStatusFn: SortingFn<Vulnerability> = (rowA, rowB) => {
    const indexA = ['unknown', 'pending analysis', 'active', 'not affected', 'fixed'].indexOf(rowA.original.simplified_status)
    const indexB = ['unknown', 'pending analysis', 'active', 'not affected', 'fixed'].indexOf(rowB.original.simplified_status)
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

function TableVulnerabilities ({ vulnerabilities, filteredVulns, appendAssessment, patchVuln }: Readonly<Props>) {

    const [modalVuln, setModalVuln] = useState<Vulnerability|undefined>(undefined);
    const [search, setSearch] = useState<string>('');
    const [filterSource, setFilterSource] = useState<string|undefined>(undefined);
    const [hidePatched, setHidePatched] = useState(false);
    const [hideIgnored, setHideIgnored] = useState(false);
    const [hideActive, setHideActive] = useState(false);
    const [hidePending, setHidePending] = useState(false);
    const [selectedRows, setSelectedRows] = useState<RowSelectionState>({})
    const [useFilteredProp, setUseFilteredProp] = useState(true);

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
                header: ({ table }: {table: Table<Vulnerability>}) => (
                    <div className="w-full text-center">
                        <input
                            type="checkbox"
                            title={table.getIsAllRowsSelected() ? "Unselect all" : "Select all"}
                            checked={table.getIsAllRowsSelected()}
                            onChange={table.getToggleAllRowsSelectedHandler()}
                        />
                    </div>
                ),
                cell: ({ row }: {row: Row<Vulnerability>}) => (
                    <div className="w-full text-center">
                        <input
                            type="checkbox"
                            title={row.getIsSelected() ? "Unselect" : "Select"}
                            checked={row.getIsSelected()}
                            disabled={!row.getCanSelect()}
                            onChange={row.getToggleSelectedHandler()}
                        />
                    </div>
                ),
                footer: ({ table }: {table: Table<Vulnerability>}) => (
                    <div className="w-full text-center">
                        {table.getSelectedRowModel().rows.length || ''}
                    </div>
                ),
                minSize: 10,
                size: 10,
                maxSize: 50
            },
            columnHelper.accessor('id', {
                header: 'ID',
                cell: info => info.getValue(),
                sortDescFirst: true,
                footer: (info) => `Total: ${info.table.getRowCount()}`,
                size: 125
            }),
            columnHelper.accessor('severity.severity', {
                header: 'Severity',
                cell: info => <SeverityTag severity={info.getValue()} />,
                sortingFn: sortSeverityFn,
                size: 100
            }),
            columnHelper.accessor('epss', {
                header: 'Exploitability',
                cell: info => {
                    const epss = info.getValue()
                    return epss.score && <>
                        <b>{Math.round(epss.score * 100)}%</b>
                        {epss.percentile && <i className="text-sm">(more than {Math.floor(epss.percentile * 100)}% of vulns)</i>}
                    </>
                },
                sortingFn: (rowA, rowB) => (rowA.original.epss?.score || 0.0) - (rowB.original.epss?.score || 0.0)
            }),
            columnHelper.accessor('packages', {
                header: 'Packages affected',
                cell: info => info.getValue().map(p => p.split('+git')[0]).join(', '),
                enableSorting: false
            }),
            columnHelper.accessor('severity', {
                header: 'Attack Vector',
                cell: info => [...(new Set(
                    info.getValue().cvss.map(cvss => cvss.attack_vector).filter(av => av != undefined)
                ))].join(', '),
                enableSorting: true,
                sortingFn: sortAttackVectorFn,
                size: 100
            }),
            columnHelper.accessor('simplified_status', {
                header: 'Status',
                cell: info => <code>{info.renderValue()}</code>,
                sortingFn: sortStatusFn,
                size: 130
            }),
            columnHelper.accessor('effort.likely', {
                header: 'Estimated effort',
                cell: info => info.getValue().formatHumanShort(),
                enableSorting: true,
                sortingFn: (rowA, rowB) => {
                    return rowA.original.effort.likely.total_seconds - rowB.original.effort.likely.total_seconds
                },
                size: 100
            }),
            columnHelper.accessor('found_by', {
                header: 'Sources',
                cell: info => info.renderValue()?.join(', '),
                enableSorting: false
            }),
            columnHelper.accessor(row => row, {
                header: 'Actions',
                cell: info => <button
                    className="bg-slate-800 hover:bg-slate-700 px-2 p-1 rounded-lg"
                    onClick={() => setModalVuln(info.getValue())}
                >
                        edit
                </button>,
                enableSorting: false,
                minSize: 50,
                size: 50
            })
        ]
    }, []);

    const filteredvulnerabilities = useMemo(() => {
        return vulnerabilities.filter((el) => {
            if (filterSource != undefined && el.found_by.every(val => val != filterSource)) return false
            if (hideIgnored && el.simplified_status == 'not affected') return false
            if (hidePatched && el.simplified_status == 'fixed') return false
            if (hideActive && el.simplified_status == 'active') return false
            if (hidePending && el.simplified_status == 'pending analysis') return false
            return true
        })
    }, [vulnerabilities, filterSource, hideIgnored, hidePatched, hideActive, hidePending])

    const dataToDisplay = useFilteredProp && filteredVulns ? filteredVulns : filteredvulnerabilities;

    const selectedVulns = useMemo(() => {
        return Object.entries(selectedRows).flatMap(([id, selected]) => selected ? [id] : [])
    }, [selectedRows])

    function resetFilters() {
        setSearch('');
        setFilterSource(undefined);
        setHidePatched(false);
        setHideIgnored(false);
        setHideActive(false);
        setHidePending(false);
        setSelectedRows({});
        setUseFilteredProp(false);
    }

    return (<>
        <div className="mb-4 p-2 bg-sky-800 text-white w-full flex flex-row items-center gap-2">
            <div>Search</div>
            <input onInput={updateSearch} type="search" className="py-1 px-2 bg-sky-900 focus:bg-sky-950 min-w-[250px] grow max-w-[800px]" placeholder="Search by ID, packages, description, ..." />
            <div className="ml-4">Source</div>
            <select
                name="source_selector"
                onChange={(event) => setFilterSource(event.target.value == "__none__" ? undefined : event.target.value)}
                className="py-1 px-2 bg-sky-900 focus:bg-sky-950 h-8"
            >
                <option value="__none__">All sources</option>
                {sources_list.map(source => <option value={escape(source)} key={encodeURIComponent(source)}>{source}</option>)}
            </select>
            <label className="ml-2">
                <input name="hide_patched" type="checkbox" className="mr-1" checked={hidePatched} onChange={() => {setHidePatched(!hidePatched)} } />
                Hide fixed
            </label>
            <label className="ml-2">
                <input name="hide_ignored" type="checkbox" className="mr-1" checked={hideIgnored} onChange={() => {setHideIgnored(!hideIgnored)} } />
                Hide ignored
            </label>
            <label className="ml-2">
                <input name="hide_active" type="checkbox" className="mr-1" checked={hideActive} onChange={() => {setHideActive(!hideActive)} } />
                Hide active
            </label>
            <label className="ml-2">
                <input name="hide_pending" type="checkbox" className="mr-1" checked={hidePending} onChange={() => {setHidePending(!hidePending)} } />
                Hide pending review
            </label>

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
        />

        <TableGeneric
            fuseKeys={fuseKeys}
            hoverField="texts"
            search={search}
            columns={columns}
            tableHeight={
                selectedVulns.length >= 1 ?
                'calc(100dvh - 44px - 64px - 48px - 16px - 48px - 16px)' :
                'calc(100dvh - 44px - 64px - 48px - 16px)'
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
            patchVuln={patchVuln}
        ></VulnModal>}
    </>)
}

export default TableVulnerabilities;

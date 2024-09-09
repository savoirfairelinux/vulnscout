import type { Vulnerability } from "../handlers/vulnerabilities";
import type { Assessment } from "../handlers/assessments";
import { createColumnHelper, SortingFn } from '@tanstack/react-table'
import { useMemo, useState } from "react";
import SeverityTag from "../components/SeverityTag";
import { SEVERITY_ORDER } from "../handlers/vulnerabilities";
import TableGeneric from "../components/TableGeneric";
import VulnModal from "../components/VulnModal";
import debounce from 'lodash-es/debounce';
import { escape } from "lodash-es";

type Props = {
    vulnerabilities: Vulnerability[];
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

const fuseKeys = ['id', 'aliases', 'related_vulnerabilities', 'packages', 'simplified_status', 'status', 'texts.content']

function TableVulnerabilities ({ vulnerabilities, appendAssessment, patchVuln }: Readonly<Props>) {

    const [modalVuln, setModalVuln] = useState<Vulnerability|undefined>(undefined);
    const [search, setSearch] = useState<string>('');
    const [filterSource, setFilterSource] = useState<string|undefined>(undefined);
    const [hidePatched, setHidePatched] = useState(false);
    const [hideIgnored, setHideIgnored] = useState(false);
    const [hideActive, setHideActive] = useState(false);
    const [hidePending, setHidePending] = useState(false);

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
            columnHelper.accessor('id', {
                header: 'ID',
                cell: info => info.getValue(),
                sortDescFirst: true,
                footer: (info) => `Total: ${info.table.getRowCount()}`
            }),
            columnHelper.accessor('severity.severity', {
                header: 'Severity',
                cell: info => <SeverityTag severity={info.getValue()} />,
                sortingFn: sortSeverityFn
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
            columnHelper.accessor('simplified_status', {
                header: 'Status',
                cell: info => <code>{info.renderValue()}</code>,
                sortingFn: sortStatusFn
            }),
            columnHelper.accessor('effort.likely', {
                header: 'Estimated effort',
                cell: info => info.getValue().formatHumanShort(),
                enableSorting: true,
                sortingFn: (rowA, rowB) => {
                    return rowA.original.effort.likely.total_seconds - rowB.original.effort.likely.total_seconds
                }
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
                enableSorting: false
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
        </div>

        <TableGeneric fuseKeys={fuseKeys} search={search} columns={columns} data={filteredvulnerabilities} estimateRowHeight={66} />

        {modalVuln != undefined && <VulnModal vuln={modalVuln} onClose={() => setModalVuln(undefined)} appendAssessment={appendAssessment} patchVuln={patchVuln}></VulnModal>}
    </>)
}

export default TableVulnerabilities;

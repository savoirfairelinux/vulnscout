import type { Vulnerability } from "../handlers/vulnerabilities";
import type { Assessment } from "../handlers/assessments";
import { createColumnHelper, SortingFn } from '@tanstack/react-table'
import { useMemo, useState } from "react";
import SeverityTag from "../components/SeverityTag";
import { SEVERITY_ORDER } from "../handlers/vulnerabilities";
import TableGeneric from "../components/TableGeneric";
import VulnModal from "../components/VulnModal";
import debounce from 'lodash-es/debounce';

type Props = {
    vulnerabilities: Vulnerability[];
    appendAssessment: (added: Assessment) => void;
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

function TableVulnerabilities ({ vulnerabilities, appendAssessment }: Props) {

    const [modalvuln, setModalVuln] = useState<Vulnerability|undefined>(undefined);
    const [search, setSearch] = useState<string>('');
    const [filterSource, setfilterSource] = useState<string|undefined>(undefined)

    const updateSearch = debounce((event: React.ChangeEvent<HTMLInputElement>) => {
        if (event.target.value.length < 2) {
            if (search != '') setSearch('');
        }
        setSearch(event.target.value);
    }, 750, { maxWait: 5000 });

    const sources_list = useMemo(() => vulnerabilities.reduce((acc: string[], vuln) => {
        if (vuln.found_by != '' && !acc.includes(vuln.found_by))
            acc.push(vuln.found_by)
        return acc;
    }, []), [vulnerabilities])

    const columns = useMemo(() => {
        const columnHelper = createColumnHelper<Vulnerability>()
        return [
            columnHelper.accessor('id', {
                header: 'ID',
                cell: info => info.getValue(),
                sortDescFirst: true
            }),
            columnHelper.accessor('severity.severity', {
                header: 'Severity',
                cell: info => <SeverityTag severity={info.getValue()} />,
                sortingFn: sortSeverityFn
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
            columnHelper.accessor('found_by', {
                header: 'Sources',
                cell: info => info.renderValue(),
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
        if (filterSource == undefined) return vulnerabilities
        return vulnerabilities.filter((el) => el.found_by == filterSource)
    }, [vulnerabilities, filterSource])

    return (<>
        <div className="mb-4 p-2 bg-sky-800 text-white w-full flex flex-row items-center gap-2">
            <div>Search</div>
            <input onInput={updateSearch} type="search" className="py-1 px-2 bg-sky-900 focus:bg-sky-950 min-w-[250px] grow max-w-[800px]" placeholder="Search by ID, packages, description, ..." />
            <div className="ml-4">Source</div>
            <select name="source_selector" onChange={(event) => setfilterSource(event.target.value)} className="py-1 px-2 bg-sky-900 focus:bg-sky-950 h-8">
                <option value={undefined}>All sources</option>
                {sources_list.map(source => <option value={source} key={source}>{source}</option>)}
            </select>
        </div>

        <TableGeneric fuseKeys={fuseKeys} search={search} columns={columns} data={filteredvulnerabilities} estimateRowHeight={66} />

        {modalvuln != undefined && <VulnModal vuln={modalvuln} onClose={() => setModalVuln(undefined)} appendAssessment={appendAssessment}></VulnModal>}
    </>)
}

export default TableVulnerabilities;

import type { Package, VulnCounts, Severities } from "../handlers/packages";
import { createColumnHelper, Row } from '@tanstack/react-table'
import { useMemo, useState } from "react";
import SeverityTag from "../components/SeverityTag";
import TableGeneric from "../components/TableGeneric";
import debounce from 'lodash-es/debounce';
import { escape } from "lodash-es";

type Props = {
    packages: Package[];
};

const addVulnCounts = (counts: VulnCounts, ignore: string[]) => {
    return Object.keys(counts).reduce((acc, key) => {
        if (!ignore.includes(key)) {
            acc += counts[key]
        }
        return acc
    }, 0)
}

const highestSeverity = (severities: Severities, ignore: string[]) => {
    return Object.keys(severities).reduce((acc, key) => {
        if (!ignore.includes(key)) {
            if (severities[key].index > acc.index) {
                return severities[key]
            }
        }
        return acc
    }, {label: 'NONE', index: 0})
}

const sortVunerabilitiesFn = (rowA: Row<Package>, rowB: Row<Package>, ignore: string[]) => {
    const vulnsA = addVulnCounts(rowA.original.vulnerabilities, ignore)
    const vulnsB = addVulnCounts(rowB.original.vulnerabilities, ignore)
    return vulnsA - vulnsB
}

const fuseKeys = ['id', 'name', 'version', 'cpe', 'purl']

function TablePackages ({ packages }: Props) {
    const [showSeverity, setShowSeverity] = useState(false);
    const [hidePatched, setHidePatched] = useState(false);
    const [hideIgnored, setHideIgnored] = useState(false);
    const [search, setSearch] = useState<string>('');
    const [filterSource, setfilterSource] = useState<string|undefined>(undefined)

    const updateSearch = debounce((event: React.ChangeEvent<HTMLInputElement>) => {
        if (event.target.value.length < 2) {
            if (search != '') setSearch('');
        }
        setSearch(event.target.value);
    }, 550, { maxWait: 2500 });

    const sources_list = useMemo(() => packages.reduce((acc: string[], pkg) => {
        for (const source of pkg.source) {
            if (source != '' && !acc.includes(source))
                acc.push(source)
        }
        return acc;
    }, []), [packages])

    const hide_filter = useMemo(() => {
        let hide_filter = []
        if (hidePatched) hide_filter.push('fixed')
        if (hideIgnored) hide_filter.push('not affected')
        return hide_filter
    }, [hidePatched, hideIgnored])

    const columns = useMemo(() => {
        const columnHelper = createColumnHelper<Package>()
        return [
            columnHelper.accessor('name', {
                header: 'Name',
                cell: info => info.getValue(),
                footer: (info) => `Total: ${info.table.getRowCount()}`
            }),
            columnHelper.accessor('version', {
                header: 'Version',
                cell: info => info.getValue()
            }),
            columnHelper.accessor(row => ({ counts: row.vulnerabilities, severity: row.maxSeverity }), {
                header: 'Vulnerabilities',
                cell: info => <>
                    <span className="min-w-8 mr-2 inline-block">{addVulnCounts(info.getValue().counts, hide_filter)}</span>
                    {showSeverity && <SeverityTag severity={highestSeverity(info.getValue().severity, hide_filter).label} />}
                </>,
                sortingFn: (a, b) => sortVunerabilitiesFn(a, b, hide_filter)
            }),
            columnHelper.accessor('source', {
                header: 'Sources',
                cell: info => info.getValue()?.join(', '),
                enableSorting: false
            })
        ]
    }, [showSeverity, hide_filter]);

    const filteredPackages = useMemo(() => {
        if (filterSource == undefined) return packages
        return packages.filter((el) => el.source.includes(filterSource))
    }, [packages, filterSource])

    return (<>
        <div className="mb-4 p-2 bg-sky-800 text-white w-full flex flex-row items-center gap-2">
            <div>Search</div>
            <input onInput={updateSearch} type="search" className="py-1 px-2 bg-sky-900 focus:bg-sky-950 min-w-[250px] grow max-w-[800px]" placeholder="Search by package name, version, ..." />
            <div className="ml-4">Source</div>
            <select
                name="source_selector"
                onChange={(event) => setfilterSource(event.target.value == "__none__" ? undefined : event.target.value)}
                className="py-1 px-2 bg-sky-900 focus:bg-sky-950 h-8"
            >
                <option value="__none__">All sources</option>
                {sources_list.map(source => <option value={escape(source)} key={encodeURIComponent(source)}>{source}</option>)}
            </select>
            <button className={["ml-4 py-1 px-2", showSeverity ? 'bg-sky-950' : 'bg-sky-900'].join(' ')} onClick={() => setShowSeverity(!showSeverity)}>Severity {showSeverity ? 'enabled' : 'disabled'}</button>
            <label className="ml-2">
                <input name="hide_patched" type="checkbox" className="mr-1" checked={hidePatched} onChange={() => {setHidePatched(!hidePatched)}} />
                Hide fixed vulns
            </label>
            <label className="ml-2">
                <input name="hide_ignored" type="checkbox" className="mr-1" checked={hideIgnored} onChange={() => {setHideIgnored(!hideIgnored)} } />
                Hide ignored vulns
            </label>
        </div>

        <TableGeneric fuseKeys={fuseKeys} search={search} columns={columns} data={filteredPackages} estimateRowHeight={57} />
    </>);
}


export default TablePackages;

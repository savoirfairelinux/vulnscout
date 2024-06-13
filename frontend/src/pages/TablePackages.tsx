import type { Package } from "../handlers/packages";
import { createColumnHelper, SortingFn } from '@tanstack/react-table'
import { useMemo, useState } from "react";
import SeverityTag from "../components/SeverityTag";
import TableGeneric from "../components/TableGeneric";
import debounce from 'lodash-es/debounce';

type Props = {
    packages: Package[];
};

const sortVunerabilitiesFn: SortingFn<Package> = (rowA, rowB) => {
    const vulnsA = rowA.original.vulnerabilities
    const vulnsB = rowB.original.vulnerabilities
    return vulnsA - vulnsB
}

const fuseKeys = ['id', 'name', 'version', 'cpe', 'purl']

function TablePackages ({ packages }: Props) {
    const [showSeverity, setShowSeverity] = useState(false);
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

    const columns = useMemo(() => {
        const columnHelper = createColumnHelper<Package>()
        return [
            columnHelper.accessor('name', {
                header: 'Name',
                cell: info => info.getValue(),
            }),
            columnHelper.accessor('version', {
                header: 'Version',
                cell: info => info.getValue()
            }),
            columnHelper.accessor(row => ({ count: row.vulnerabilities, severity: row.maxSeverity }), {
                header: 'Vulnerabilities',
                cell: info => <>
                    <span className="min-w-8 mr-2 inline-block">{info.getValue().count}</span>
                    {showSeverity && <SeverityTag severity={info.getValue().severity} />}
                </>,
                sortingFn: sortVunerabilitiesFn
            }),
            columnHelper.accessor('source', {
                header: 'Sources',
                cell: info => info.getValue()?.join(', '),
                enableSorting: false
            })
        ]
    }, [showSeverity]);

    const filteredPackages = useMemo(() => {
        if (filterSource == undefined) return packages
        return packages.filter((el) => el.source.includes(filterSource))
    }, [packages, filterSource])

    return (<>
        <div className="mb-4 p-2 bg-sky-800 text-white w-full flex flex-row items-center gap-2">
            <div>Search</div>
            <input onInput={updateSearch} type="search" className="py-1 px-2 bg-sky-900 focus:bg-sky-950 min-w-[250px] grow max-w-[800px]" placeholder="Search by package name, version, ..." />
            <div className="ml-4">Source</div>
            <select name="source_selector" onChange={(event) => setfilterSource(event.target.value)} className="py-1 px-2 bg-sky-900 focus:bg-sky-950 h-8">
                <option value={undefined}>All sources</option>
                {sources_list.map(source => <option value={source} key={source}>{source}</option>)}
            </select>
            <button className={["ml-4 py-1 px-2", showSeverity ? 'bg-sky-950' : 'bg-sky-900'].join(' ')} onClick={() => setShowSeverity(!showSeverity)}>Severity {showSeverity ? 'enabled' : 'disabled'}</button>
        </div>

        <TableGeneric fuseKeys={fuseKeys} search={search} columns={columns} data={filteredPackages} estimateRowHeight={57} />
    </>);
}


export default TablePackages;

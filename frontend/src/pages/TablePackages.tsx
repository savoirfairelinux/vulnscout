import type { Package, VulnCounts, Severities } from "../handlers/packages";
import { createColumnHelper, Row } from '@tanstack/react-table'
import { useMemo, useState } from "react";
import SeverityTag from "../components/SeverityTag";
import TableGeneric from "../components/TableGeneric";
import debounce from 'lodash-es/debounce';
import FilterOption from "../components/FilterOption";
import ToggleSwitch from "../components/ToggleSwitch";

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

function TablePackages({ packages }: Readonly<Props>) {
    const [showSeverity, setShowSeverity] = useState(false);
    const [search, setSearch] = useState<string>('');
    const [selectedSources, setSelectedSources] = useState<string[]>([]);
    const [selectedStatuses, setSelectedStatuses] = useState<string[]>([]);
    const [selectedLicences, setSelectedLicences] = useState<string[]>([]);

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

    const licences_list = useMemo(() => {
        const licenceSet = new Set<string>();
        packages.forEach(pkg => {
            const licence = pkg.licences;
            if (licence) {
                licence.split(/\s+(?:AND|OR)\s+/).forEach(l => {
                    if (l && !licenceSet.has(l)) {
                        licenceSet.add(l);
                    }
                });
            }
        });
        return Array.from(licenceSet);
    }, [packages]);
    
    const statusOptions = useMemo(() => {
        const statuses = new Set<string>();
        for (const pkg of packages) {
            Object.keys(pkg.vulnerabilities).forEach(status => statuses.add(status));
        }
        return Array.from(statuses);
    }, [packages]);

    const hide_filter = useMemo(() => {
        return statusOptions.filter(status => selectedStatuses.includes(status))
    }, [selectedStatuses])

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
            columnHelper.accessor('licences', {
                header: 'Licences',
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
        return packages.filter((el) => {
            if (selectedSources.length && !selectedSources.some(src => el.source.includes(src))) {
                return false;
            }

            if (selectedStatuses.length) {
                const vulnStatuses = Object.keys(el.vulnerabilities);
                if (!vulnStatuses.some(status => selectedStatuses.includes(status))) {
                    return false;
                }
            }

           if (selectedLicences.length && !selectedLicences.includes(el.licences)) {
                return false;
            }


            return true;
        });
    }, [packages, selectedSources, selectedStatuses, selectedLicences]);

    return (<>
        <div className="mb-4 p-2 bg-sky-800 text-white w-full flex flex-row items-center gap-2">
            <div>Search</div>
            <input onInput={updateSearch} type="search" className="py-1 px-2 bg-sky-900 focus:bg-sky-950 min-w-[250px] grow max-w-[800px]" placeholder="Search by package name, version, ..." />
            
            <FilterOption
                label="Source"
                options={sources_list}
                selected={selectedSources}
                setSelected={setSelectedSources}
            />

            <FilterOption
                label="Status"
                options={statusOptions}
                selected={selectedStatuses}
                setSelected={setSelectedStatuses}
            />

            <FilterOption
                label="Licences"
                options={licences_list}
                selected={selectedLicences}
                setSelected={setSelectedLicences}
            />

            <div className="ml-4">
                <ToggleSwitch
                    enabled={showSeverity}
                    setEnabled={setShowSeverity}
                    label="Severity"
                />
            </div>
        </div>

        <TableGeneric fuseKeys={fuseKeys} search={search} columns={columns} data={filteredPackages} estimateRowHeight={57} />
    </>);
}

export default TablePackages;

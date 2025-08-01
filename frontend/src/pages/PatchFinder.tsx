import type { Vulnerability } from "../handlers/vulnerabilities";
import type { Package } from '../handlers/packages';
import type { PackageVulnerabilities } from '../handlers/patch_finder';
import PatchFinderLogic from '../handlers/patch_finder';
import { useMemo, useState } from "react";
import debounce from 'lodash-es/debounce';
import FilterOption from "../components/FilterOption";

import PackageDetails from "../components/PackageDetails";
import type { version as VersionLineEntry } from "../components/VersionsLine";
import VersionsLine from "../components/VersionsLine";

type Props = {
    vulnerabilities: Vulnerability[];
    packages: Package[];
    patchData: PackageVulnerabilities;
    db_ready: boolean;
};

function PatchFinder ({ packages, patchData, db_ready }: Readonly<Props>) {
    const [search, setSearch] = useState<string>('');
    const [showLegend, setShowLegend] = useState<boolean>(true);
    const [selectedSources, setSelectedSources] = useState<string[]>([]);

    const actual_pkgs = useMemo(() => {
        let output: {[key: string]: string} = {}
        packages.forEach(pkg => {
            output[pkg.name] = pkg.version;
        });
        return output;
    }, [packages])

    const updateSearch = debounce((event: React.ChangeEvent<HTMLInputElement>) => {
        if (event.target.value.length < 2) {
            if (search != '') setSearch('');
        }
        setSearch(event.target.value);
    }, 100, { maxWait: 800 });

    const sources_list = useMemo(() => Object.values(patchData).reduce((acc: string[], cves_methods) => {
        const methods = Object.values(cves_methods).flatMap(a => Object.keys(a))
        methods.forEach(method => {
            if (method && !acc.includes(method)) acc.push(method)
        })
        return acc;
    }, []), [patchData])

    const RenderData = useMemo(() => {
        return PatchFinderLogic.compute_versions_and_patch(patchData, actual_pkgs, selectedSources, search)
    }, [patchData, actual_pkgs, selectedSources, search])

    const RenderDetailled = useMemo(() => {
        return PatchFinderLogic.compute_vulns_per_versions(patchData, actual_pkgs, selectedSources, search)
    }, [patchData, actual_pkgs, selectedSources, search])


    return (<>
        <div className="mb-4 p-2 bg-sky-800 text-white w-full flex flex-row items-center gap-2">
            <div className="ml-2">Search</div>
            <input onInput={updateSearch} type="search" className="py-1 px-2 bg-sky-900 focus:bg-sky-950 min-w-[250px] grow max-w-[400px]" placeholder="Search by version or vulnerability ID" />

            <FilterOption
                label="Source"
                options={sources_list}
                selected={selectedSources}
                setSelected={setSelectedSources}
            />

            <div className="flex-1"></div>
            <button className="p-2 px-4 bg-sky-900 hover:bg-sky-950" onClick={() => setShowLegend(!showLegend)}>{showLegend ? 'Hide' : 'Show'} Legend</button>
        </div>

        {!db_ready && <div className="p-4 bg-orange-600">
            Database is currently updating, please wait. This page will refresh when patch data are available.<br/>
            <i>You can leave and come back at this page, DB will continue update in background. To speed up the process, ensure you have cache configured in vulnscout configuration.</i>
        </div>}

        <div className="my-4 p-4 bg-slate-700 flex flex-row flex-wrap">
            {showLegend && <div className="flex-none w-full px-8 bg-slate-600">
                <h2 className="pt-4 font-bold font-mono text-center">Legend</h2>
                <VersionsLine reduce_size={true} versions={[
                    {title: 'current version', details: 'current'},
                    {title: 'next patch version', details: 'safe to upgrade', left_color: 'bg-gray-400 h-0.5'},
                    {title: 'next minor version', details: 'may require some changes', left_color: 'bg-gray-400 h-1'},
                    {title: 'next major', details: 'breaking change !', left_color: 'bg-gray-400 h-1.5'}
                ]}></VersionsLine>
            </div>}

            {Object.keys(RenderData).map(pkg_name => {
                const info = RenderData[pkg_name];

                const versions: VersionLineEntry[] = [
                    {title: actual_pkgs[pkg_name] ?? '', details: 'current'}
                ]
                if (info.same_minor.version) {
                    versions.push({
                        title: info.same_minor.version,
                        highlight: `-${info.same_minor.solve}`,
                        details: ' vulnerabilities', left_color: 'bg-gray-400 h-0.5'
                    })
                }
                if (info.same_major.version && info.same_major.version != info.same_minor.version) {
                    versions.push({
                        title: info.same_major.version,
                        highlight: `-${info.same_major.solve}`,
                        details: ' vulnerabilities', left_color: 'bg-gray-400 h-1'
                    })
                }
                if (info.latest.version && info.latest.version != info.same_major.version) {
                    versions.push({
                        title: info.latest.version,
                        highlight: `-${info.latest.solve}`,
                        details: ' vulnerabilities', left_color: 'bg-gray-400 h-1.5'
                    })
                }
                if (versions.length <= 1) return

                return <div key={pkg_name} className="flex-none w-full 2xl:w-1/2 py-8">
                    <h2 className="pt-4 font-bold font-mono text-center">{pkg_name}</h2>
                    <VersionsLine versions={versions}></VersionsLine>

                    {RenderDetailled[pkg_name] && Object.keys(RenderDetailled[pkg_name]).length > 0 &&
                    <div className="px-8 md:px-16">
                        <PackageDetails title={`see more versions for ${pkg_name}`}>
                            {Object.keys(RenderDetailled[pkg_name]).sort().map((version) => {
                                const cves = RenderDetailled[pkg_name][version]
                                return <li key={version} className="p-1">
                                    <span className="font-mono">{version}</span>
                                    <span className="text-slate-200"> patches {cves.length} vulnerabilities: </span>
                                    <i className='text-xs text-slate-300'>{cves.join(', ')}</i>
                                </li>
                            })}
                        </PackageDetails>
                    </div>}
                </div>
            })}
        </div>
    </>)
}

export default PatchFinder;

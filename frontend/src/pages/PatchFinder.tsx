import type { Vulnerability } from "../handlers/vulnerabilities";
import type { Package } from '../handlers/packages';
import type { PackageVulnerabilities } from '../handlers/patch_finder';
import PatchFinderLogic from '../handlers/patch_finder';
import type { NVDProgress } from '../handlers/nvd_progress';
import NVDProgressHandler from '../handlers/nvd_progress';
import { useMemo, useState } from "react";
import debounce from 'lodash-es/debounce';
import FilterOption from "../components/FilterOption";

import PackageDetails from "../components/PackageDetails";
import type { version as VersionLineEntry } from "../components/VersionsLine";
import VersionsLine from "../components/VersionsLine";
import ToggleSwitch from "../components/ToggleSwitch";
type Props = {
    vulnerabilities: Vulnerability[];
    packages: Package[];
    patchData: PackageVulnerabilities;
    db_ready: boolean;
    nvdProgress: NVDProgress | null;
};

function PatchFinder ({ packages, patchData, db_ready, nvdProgress }: Readonly<Props>) {
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

    const progressPercentage = nvdProgress ? NVDProgressHandler.getProgressPercentage(nvdProgress) : 0;
    const showProgressOverlay = !db_ready && nvdProgress?.in_progress;

    return (<div className="relative">
        <div className="rounded-md mb-4 p-2 bg-sky-800 text-white w-full flex flex-row items-center gap-2">
            <div>Search</div>
            <input 
                onInput={updateSearch} 
                type="search" 
                className="py-1 px-2 bg-sky-900 focus:bg-sky-950 min-w-[250px] grow max-w-[400px]" 
                placeholder="Search by version or vulnerability ID"
                disabled={showProgressOverlay}
            />

            <FilterOption
                label="Source"
                options={sources_list}
                selected={selectedSources}
                setSelected={setSelectedSources}
            />

            <div className="flex-1"></div>

            <ToggleSwitch
                enabled={showLegend}
                setEnabled={setShowLegend}
                label="Legend"
            />
        </div>

        {!db_ready && !showProgressOverlay && <div className="p-4 bg-orange-600">
            Database is currently updating, please wait. This page will refresh when patch data are available.<br/>
            <i>You can leave and come back at this page, DB will continue update in background. To speed up the process, ensure you have cache configured in vulnscout configuration.</i>
        </div>}

        {showProgressOverlay && (
            <div className="absolute inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                <div className="bg-slate-800 rounded-lg p-8 max-w-lg w-full mx-4 shadow-2xl">
                    <h2 className="text-2xl font-bold text-white mb-4 text-center">
                        Building NVD Database
                    </h2>
                    <div className="mb-6">
                        <div className="flex justify-between text-sm text-slate-300 mb-2">
                            <span>{nvdProgress?.phase || 'Initializing...'}</span>
                            <span>{Math.round(progressPercentage * 100)}%</span>
                        </div>
                        <div className="w-full bg-slate-700 rounded-full h-4 overflow-hidden">
                            <div 
                                className="bg-gradient-to-r from-blue-500 to-cyan-500 h-full transition-all duration-300 ease-out"
                                style={{ width: `${progressPercentage * 100}%` }}
                            ></div>
                        </div>
                        {nvdProgress?.current !== undefined && nvdProgress?.total !== undefined && (
                            <div className="text-sm text-slate-400 mt-2 text-center">
                                Processing {nvdProgress.current} of {nvdProgress.total} items
                            </div>
                        )}
                    </div>
                </div>
            </div>
        )}

        <div className={`rounded-md my-4 p-4 bg-slate-700 flex flex-row flex-wrap ${showProgressOverlay ? 'pointer-events-none opacity-50' : ''}`}>
            {showLegend && <div className="rounded-md flex-none w-full px-8 bg-slate-600">
                <h2 className="pt-4 font-bold font-mono text-center text-white">Legend</h2>
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
                    <h2 className="pt-4 font-bold font-mono text-center text-white">{pkg_name}</h2>
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
    </div>)
}

export default PatchFinder;

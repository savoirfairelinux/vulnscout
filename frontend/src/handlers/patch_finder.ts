import semver from 'semver';
// [package name]: vulnerabilities
type PackageVulnerabilities = { [key: string]: VulnerabilitySources }
// [vuln ID]: sources
type VulnerabilitySources = { [key: string]: SourceInfos }
// [source] : info
type SourceInfos = { [key: string]: PatchInfos }
type PatchInfos = { affected: string[], fix: string[], solve_all?: string }
/* {
    [package name]: {
        [vuln ID]: {
            [source]: {
                affected: string[],
                fix: string[],
                solve_all?: string
            }
        }
    }
} */



type PackageVersions = {
    nb_vulns: number,
    same_minor: VersionPatchs,
    same_major: VersionPatchs,
    latest: VersionPatchs
}
// [version]: number of vulnerabilities patching
type VersionPatchs = {
    version?: string,
    solve: number
}


// [version]: list of vulns ID
type VersionVulns = {
    [key: string]: string[]
}


export type { PackageVulnerabilities, PackageVersions };

const asPatchInfos = (data: any): PatchInfos | undefined => {
    if (typeof data !== "object") return undefined;
    if (!Array.isArray(data?.affected)) data.affected = [];
    if (!Array.isArray(data?.fix)) data.fix = [];
    const affected = data.affected.filter((a: any) => typeof a === "string")
    const fix = data.fix.filter((a: any) => typeof a === "string")
    const solve_eq = fix
        .filter((a: string) => {
            const a_no_prefix = a.split(' ')
            a_no_prefix.shift()
            return semver.valid(a_no_prefix.join(' '))
        })
        .join(' ')
        .replace(/\?/g, '')
    return {
        affected,
        fix,
        solve_all: solve_eq.length == 0 ? undefined : semver.minVersion(solve_eq)?.version
    }
}

const asVulnerabilitySources = (data: any): VulnerabilitySources => {
    let output: VulnerabilitySources = {};
    if (typeof data !== "object") return output;
    for (const [key, value] of Object.entries(data)) {
        if (typeof key !== "string") continue;

        const cve = key.split(' (')[0];
        const source = key.split(' ').pop()
        if (!output?.[cve]) output[cve] = {};
        const patchInfos = asPatchInfos(value);
        if (source && patchInfos) output[cve][source] = patchInfos;
    }
    return output;
}

const asPackageVulnerabilities = (data: any): PackageVulnerabilities => {
    let output: PackageVulnerabilities = {};
    if (typeof data !== "object") return output;
    for (const [key, value] of Object.entries(data)) {
        if (typeof key !== "string") return output;
        const patchInfos = asVulnerabilitySources(value);
        if (patchInfos) output[key] = patchInfos;
    }
    return output;
};

class PatchFinderLogic {
    static async scan(cves: string[]): Promise<PackageVulnerabilities> {
        const response = await fetch(import.meta.env.VITE_API_URL + "/api/patch-finder/scan", {
            mode: "cors",
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(cves)
        });
        const data = await response.json();
        return asPackageVulnerabilities(data);
    }

    static compute_versions_and_patch(
        data: PackageVulnerabilities,
        current: {[key: string]: string},
        filter_source: string|undefined,
        search: string
    ): {[key: string]: PackageVersions} {

        let output: {[key: string]: PackageVersions} = {}
        for (const [pkg_name, pkg_data] of Object.entries(data)) {
            if (!current?.[pkg_name]) continue;
            const cur_version = current[pkg_name]
            let minor_range = null;
            let major_range = null;
            try {
                minor_range = new semver.Range(`~${cur_version}`)
                major_range = new semver.Range(`^${cur_version}`)
            }
            catch (e) { continue; }
            if (minor_range == null || major_range == null) continue;
            let info: PackageVersions = {
                nb_vulns: 0,
                same_minor: { solve: 0 },
                same_major: { solve: 0 },
                latest: { solve: 0 }
            }

            for (const [vuln_id, vuln_data] of Object.entries(pkg_data)) {
                info.nb_vulns++;

                for (const [source, patch_infos] of Object.entries(vuln_data)) {
                    if (filter_source != undefined && source != filter_source) continue;
                    if (!patch_infos.solve_all) continue;
                    if (
                        search != '' && !(
                            patch_infos.solve_all.includes(search) ||
                            vuln_id.includes(search)
                        )
                    ) { continue; }

                    if (info.latest.version == undefined || semver.gt(patch_infos.solve_all, info.latest.version)) {
                        info.latest.version = patch_infos.solve_all
                    }
                    info.latest.solve++;
                    if (semver.satisfies(patch_infos.solve_all, major_range)) {
                        if (info.same_major.version == undefined || semver.gt(patch_infos.solve_all, info.same_major.version)) {
                            info.same_major.version = patch_infos.solve_all
                        }
                        info.same_major.solve++;

                        if (semver.satisfies(patch_infos.solve_all, minor_range)) {
                            if (info.same_minor.version == undefined || semver.gt(patch_infos.solve_all, info.same_minor.version)) {
                                info.same_minor.version = patch_infos.solve_all
                            }
                            info.same_minor.solve++;
                        }
                    }
                }
            }
            output[pkg_name] = info
        }
        return output
    }

    static compute_vulns_per_versions (
        data: PackageVulnerabilities,
        current: {[key: string]: string},
        filter_source: string|undefined,
        search: string
): {[key: string]: VersionVulns} {

        let output: {[key: string]: VersionVulns} = {}
        for (const [pkg_name, pkg_data] of Object.entries(data)) {
            if (!current?.[pkg_name]) continue;
            output[pkg_name] = {}

            for (const [vuln_id, vuln_data] of Object.entries(pkg_data)) {
                for (const [source, patch_infos] of Object.entries(vuln_data)) {
                    if (filter_source != undefined && source != filter_source) continue;
                    if (!patch_infos.solve_all) continue;
                    if (
                        search != '' && !(
                            patch_infos.solve_all.includes(search) ||
                            vuln_id.includes(search)
                        )
                    ) { continue; }
                    if (!output[pkg_name][patch_infos.solve_all]) output[pkg_name][patch_infos.solve_all] = []
                    output[pkg_name][patch_infos.solve_all].push(vuln_id)
                }
            }
        }
        return output
    }
}

export default PatchFinderLogic;
export { asPackageVulnerabilities, asPatchInfos };

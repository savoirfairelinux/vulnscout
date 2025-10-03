import { useState } from "react";
import type { Vulnerability } from "../handlers/vulnerabilities";
import StatusEditor from "./StatusEditor";
import type { PostAssessment } from './StatusEditor';
import TimeEstimateEditor from "./TimeEstimateEditor";
import type { PostTimeEstimate } from "./TimeEstimateEditor";
import { asAssessment, Assessment } from "../handlers/assessments";
import Iso8601Duration from '../handlers/iso8601duration';

type Props = {
    vulnerabilities: Vulnerability[];
    selectedVulns: string[];
    resetVulns: () => void;
    appendAssessment: (added: Assessment) => void;
    patchVuln: (vulnId: string, replace_vuln: Vulnerability) => void;
    triggerBanner: (message: string, type: 'error' | 'success') => void;
    hideBanner: () => void;
};

function MultiEditBar ({vulnerabilities, selectedVulns, resetVulns, appendAssessment, patchVuln, triggerBanner, hideBanner} : Readonly<Props>) {

    const [panelOpened, setPanelOpened] = useState<number>(0)
    const [progressBar, setProgressBar] = useState<number|undefined>(undefined)

    if (selectedVulns.length == 0) {
        if (panelOpened) setPanelOpened(0)
        if (progressBar !== undefined) setProgressBar(undefined)
    }

    function pkg_for_vulns () {
        const pkg_vulns: {[key: string]: string[]} = {}
        for (const vuln of vulnerabilities) {
            if (selectedVulns.includes(vuln.id)) {
                pkg_vulns[vuln.id] = vuln.packages
            }
        }
        return pkg_vulns
    }

    const addAssessment = async (content: PostAssessment) => {
        const pkg_vulns = pkg_for_vulns();
        const assessments: Assessment[] = [];
        const errors = []
        let index = 0
        setProgressBar(0)

        for (const vuln of selectedVulns) {
            content.vuln_id = vuln;
            content.packages = pkg_vulns[vuln] ?? [];
            try {
                const response = await fetch(import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(vuln)}/assessments`, {
                    method: 'POST',
                    mode: 'cors',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(content)
                })
                const data = await response.json().catch(() => {})
                if (data?.status === 'success') {
                    const casted = asAssessment(data?.assessment);
                    if (!Array.isArray(casted) && typeof casted === "object")
                        assessments.push(casted)
                } else {
                    errors.push(Number(response?.status))
                }
            }
            catch (e) {
                errors.push(`Exception: ${e}`);
            }
            index++
            setProgressBar(index / selectedVulns.length)
        }

        if (errors.length >= 1) {
            triggerBanner(`Failed to add assessment: HTTP code ${errors.join(', ')}`, 'error');
        } else if (assessments.length > 0) {
            triggerBanner(`Successfully added assessments to ${assessments.length} vulnerabilities`, 'success');
        }
        assessments.forEach(appendAssessment)
        setProgressBar(undefined)
        setPanelOpened(0)
    };

    function vuln_ids_to_vulns () {
        const vulns: {[key: string]: Vulnerability} = {}
        for (const vuln of vulnerabilities) {
            if (selectedVulns.includes(vuln.id)) {
                vulns[vuln.id] = vuln
            }
        }
        return vulns
    }

    const saveTimeEstimation = async (content: PostTimeEstimate) => {
        const vulns = vuln_ids_to_vulns();
        const patchs: Vulnerability[] = [];
        const errors = []
        let index = 0
        setProgressBar(0)

        for (const vuln_id of selectedVulns) {
            try {
                const vuln = vulns[vuln_id];
                const response = await fetch(import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(vuln.id)}`, {
                    method: 'PATCH',
                    mode: 'cors',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({effort: {
                        optimistic: content.optimistic.formatAsIso8601(),
                        likely: content.likely.formatAsIso8601(),
                        pessimistic: content.pessimistic.formatAsIso8601()
                    }})
                })

                if (response.status == 200) {
                    const data = await response.json()
                    if (typeof data?.effort?.optimistic === "string")
                        vuln.effort.optimistic = new Iso8601Duration(data.effort.optimistic);
                    if (typeof data?.effort?.likely === "string")
                        vuln.effort.likely = new Iso8601Duration(data.effort.likely);
                    if (typeof data?.effort?.pessimistic === "string")
                        vuln.effort.pessimistic = new Iso8601Duration(data.effort.pessimistic);

                    patchs.push(vuln);
                } else {
                    errors.push(Number(response?.status))
                }
            }
            catch (e) {
                errors.push(`Exception: ${e}`);
            }

            index++
            setProgressBar(index / selectedVulns.length)
        }

        if (errors.length >= 1) {
            triggerBanner(`Failed to save time estimates: HTTP code ${errors.join(', ')}`, 'error');
        } else if (patchs.length > 0) {
            triggerBanner(`Successfully updated time estimates for ${patchs.length} vulnerabilities`, 'success');
        }
        patchs.forEach((vuln: Vulnerability) => patchVuln(vuln.id, vuln))
        setProgressBar(undefined)
        setPanelOpened(0)
    }

    return (<>
        {selectedVulns.length >= 1 && <>
            {panelOpened > 0 && <div className="absolute top-0 left-0 right-0 bottom-0 z-30 bg-black/40"></div>}

            <div className="relative mb-4 z-40 w-full">
                <div className="bg-slate-600/70 text-white w-full">
                    <div className="p-2 flex flex-row items-center gap-2">
                        <div>Selected vulnerabilities: {selectedVulns.length}</div>
                        <button className="bg-sky-900 p-1 px-2 mr-4" onClick={() => { hideBanner(); resetVulns(); }}>Reset selection</button>

                        <button className="bg-sky-900 p-1 px-2" onClick={() => { hideBanner(); setPanelOpened(panelOpened == 1 ? 0 : 1); }}>Change status</button>
                        <button className="bg-sky-900 p-1 px-2 mr-4" onClick={() => { hideBanner(); setPanelOpened(panelOpened == 2 ? 0 : 2); }}>Change estimated time</button>
                    </div>
                </div>
            </div>

            <div className={[
                'absolute z-40 p-4 bg-slate-700 shadow-md shadow-slate-400/40 top-48 left-32 w-1/2',
                panelOpened == 1 ? 'block' : 'hidden'
            ].join(' ')}>
                <StatusEditor 
                    onAddAssessment={(data) => addAssessment(data)} 
                    progressBar={progressBar}
                />
            </div>

            <div className={[
                'absolute z-40 p-4 bg-slate-700 shadow-md shadow-slate-400/40 top-48 left-32 w-1/2',
                panelOpened == 2 ? 'block' : 'hidden'
            ].join(' ')}>
                <TimeEstimateEditor
                    onSaveTimeEstimation={(data) => saveTimeEstimation(data)}
                    progressBar={progressBar}
                    actualEstimate={{optimistic: '', likely: '', pessimistic: ''}}
                />
            </div>
        </>}
    </>);
}

export default MultiEditBar;

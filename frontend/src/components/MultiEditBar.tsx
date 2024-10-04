import { useState } from "react";
import type { Vulnerability } from "../handlers/vulnerabilities";
import StatusEditor from "./StatusEditor";
import type { PostAssessment } from './StatusEditor';
import { asAssessment, Assessment } from "../handlers/assessments";

type Props = {
    vulnerabilities: Vulnerability[];
    selectedVulns: string[];
    resetVulns: () => void;
    appendAssessment: (added: Assessment) => void;
};

function MultiEditBar ({vulnerabilities, selectedVulns, resetVulns, appendAssessment} : Readonly<Props>) {

    const [panelStatus, setPanelStatus] = useState<boolean>(false)
    const [progressBar, setProgressBar] = useState<number|undefined>(undefined)

    if (selectedVulns.length == 0) {
        if (panelStatus) setPanelStatus(false)
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
                const response = await fetch(`/api/vulnerabilities/${encodeURIComponent(vuln)}/assessments`, {
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
                alert(`Failed to add assessment: ${e}`);
            }
            index++
            setProgressBar(index / selectedVulns.length)
        }

        if (errors.length >= 1) {
            alert(`Failed to add assessment: HTTP code ${errors.join(', ')}`);
        }
        assessments.forEach(appendAssessment)
        setProgressBar(undefined)
        setPanelStatus(false)
    };

    return (<>
        {selectedVulns.length >= 1 && <>
            {panelStatus && <div className="absolute top-0 left-0 right-0 bottom-0 z-30 bg-black/40"></div>}

            <div className="relative mb-4 p-2 z-40 bg-slate-600/70 text-white w-full flex flex-row items-center gap-2">
                <div>Selected vulnerabilities: {selectedVulns.length}</div>
                <button className="bg-sky-900 p-1 px-2 mr-4" onClick={resetVulns}>Reset selection</button>

                <button className="bg-sky-900 p-1 px-2" onClick={() => setPanelStatus(!panelStatus)}>Change status</button>
            </div>

            <div className={[
                'absolute z-40 p-4 bg-slate-700 shadow-md shadow-slate-500 top-48 left-32 w-1/2',
                panelStatus ? 'block' : 'hidden'
            ].join(' ')}>
                <StatusEditor onAddAssessment={(data) => addAssessment(data)} progressBar={progressBar} />
            </div>
        </>}
    </>);
}

export default MultiEditBar;

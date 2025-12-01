import { useState, useMemo } from "react";
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
    const [isLoading, setIsLoading] = useState<boolean>(false)

    if (selectedVulns.length == 0) {
        if (panelOpened) setPanelOpened(0)
        if (isLoading) setIsLoading(false)
    }

    // Get the status only if ALL selected vulnerabilities have the exact same status
    const uniformStatus = useMemo((): string | undefined => {
        if (selectedVulns.length === 0) return undefined;
        
        const selectedVulnerabilities = vulnerabilities.filter(vuln => selectedVulns.includes(vuln.id));
        if (selectedVulnerabilities.length === 0) return undefined;
        
        const firstStatus = selectedVulnerabilities[0].status;
        const allHaveSameStatus = selectedVulnerabilities.every(vuln => vuln.status === firstStatus);
        
        // Debug logging
        
        // Only return the status if ALL vulnerabilities have the same status
        return allHaveSameStatus ? firstStatus : undefined;
    }, [selectedVulns, vulnerabilities]);

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
        setIsLoading(true);

        // Prepare batch request payload
        const assessmentRequests = selectedVulns.map(vuln_id => ({
            vuln_id,
            packages: pkg_vulns[vuln_id] ?? [],
            status: content.status,
            status_notes: content.status_notes,
            justification: content.justification,
            impact_statement: content.impact_statement,
            workaround: content.workaround
        }));

        try {
            const response = await fetch(import.meta.env.VITE_API_URL + '/api/assessments/batch', {
                method: 'POST',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ assessments: assessmentRequests })
            });

            const data = await response.json().catch(() => ({}));
            
            if (data?.status === 'success' && Array.isArray(data?.assessments)) {
                // Process successful assessments
                for (const assessmentData of data.assessments) {
                    const casted = asAssessment(assessmentData);
                    if (!Array.isArray(casted) && typeof casted === "object") {
                        appendAssessment(casted);
                        
                        // Update the vulnerability
                        const vuln = vulnerabilities.find(v => v.id === casted.vuln_id);
                        if (vuln) {
                            vuln.assessments.push(casted);
                            vuln.status = casted.status;
                            vuln.simplified_status = casted.simplified_status;
                            patchVuln(casted.vuln_id, vuln);
                        }
                    }
                }

                const errorMsg = data.error_count ? ` (${data.error_count} failed)` : '';
                triggerBanner(`Successfully added assessments to ${data.count} vulnerabilities${errorMsg}`, 'success');
            } else {
                const errorMsg = data?.errors?.length 
                    ? `Errors: ${data.errors.map((e: {error?: string}) => e.error).join(', ')}`
                    : `HTTP ${response.status}`;
                triggerBanner(`Failed to add assessments: ${errorMsg}`, 'error');
            }
        } catch (e) {
            triggerBanner(`Failed to add assessments: ${e}`, 'error');
        }

        setIsLoading(false);
        setPanelOpened(0);
    };

    const saveTimeEstimation = async (content: PostTimeEstimate) => {
        setIsLoading(true);

        // Prepare batch request payload
        const vulnerabilityUpdates = selectedVulns.map(vuln_id => ({
            id: vuln_id,
            effort: {
                optimistic: content.optimistic.formatAsIso8601(),
                likely: content.likely.formatAsIso8601(),
                pessimistic: content.pessimistic.formatAsIso8601()
            }
        }));

        try {
            const response = await fetch(import.meta.env.VITE_API_URL + '/api/vulnerabilities/batch', {
                method: 'PATCH',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ vulnerabilities: vulnerabilityUpdates })
            });

            const data = await response.json().catch(() => ({}));

            if (data?.status === 'success' && Array.isArray(data?.vulnerabilities)) {
                // Process successful updates
                for (const vulnData of data.vulnerabilities) {
                    const vuln = vulnerabilities.find(v => v.id === vulnData.id);
                    if (vuln) {
                        if (typeof vulnData?.effort?.optimistic === "string")
                            vuln.effort.optimistic = new Iso8601Duration(vulnData.effort.optimistic);
                        if (typeof vulnData?.effort?.likely === "string")
                            vuln.effort.likely = new Iso8601Duration(vulnData.effort.likely);
                        if (typeof vulnData?.effort?.pessimistic === "string")
                            vuln.effort.pessimistic = new Iso8601Duration(vulnData.effort.pessimistic);
                        
                        patchVuln(vuln.id, vuln);
                    }
                }

                const errorMsg = data.error_count ? ` (${data.error_count} failed)` : '';
                triggerBanner(`Successfully updated time estimates for ${data.count} vulnerabilities${errorMsg}`, 'success');
            } else {
                const errorMsg = data?.errors?.length 
                    ? `Errors: ${data.errors.map((e: {error?: string}) => e.error).join(', ')}`
                    : `HTTP ${response.status}`;
                triggerBanner(`Failed to save time estimates: ${errorMsg}`, 'error');
            }
        } catch (e) {
            triggerBanner(`Failed to save time estimates: ${e}`, 'error');
        }

        setIsLoading(false);
        setPanelOpened(0);
    }

    return (<>
        {selectedVulns.length >= 1 && <>
            {panelOpened > 0 && <div className="absolute top-0 left-0 right-0 bottom-0 z-30 bg-black/40"></div>}
            
            {isLoading && (
                <div className="absolute top-0 left-0 right-0 bottom-0 z-50 bg-black/50 flex items-center justify-center">
                    <div className="animate-spin rounded-full h-16 w-16 border-t-4 border-b-4 border-sky-500"></div>
                </div>
            )}

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
                    progressBar={undefined}
                    defaultStatus={uniformStatus}
                />
            </div>

            <div className={[
                'absolute z-40 p-4 bg-slate-700 shadow-md shadow-slate-400/40 top-48 left-32 w-1/2',
                panelOpened == 2 ? 'block' : 'hidden'
            ].join(' ')}>
                <TimeEstimateEditor
                    onSaveTimeEstimation={(data) => saveTimeEstimation(data)}
                    progressBar={undefined}
                    actualEstimate={{optimistic: '', likely: '', pessimistic: ''}}
                />
            </div>
        </>}
    </>);
}

export default MultiEditBar;

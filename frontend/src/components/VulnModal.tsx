import type { Vulnerability } from "../handlers/vulnerabilities";
import type { CVSS } from "../handlers/vulnerabilities";
import type { Assessment } from "../handlers/assessments";
import { asAssessment } from "../handlers/assessments";
import { escape } from "lodash-es";
import CvssGauge from "./CvssGauge";
import CustomCvss from "./CustomCvss";
import SeverityTag from "./SeverityTag";
import StatusEditor from "./StatusEditor";
import type { PostAssessment } from './StatusEditor';
import TimeEstimateEditor from "./TimeEstimateEditor";
import type { PostTimeEstimate } from "./TimeEstimateEditor";
import Iso8601Duration from '../handlers/iso8601duration';
import ConfirmationModal from "./ConfirmationModal";
import { useState, useEffect } from "react";

type Props = {
    vuln: Vulnerability;
    onClose: () => void;
    appendAssessment: (added: Assessment) => void;
    appendCVSS: (vulnId: string, vector: string) => CVSS | null;
    patchVuln: (vulnId: string, replace_vuln: Vulnerability) => void;
};

const dt_options: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: 'numeric',
    minute: 'numeric',
    timeZoneName: 'shortOffset'
};
  function VulnModal(props: Readonly<Props>) {
    const { vuln, onClose, appendAssessment, appendCVSS, patchVuln } = props;
    const [showCustomCvss, setShowCustomCvss] = useState(false);
    const [clearTimeFields, setClearTimeFields] = useState(false);
    const [clearAssessmentFields, setClearAssessmentFields] = useState(false);
    const [showConfirmClose, setShowConfirmClose] = useState(false);

    const [hasTimeChanges, setHasTimeChanges] = useState(false);
    const [hasAssessmentChanges, setHasAssessmentChanges] = useState(false);
    const hasUnsavedChanges = hasTimeChanges || hasAssessmentChanges;

    const handleClose = () => {
        if (hasUnsavedChanges) {
            setShowConfirmClose(true);
        } else {
            onClose();
        }
    };

    const handleConfirmClose = () => {
        setShowConfirmClose(false);
        onClose();
    };

    const handleCancelClose = () => {
        setShowConfirmClose(false);
    };

    // Handle ESC key press
    useEffect(() => {
        const handleKeyDown = (event: KeyboardEvent) => {
            if (event.key === 'Escape') {
                event.preventDefault();
                if (hasUnsavedChanges) {
                    setShowConfirmClose(true);
                } else {
                    onClose();
                }
            }
        };

        document.addEventListener('keydown', handleKeyDown);
        return () => {
            document.removeEventListener('keydown', handleKeyDown);
        };
    }, [hasUnsavedChanges, onClose]);

    const addAssessment = async (content: PostAssessment) => {
        content.vuln_id = vuln.id
        content.packages = vuln.packages

        const response = await fetch(import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(vuln.id)}/assessments`, {
            method: 'POST',
            mode: 'cors',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(content)
        })
        const data = await response.json()
        if (data?.status === 'success') {
            const casted = asAssessment(data?.assessment);
            if (!Array.isArray(casted) && typeof casted === "object") {
                appendAssessment(casted);
                vuln.assessments.push(casted);
                patchVuln(vuln.id, vuln);
                alert("Successfully added assessment.");
                setClearAssessmentFields(true);
                setTimeout(() => setClearAssessmentFields(false), 100);
            }
        } else {
            alert(`Failed to add assessment: HTTP code ${Number(response?.status)} | ${escape(JSON.stringify(data))}`);
        }
    };

    const addCvss = async (vector: string) => {
        const content = appendCVSS(vuln.id, vector);

        if (content === null) {
            alert("The vector string is invalid, please check the format.");
            return;
        }


        const response = await fetch(import.meta.env.VITE_API_URL + `/api/vulnerabilities/${encodeURIComponent(vuln.id)}`, {
            method: 'PATCH',
            mode: 'cors',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                cvss: content
            })
        });

        if (response.status == 200) {
            const data = await response.json();

            if (Array.isArray(data?.severity?.cvss)) {
                vuln.severity.cvss = data.severity.cvss;
            }

            patchVuln(vuln.id, vuln);
            setShowCustomCvss(false);
            alert("successfully added Custom CVSS.");
        } else {
            const data = await response.text();
            console.error("API error response:", response.status, data);
            alert(`Failed to save CVSS: HTTP code ${Number(response?.status)} | ${escape(data)}`);
        }
    };

    const saveEstimation = async (content: PostTimeEstimate) => {
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

            patchVuln(vuln.id, vuln);
            setClearTimeFields(true);
            setTimeout(() => setClearTimeFields(false), 100);
            alert("Successfully added estimation.");
        } else {
            const data = await response.text();
            alert(`Failed to save estimation: HTTP code ${Number(response?.status)} | ${escape(data)}`);
        }
    };

    return (
        <div
            tabIndex={-1}
            className="overflow-x-hidden fixed top-0 right-0 left-0 z-50 justify-center items-center w-full md:inset-0 h-full max-h-full bg-gray-900/90"
        >
            <div className="relative p-16 h-full">
                <div className="relative rounded-lg shadow bg-gray-700 h-full overflow-y-auto">

                    {/* Modal header */}
                    <div className="flex items-center justify-between p-4 md:p-5 border-b rounded-t dark:border-gray-600">
                        <h3 id="vulnerability_modal_title" className="text-xl font-semibold text-gray-900 dark:text-white">
                            {vuln.id}
                        </h3>
                        <button
                            onClick={handleClose}
                            type="button"
                            className="text-gray-400 bg-transparent hover:bg-gray-200 hover:text-gray-900 rounded-lg text-sm w-8 h-8 ms-auto inline-flex justify-center items-center dark:hover:bg-gray-600 dark:hover:text-white"
                        >
                            <svg className="w-3 h-3" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 14 14">
                                <path stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="m1 1 6 6m0 0 6 6M7 7l6-6M7 7l-6 6"/>
                            </svg>
                            <span className="sr-only">Close modal</span>
                        </button>
                    </div>

                    {/* Modal body */}
                    <div className="p-4 md:p-5 space-y-4 text-gray-300 text-justify" id="vulnerability_modal_body">

                        <div className="flex flex-row">
                            <ul className="grow leading-6">
                                <li key="severity">
                                    <span className="font-bold mr-1">Severity:</span>
                                    <SeverityTag severity={vuln.severity.severity} className="text-white" />
                                </li>
                                {vuln.epss?.score && <li key="epss">
                                    <span className="font-bold mr-1">Exploitability (EPSS):</span>
                                    <b>{Number(vuln.epss.score * 100).toFixed(2)} %</b>
                                    {vuln.epss.percentile && <i className="text-sm">(more than {Math.floor(vuln.epss.percentile * 100)}% of vulns)</i>}
                                </li>}
                                <li key="sources">
                                    <span className="font-bold mr-1">Found by:</span>
                                    {vuln.found_by.join(', ')}
                                </li>
                                <li key="status">
                                    <span className="font-bold mr-1">Status:</span>
                                    {vuln.simplified_status}
                                </li>
                                <li key="packages">
                                    <span className="font-bold mr-1">Affects:</span>
                                    <code>{vuln.packages.join(', ')}</code>
                                </li>
                                <li key="aliases">
                                    <span className="font-bold mr-1">Aliases:</span>
                                    <code>{vuln.aliases.join(', ')}</code>
                                </li>
                                <li key="related_vulns">
                                    <span className="font-bold mr-1">Related vulnerabilities:</span>
                                    <code>{vuln.related_vulnerabilities.join(', ')}</code>
                                </li>
                            </ul>

                            <div className="ml-4">
                                <div className="flex justify-between items-center mb-2">
                                    <h3 className="text-lg font-bold text-white">CVSS</h3>
                                    <div className="relative">
                                    <button
                                        onClick={() => setShowCustomCvss(!showCustomCvss)}
                                        className="ml-2 px-3 py-1 text-sm rounded-lg bg-sky-600 hover:bg-sky-700 text-white"
                                    >
                                        Add Custom
                                    </button>

                                    {showCustomCvss && (
                                        <div className="absolute right-0 mt-2 z-50 w-64">
                                        <CustomCvss
                                            onCancel={() => setShowCustomCvss(false)}
                                            onAddCvss={(vector) => {
                                                addCvss(vector);
                                            }}
                                        />
                                        </div>
                                    )}
                                    </div>
                                </div>

                                <div className="flex flex-wrap gap-2">
                                    {vuln.severity.cvss.map((cvss) => (
                                    <div
                                        key={encodeURIComponent(
                                        `${cvss.author}-${cvss.version}-${cvss.base_score}`
                                        )}
                                        className="bg-gray-800 p-2 rounded-xl flex-1 min-w-[150px]"
                                    >
                                        <h3 className="text-center font-bold">CVSS {cvss.version}</h3>
                                        <CvssGauge data={cvss} />
                                    </div>
                                    ))}
                                </div>
                            </div>

                        </div>

                        {vuln.texts.map((text) => {
                            const title = text.title.split('');
                            return (<div key={encodeURIComponent(text.title)}>
                                <h3 className="font-bold">{title?.shift()?.toLocaleUpperCase()}{title.join('')}</h3>
                                <p className="leading-relaxed bg-gray-800 p-2 px-4 rounded-lg whitespace-pre-line">{text.content}</p>
                            </div>)
                        })}

                        <h3 className="font-bold">Links</h3>
                        <ul>
                            {[...new Set([vuln.datasource, ...vuln.urls])].map(url => (
                                <li key={encodeURIComponent(url)}><a className="underline" href={encodeURI(url)} target="_blank">{url}</a></li>
                            ))}
                        </ul>

                        <TimeEstimateEditor
                            progressBar={undefined}
                            onSaveTimeEstimation={(data) => saveEstimation(data)}
                            clearFields={clearTimeFields}
                            onFieldsChange={setHasTimeChanges}
                            actualEstimate={{
                                optimistic: vuln?.effort?.optimistic?.formatHumanShort(),
                                likely: vuln?.effort?.likely?.formatHumanShort(),
                                pessimistic: vuln?.effort?.pessimistic?.formatHumanShort(),
                            }}
                        />

                        <h3 className="font-bold">Assessments</h3>
                        <ol className="relative border-s border-gray-800">

                            {vuln.assessments.map(assess => {
                                const dt = new Date(assess.timestamp);
                                return (
                                    <li key={encodeURIComponent(assess.id)} className="mb-10 ms-4">
                                        <div className="absolute w-3 h-3 bg-gray-200 rounded-full mt-1.5 -start-1.5 border border-gray-800 bg-gray-800"></div>
                                        <time className="mb-1 text-sm font-normal leading-none text-gray-400">{dt.toLocaleString(undefined, dt_options)}</time>
                                        <div className="text-sm mb-2">
                                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300">
                                                {assess.packages}
                                            </span>
                                        </div>
                                        <h3 className="text-lg font-semibold text-white mb-2">
                                            {assess.simplified_status}{assess.justification && <> - {assess.justification}</>}
                                        </h3>
                                        <p className="text-base font-normal text-gray-300">
                                            {assess.impact_statement && <>{assess.impact_statement}<br/></>}
                                            {!assess.impact_statement && assess.status == 'not_affected' && <>no impact statement<br/></>}
                                            {assess.status_notes ?? 'no status notes'}<br/>
                                            {assess.workaround ?? 'no workaround available'}
                                        </p>
                                    </li>
                                );
                            })}

                            <li className="ms-4 text-white">
                                <div className="absolute w-3 h-3 bg-gray-200 rounded-full mt-1.5 -start-1.5 border border-sky-500 bg-sky-500"></div>
                                <time className="mb-1 text-sm font-normal leading-none text-gray-400">Add a new assessment</time>
                                <StatusEditor 
                                    onAddAssessment={(data) => addAssessment(data)} 
                                    clearFields={clearAssessmentFields}
                                    onFieldsChange={setHasAssessmentChanges} 
                                />
                            </li>
                        </ol>
                    </div>

                    {/* Modal footer */}
                    <div className="flex items-center p-4 md:p-5 border-t border-gray-200 rounded-b dark:border-gray-600">
                        <button
                            onClick={handleClose}
                            type="button"
                            className="py-2.5 px-5 ms-3 text-sm font-medium text-gray-400 focus:outline-none rounded-lg border border-gray-600 hover:bg-gray-700 hover:text-white focus:z-10 focus:ring-4 focus:ring-gray-700 bg-gray-800"
                        >
                            Close
                        </button>
                    </div>

                </div>
            </div>

            <ConfirmationModal
                isOpen={showConfirmClose}
                title="Unsaved Changes"
                message="Are you sure you want to close without saving? All unsaved changes will be lost."
                confirmText="Yes, close"
                cancelText="No, stay"
                showTitleIcon={true}
                onConfirm={handleConfirmClose}
                onCancel={handleCancelClose}
            />
        </div>
    );
}

export default VulnModal;

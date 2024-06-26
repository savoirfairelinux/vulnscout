import type { Vulnerability } from "../handlers/vulnerabilities";
import type { Assessment } from "../handlers/assessments";
import Assessments from "../handlers/assessments";
import { useState } from "react";
import CvssGauge from "./CvssGauge";
import SeverityTag from "./SeverityTag";

type Props = {
    vuln: Vulnerability;
    onClose: () => void;
    appendAssessment: (added: Assessment) => void;
};

type PostAssessment = {
    vuln_id: String,
    packages: String[],
    status: String,
    justification?: String,
    impact_statement?: String,
    status_notes?: String,
    workaround?: String
}

const dt_options: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: 'numeric',
    minute: 'numeric',
    timeZoneName: 'shortOffset'
};

function VulnModal(props: Props) {
  const { vuln, onClose, appendAssessment } = props;

  const [new_status, set_new_status] = useState("under_investigation");
  const [new_justification, set_new_justification] = useState("none");
  const [new_status_notes, set_new_status_notes] = useState("");
  const [new_workaround, set_new_workaround] = useState("");
  const [new_impact, set_new_impact] = useState("");


  const addAssessment = async () => {
    if (new_status == '' || new_justification == '')
        return;
    let content: PostAssessment = {
        vuln_id: vuln.id,
        packages: vuln.packages,
        status: new_status,
        impact_statement: new_status == "not_affected" ? new_impact : undefined,
        status_notes: new_status_notes,
        workaround: new_workaround
    }
    if (new_status == "not_affected") {
        if (new_justification != 'none') {
            content.justification = new_justification;
        } else {
            alert("You must provide a justification for this status");
            return;
        }
    }

    const response = await fetch(`/api/vulnerabilities/${vuln.id}/assessments`, {
        method: 'POST',
        mode: 'cors',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(content)
    })
    const data = await response.json()
    if (data.status == 'success') {
        appendAssessment(Assessments.from_json(data.assessment));
        onClose();
    } else {
        alert(`Failed to add assessment: HTTP code ${response.status} | ${JSON.stringify(data)}`);
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
                        onClick={onClose}
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
                            <li key="sources">
                                <span className="font-bold mr-1">Found by:</span>
                                {vuln.found_by}
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
                        {vuln.severity.cvss.map((cvss, ind) => (
                            <div key={ind} className="bg-gray-800 p-2 rounded-xl flex-initial ml-4">
                                <h3 className="text-center font-bold">CVSS {cvss.version}</h3>
                                <CvssGauge data={cvss} />
                            </div>
                        ))}
                    </div>

                    {vuln.texts.map((text) => {
                        const title = text.title.split('');
                        return (<div key={text.title}>
                            <h3 className="font-bold">{title?.shift()?.toLocaleUpperCase()}{title.join('')}</h3>
                            <p className="leading-relaxed bg-gray-800 p-2 px-4 rounded-lg">{text.content}</p>
                        </div>)
                    })}

                    <h3 className="font-bold">Links</h3>
                    <ul>
                        {[...new Set([vuln.datasource, ...vuln.urls])].map(url => (
                            <li key={url}><a className="underline" href={url} target="_blank">{url}</a></li>
                        ))}
                    </ul>

                    <h3 className="font-bold">Assessments</h3>
                    <ol className="relative border-s border-gray-800">

                        {vuln.assessments.map(assess => {
                            const dt = new Date(assess.timestamp);
                            return (
                                <li key={assess.id} className="mb-10 ms-4">
                                    <div className="absolute w-3 h-3 bg-gray-200 rounded-full mt-1.5 -start-1.5 border border-gray-800 bg-gray-800"></div>
                                    <time className="mb-1 text-sm font-normal leading-none text-gray-400">{dt.toLocaleString(undefined, dt_options)}</time>
                                    <h3 className="text-lg font-semibold text-white">
                                        {assess.simplified_status}{assess.justification && <> - {assess.justification}</>}
                                    </h3>
                                    <p className="text-base font-normal text-gray-300">
                                        {assess.impact_statement && <>{assess.impact_statement}<br/></>}
                                        {!assess.impact_statement && assess.status == 'not_affected' && <>no impact statement<br/></>}
                                        {assess.status_notes || 'no status notes'}<br/>
                                        {assess.workaround || 'no workaround available'}
                                    </p>
                                </li>
                            );
                        })}

                        <li className="ms-4 text-white">
                            <div className="absolute w-3 h-3 bg-gray-200 rounded-full mt-1.5 -start-1.5 border border-sky-500 bg-sky-500"></div>
                            <time className="mb-1 text-sm font-normal leading-none text-gray-400">Add a new assessment</time>
                            <h3 className="m-1">
                                Status:
                                <select
                                    onChange={(event) => set_new_status(event.target.value)}
                                    className="p-1 px-2 bg-gray-800 mr-4"
                                    name="new_assessment_status"
                                >
                                    <option value="under_investigation">Pending Analysis</option>
                                    <option value="affected">Affected / Exploitable</option>
                                    <option value="fixed">Fixed / Patched</option>
                                    <option value="not_affected">Not applicable</option>
                                    <option value="false_positive">Faux positif</option>
                                </select>
                                {new_status == "not_affected" && <>
                                    Justification:
                                    <select
                                        onChange={(event) => set_new_justification(event.target.value)}
                                        className="p-1 px-2 bg-gray-800"
                                        name="new_assessment_justification"
                                    >
                                        <option value="none">No justification</option>
                                        <option value="component_not_present">Component not present</option>
                                        <option value="vulnerable_code_not_present">vulnerable code not present</option>
                                        <option value="code_not_reachable">The vulnerable code is not invoked at runtime</option>
                                        <option value="requires_configuration">Exploitability requires a configurable option to be set/unset</option>
                                        <option value="requires_environment">Exploitability requires a certain environment which is not present</option>
                                        <option value="inline_mitigations_already_exist">Inline Mitigation already exist</option>
                                    </select>
                                </>}
                            </h3>
                            {(new_status == "not_affected" || new_status == "false_positive") && <>
                                <input
                                    onInput={(event: React.ChangeEvent<HTMLInputElement>) => set_new_impact(event.target.value)}
                                    name="new_assessment_impact"
                                    className="bg-gray-800 m-1 p-1 px-2 min-w-[50%] placeholder:text-slate-400"
                                    type="text"
                                    placeholder="why this vulnerability is not exploitable ?"
                                /><br/>
                            </>}
                            <input
                                onInput={(event: React.ChangeEvent<HTMLInputElement>) => set_new_status_notes(event.target.value)}
                                name="new_assessment_status_notes"
                                className="bg-gray-800 m-1 p-1 px-2 min-w-[50%] placeholder:text-slate-400"
                                type="text"
                                placeholder="Free text notes about your review, details, actions taken, ..."
                            /><br/>
                            <input
                                onInput={(event: React.ChangeEvent<HTMLInputElement>) => set_new_workaround(event.target.value)}
                                name="new_assessment_workaround"
                                className="bg-gray-800 m-1 p-1 px-2 min-w-[50%] placeholder:text-slate-400 text-white"
                                type="text"
                                placeholder="Describe workaround here if available"
                            /><br/>
                            <button
                                onClick={addAssessment}
                                type="button"
                                className="mt-2 bg-blue-600 hover:bg-blue-700 focus:ring-4 focus:outline-none focus:ring-blue-800 font-medium rounded-lg px-4 py-2 text-center"
                            >Add assessment</button>
                        </li>
                    </ol>
				</div>

				{/* Modal footer */}
				<div className="flex items-center p-4 md:p-5 border-t border-gray-200 rounded-b dark:border-gray-600">
					<button
                        onClick={onClose}
                        type="button"
                        className="py-2.5 px-5 ms-3 text-sm font-medium text-gray-400 focus:outline-none rounded-lg border border-gray-600 hover:bg-gray-700 hover:text-white focus:z-10 focus:ring-4 focus:ring-gray-700 bg-gray-800"
                    >
                        Close
                    </button>
				</div>

            </div>
        </div>
    </div>
  );
}

export default VulnModal;

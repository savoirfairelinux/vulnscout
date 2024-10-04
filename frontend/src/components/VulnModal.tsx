import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCircleQuestion } from '@fortawesome/free-regular-svg-icons';
import type { Vulnerability } from "../handlers/vulnerabilities";
import type { Assessment } from "../handlers/assessments";
import { asAssessment } from "../handlers/assessments";
import { useState } from "react";
import { escape } from "lodash-es";
import CvssGauge from "./CvssGauge";
import SeverityTag from "./SeverityTag";
import StatusEditor from "./StatusEditor";
import type { PostAssessment } from './StatusEditor';
import Iso8601Duration from '../handlers/iso8601duration';

type Props = {
    vuln: Vulnerability;
    onClose: () => void;
    appendAssessment: (added: Assessment) => void;
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
    const { vuln, onClose, appendAssessment, patchVuln } = props;

    const [estimateHelp, setEstimateHelp] = useState(false);
    const [newOptimistic, setNewOptimistic] = useState("");
    const [newLikely, setNewLikely] = useState("");
    const [newPessimistic, setNewPessimistic] = useState("");


    const addAssessment = async (content: PostAssessment) => {
        content.vuln_id = vuln.id
        content.packages = vuln.packages

        const response = await fetch(`/api/vulnerabilities/${encodeURIComponent(vuln.id)}/assessments`, {
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
            if (!Array.isArray(casted) && typeof casted === "object")
                appendAssessment(casted);
            onClose();
        } else {
            alert(`Failed to add assessment: HTTP code ${Number(response?.status)} | ${escape(JSON.stringify(data))}`);
        }
    };

    const saveEstimation = async () => {
        let content: {
            optimistic?: Iso8601Duration,
            likely?: Iso8601Duration,
            pessimistic?: Iso8601Duration
        } = {};
        try {
            content.optimistic = new Iso8601Duration(newOptimistic);
            content.likely = new Iso8601Duration(newLikely);
            content.pessimistic = new Iso8601Duration(newPessimistic);

            if(content.optimistic.total_seconds <= 0)
                throw new Error('Invalid optimistic duration, must be strictly positive');
            if(content.likely.total_seconds <= 0)
                throw new Error('Invalid likely duration, must be strictly positive');
            if(content.pessimistic.total_seconds <= 0)
                throw new Error('Invalid pessimistic duration, must be strictly positive');
            if(content.optimistic.total_seconds > content.likely.total_seconds)
                throw new Error('Optimistic duration must be lower than likely duration');
            if(content.likely.total_seconds > content.pessimistic.total_seconds)
                throw new Error('Likely duration must be lower than pessimistic duration');
        } catch (e) {
            alert(`Failed to parse estimation: ${escape(String(e))}`);
            return;
        }

        const response = await fetch(`/api/vulnerabilities/${encodeURIComponent(vuln.id)}`, {
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
            onClose();
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
                                {vuln.epss?.score && <li key="epss">
                                    <span className="font-bold mr-1">Exploitability:</span>
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
                            {vuln.severity.cvss.map((cvss) => (
                                <div key={encodeURIComponent(`${cvss.author}-${cvss.version}-${cvss.base_score}`)} className="bg-gray-800 p-2 rounded-xl flex-initial ml-4">
                                    <h3 className="text-center font-bold">CVSS {cvss.version}</h3>
                                    <CvssGauge data={cvss} />
                                </div>
                            ))}
                        </div>

                        {vuln.texts.map((text) => {
                            const title = text.title.split('');
                            return (<div key={encodeURIComponent(text.title)}>
                                <h3 className="font-bold">{title?.shift()?.toLocaleUpperCase()}{title.join('')}</h3>
                                <p className="leading-relaxed bg-gray-800 p-2 px-4 rounded-lg">{text.content}</p>
                            </div>)
                        })}

                        <h3 className="font-bold">Links</h3>
                        <ul>
                            {[...new Set([vuln.datasource, ...vuln.urls])].map(url => (
                                <li key={encodeURIComponent(url)}><a className="underline" href={encodeURI(url)} target="_blank">{url}</a></li>
                            ))}
                        </ul>

                        <h3 className="font-bold">Estimated efforts to fix</h3>
                        <div className="flex flex-row space-x-4 max-w-[900px]">
                            <div className="flex-1">
                                <h4 className="font-bold">Optimistic</h4>
                                <p>{vuln.effort?.optimistic?.formatHumanShort() || "not defined"}</p>
                                <input
                                    onInput={(event: React.ChangeEvent<HTMLInputElement>) => setNewOptimistic(event.target.value)}
                                    type="text"
                                    className="bg-gray-800 m-1 w-full p-1 px-2 placeholder:text-slate-400"
                                    placeholder="shortest estimate [eg: 5h]"
                                />
                            </div>
                            <div className="flex-1">
                                <h4 className="font-bold">Most Likely</h4>
                                <p>{vuln.effort?.likely?.formatHumanShort() || "not defined"}</p>
                                <input
                                    onInput={(event: React.ChangeEvent<HTMLInputElement>) => setNewLikely(event.target.value)}
                                    type="text"
                                    className="bg-gray-800 m-1 w-full p-1 px-2 placeholder:text-slate-400"
                                    placeholder="balanced estimate [eg: 2d 4h, or 2.5d]"
                                />
                            </div>
                            <div className="flex-1">
                                <h4 className="font-bold">Pessimistic</h4>
                                <p>{vuln.effort?.pessimistic?.formatHumanShort() || "not defined"}</p>
                                <input
                                    onInput={(event: React.ChangeEvent<HTMLInputElement>) => setNewPessimistic(event.target.value)}
                                    type="text"
                                    className="bg-gray-800 m-1 w-full p-1 px-2 placeholder:text-slate-400"
                                    placeholder="longest estimate [eg: 1w]"
                                />
                            </div>
                            <div>
                                <button type='button' className='pt-8 pl-2 hover:text-blue-400' onClick={() => setEstimateHelp(!estimateHelp)}>
                                    <FontAwesomeIcon icon={faCircleQuestion} size='xl' className='pr-2' />
                                    Show help
                                </button>
                            </div>
                        </div>
                        {estimateHelp && <div className="m-2 p-2 rounded-lg bg-gray-800/70 border-2 border-gray-800">
                            We follow the same time scale as Gitlab, which count only worked days.<br/>
                            When estimating a task to 12h, it's in fact 1 day (8h) and a half (4h).<br/>
                            Time scale: 1 month = 4 weeks; 1 week = 5 days = 40 hours.<br/>
                            <b>Tips:</b><br/>
                            You can enter duration as days of work without units (eg: 1 or 2.5).<br/>
                            You can also use following units for duration: h[ours], d[ays], w[weeks], m[onths], y[ears] (eg: 5h, 3d, 1w, 0.5m, 2y).<br/>
                            Finaly, you can enter ISO 8601 duration format (eg: P1DT12H, P2W, P3M, PT5H).
                        </div>}
                        <div className="pb-2 text-white font-medium">
                            <button
                                onClick={saveEstimation}
                                type="button"
                                className="bg-blue-600 hover:bg-blue-700 focus:ring-4 focus:outline-none focus:ring-blue-800 rounded-lg px-4 py-2 text-center"
                            >Save estimation</button>
                        </div>

                        <h3 className="font-bold">Assessments</h3>
                        <ol className="relative border-s border-gray-800">

                            {vuln.assessments.map(assess => {
                                const dt = new Date(assess.timestamp);
                                return (
                                    <li key={encodeURIComponent(assess.id)} className="mb-10 ms-4">
                                        <div className="absolute w-3 h-3 bg-gray-200 rounded-full mt-1.5 -start-1.5 border border-gray-800 bg-gray-800"></div>
                                        <time className="mb-1 text-sm font-normal leading-none text-gray-400">{dt.toLocaleString(undefined, dt_options)}</time>
                                        <h3 className="text-lg font-semibold text-white">
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
                                <StatusEditor onAddAssessment={(data) => addAssessment(data)} />
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

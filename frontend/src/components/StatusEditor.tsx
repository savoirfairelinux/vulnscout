import { useState } from "react";

type PostAssessment = {
    vuln_id?: string,
    packages?: string[],
    status: string,
    justification?: string,
    impact_statement?: string,
    status_notes?: string,
    workaround?: string
}

type Props = {
    onAddAssessment: (data: PostAssessment) => void;
    progressBar?: number;
}

function StatusEditor ({onAddAssessment, progressBar}: Readonly<Props>) {
    const [status, setStatus] = useState("under_investigation");
    const [justification, setJustification] = useState("none");
    const [statusNotes, setStatusNotes] = useState("");
    const [workaround, setWorkaround] = useState("");
    const [impact, setImpact] = useState("");

    function addAssessment () {
        if (status == '' || justification == '')
            return;
        if (status == "not_affected" && justification == 'none') {
            alert("You must provide a justification for this status");
            return;
        }
        onAddAssessment({
            status,
            justification: status == "not_affected" ? justification : undefined,
            status_notes: statusNotes,
            workaround,
            impact_statement: status == "not_affected" ? impact : undefined
        });
    }

    return (<>
        <h3 className="m-1">
            Status:
            <select
                onChange={(event) => setStatus(event.target.value)}
                className="p-1 px-2 bg-gray-800 mr-4"
                name="new_assessment_status"
            >
                <option value="under_investigation">Pending Analysis</option>
                <option value="affected">Affected / Exploitable</option>
                <option value="fixed">Fixed / Patched</option>
                <option value="not_affected">Not applicable</option>
                <option value="false_positive">False positive</option>
            </select>
            {status == "not_affected" && <>
                Justification:
                <select
                    onChange={(event) => setJustification(event.target.value)}
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
        {(status == "not_affected" || status == "false_positive") && <>
            <input
                onInput={(event: React.ChangeEvent<HTMLInputElement>) => setImpact(event.target.value)}
                name="new_assessment_impact"
                className="bg-gray-800 m-1 p-1 px-2 min-w-[50%] placeholder:text-slate-400"
                type="text"
                placeholder="why this vulnerability is not exploitable ?"
            /><br/>
        </>}
        <input
            onInput={(event: React.ChangeEvent<HTMLInputElement>) => setStatusNotes(event.target.value)}
            name="new_assessment_status_notes"
            className="bg-gray-800 m-1 p-1 px-2 min-w-[50%] placeholder:text-slate-400"
            type="text"
            placeholder="Free text notes about your review, details, actions taken, ..."
        /><br/>
        <input
            onInput={(event: React.ChangeEvent<HTMLInputElement>) => setWorkaround(event.target.value)}
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

        {progressBar !== undefined && <div className="p-4 pb-1 w-full">
             <progress max={1} value={progressBar} className="w-full h-2"></progress>
        </div>}
    </>);
}

export default StatusEditor

export type {PostAssessment}

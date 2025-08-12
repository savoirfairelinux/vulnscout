const STATUS_VEX_TO_GRAPH: { [key: string]: string } = {
    "under_investigation": "Community Analysis Pending",
    "in_triage": "Community Analysis Pending",
    "false_positive": "not affected",
    "not_affected": "not affected",
    "exploitable": "active",
    "affected": "active",
    "resolved": "fixed",
    "fixed": "fixed",
    "resolved_with_pedigree": "fixed"
};

type Assessment = {
    id: string;
    vuln_id: string;
    packages: string[];
    status: string;
    simplified_status: string;
    status_notes?: string;
    justification?: string;
    impact_statement?: string;
    workaround?: string;
    workaround_timestamp?: string;
    timestamp: string;
    last_update?: string;
    responses: string[];
};

export type { Assessment };

const asStringArray = (data: any): string[] => {
    if (!Array.isArray(data)) return [];
    return data.filter((item: any) => typeof item === "string");
}

const asAssessment = (data: any): Assessment | [] => {
    if (typeof data !== "object") return [];
    if (typeof data?.id !== "string") return [];
    if (typeof data?.vuln_id !== "string") return [];
    if (typeof data?.status !== "string") return [];
    if (typeof data?.timestamp !== "string") return [];
    let item: Assessment = {
        id: data.id,
        vuln_id: data.vuln_id,
        packages: asStringArray(data?.packages),
        status: data.status,
        simplified_status: `[invalid status] ${data.status}`,
        status_notes: undefined,
        justification: undefined,
        impact_statement: undefined,
        workaround: undefined,
        workaround_timestamp: undefined,
        timestamp: data.timestamp,
        last_update: undefined,
        responses: asStringArray(data?.responses),
    };
    if (typeof STATUS_VEX_TO_GRAPH?.[data.status] === "string")
        item.simplified_status = STATUS_VEX_TO_GRAPH[data.status];
    if (typeof data?.status_notes === "string") item.status_notes = data.status_notes;
    if (typeof data?.justification === "string") item.justification = data.justification;
    if (typeof data?.impact_statement === "string") item.impact_statement = data.impact_statement;
    if (typeof data?.workaround === "string") item.workaround = data.workaround;
    if (typeof data?.workaround_timestamp === "string") item.workaround_timestamp = data.workaround_timestamp;
    if (typeof data?.last_update === "string") item.last_update = data.last_update;
    return item
}

class Assessments {
    /**
     * Fetch server API to list all packages
     * @returns {Promise<Assessment[]>} A promise that resolves to a list of packages
     */
    static async list(): Promise<Assessment[]> {
        const response = await fetch(import.meta.env.VITE_API_URL + "/api/assessments?format=list", {
            mode: "cors",
        });
        const data = await response.json();
        return data.flatMap(asAssessment);
    }
}

export default Assessments;
export { STATUS_VEX_TO_GRAPH, asStringArray, asAssessment };

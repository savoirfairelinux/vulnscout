const STATUS_VEX_TO_GRAPH: { [key: string]: string } = {
    "under_investigation": "pending analysis",
    "in_triage": "pending analysis",
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
        return data.map(Assessments.from_json);
    }

    static from_json(data: Assessment): Assessment {
        return {
            ...data,
            simplified_status: STATUS_VEX_TO_GRAPH[data.status] || '[invalid status] '+data.status,
        };
    }
}

export default Assessments;
export { STATUS_VEX_TO_GRAPH };

import type { Assessment } from "./assessments";
import { asStringArray } from "./assessments";
import Iso8601Duration from "./iso8601duration";

type CVSS = {
    author: string;
    severity: string;
    version: string;
    vector_string: string;
    base_score: number;
    exploitability_score: number;
    impact_score: number;
};

type Vulnerability = {
    id: string;
    aliases: string[];
    related_vulnerabilities: string[];
    namespace: string;
    found_by: string[];
    datasource: string;
    packages: string[];
    urls: string[];
    texts: {
        title: string;
        content: string;
    }[];
    severity: {
        severity: string;
        min_score: number;
        max_score: number;
        cvss: CVSS[];
    };
    epss: {
        score: number | undefined;
        percentile: number | undefined;
    };
    effort: {
        optimistic: Iso8601Duration;
        likely: Iso8601Duration;
        pessimistic: Iso8601Duration;
    };
    fix: {
        state: string;
    };
    status: string;
    simplified_status: string;
    assessments: Assessment[];
};

export type { Vulnerability, CVSS };

const SEVERITY_ORDER = ['NONE', 'UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

const asCVSS = (data: any): CVSS | [] => {
    if (typeof data !== "object") return [];
    if (typeof data?.version !== "string") return [];
    if (typeof data?.base_score !== "number") return [];
    let score: CVSS = {
        author: "unknown",
        severity: "unknown",
        version: data.version,
        vector_string: "",
        base_score: Number(data.base_score),
        exploitability_score: 0,
        impact_score: 0,
    };
    if (typeof data?.author === "string") score.author = data.author
    if (typeof data?.severity === "string") score.severity = data.severity
    if (typeof data?.vector_string === "string") score.vector_string = data.vector_string
    if (typeof data?.exploitability_score === "number") score.exploitability_score = Number(data.exploitability_score)
    if (typeof data?.impact_score === "number") score.impact_score = Number(data.impact_score)
    return score
}

const asVulnerability = (data: any): Vulnerability | [] => {
    if (typeof data !== "object") return [];
    if (typeof data?.id !== "string") return [];
    let vuln: Vulnerability = {
        id: data.id,
        aliases: asStringArray(data?.aliases),
        related_vulnerabilities: asStringArray(data?.related_vulnerabilities),
        namespace: "unknown",
        found_by: asStringArray(data?.found_by),
        datasource: "unknown",
        packages: asStringArray(data?.packages),
        urls: asStringArray(data?.urls),
        texts: [],
        severity: {
            severity: "unknown",
            min_score: 0,
            max_score: 0,
            cvss: [],
        },
        epss: {
            score: undefined,
            percentile: undefined,
        },
        effort: {
            optimistic: new Iso8601Duration("P0D"),
            likely: new Iso8601Duration("P0D"),
            pessimistic: new Iso8601Duration("P0D"),
        },
        fix: {
            state: "unknown",
        },
        status: 'unknown',
        simplified_status: 'unknown',
        assessments: [],
    };
    if (typeof data?.namespace === "string") vuln.namespace = data.namespace
    if (typeof data?.datasource === "string") vuln.datasource = data.datasource
    if (typeof data?.texts === "object")
        vuln.texts = Object.entries(data.texts).flatMap(([key, value]) => {
            if (typeof value !== "string") return [];
            return { title: key, content: value }
        })
    if (typeof data?.severity?.severity === "string") vuln.severity.severity = data.severity.severity
    if (typeof data?.severity?.min_score === "number") vuln.severity.min_score = Number(data.severity.min_score)
    if (typeof data?.severity?.max_score === "number") vuln.severity.max_score = Number(data.severity.max_score)
    if (Array.isArray(data?.severity?.cvss)) vuln.severity.cvss = data.severity.cvss.flatMap(asCVSS)
    if (!isNaN(Number(data?.epss?.score))) vuln.epss.score = Number(data.epss.score)
    if (!isNaN(Number(data?.epss?.percentile))) vuln.epss.percentile = Number(data.epss.percentile)
    if (typeof data?.effort?.optimistic === "string") vuln.effort.optimistic = new Iso8601Duration(data.effort.optimistic)
    if (typeof data?.effort?.likely === "string") vuln.effort.likely = new Iso8601Duration(data.effort.likely)
    if (typeof data?.effort?.pessimistic === "string") vuln.effort.pessimistic = new Iso8601Duration(data.effort.pessimistic)
    if (typeof data?.fix?.state === "string") vuln.fix.state = data.fix.state
    return vuln
}

class Vulnerabilities {
    static async list(): Promise<Vulnerability[]> {
        const response = await fetch(import.meta.env.VITE_API_URL + "/api/vulnerabilities?format=list", {
            mode: "cors",
        });
        const data = await response.json();
        return data.flatMap(asVulnerability);
    }

    static enrich_with_assessments(vulns: Vulnerability[], assessments: Assessment[]): Vulnerability[] {
        const assessments_per_vuln = assessments.reduce((acc, assessment: Assessment) => {
            if (!acc[assessment.vuln_id]) {
                acc[assessment.vuln_id] = [];
            }
            acc[assessment.vuln_id].push(assessment);
            return acc;
        }, {} as {[key: string]: Assessment[]});

        return vulns.map((vuln) => {
            if (!assessments_per_vuln[vuln.id]) return vuln;
            if (assessments_per_vuln[vuln.id].length < 1) return vuln;

            assessments_per_vuln[vuln.id].sort((a, b) => {
                return new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
            });
            const latest = assessments_per_vuln[vuln.id][assessments_per_vuln[vuln.id].length - 1];
            return {
                ...vuln,
                status: latest?.status ?? 'unknown',
                simplified_status: latest?.simplified_status ?? 'unknown',
                assessments: assessments_per_vuln[vuln.id],
            };
        });
    }

    static append_assessment(vulns: Vulnerability[], assessment: Assessment): Vulnerability[] {
        return vulns.map((vuln) => {
            if (vuln.id === assessment.vuln_id) {
                return {
                    ...vuln,
                    status: assessment.status,
                    simplified_status: assessment.simplified_status,
                    assessments: [...vuln.assessments, assessment],
                };
            }

            return vuln
        })
    }
}

export default Vulnerabilities;
export { SEVERITY_ORDER };

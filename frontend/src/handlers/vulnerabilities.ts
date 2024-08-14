import type { Assessment } from "./assessments";

type CVSS = {
    author: string;
    severity: string;
    version: string;
    vector_string: string;
    base_score: number;
    exploitability_score: number;
    impact_score: number;
};

type received_vulnerability = {
    id: string;
    aliases: string[];
    related_vulnerabilities: string[];
    namespace: string;
    found_by: string[];
    datasource: string;
    packages: string[];
    urls: string[];
    texts: {[key: string]: string};
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
    fix: {
        state: string;
    };
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
    fix: {
        state: string;
    };
    status: string;
    simplified_status: string;
    assessments: Assessment[];
};

export type { Vulnerability, CVSS };

const SEVERITY_ORDER = ['NONE', 'UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

class Vulnerabilities {
    static async list(): Promise<Vulnerability[]> {
        const response = await fetch(import.meta.env.VITE_API_URL + "/api/vulnerabilities?format=list", {
            mode: "cors",
        });
        const data = await response.json();
        return data.map((vuln: received_vulnerability) => ({
            ...vuln,
            texts: Object.entries(vuln.texts).map(([key, value]) => ({ title: key, content: value })),
            status: 'unknown',
            simplified_status: 'unknown',
            assessments: []
        }));
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
            if (!assessments_per_vuln[vuln.id]) {
                return {
                    ...vuln,
                    status: 'unknown',
                    simplified_status: 'unknown',
                    assessments: [],
                };
            }
            const vulnAssessments = assessments_per_vuln[vuln.id].sort((a, b) => {
                return new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
            });
            return {
                ...vuln,
                status: vulnAssessments.length > 0 ? vulnAssessments[vulnAssessments.length -1].status : 'unknown',
                simplified_status: vulnAssessments.length > 0 ? vulnAssessments[vulnAssessments.length -1].simplified_status : 'unknown',
                assessments: vulnAssessments,
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

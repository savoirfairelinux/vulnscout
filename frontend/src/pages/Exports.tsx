import { useCallback, useEffect, useRef, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faGear } from "@fortawesome/free-solid-svg-icons";
import ExportWizard from "../components/ExportWizard";
import type { ExportDocument } from "../components/ExportWizard";
import Projects from "../handlers/project";
import type { Project } from "../handlers/project";
import Variants from "../handlers/variant";
import type { Variant } from "../handlers/variant";

const asExportDocument = (data: any): ExportDocument | [] => {
    if (typeof data !== "object" || typeof data?.id !== "string") return [];
    return {
        id: data.id,
        category: Array.isArray(data.category)
            ? data.category.filter((entry: any) => typeof entry === "string")
            : [],
        extension: typeof data.extension === "string"
            ? data.extension
            : data.id.split(".").at(-1) ?? "unk",
    };
};

type Props = {
    projectId?: string;
    variantId?: string;
    variantIds?: string[];
};

function Exports({ projectId }: Readonly<Props>) {
    const [documents, setDocuments] = useState<ExportDocument[]>([]);
    const [projects, setProjects] = useState<Project[]>([]);
    const [variants, setVariants] = useState<Variant[]>([]);
    const variantLoadGeneration = useRef(0);

    const loadDocuments = useCallback(() => {
        fetch(import.meta.env.VITE_API_URL + "/api/documents", { mode: "cors" })
            .then(response => response.json())
            .then(data => setDocuments(Array.isArray(data) ? data.flatMap(asExportDocument) : []))
            .catch(error => {
                console.error("Error:", error);
                setDocuments([]);
            });
    }, []);

    useEffect(() => loadDocuments(), [loadDocuments]);
    useEffect(() => {
        Projects.list().then(setProjects).catch(() => setProjects([]));
    }, []);
    useEffect(() => {
        const generation = ++variantLoadGeneration.current;
        setVariants([]);
        if (!projectId) {
            return;
        }
        Variants.list(projectId)
            .then(result => {
                if (generation === variantLoadGeneration.current) setVariants(result);
            })
            .catch(() => {
                if (generation === variantLoadGeneration.current) setVariants([]);
            });
    }, [projectId]);

    const project = projects.find(current => current.id === projectId);

    return <div className="w-full space-y-6">
        <div className="space-y-6">
            <div>
                <h1 className="text-3xl font-bold text-white">Export</h1>
                <p className="mt-2 text-base text-neutral-400">Generate reports and SBOM files for the selected project.</p>
            </div>

            <div className="flex items-center gap-4 rounded-lg border border-sky-800/70 bg-sky-950/30 px-6 py-5 text-lg text-sky-100">
                <FontAwesomeIcon icon={faGear} className="shrink-0 text-sky-400" aria-hidden="true" />
                <p>Custom report templates and their image assets can be managed from <span className="font-semibold text-white">Settings &gt; Custom reports &amp; assets</span>.</p>
            </div>

            <ExportWizard
                isOpen={true}
                embedded={true}
                project={project}
                variants={variants}
                documents={documents}
            />
        </div>
    </div>;
}

export default Exports;
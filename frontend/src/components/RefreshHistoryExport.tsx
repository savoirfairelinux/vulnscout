import { useEffect, useRef, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faDownload } from "@fortawesome/free-solid-svg-icons";
import ExportWizard from "./ExportWizard";
import Projects from "../handlers/project";
import type { Project } from "../handlers/project";
import Variants from "../handlers/variant";
import type { Variant } from "../handlers/variant";

type Props = {
    projectId?: string;
};

export default function RefreshHistoryExport({ projectId }: Readonly<Props>) {
    const [isOpen, setIsOpen] = useState(false);
    const [project, setProject] = useState<Project>();
    const [variants, setVariants] = useState<Variant[]>([]);
    const loadGeneration = useRef(0);

    useEffect(() => {
        if (!isOpen) return;
        const generation = ++loadGeneration.current;
        setProject(undefined);
        setVariants([]);
        if (!projectId) return;

        Projects.list().then(projects => {
            if (generation === loadGeneration.current) {
                setProject(projects.find(candidate => candidate.id === projectId));
            }
        }).catch(() => {
            if (generation === loadGeneration.current) setProject(undefined);
        });
        Variants.list(projectId).then(result => {
            if (generation === loadGeneration.current) setVariants(result);
        }).catch(() => {
            if (generation === loadGeneration.current) setVariants([]);
        });
        return () => { loadGeneration.current += 1; };
    }, [isOpen, projectId]);

    return <>
        <button type="button" className="py-1 px-2 rounded flex items-center gap-1 text-sm font-semibold bg-sky-900 hover:bg-sky-950 transition-colors"
            onClick={() => setIsOpen(true)}>
            <FontAwesomeIcon icon={faDownload} aria-hidden="true" />
            Export vulnerability history
        </button>
        <ExportWizard
            isOpen={isOpen}
            historyOnly
            project={project}
            variants={variants}
            documents={[]}
            onClose={() => setIsOpen(false)}
        />
    </>;
}

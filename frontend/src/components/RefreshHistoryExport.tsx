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

type ScopeState =
    | { status: "loading" }
    | { status: "ready"; project: Project; variants: Variant[] }
    | { status: "error"; message: string };

export default function RefreshHistoryExport({ projectId }: Readonly<Props>) {
    const [isOpen, setIsOpen] = useState(false);
    const [scope, setScope] = useState<ScopeState>({ status: "loading" });
    const [retry, setRetry] = useState(0);
    const loadGeneration = useRef(0);

    useEffect(() => {
        if (!isOpen) return;
        const generation = ++loadGeneration.current;
        setScope({ status: "loading" });
        if (!projectId) {
            setScope({ status: "error", message: "No project is selected. Select a project and retry." });
            return;
        }

        Promise.all([Projects.list(), Variants.list(projectId)]).then(([projects, variants]) => {
            const project = projects.find(candidate => candidate.id === projectId);
            if (!project) throw new Error("The selected project is no longer available. Reload the project list and retry.");
            if (variants.some(variant => variant.project_id !== projectId)) {
                throw new Error("The server returned variants outside the selected project. Retry before exporting.");
            }
            if (generation === loadGeneration.current) setScope({ status: "ready", project, variants });
        }).catch(reason => {
            if (generation !== loadGeneration.current) return;
            setScope({
                status: "error",
                message: reason instanceof Error ? reason.message : "Unable to load the selected project and its variants.",
            });
        });
        return () => { loadGeneration.current += 1; };
    }, [isOpen, projectId, retry]);

    return <>
        <button type="button" className="py-1 px-2 rounded flex items-center gap-1 text-sm font-semibold bg-sky-900 hover:bg-sky-950 transition-colors"
            onClick={() => {
                setScope({ status: "loading" });
                setIsOpen(true);
            }}>
            <FontAwesomeIcon icon={faDownload} aria-hidden="true" />
            Export vulnerability history
        </button>
        <ExportWizard
            isOpen={isOpen}
            historyOnly
            scopeLoading={scope.status === "loading"}
            scopeError={scope.status === "error" ? scope.message : undefined}
            onRetryScopeLoad={() => setRetry(value => value + 1)}
            project={scope.status === "ready" ? scope.project : undefined}
            variants={scope.status === "ready" ? scope.variants : []}
            documents={[]}
            onClose={() => setIsOpen(false)}
        />
    </>;
}

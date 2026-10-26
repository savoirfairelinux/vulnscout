import { useEffect, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner } from "@fortawesome/free-solid-svg-icons";
import ModalShell from "../ModalShell";
import { BUTTON_PRIMARY, BUTTON_SECONDARY, FIELD, HELP, LABEL, WARNING } from "./styles";

export type CopySourceProject = { id: string; name: string; variants: { id: string; name: string }[] };

type Props = {
    isOpen: boolean;
    currentVariantId: string;
    projects: CopySourceProject[];
    /** Loads the source into the draft; the dialog closes once it settles. */
    onCopy: (projectId: string, variantId: string) => Promise<void>;
    onClose: () => void;
};

const SELECT_ID = "ai-copy-source";

function CopyFromDialog({ isOpen, currentVariantId, projects, onCopy, onClose }: Readonly<Props>) {
    const [source, setSource] = useState('');
    const [copying, setCopying] = useState(false);

    useEffect(() => {
        if (isOpen) setSource('');
    }, [isOpen]);

    const groups = projects
        .map(p => ({ ...p, variants: p.variants.filter(v => v.id !== currentVariantId) }))
        .filter(p => p.variants.length > 0);

    const handleCopy = async () => {
        const project = groups.find(p => p.variants.some(v => v.id === source));
        if (!project) return;
        setCopying(true);
        try {
            await onCopy(project.id, source);
        } finally {
            setCopying(false);
            onClose();
        }
    };

    const footer = (
        <div className="flex justify-end gap-3">
            <button type="button" onClick={() => { void handleCopy(); }} disabled={!source || copying} className={BUTTON_PRIMARY}>
                {copying && <FontAwesomeIcon icon={faSpinner} spin />}
                Copy
            </button>
            <button type="button" onClick={onClose} disabled={copying} className={BUTTON_SECONDARY}>Cancel</button>
        </div>
    );

    return (
        <ModalShell
            isOpen={isOpen}
            title="Copy context from another variant"
            onClose={onClose}
            closeDisabled={copying}
            closeOnEscape={!copying}
            closeOnBackdrop={!copying}
            footer={footer}
            size="compact"
            testId="copy-from-backdrop"
        >
            <div className="space-y-3">
                {groups.length === 0 ? (
                    <p className={HELP}>No other variant to copy from.</p>
                ) : (
                    <div>
                        <label htmlFor={SELECT_ID} className={LABEL}>Source variant</label>
                        <select
                            id={SELECT_ID}
                            value={source}
                            onChange={event => setSource(event.target.value)}
                            disabled={copying}
                            className={FIELD}
                        >
                            <option value="">Choose a variant…</option>
                            {groups.map(p => (
                                <optgroup key={p.id} label={p.name}>
                                    {p.variants.map(v => <option key={v.id} value={v.id}>{v.name}</option>)}
                                </optgroup>
                            ))}
                        </select>
                    </div>
                )}
                <p className={WARNING}>
                    This replaces the whole draft of this variant. Uploaded codebase references are not copied: when the source uses them, this variant keeps its own codebase source and paths. Nothing is saved until you click Save changes.
                </p>
            </div>
        </ModalShell>
    );
}

export default CopyFromDialog;

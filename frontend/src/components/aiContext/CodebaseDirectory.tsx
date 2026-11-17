import { useEffect, useState } from "react";
import Context, { type CodebaseDirectory as Directory } from "../../handlers/context";
import { BUTTON_SECONDARY, HELP } from "./styles";

function CodebaseDirectory({ variantId, disabled }: Readonly<{
    variantId: string; disabled: boolean;
}>) {
    const [directory, setDirectory] = useState<Directory | null>(null);
    const [error, setError] = useState("");
    const [busy, setBusy] = useState(true);

    useEffect(() => {
        let cancelled = false;
        setDirectory(null);
        setError("");
        setBusy(true);
        Context.getDirectory(variantId).then(value => {
            if (!cancelled) setDirectory(value);
        }).catch((failure: unknown) => {
            if (!cancelled) setError(failure instanceof Error ? failure.message : "Could not load codebase directory.");
        }).finally(() => { if (!cancelled) setBusy(false); });
        return () => { cancelled = true; };
    }, [variantId]);

    const refresh = async (create: boolean) => {
        setBusy(true);
        setError("");
        setDirectory(current => current ? { ...current, file_count: null, directory_count: null } : null);
        try {
            setDirectory(await Context.getDirectory(variantId, create));
        } catch (failure) {
            setError(failure instanceof Error ? failure.message : "Could not load codebase directory.");
        } finally {
            setBusy(false);
        }
    };

    return (
        <section aria-label="Codebase directory" className="space-y-2">
            <p className={HELP}>
                Administrators can copy source into this server directory or bind-mount a codebase read-only.
                Files on a remote workstation are not automatically accessible.
                Once created, this directory is available to agents without saving other context fields.
            </p>
            {directory?.path && <p className="text-sm text-zinc-200 break-all">
                Container path: <code>{directory.path}</code>
            </p>}
            {busy && <p role="status" className={HELP}>Checking codebase directory...</p>}
            {directory && <p role="status" className={HELP}>{directory.message}</p>}
            {directory?.file_count != null && directory.directory_count != null && (
                <p className={HELP}>Files: {directory.file_count} / Directories: {directory.directory_count}</p>
            )}
            {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
            <div className="flex gap-2">
                {(!directory?.path || directory.status === 'missing') && (
                    <button type="button" className={BUTTON_SECONDARY} disabled={disabled || busy}
                        onClick={() => void refresh(true)}>
                        Create codebase directory
                    </button>
                )}
                <button type="button" className={BUTTON_SECONDARY} disabled={disabled || busy}
                    onClick={() => void refresh(false)}>Refresh directory status</button>
            </div>
            <p className={HELP}>
                Browsing is read-only and bounded. Hidden and sensitive filenames, links and special files are excluded.
                Counts include eligible files and subdirectories, excluding the root directory.
                Paths remain stable after renames; directories are retained after project or variant deletion for administrator cleanup.
                Only expose source you may share with the selected AI provider, and remove secrets first.
            </p>
        </section>
    );
}

export default CodebaseDirectory;

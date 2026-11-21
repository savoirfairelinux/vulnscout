import { useCallback, useEffect, useRef, useState } from "react";
import Context, { type HostMountList } from "../../handlers/context";
import AgentCodeBlock from "../AgentCodeBlock";
import { BUTTON_SECONDARY, ERROR, HELP, LABEL, WARNING } from "./styles";

const message = (failure: unknown, fallback: string) => failure instanceof Error ? failure.message : fallback;
const quote = (value: string) => `'${value.replace(/'/g, "'\\''")}'`;

type Props = { variantId: string; projectName: string; variantName: string; disabled: boolean };

function HostFolders({ variantId, projectName, variantName, disabled }: Readonly<Props>) {
    const [list, setList] = useState<HostMountList | null>(null);
    const [error, setError] = useState('');
    const [notice, setNotice] = useState('');
    const [busy, setBusy] = useState(true);

    const latestRequest = useRef<symbol | null>(null);
    const load = useCallback(async () => {
        const request = Symbol();
        latestRequest.current = request;
        setBusy(true);
        setError('');
        try {
            const value = await Context.listMounts(variantId);
            if (latestRequest.current === request) {
                setList({ helper: value.helper ?? { available: true, message: null }, mounts: value.mounts ?? [] });
            }
        } catch (failure) {
            if (latestRequest.current === request) setError(message(failure, 'Could not load attached folders.'));
        } finally {
            if (latestRequest.current === request) setBusy(false);
        }
    }, [variantId]);

    useEffect(() => {
        setList(null);
        setNotice('');
        void load();
        return () => { latestRequest.current = null; };
    }, [load]);

    const detach = async (alias: string) => {
        setBusy(true);
        setError('');
        setNotice('');
        try {
            const warning = await Context.detachMount(variantId, alias);
            setNotice(warning ? `Detached ${alias}. ${warning}` : `Detached ${alias}.`);
            await load();
        } catch (failure) {
            setError(message(failure, 'Could not detach this folder.'));
            setBusy(false);
        }
    };

    const mounts = list?.mounts ?? [];
    return (
        <section aria-label="Attached host folders" className="space-y-2">
            <p className={LABEL}>Attached host folders</p>
            <p className={HELP}>
                Agents can read and search each attached folder using <code>mount:&lt;alias&gt;</code>, without uploading
                its contents. Run this command from the launcher directory on the container host. Replace <code>src</code> with
                your alias and <code>/path/to/folder</code> with the host folder path, then refresh the list.
            </p>
            {projectName && variantName && (
                <AgentCodeBlock buttonClassName={BUTTON_SECONDARY}
                    onCopyError={() => setError('Could not copy the command. Select and copy it manually.')}>
                    <code>{`./vulnscout ai-context attach -p ${quote(projectName)} -v ${quote(variantName)} 'src=/path/to/folder'`}</code>
                </AgentCodeBlock>
            )}
            {list && !list.helper.available && (
                <p role="alert" className={WARNING}>Host folder helper unavailable: {list.helper.message}</p>
            )}
            {list && mounts.length === 0 && <p className={HELP}>No host folders attached.</p>}
            {mounts.length > 0 && (
                <ul aria-label="Attached folders" className="space-y-1">
                    {mounts.map(mount => (
                        <li key={mount.alias} className="flex flex-wrap items-center gap-2 text-sm text-zinc-200">
                            <code>{mount.alias}</code>
                            <span className="break-all">{mount.host_path}</span>
                            <span className={mount.status === 'available' ? 'text-xs text-green-400' : 'text-xs text-amber-300'}>
                                {mount.status === 'available' ? 'Available' : 'Unavailable'}
                            </span>
                            {mount.status !== 'available' && mount.message && <span className={WARNING}>{mount.message}</span>}
                            <button type="button" className={BUTTON_SECONDARY} disabled={disabled || busy}
                                aria-label={`Detach ${mount.alias}`} onClick={() => void detach(mount.alias)}>
                                Detach
                            </button>
                        </li>
                    ))}
                </ul>
            )}
            {busy && <p role="status" className={HELP}>Checking attached folders...</p>}
            {notice && <p role="status" className={HELP}>{notice}</p>}
            {error && <p role="alert" className={ERROR}>{error}</p>}
            <button type="button" className={BUTTON_SECONDARY} disabled={busy} onClick={() => void load()}>
                Refresh folder status
            </button>
        </section>
    );
}

export default HostFolders;

import { useCallback, useEffect, useId, useRef, useState } from "react";
import Context, { type HostMountList } from "../../handlers/context";
import AgentCodeBlock from "../AgentCodeBlock";
import HelpPopover from "../HelpPopover";
import { BUTTON_SECONDARY, ERROR, HELP, LABEL, WARNING } from "./styles";

const message = (failure: unknown, fallback: string) => failure instanceof Error ? failure.message : fallback;
const quote = (value: string) => `'${value.replace(/'/g, "'\\''")}'`;
const HELPER_START = './vulnscout ai-context helper start';
const HELPER_RESTART = './vulnscout ai-context helper restart';
const HELP_BUTTON = 'text-sky-300 hover:text-sky-100 focus-visible:ring-2 focus-visible:ring-cyan-400';

type Props = { variantId: string; projectName: string; variantName: string; disabled: boolean };

function HostFolders({ variantId, projectName, variantName, disabled }: Readonly<Props>) {
    const headingId = useId();
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

    const detach = async (alias: string, revision: string) => {
        setBusy(true);
        setError('');
        setNotice('');
        try {
            const warning = await Context.detachMount(variantId, alias, revision);
            setNotice(warning ? `Detached ${alias}. ${warning}` : `Detached ${alias}.`);
            await load();
        } catch (failure) {
            setError(message(failure, 'Could not detach this folder.'));
            setBusy(false);
        }
    };

    const mounts = list?.mounts ?? [];
    const unavailable = mounts.filter(mount => mount.status !== 'available');
    const attach = projectName && variantName
        ? `./vulnscout ai-context attach -p ${quote(projectName)} -v ${quote(variantName)}` : null;
    const helperDown = list?.helper.available === false;
    const recoveryCommand = unavailable.length === 0 ? null : helperDown
        ? (list.helper.message?.includes(HELPER_RESTART) ? HELPER_RESTART : HELPER_START)
        : attach && `${attach} ${unavailable.map(mount => quote(`${mount.alias}=${mount.host_path}`)).join(' ')}`;
    const copyError = () => setError('Could not copy the command. Select and copy it manually.');

    return (
        <section aria-labelledby={headingId} className="space-y-2">
            <div className={`relative flex items-center gap-2 ${LABEL}`}>
                <h3 id={headingId}>Attached host folders</h3>
                <HelpPopover ariaLabel="Attached host folders help" role="tooltip" className="!static"
                    buttonClassName={HELP_BUTTON} surfaceClassName="!left-0 !right-auto max-w-full">
                    <p>
                        Agents can read and search each attached folder using <code>mount:&lt;alias&gt;</code>, without
                        uploading its contents. Run this command from the launcher directory on the container host.
                        Replace <code>src</code> with your alias and <code>/path/to/folder</code> with the host folder
                        path, then refresh the list.
                    </p>
                </HelpPopover>
            </div>
            {attach && (
                <AgentCodeBlock buttonClassName={BUTTON_SECONDARY} onCopyError={copyError}>
                    <code>{`${attach} 'src=/path/to/folder'`}</code>
                </AgentCodeBlock>
            )}
            {helperDown && (
                <p role="alert" className={WARNING}>Host folder helper unavailable: {list.helper.message}</p>
            )}
            {list && mounts.length === 0 && <p className={HELP}>No host folders attached.</p>}
            {mounts.length > 0 && (
                <table aria-label="Attached folders" className="w-full text-left text-sm text-zinc-200">
                    <thead className="border-b border-slate-600">
                        <tr>
                            <th scope="col" className="py-1 pr-2">Name</th>
                            <th scope="col" className="py-1 pr-2">Host folder</th>
                            <th scope="col" className="py-1 pr-2">Status</th>
                            <th scope="col" className="py-1">Detach</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-700">
                        {mounts.map(mount => (
                            <tr key={mount.attachment_id}>
                                <th scope="row" className="py-1 pr-2 font-normal [overflow-wrap:anywhere]">
                                    <code>{mount.alias}</code>
                                </th>
                                <td className="py-1 pr-2 [overflow-wrap:anywhere]">{mount.host_path}</td>
                                <td className="py-1 pr-2">
                                    {mount.status === 'available' ? (
                                        <span className="text-xs text-green-400">Available</span>
                                    ) : (
                                        <div className={`flex flex-wrap items-center gap-x-1 ${WARNING}`}>
                                            <span>Unavailable</span>
                                            {mount.message && (
                                                <HelpPopover ariaLabel={`Unavailable: ${mount.alias} status details`} role="tooltip"
                                                    buttonClassName={HELP_BUTTON}
                                                    surfaceClassName="max-w-[16rem] [overflow-wrap:anywhere]">
                                                    {mount.message}
                                                </HelpPopover>
                                            )}
                                        </div>
                                    )}
                                </td>
                                <td className="py-1">
                                    <button type="button" className={BUTTON_SECONDARY} disabled={disabled || busy}
                                        aria-label={`Detach ${mount.alias}`} onClick={() => void detach(mount.alias, mount.approval_revision)}>
                                        Detach
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}
            {busy && <p role="status" className={HELP}>Checking attached folders...</p>}
            {notice && <p role="status" className={HELP}>{notice}</p>}
            {error && <p role="alert" className={ERROR}>{error}</p>}
            {recoveryCommand && (
                <div role="group" aria-label="Reconnect host folders">
                    <p className={HELP}>
                        {helperDown
                            ? 'Try restoring the shared helper. If folders remain unavailable after refreshing, check their status details.'
                            : 'Verify that each path still points to the intended folder before reapproving it.'}
                        {' Run this from the launcher directory on the container host, then refresh.'}
                    </p>
                    <AgentCodeBlock key={recoveryCommand} buttonClassName={BUTTON_SECONDARY} onCopyError={copyError}>
                        <code>{recoveryCommand}</code>
                    </AgentCodeBlock>
                </div>
            )}
            <button type="button" className={BUTTON_SECONDARY} disabled={busy} onClick={() => void load()}>
                Refresh folder status
            </button>
        </section>
    );
}

export default HostFolders;

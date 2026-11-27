import { useCallback, useEffect, useId, useRef, useState } from "react";
import Context, { type HostMountList } from "../../handlers/context";
import AgentCodeBlock from "../AgentCodeBlock";
import HelpPopover from "../HelpPopover";
import { BUTTON_SECONDARY, ERROR, HELP, LABEL, WARNING } from "./styles";

const message = (failure: unknown, fallback: string) => failure instanceof Error ? failure.message : fallback;
const quote = (value: string) => `'${value.replace(/'/g, "'\\''")}'`;
const HELPER_START = './vulnscout ai-context helper start';
const HELPER_RESTART = './vulnscout ai-context helper restart';
const MISSING_FOLDER = 'Host folder not found.';
const HELP_BUTTON = 'text-sky-300 hover:text-sky-100 focus-visible:ring-2 focus-visible:ring-cyan-400';

type Props = { variantId: string; projectName: string; variantName: string; disabled: boolean };
type HostMount = HostMountList['mounts'][number];

function helperRecovery(diagnostic: string | null) {
    if (diagnostic?.startsWith(`Host folder helper is not running. On the container host, run '${HELPER_START}'.`)) {
        return HELPER_START;
    }
    if (diagnostic === `Incompatible host folder helper. On the host, run '${HELPER_RESTART}'.`) {
        return HELPER_RESTART;
    }
    return null;
}

function HostFolders({ variantId, projectName, variantName, disabled }: Readonly<Props>) {
    const headingId = useId();
    const [list, setList] = useState<HostMountList | null>(null);
    const [error, setError] = useState('');
    const [notice, setNotice] = useState('');
    const [loading, setLoading] = useState(true);
    const [detaching, setDetaching] = useState(false);
    const busy = loading || detaching;

    const activeScope = useRef<symbol | null>(null);
    const latestRequest = useRef<symbol | null>(null);
    const load = useCallback(async () => {
        const request = Symbol();
        latestRequest.current = request;
        setLoading(true);
        setError('');
        try {
            const value = await Context.listMounts(variantId);
            if (latestRequest.current === request) {
                setList({ helper: value.helper ?? { available: true, message: null }, mounts: value.mounts ?? [] });
            }
        } catch (failure) {
            if (latestRequest.current === request) setError(message(failure, 'Could not load attached folders.'));
        } finally {
            if (latestRequest.current === request) setLoading(false);
        }
    }, [variantId]);

    useEffect(() => {
        activeScope.current = Symbol();
        setList(null);
        setNotice('');
        setDetaching(false);
        void load();
        return () => {
            activeScope.current = null;
            latestRequest.current = null;
        };
    }, [load]);

    const detach = async ({ alias, approval_revision: revision, attachment_id: id }: HostMount) => {
        const scope = activeScope.current;
        setDetaching(true);
        setError('');
        setNotice('');
        try {
            const warning = await Context.detachMount(variantId, alias, revision);
            if (activeScope.current !== scope) return;
            setList(current => current && {
                ...current,
                mounts: current.mounts.filter(mount => mount.attachment_id !== id || mount.approval_revision !== revision),
            });
            setNotice(warning ? `Detached ${alias}. ${warning}` : `Detached ${alias}.`);
            // Starting this refresh invalidates any GET issued before the detach completed.
            await load();
        } catch (failure) {
            if (activeScope.current === scope) setError(message(failure, 'Could not detach this folder.'));
        } finally {
            if (activeScope.current === scope) setDetaching(false);
        }
    };

    const mounts = list?.mounts ?? [];
    const unavailable = mounts.filter(mount => mount.status !== 'available');
    const attach = projectName && variantName
        ? `./vulnscout ai-context attach -p ${quote(projectName)} -v ${quote(variantName)}` : null;
    const helperDown = list?.helper.available === false;
    const helperCommand = helperDown && unavailable.length > 0 ? helperRecovery(list.helper.message) : null;
    const missingFolders = helperDown ? [] : unavailable.filter(mount => mount.message === MISSING_FOLDER);
    const reapprovable = helperDown || !attach ? [] : unavailable.filter(mount => mount.message !== MISSING_FOLDER);
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
                                        aria-label={`Detach ${mount.alias}`} onClick={() => void detach(mount)}>
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
            {(helperCommand || missingFolders.length > 0 || reapprovable.length > 0) && (
                <div role="group" aria-label="Reconnect host folders">
                    {helperCommand && (
                        <>
                            <p className={HELP}>
                                Try restoring the shared helper. Run this from the launcher directory on the
                                container host, then refresh. If folders remain unavailable, check their status details.
                            </p>
                            <AgentCodeBlock key={helperCommand} buttonClassName={BUTTON_SECONDARY} onCopyError={copyError}>
                                <code>{helperCommand}</code>
                            </AgentCodeBlock>
                        </>
                    )}
                    {missingFolders.length > 0 && (
                        <p className={HELP}>
                            Missing folders: {missingFolders.map(mount => mount.alias).join(', ')}.
                            {' Restore them at their listed host paths, then refresh.'}
                        </p>
                    )}
                    {reapprovable.length > 0 && (
                        <>
                            <p className={HELP}>
                                Verify each path still points to the intended folder before reapproving it.
                                Run the individual command from the launcher directory on the container host, then refresh.
                            </p>
                            {reapprovable.map(mount => {
                                const command = `${attach} ${quote(`${mount.alias}=${mount.host_path}`)}`;
                                return (
                                    <div key={command} role="group" aria-label={`Reapprove ${mount.alias}`}>
                                        <AgentCodeBlock buttonClassName={BUTTON_SECONDARY} onCopyError={copyError}>
                                            <code>{command}</code>
                                        </AgentCodeBlock>
                                    </div>
                                );
                            })}
                        </>
                    )}
                </div>
            )}
            <button type="button" className={BUTTON_SECONDARY} disabled={busy} onClick={() => void load()}>
                Refresh folder status
            </button>
        </section>
    );
}

export default HostFolders;

import { useCallback, useEffect, useState } from "react";
import Context, { type HostFolderListing, type HostHelperStatus, type HostMount, type HostMountList } from "../../handlers/context";
import { BUTTON_PRIMARY, BUTTON_SECONDARY, ERROR, FIELD, HELP, LABEL, WARNING } from "./styles";

const ALIAS_PATTERN = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const ALIAS_RULE = "Use 1-32 lowercase letters, digits, '_' or '-', starting with a letter or digit.";

const message = (failure: unknown, fallback: string) => failure instanceof Error ? failure.message : fallback;

/** A safe alias suggestion from a folder name, e.g. "Build Tmp" -> "build-tmp". */
function suggestAlias(path: string): string {
    const name = path.split('/').filter(Boolean).pop() ?? '';
    return name.toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^[-_]+/, '').slice(0, 32).replace(/[-_]+$/, '');
}

type PanelProps = {
    variantId: string;
    takenAliases: string[];
    onCancel: () => void;
    onAttached: (mount: HostMount) => void;
};

function AttachFolderPanel({ variantId, takenAliases, onCancel, onAttached }: Readonly<PanelProps>) {
    const [roots, setRoots] = useState<HostHelperStatus | null>(null);
    const [listing, setListing] = useState<HostFolderListing | null>(null);
    const [alias, setAlias] = useState('');
    const [aliasEdited, setAliasEdited] = useState(false);
    const [error, setError] = useState('');
    const [busy, setBusy] = useState(true);

    useEffect(() => {
        let cancelled = false;
        (async () => {
            try {
                const status = await Context.getHostRoots();
                if (cancelled) return;
                setRoots(status);
                if (status.available) {
                    const first = await Context.browseHostFolder(null);
                    if (!cancelled) setListing(first);
                }
            } catch (failure) {
                if (!cancelled) setError(message(failure, 'Could not load approved host folders.'));
            } finally {
                if (!cancelled) setBusy(false);
            }
        })();
        return () => { cancelled = true; };
    }, []);

    const open = async (path: string | null) => {
        setBusy(true);
        setError('');
        try {
            const next = await Context.browseHostFolder(path);
            setListing(next);
            if (!aliasEdited) setAlias(next.path ? suggestAlias(next.path) : '');
        } catch (failure) {
            setError(message(failure, 'Could not open this folder.'));
        } finally {
            setBusy(false);
        }
    };

    const selected = listing?.path ?? null;
    const aliasError = !alias ? '' : !ALIAS_PATTERN.test(alias) ? ALIAS_RULE
        : takenAliases.includes(alias) ? `Alias '${alias}' is already used by this variant.` : '';

    const attach = async () => {
        if (!selected || !alias || aliasError) return;
        setBusy(true);
        setError('');
        try {
            onAttached(await Context.attachMount(variantId, alias, selected));
        } catch (failure) {
            setError(message(failure, 'Could not attach this folder.'));
            setBusy(false);
        }
    };

    return (
        <div role="group" aria-label="Attach folder" className="space-y-2 rounded border border-slate-600 p-3">
            <p className={HELP}>
                Choose a folder inside a location approved by the operator. Only these locations can be browsed.
            </p>
            {roots && !roots.available && <p role="alert" className={WARNING}>{roots.message}</p>}
            {roots?.available && roots.roots.length === 0 && (
                <p role="alert" className={WARNING}>No approved host folders are configured.</p>
            )}
            {listing && (
                <>
                    <p className="text-sm text-zinc-200 break-all">
                        {selected ? <>Selected folder: <code>{selected}</code></> : 'Approved host folders'}
                    </p>
                    {selected && (
                        <button type="button" className={BUTTON_SECONDARY} disabled={busy}
                            onClick={() => void open(listing.parent)}>
                            Up
                        </button>
                    )}
                    <ul aria-label="Host folders" className="max-h-48 overflow-y-auto space-y-1">
                        {listing.directories.map(entry => (
                            <li key={entry.path}>
                                <button type="button" className="text-sm text-cyan-300 hover:underline break-all text-left"
                                    disabled={busy} onClick={() => void open(entry.path)}>
                                    {selected ? entry.name : entry.path}
                                </button>
                            </li>
                        ))}
                        {listing.directories.length === 0 && <li className={HELP}>No subfolders.</li>}
                    </ul>
                    {listing.truncated && <p className={HELP}>Only the first 500 subfolders are shown.</p>}
                </>
            )}
            <div>
                <label className={LABEL} htmlFor={`host-folder-alias-${variantId}`}>Alias</label>
                <input id={`host-folder-alias-${variantId}`} className={FIELD} value={alias}
                    placeholder="src" maxLength={32}
                    onChange={event => { setAlias(event.target.value); setAliasEdited(true); }} />
                {aliasError && <p className={ERROR}>{aliasError}</p>}
            </div>
            {busy && <p role="status" className={HELP}>Loading host folders...</p>}
            {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
            <div className="flex gap-2">
                <button type="button" className={BUTTON_PRIMARY}
                    disabled={busy || !selected || !alias || Boolean(aliasError)} onClick={() => void attach()}>
                    Attach selected folder
                </button>
                <button type="button" className={BUTTON_SECONDARY} onClick={onCancel}>Cancel</button>
            </div>
        </div>
    );
}

function HostFolders({ variantId, disabled }: Readonly<{ variantId: string; disabled: boolean }>) {
    const [list, setList] = useState<HostMountList | null>(null);
    const [error, setError] = useState('');
    const [notice, setNotice] = useState('');
    const [busy, setBusy] = useState(true);
    const [picking, setPicking] = useState(false);

    const load = useCallback(async (isCancelled: () => boolean = () => false) => {
        setBusy(true);
        setError('');
        try {
            const value = await Context.listMounts(variantId);
            if (!isCancelled()) setList({ helper: value.helper ?? { available: true, message: null }, mounts: value.mounts ?? [] });
        } catch (failure) {
            if (!isCancelled()) setError(message(failure, 'Could not load attached folders.'));
        } finally {
            if (!isCancelled()) setBusy(false);
        }
    }, [variantId]);

    useEffect(() => {
        let cancelled = false;
        setList(null);
        setNotice('');
        setPicking(false);
        void load(() => cancelled);
        return () => { cancelled = true; };
    }, [load]);

    const detach = async (alias: string) => {
        setBusy(true);
        setError('');
        setNotice('');
        try {
            const warning = await Context.detachMount(variantId, alias);
            setNotice(warning ? `Detached ${alias}. ${warning}` : `Detached ${alias}.`);
        } catch (failure) {
            setError(message(failure, 'Could not detach this folder.'));
        }
        await load();
    };

    const mounts = list?.mounts ?? [];
    return (
        <section aria-label="Attached host folders" className="space-y-2">
            <p className={LABEL}>Attached host folders</p>
            <p className={HELP}>
                Attach folders from the container host without copying or uploading them. Agents browse, read and search
                each folder read-only with the file ID <code>mount:&lt;alias&gt;</code>, so they can search one folder
                without scanning the others. Only folders inside operator-approved locations can be attached.
            </p>
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
            {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
            <div className="flex gap-2">
                <button type="button" className={BUTTON_SECONDARY} disabled={disabled || picking}
                    onClick={() => { setNotice(''); setPicking(true); }}>
                    Attach folder
                </button>
                <button type="button" className={BUTTON_SECONDARY} disabled={busy} onClick={() => void load()}>
                    Refresh folder status
                </button>
            </div>
            {picking && (
                <AttachFolderPanel
                    variantId={variantId}
                    takenAliases={mounts.map(mount => mount.alias)}
                    onCancel={() => setPicking(false)}
                    onAttached={mount => {
                        setPicking(false);
                        setNotice(`Attached ${mount.alias} (${mount.file_id}).`);
                        void load();
                    }}
                />
            )}
        </section>
    );
}

export default HostFolders;

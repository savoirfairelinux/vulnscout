import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faLock } from "@fortawesome/free-solid-svg-icons";

export type SidebarSelection = { kind: 'project' } | { kind: 'variant'; id: string };

type Props = {
    projectName: string;
    variants: { id: string; name: string }[];
    inScopeIds: string[];
    selected: SidebarSelection | null;
    onSelect: (selection: SidebarSelection) => void;
};

const HINT_ID = "ai-context-scope-hint";
const ITEM = "w-full rounded px-3 py-2 text-left text-sm flex items-center gap-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400";

function ContextSidebar({ projectName, variants, inScopeIds, selected, onSelect }: Readonly<Props>) {
    const projectSelected = selected?.kind === 'project';
    const hasLocked = variants.some(v => !inScopeIds.includes(v.id));

    return (
        <nav aria-label="AI context items" className="w-64 shrink-0 self-start rounded-lg bg-slate-800 border border-slate-700 p-2">
            <p className="px-3 pt-1 pb-2 text-xs font-semibold uppercase tracking-wide text-zinc-400 truncate">{projectName}</p>
            <button
                type="button"
                aria-current={projectSelected ? 'true' : undefined}
                onClick={() => onSelect({ kind: 'project' })}
                className={`${ITEM} ${projectSelected ? 'bg-sky-900 text-white' : 'text-zinc-200 hover:bg-slate-700'}`}
            >
                Project description
            </button>
            <div className="mt-4 mb-1 flex items-baseline justify-between px-3">
                <h2 className="text-xs font-semibold uppercase tracking-wide text-zinc-400">Variants</h2>
                <span className="text-xs text-zinc-400">{inScopeIds.length} of {variants.length} in scope</span>
            </div>
            <ul className="space-y-0.5">
                {variants.map(variant => {
                    const locked = !inScopeIds.includes(variant.id);
                    const current = selected?.kind === 'variant' && selected.id === variant.id;
                    const tone = locked
                        ? 'text-zinc-500 cursor-not-allowed'
                        : current ? 'bg-violet-950 text-white' : 'text-zinc-200 hover:bg-slate-700';
                    return (
                        <li key={variant.id}>
                            <button
                                type="button"
                                aria-current={current ? 'true' : undefined}
                                aria-disabled={locked ? 'true' : undefined}
                                aria-describedby={locked ? HINT_ID : undefined}
                                onClick={() => { if (!locked) onSelect({ kind: 'variant', id: variant.id }); }}
                                className={`${ITEM} ${tone}`}
                            >
                                {current && <span aria-hidden="true" className="h-2 w-2 shrink-0 rounded-full bg-violet-400" />}
                                <span className="truncate">{variant.name}</span>
                                {locked && <FontAwesomeIcon icon={faLock} aria-hidden="true" className="ml-auto text-xs" />}
                            </button>
                        </li>
                    );
                })}
            </ul>
            {hasLocked && (
                <p id={HINT_ID} className="mt-3 px-3 text-xs text-zinc-400">
                    Locked variants are outside the current scope. Add them with the project/variant selector in the top bar.
                </p>
            )}
        </nav>
    );
}

export default ContextSidebar;

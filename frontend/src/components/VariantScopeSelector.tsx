import type { VariantChoice } from "../helpers/sharedContext";

type Props = {
    label: string; variants: VariantChoice[]; selected: string[];
    disabled?: boolean; onChange: (ids: string[]) => void;
};

export default function VariantScopeSelector({ label, variants, selected, disabled, onChange }: Readonly<Props>) {
    return <fieldset disabled={disabled} className="text-sm">
        <legend className="text-zinc-300 mb-1">{label} variants</legend>
        <details className="rounded border border-slate-600 bg-slate-900/40">
            <summary className="cursor-pointer px-2 py-1.5 text-cyan-300">
                {selected.length === variants.length && selected.length > 0 ? `All current variants (${selected.length})`
                    : selected.length ? variants.filter(variant => selected.includes(variant.id)).map(variant => variant.name).join(", ")
                    : "Select variants"}
            </summary>
            <div className="p-2 space-y-2">
                <div className="flex gap-3">
                    <button type="button" className="text-cyan-300" onClick={() => onChange(variants.map(variant => variant.id))}
                        aria-label={`${label} select all variants`}>All</button>
                    <button type="button" className="text-cyan-300" onClick={() => onChange([])}
                        aria-label={`${label} clear variants`}>None</button>
                </div>
                {variants.map(variant => <label key={variant.id} className="flex items-center gap-2 text-zinc-200">
                    <input type="checkbox" checked={selected.includes(variant.id)}
                        aria-label={`${label} applies to ${variant.name}`}
                        onChange={event => onChange(event.target.checked
                            ? [...selected, variant.id] : selected.filter(target => target !== variant.id))} />
                    {variant.name}
                </label>)}
            </div>
        </details>
    </fieldset>;
}

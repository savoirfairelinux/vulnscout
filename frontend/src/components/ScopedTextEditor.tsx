import { useId } from "react";
import type { ScopedText, VariantChoice } from "../helpers/sharedContext";
import VariantScopeSelector from "./VariantScopeSelector";

type Props = {
    label: string; help?: string; rows: ScopedText[]; variants: VariantChoice[];
    disabled: boolean; path?: boolean; allocateId: (reserved?: string[]) => string; onChange: (rows: ScopedText[]) => void;
};
const labelClass = "block text-sm text-zinc-300 mb-1";
const inputClass = "w-full rounded px-2 py-1.5 text-sm bg-slate-900/60 border border-slate-600 text-white focus:outline-none focus:border-cyan-400";
const buttonClass = "rounded px-3 py-1.5 text-sm border border-slate-500 text-cyan-300 hover:bg-slate-700 disabled:opacity-40";

export default function ScopedTextEditor({
    label, help, rows, variants, disabled, path, allocateId, onChange,
}: Readonly<Props>) {
    const id = useId();
    const blank = (reserved: string[] = []): ScopedText => ({
        id: allocateId(reserved), value: "", variant_ids: variants.map(variant => variant.id),
    });
    const displayed = rows.length ? rows : [blank()];
    const update = (index: number, changes: Partial<ScopedText>) => onChange(
        displayed.map((row, position) => position === index ? { ...row, ...changes } : row),
    );
    return <fieldset disabled={disabled} aria-describedby={help ? `${id}-help` : undefined}>
        <legend className={labelClass}>{path ? "Codebase Paths" : label}</legend>
        {help && <p id={`${id}-help`} className="text-xs text-zinc-400 mb-1">{help}</p>}
        <div className="space-y-3">
            {displayed.map((row, index) => {
                const name = `${label}${path || displayed.length > 1 ? ` ${index + 1}` : ""}`;
                return <div key={row.id} className="rounded border border-slate-700 p-3 space-y-2">
                    <label className={path || displayed.length > 1 ? labelClass : "sr-only"} htmlFor={`${id}-${index}`}>{name}</label>
                    {path ? <input id={`${id}-${index}`} className={inputClass} value={row.value}
                        onChange={event => update(index, { value: event.target.value })} placeholder="e.g. /workspace/firmware" />
                        : <textarea id={`${id}-${index}`} className={inputClass + " resize-y min-h-[80px]"} value={row.value}
                            onChange={event => update(index, { value: event.target.value })} />}
                    <VariantScopeSelector label={name} variants={variants} selected={row.variant_ids}
                        onChange={targets => update(index, { variant_ids: targets })} />
                    {rows.length > 0 && <button type="button" className={buttonClass}
                        aria-label={`Remove ${name}`} onClick={() => onChange(rows.filter((_, position) => position !== index))}>
                        Remove {label}
                    </button>}
                </div>;
            })}
            <button type="button" className={buttonClass}
                onClick={() => onChange([...displayed, blank(displayed.map(row => row.id))])}>Add {label}</button>
        </div>
    </fieldset>;
}

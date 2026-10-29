import type { MutableRefObject, ReactNode } from "react";
import type { StrideComponent, StrideInteraction, VariantDraft } from "../../handlers/context";
import { isReferenced, nextId } from "../../helpers/strideModel";
import FieldErrorText from "./FieldErrorText";
import { RequiredMark, RequiredNote } from "./RequiredMark";
import { describeField } from "./fieldErrors";
import { BUTTON_SECONDARY, FIELD, HELP } from "./styles";

type Props = {
    draft: VariantDraft;
    onDraftChange: (draft: VariantDraft) => void;
    fieldErrors: Record<string, string>;
    removedIds: MutableRefObject<string[]>;
    disabled: boolean;
};

export const TH = "px-2 py-1 text-left text-xs font-semibold text-zinc-300";
export const CELL = "px-1 py-1 align-top";
export const CELL_FIELD = `${FIELD} resize-y`;
const BLOCKED_HINT = 'Remove its interactions, threat targets and risks first.';

type Column<T> = {
    key: keyof T & string; header: string; label: string; kind: 'input' | 'text' | 'source' | 'destination'; required?: boolean;
};

const COMPONENT_COLUMNS: Column<StrideComponent>[] = [
    { key: 'name', header: 'Name', label: 'name', kind: 'input', required: true },
    { key: 'description', header: 'Description / role', label: 'description', kind: 'text' },
    { key: 'trust_zone', header: 'Trust zone', label: 'trust zone', kind: 'text' },
];
const INTERACTION_COLUMNS: Column<StrideInteraction>[] = [
    { key: 'name', header: 'Name', label: 'name', kind: 'input' },
    { key: 'source_id', header: 'Source', label: 'source', kind: 'source', required: true },
    { key: 'destination_id', header: 'Destination', label: 'destination', kind: 'destination', required: true },
    { key: 'interface', header: 'Interface / protocol', label: 'interface', kind: 'input' },
    { key: 'data', header: 'Data / commands', label: 'data', kind: 'text' },
    { key: 'trust_boundary', header: 'Trust boundary', label: 'trust boundary', kind: 'input' },
];

type TableProps<T extends { id: string }> = {
    title: string;
    noun: 'component' | 'interaction';
    prefix: 'components' | 'interactions';
    rows: T[];
    columns: Column<T>[];
    components: StrideComponent[];
    addLabel: string;
    errors: Record<string, string>;
    disabled: boolean;
    blocked: (id: string) => boolean;
    onAdd: () => void;
    onEdit: (index: number, key: string, value: string) => void;
    onRemove: (index: number) => void;
};

type EntityProps<T> = Pick<TableProps<T & { id: string }>, 'noun' | 'prefix' | 'components' | 'errors' | 'disabled'> & {
    row: T & { id: string };
    index: number;
    columns: Column<T & { id: string }>[];
    onEdit: (index: number, key: string, value: string) => void;
};

function EndpointSelect({ components, value, exclude, label, disabled, onChange, aria }: Readonly<{
    components: StrideComponent[];
    value: string;
    exclude: string;
    label: string;
    disabled: boolean;
    onChange: (value: string) => void;
    aria: object;
}>) {
    return (
        <select className={FIELD} aria-label={label} value={value} disabled={disabled}
            onChange={e => onChange(e.target.value)} {...aria}>
            <option value="">Select a component</option>
            {components.map(c => (
                <option key={c.id} value={c.id} disabled={c.name.trim() === '' || (c.id === exclude && c.id !== value)}>
                    {`${c.id}: ${c.name}`}
                </option>
            ))}
        </select>
    );
}

function Cell<T extends { id: string }>({ row, index, col, noun, prefix, components, errors, disabled, onEdit }: Readonly<
    Omit<EntityProps<T>, 'columns'> & { col: Column<T> }
>) {
    const path = `${prefix}[${index}].${col.key}`;
    const value = String((row as Record<string, unknown>)[col.key] ?? '');
    const label = `${noun === 'component' ? 'Component' : 'Interaction'} ${row.id} ${col.label}`;
    const aria = { ...describeField(path, errors), 'aria-required': col.required ? true : undefined };
    const onChange = (v: string) => onEdit(index, col.key, v);
    let control: ReactNode;
    if (col.kind === 'source' || col.kind === 'destination') {
        const other = col.kind === 'source' ? 'destination_id' : 'source_id';
        const exclude = String((row as Record<string, unknown>)[other] ?? '');
        control = <EndpointSelect components={components} value={value} exclude={exclude} label={label}
            disabled={disabled} onChange={onChange} aria={aria} />;
    } else if (col.kind === 'text') {
        control = <textarea rows={2} className={CELL_FIELD} aria-label={label} value={value}
            disabled={disabled} onChange={e => onChange(e.target.value)} {...aria} />;
    } else {
        control = <input type="text" className={FIELD} aria-label={label} value={value}
            disabled={disabled} onChange={e => onChange(e.target.value)} {...aria} />;
    }
    return (
        <td className={CELL}>
            {control}
            <FieldErrorText path={path} errors={errors} />
        </td>
    );
}

export function RemoveButton({ noun, id, hintId, blocked, disabled, onClick, hint = BLOCKED_HINT }: Readonly<{
    noun: string; id: string; hintId: string; blocked: boolean; disabled: boolean; onClick: () => void; hint?: string;
}>) {
    return (
        <td className={CELL}>
            <button type="button" className={BUTTON_SECONDARY} aria-label={`Remove ${noun} ${id}`}
                disabled={disabled || blocked} aria-describedby={blocked ? hintId : undefined} onClick={onClick}>
                Remove
            </button>
            {blocked && <span id={hintId} className="sr-only">{hint}</span>}
        </td>
    );
}

function EntityTable<T extends { id: string }>(props: Readonly<TableProps<T>>) {
    const { title, noun, prefix, rows, columns, disabled } = props;
    const headingId = `ai-variant-${prefix}-heading`;
    return (
        <div className="space-y-2">
            <h3 id={headingId} className="text-sm font-semibold text-zinc-200">{title}</h3>
            <div className="overflow-x-auto">
                <table aria-labelledby={headingId} className="w-full min-w-[40rem] table-auto border-collapse">
                    <thead>
                        <tr>
                            <th scope="col" className={TH}>ID</th>
                            {columns.map(col => (
                                <th key={col.key} scope="col" className={TH}>{col.header}{col.required && <RequiredMark />}</th>
                            ))}
                            <th scope="col" className={TH}><span className="sr-only">Remove</span></th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows.map((row, index) => (
                            <tr key={row.id} className="border-t border-slate-700">
                                <th scope="row" className="px-2 py-1 text-left text-sm font-mono text-zinc-200">{row.id}</th>
                                {columns.map(col => <Cell key={col.key} {...props} row={row} index={index} col={col} />)}
                                <RemoveButton noun={noun} id={row.id} hintId={`ai-variant-${prefix}-${index}-blocked`}
                                    blocked={props.blocked(row.id)} disabled={disabled} onClick={() => props.onRemove(index)} />
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
            {rows.length === 0 && <p className={HELP}>{`No ${noun}s yet.`}</p>}
            <button type="button" className={BUTTON_SECONDARY} disabled={disabled} onClick={props.onAdd}>
                {props.addLabel}
            </button>
        </div>
    );
}

function SystemTables({ draft, onDraftChange, fieldErrors, removedIds, disabled }: Readonly<Props>) {
    const { stride } = draft;
    const update = (patch: Partial<typeof stride>) => onDraftChange({ ...draft, stride: { ...stride, ...patch } });
    const edit = <T,>(rows: T[], index: number, key: string, value: string): T[] =>
        rows.map((row, i) => (i === index ? { ...row, [key]: value } : row));
    const remove = <T extends { id: string }>(rows: T[], index: number): T[] => {
        removedIds.current = [...removedIds.current, rows[index].id];
        return rows.filter((_, i) => i !== index);
    };

    return (
        <>
            <RequiredNote />
            <EntityTable<StrideComponent>
                title="Components" noun="component" prefix="components" addLabel="Add component"
                rows={stride.components} columns={COMPONENT_COLUMNS} components={stride.components}
                errors={fieldErrors} disabled={disabled}
                blocked={id => isReferenced(stride, id)}
                onAdd={() => update({
                    components: [...stride.components,
                        { id: nextId(stride.components, 'C', removedIds.current), name: '', description: '', trust_zone: '' }],
                })}
                onEdit={(i, key, value) => update({ components: edit(stride.components, i, key, value) })}
                onRemove={i => update({ components: remove(stride.components, i) })}
            />
            <EntityTable<StrideInteraction>
                title="Interactions" noun="interaction" prefix="interactions" addLabel="Add interaction"
                rows={stride.interactions} columns={INTERACTION_COLUMNS} components={stride.components}
                errors={fieldErrors} disabled={disabled}
                blocked={id => isReferenced(stride, id)}
                onAdd={() => update({
                    interactions: [...stride.interactions, {
                        id: nextId(stride.interactions, 'I', removedIds.current), name: '', source_id: '',
                        destination_id: '', interface: '', data: '', trust_boundary: '',
                    }],
                })}
                onEdit={(i, key, value) => update({ interactions: edit(stride.interactions, i, key, value) })}
                onRemove={i => update({ interactions: remove(stride.interactions, i) })}
            />
        </>
    );
}

export default SystemTables;

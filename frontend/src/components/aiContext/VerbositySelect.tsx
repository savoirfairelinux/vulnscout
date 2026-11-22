import type { Verbosity } from "../../handlers/context";
import { FIELD, LABEL } from "./styles";

type Props = { label: string; value: Verbosity; onChange: (value: Verbosity) => void; disabled: boolean };

export default function VerbositySelect({ label, value, onChange, disabled }: Readonly<Props>) {
    return (
        <label className={LABEL}>
            {label}
            <select className={FIELD} value={value} disabled={disabled} onChange={e => onChange(e.target.value as Verbosity)}>
                <option value="standard">Standard</option>
                <option value="brief">Brief</option>
                <option value="detailed">Detailed</option>
            </select>
        </label>
    );
}

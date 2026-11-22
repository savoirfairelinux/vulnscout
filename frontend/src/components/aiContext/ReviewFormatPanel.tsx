import type { ReviewFormat } from "../../handlers/context";
import VerbositySelect from "./VerbositySelect";
import { ERROR, FIELD, HELP, LABEL, PANEL } from "./styles";

type Props = {
    value: ReviewFormat;
    onChange: (value: ReviewFormat) => void;
    disabled: boolean;
    errors: Record<string, string>;
};

export default function ReviewFormatPanel({ value, onChange, disabled, errors }: Readonly<Props>) {
    return (
        <section className={`${PANEL} space-y-3`} aria-labelledby="ai-review-format-heading">
            <h3 id="ai-review-format-heading" className="text-xl font-bold text-white">Review rationale</h3>
            <p className={HELP}>Choose what the reviewer explains first. Every difference and its supporting evidence are still required.</p>
            <label className={LABEL}>
                Review emphasis
                <select className={FIELD} disabled={disabled} value={value.focus}
                    onChange={e => onChange({ ...value, focus: e.target.value as ReviewFormat['focus'] })}>
                    <option value="balanced">Balanced</option>
                    <option value="evidence">Supporting evidence</option>
                    <option value="differences">Field differences</option>
                    <option value="uncertainty">Uncertainty and gaps</option>
                </select>
            </label>
            <VerbositySelect label="Review verbosity" value={value.verbosity} disabled={disabled}
                onChange={verbosity => onChange({ ...value, verbosity })} />
            {Object.entries(errors).filter(([key]) => key.startsWith("review_format")).map(([key, text]) =>
                <p role="alert" key={key} className={ERROR}>{key}: {text}</p>)}
        </section>
    );
}

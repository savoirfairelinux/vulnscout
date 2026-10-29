import { HELP } from "./styles";

/** Visual "*" after a required column header; controls carry aria-required for assistive tech. */
export function RequiredMark() {
    return <span aria-hidden="true" className="ml-0.5 text-red-400">*</span>;
}

export function RequiredNote() {
    return (
        <p className={HELP}>
            Fields marked <span aria-hidden="true" className="text-red-400">*</span>
            <span className="sr-only">with an asterisk</span> are required.
        </p>
    );
}

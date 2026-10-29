import { useRef } from "react";
import type { InputHTMLAttributes } from "react";

type Props = Omit<InputHTMLAttributes<HTMLInputElement>, "type" | "className"> & {
    buttonLabel: string;
    status?: string;
    buttonClassName?: string;
};

/** Native file inputs render browser-locale text; this keeps the picker UI in English. */
function FileInputButton({ buttonLabel, status, buttonClassName, disabled, ...inputProps }: Props) {
    const ref = useRef<HTMLInputElement>(null);
    return (
        <div className="flex items-center gap-3 text-sm text-zinc-300">
            <input {...inputProps} ref={ref} type="file" className="hidden" disabled={disabled} />
            <button
                type="button"
                disabled={disabled}
                onClick={() => ref.current?.click()}
                className={buttonClassName ?? "px-3 py-1 rounded bg-slate-700 hover:bg-slate-600 text-white disabled:opacity-40 disabled:cursor-not-allowed"}
            >
                {buttonLabel}
            </button>
            {status && <span className="text-zinc-400">{status}</span>}
        </div>
    );
}

export default FileInputButton;

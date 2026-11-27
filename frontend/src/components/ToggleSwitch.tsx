type Props = {
    enabled: boolean;
    setEnabled: (value: boolean) => void;
    label?: string;
    disabled?: boolean;
};

export default function ToggleSwitch({ enabled, setEnabled, label, disabled = false }: Props) {
    const accessible = label ? (enabled ? `Hide ${label}` : `Show ${label}`) : (enabled ? 'On' : 'Off');

    return (
        <div className="flex items-center gap-2">
            {label && <span className="text-white">{label}</span>}
            <button
                type="button"
                disabled={disabled}
                onClick={() => setEnabled(!enabled)}
                aria-label={accessible}
                aria-pressed={enabled}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors duration-300 disabled:cursor-wait disabled:opacity-60 ${
                    enabled ? 'bg-green-500' : 'bg-gray-400'
                }`}
            >
                <span className="sr-only">{accessible}</span>
                <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform duration-300 ${
                        enabled ? 'translate-x-6' : 'translate-x-1'
                    }`}
                />
            </button>
        </div>
    );
}

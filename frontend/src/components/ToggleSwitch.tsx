type Props = {
    enabled: boolean;
    setEnabled: (value: boolean) => void;
    label?: string;
};

export default function ToggleSwitch({ enabled, setEnabled, label }: Props) {
    const accessible = label ? (enabled ? `Hide ${label}` : `Show ${label}`) : (enabled ? 'On' : 'Off');

    return (
        <div className="flex items-center gap-2">
            {label && <span className="text-white">{label}</span>}
            <button
                onClick={() => setEnabled(!enabled)}
                aria-label={accessible}
                aria-pressed={enabled}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors duration-300 ${
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


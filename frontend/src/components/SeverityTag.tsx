import { escape } from "lodash-es";
type Props = {
    severity: string;
    icon?: boolean;
    className?: string;
};

const severityColors: { [key: string]: string } = {
    "CRITICAL": "bg-red-500",
    "HIGH": "bg-orange-600",
    "MEDIUM": "bg-yellow-500",
    "LOW": "bg-yellow-300",
    "UNKNOWN": "bg-gray-500",
    "NONE": "bg-green-500",
}

function SeverityTag ({ severity, className }: Readonly<Props>) {
    const color = severityColors[severity.toUpperCase()] || "bg-gray-500";

    return (
        <span className={['py-1 px-2', color, escape(className)].join(' ')}>{severity}</span>
    );
}

export default SeverityTag;

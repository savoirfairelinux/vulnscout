type version = {
    title: string;
    details?: string;
    highlight?: string;
    left_color?: string;
}

type Props = {
    versions: version[];
    reduce_size?: boolean;
};

export type { version };

const width_sizes = ['w-4', 'w-5', 'w-6', 'w-7']
const height_sizes = ['h-4', 'h-5', 'h-6', 'h-7']

function VersionsLine ({ versions, reduce_size=false }: Readonly<Props>) {
    return (
        <div className="w-full px-8 md:px-16 py-10 flex flex-row items-center">
            {versions.map((version, index) => [
                (index > 0 || version.left_color) && <div key={'color_'+version.title} className={["min-h-0.5 flex-1", version.left_color ?? "bg-gray-900"].join(' ')}></div>,
                <div key={version.title} className={[
                    "flex-none rounded-full bg-slate-100 text-center relative",
                    width_sizes[index] ?? 'w-7', height_sizes[index] ?? 'h-7'
                ].join(' ')}>
                    <div className={[
                        "absolute text-white -top-8 left-1/2 -translate-x-1/2 font-mono whitespace-nowrap",
                        reduce_size ? 'text-sm' : 'text-lg'
                    ].join(' ')}>
                        {version.title}
                    </div>
                    {(version.details || version.highlight) && <div
                        className={[
                            "absolute text-slate-300 top-8 left-1/2 -translate-x-1/2 whitespace-nowrap",
                            reduce_size ? 'text-xs' : 'text-sm'
                    ].join(' ')}>
                        {version.highlight && <span className="font-mono">{version.highlight}</span>}
                        {version.details}
                    </div>}
                </div>
            ])}
        </div>
    );
}

export default VersionsLine;

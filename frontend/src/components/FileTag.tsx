type Props = {
    name: string;
    extension: string;
    icon?: boolean;
    onOpen?: () => void;
    opened?: boolean;
};

const documentTypes: {[key: string]: string|undefined} = {
    'ADOC': 'AsciiDoc',
    'XLSX': 'Excel Spreadsheet'
}

function FileTag ({ name, extension, onOpen, opened }: Readonly<Props>) {
    return (
        <div className="relative inline-block">
            <div>
                <button className="border-2 border-sfl-light rounded-lg inline-block hover:bg-sfl-light" onClick={onOpen}>
                    <div className="py-1 px-2 bg-zinc-600 rounded-l-md font-medium inline-block">{extension.toUpperCase().replace(/\|/g, ' | ')}</div>
                    <div className="py-1 px-2 inline-block">{name}</div>
                </button>
            </div>
            <div className={["absolute left-0 z-10 mt-2 min-w-56 w-[110%] origin-top-left rounded-md bg-slate-50 text-black", !opened && "hidden"].join(' ')}>
                {extension.split('|').map((value, index) => (
                    <a
                        href={`${import.meta.env.VITE_API_URL}/api/documents/${encodeURIComponent(name)}?ext=${encodeURIComponent(value)}`}
                        key={encodeURIComponent(value)}
                        target="_blank"
                        className={[
                            "inline-block w-full py-2 px-4 hover:bg-slate-300 text-left",
                            index == 0 && 'rounded-t-md',
                            index == extension.split('|').length - 1 && 'rounded-b-md'
                        ].join(' ')}
                    >Download as {documentTypes?.[value.toUpperCase()] ?? value.toUpperCase()}</a>
                ))}
            </div>
        </div>
    );
}

export default FileTag;

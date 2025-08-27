import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faDownload } from '@fortawesome/free-solid-svg-icons';

const documentTypes: { [key: string]: string | undefined } = {
  'ADOC': 'AsciiDoc',
  'XLSX': 'Excel Spreadsheet',
  'PDF': 'PDF Document'
};

type Props = {
  name: string;
  extension: string;
  opened?: boolean;
  onOpen?: () => void;
};

function FileTag({ name, extension, opened, onOpen }: Readonly<Props>) {
  const formats = extension.split(' | ');

  return (
    <div className="relative inline-block">
      <button
        className="border-2 border-sfl-light rounded-lg px-4 py-2 bg-slate-800 text-white shadow hover:bg-sfl-light w-full"
        onClick={onOpen}
      >
        {name} ({extension})
      </button>

      <div
        className={[
          "absolute left-0 z-10 mt-2 w-72 origin-top-left rounded-2xl bg-white shadow-lg border border-gray-200 p-4 grid gap-4",
          !opened && "hidden"
        ].join(" ")}
      >
        {formats.map((value) => (
          <div
            key={value}
          >
            <a
              href={`${import.meta.env.VITE_API_URL}/api/documents/${encodeURIComponent(
                name
              )}?ext=${encodeURIComponent(value)}`}
              target="_blank"
              className="flex items-left justify-left gap-2 rounded-xl bg-sfl-dark text-white py-2 px-4"
            >
              <FontAwesomeIcon icon={faDownload} />
              Download {documentTypes?.[value.toUpperCase()] ?? value.toUpperCase()}
            </a>
          </div>
        ))}
      </div>
    </div>
  );
}

export default FileTag;

import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faDownload } from '@fortawesome/free-solid-svg-icons';
import React from 'react';

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
  const formats = extension.split('|');

  return (
    <div className="relative inline-block">
      <button
        className="border-2 border-sfl-light rounded-lg px-4 py-2 bg-white shadow hover:bg-sfl-light w-full"
        onClick={onOpen}
      >
        {name}
      </button>

      <div
        className={[
          "absolute left-0 z-10 mt-2 w-72 origin-top-left rounded-2xl bg-white shadow-lg border border-gray-200 p-4 grid gap-4",
          !opened && "hidden"
        ].join(" ")}
      >
        <div className="font-semibold text-gray-800">
            hover title
        </div>
        <div className="text-sm text-gray-500 mb-3">hover description</div>

        {formats.map((value) => (
          <div
            key={value}
          >
            <a
              href={`${import.meta.env.VITE_API_URL}/api/documents/${encodeURIComponent(
                name
              )}?ext=${encodeURIComponent(value)}`}
              target="_blank"
              className="flex items-center justify-center gap-2 rounded-xl bg-blue-600 text-white py-2 px-4 hover:bg-blue-700"
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

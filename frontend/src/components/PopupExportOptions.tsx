import { useState } from "react";

type Options = {
    docName: string;
    extension: string;
    onClose?: () => void;
};


export type { Options }

function PopupExportOptions({docName, extension, onClose = () => {}}: Readonly<Options>) {
    const [clientName, setClientName] = useState("");
    const [author, setAuthor] = useState("Savoir-Faire Linux");
    const [exportDate, setExportDate] = useState((new Date()).toISOString().split('T')[0]);

    return (
        <div
            tabIndex={-1}
            className="overflow-x-hidden fixed top-0 right-0 left-0 z-50 justify-center items-center w-full md:inset-0 h-full max-h-full bg-gray-900/90"
        >
            <div className="relative p-4 md:p-32 xl:px-64 h-full">
                <div className="relative rounded-lg shadow bg-gray-700 h-full overflow-y-auto">

                    {/* Modal header */}
                    <div className="flex items-center justify-between p-4 md:p-5 border-b rounded-t dark:border-gray-600">
                        <h3 id="vulnerability_modal_title" className="text-xl text-gray-900 dark:text-white">
                            Exporting <span className="font-semibold">{docName}</span> in <span className="font-mono">{extension}</span> format
                        </h3>
                        <button
                            onClick={onClose}
                            type="button"
                            className="text-gray-400 bg-transparent hover:bg-gray-200 hover:text-gray-900 rounded-lg text-sm w-8 h-8 ms-auto inline-flex justify-center items-center dark:hover:bg-gray-600 dark:hover:text-white"
                        >
                            <svg className="w-3 h-3" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 14 14">
                                <path stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="m1 1 6 6m0 0 6 6M7 7l6-6M7 7l-6 6"/>
                            </svg>
                            <span className="sr-only">Close modal</span>
                        </button>
                    </div>

                    {/* Modal body */}
                    <div className="p-4 md:p-5 space-y-4" id="vulnerability_modal_body">

                        <div className="w-full flex flex-col md:flex-row">
                            <label className="w-full md:w-1/2 px-4">
                                Client name<br/>
                                <input
                                    type="text"
                                    className="bg-slate-800 text-gray-200 p-1 px-2 my-1 w-full"
                                    placeholder="eg. ACME org. or Savoir-Faire Linux for internal production"
                                    value={clientName}
                                    onChange={(e) => setClientName(e.target.value)}
                                />
                            </label>
                            <label className="w-full md:w-1/2 px-4">
                                Author <br/>
                                <input
                                    type="text"
                                    className="bg-slate-800 text-gray-200 p-1 px-2 my-1 w-full"
                                    placeholder="Enter your name or Savoir-Faire Linux"
                                    value={author}
                                    onChange={(e) => setAuthor(e.target.value)}
                                />
                            </label>
                        </div>
                        <div className="w-full flex flex-col md:flex-row">
                            <label className="px-4">
                                Export Date <br/>
                                <input
                                    type="date"
                                    className="bg-slate-800 text-gray-200 p-1 px-2 my-1"
                                    value={exportDate}
                                    onChange={(e) => setExportDate(e.target.value)}
                                />
                            </label>
                        </div>
                    </div>

                    {/* Modal footer */}
                    <div className="flex flex-row items-center p-4 md:p-5 border-t border-gray-200 rounded-b dark:border-gray-600">
                        <button
                            onClick={onClose}
                            type="button"
                            className="py-2.5 px-5 ms-3 text-sm font-medium text-gray-400 focus:outline-none rounded-lg border border-gray-600 hover:bg-gray-700 hover:text-white focus:z-10 focus:ring-4 focus:ring-gray-700 bg-gray-800"
                        >
                            Close
                        </button>
                        <div className="flex-grow px-4">
                            <i>All fields are optional.</i>
                        </div>
                        <a
                            href={
                                `${import.meta.env.VITE_API_URL}/api/documents/${encodeURIComponent(docName)}?` + [
                                    `ext=${encodeURIComponent(extension)}`,
                                    clientName != '' ? `client_name=${encodeURIComponent(clientName)}` : undefined,
                                    author != '' ? `author=${encodeURIComponent(author)}` : undefined,
                                    exportDate != '' ? `export_date=${encodeURIComponent(exportDate)}` : undefined
                                ].filter(a => a != undefined).join('&')
                            }
                            onClick={onClose}
                            className="py-2.5 px-5 ms-3 text-gray-400 rounded-lg bg-sfl-dark hover:bg-sfl-light text-white"
                        >
                            Generate
                        </a>
                    </div>

                </div>
            </div>
        </div>
    );
}

export default PopupExportOptions;

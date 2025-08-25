import { useEffect, useState } from "react";
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faStar, faThumbTack, faFolderOpen, faFileShield, faCompassDrafting, faBoxes } from "@fortawesome/free-solid-svg-icons";
import FileTag from "../components/FileTag";
import PopupExportOptions from "../components/PopupExportOptions";
import type { Options as PopupOptions } from "../components/PopupExportOptions";

type Props = {};

type ExportDoc = {
    id: string;
    category: string[];
    extension: string;
}

const asExportDoc = (data: any): ExportDoc | [] => {
    if (typeof data !== "object") return [];
    if (typeof data?.id !== "string") return [];
    let item: ExportDoc = {
        id: data.id,
        category: [],
        extension: "unk"
    };
    if (Array.isArray(data?.category))
        item.category = data.category.filter((e: any) => typeof e === "string");
    if (typeof data?.extension === "string")
        item.extension = data.extension;
    else if (typeof data?.id?.split('.')?.at(-1) === "string")
        item.extension = data.id.split('.').at(-1);
    return item
}


function Exports ({}: Props) {
    const [tab, setTab] = useState<string>("all");
    const [docs, setDocs] = useState<ExportDoc[]>([]);
    const [openDl, setOpenDl] = useState<string | null>(null);
    const [popupOptions, setPopupOptions] = useState<PopupOptions|undefined>(undefined);

    useEffect(() => {
        fetch(import.meta.env.VITE_API_URL + "/api/documents", {
            mode: 'cors'
        })
        .then(res => res.json())
        .then(data => {
            if (Array.isArray(data)) {
                setDocs(data.flatMap(asExportDoc));
            }
        })
        .catch(error => {
            console.error('Error:', error);
        })
    }, []);


    return (<>
        <div className="w-full pt-32 flex justify-center" onClick={() => setOpenDl(null)}>
        <div className="w-[70%]">
            <div className="flex gap-2 bg-sky-800 rounded-2xl p-2 shadow-lg backdrop-blur-md justify-center">
            {[
                { key: "all", icon: faBoxes, label: "All" },

                { key: "built-in", icon: faThumbTack, label: "Built-in reports" },
                { key: "custom", icon: faFolderOpen, label: "Custom reports" },
                { key: "sbom", icon: faFileShield, label: "SBOM files" },
            ].map(({ key, icon, label }) => (
                <button
                key={key}
                onClick={(e) => {
                    e.stopPropagation()
                    setTab(key)
                    setOpenDl(null)
                }}
                className={[
                    "flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-all duration-200",
                    tab === key
                    ? "bg-white/20 text-white shadow-inner"
                    : "text-white/70 hover:text-white hover:bg-white/10",
                ].join(" ")}
                >
                <FontAwesomeIcon icon={icon} className="w-4 h-4" />
                {label}
                </button>
            ))}
            </div>
    </div>
</div>

<div className="w-full pt-4 flex justify-center">
  <div className="w-[70%] bg-gray-700 from-zinc-800 to-zinc-900 rounded-3xl p-6 grid grid-cols-3 gap-6 justify-center shadow-xl border border-white/10 backdrop-blur-sm">
    {docs.filter((doc) => doc.category.includes(tab) || tab === 'all').map((doc) => (
      <FileTag
        name={doc.id}
        key={encodeURIComponent(doc.id)}
        extension={doc.extension}
        opened={openDl === doc.id}
        onOpen={() => openDl === doc.id ? setOpenDl(null) : setOpenDl(doc.id)}
        openOptions={(name: string, ext: string) => setPopupOptions({ docName: name, extension: ext })}
      />
    ))}

    {docs.filter((doc) => doc.category.includes(tab) || tab === 'all').length === 0 && (
      <div className="col-span-2 flex flex-col items-center justify-center text-white/70 w-full py-10">
        <div className="text-lg font-medium">No documents found</div>
        {tab === 'custom' && (
          <div className="mt-2 text-sm">
            You can upload your own templates in 
            <code className="p-1 mx-1 bg-white/10 rounded">.vulnscout/templates</code>
          </div>
        )}
      </div>
    )}
  </div>
</div>



        {popupOptions && <PopupExportOptions
            docName={popupOptions.docName}
            extension={popupOptions.extension}
            onClose={() => {setPopupOptions(undefined)}}
        ></PopupExportOptions>}
    </>);
}

export default Exports;

import { useEffect, useState } from "react";
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faStar, faThumbTack, faFolderOpen, faFileShield, faCompassDrafting, faBoxes } from "@fortawesome/free-solid-svg-icons";
import FileTag from "../components/FileTag";

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
    const [tab, setTab] = useState<string>("recommended");
    const [docs, setDocs] = useState<ExportDoc[]>([]);
    const [openDl, setOpenDl] = useState<string | null>(null);

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
        <div className="w-full pt-32 flex" onClick={() => setOpenDl(null)}>
            <div className="grow"></div>
            <div className="flex gap-6 text-lg flex-wrap">

                <div
                    className={[tab == 'recommended' ? "border-b-2 border-white/60" : "hover:border-b-2 hover:border-white/40"].join(" ")}
                    onClick={() => {setTab('recommended'); setOpenDl(null)}}>
                        <FontAwesomeIcon icon={faStar} className="mr-2" />
                        Recommended
                </div>
                <div
                    className={[tab == 'built-in' ? "border-b-2 border-white/60" : "hover:border-b-2 hover:border-white/40"].join("")}
                    onClick={() => {setTab('built-in'); setOpenDl(null)}}>
                        <FontAwesomeIcon icon={faThumbTack} className="mr-2" />
                        Built-in reports
                </div>
                <div
                    className={[tab == 'custom' ? "border-b-2 border-white/60" : "hover:border-b-2 hover:border-white/40"].join("")}
                    onClick={() => {setTab('custom'); setOpenDl(null)}}>
                        <FontAwesomeIcon icon={faFolderOpen} className="mr-2" />
                        Custom reports
                </div>
                <div
                    className={[tab == 'sbom' ? "border-b-2 border-white/60" : "hover:border-b-2 hover:border-white/40"].join("")}
                    onClick={() => {setTab('sbom'); setOpenDl(null)}}>
                        <FontAwesomeIcon icon={faFileShield} className="mr-2" />
                        SBOM files
                </div>
                <div
                    className={[tab == 'misc' ? "border-b-2 border-white/60" : "hover:border-b-2 hover:border-white/40"].join("")}
                    onClick={() => {setTab('misc'); setOpenDl(null)}}>
                        <FontAwesomeIcon icon={faCompassDrafting} className="mr-2" />
                        Miscellaneous
                </div>
                <div
                    className={[tab == 'all' ? "border-b-2 border-white/60" : "hover:border-b-2 hover:border-white/40"].join("")}
                    onClick={() => {setTab('all'); setOpenDl(null)}}>
                        <FontAwesomeIcon icon={faBoxes} className="mr-2" />
                        All
                </div>

            </div>
            <div className="grow"></div>
        </div>


        <div className="w-full pt-4 flex">
            <div className="grow"></div>

            <div className="min-w-[40%] max-w-[60%] bg-zinc-500/25 rounded-2xl p-4 px-12 flex gap-4 flex-wrap">
                {docs.filter((doc) => doc.category.includes(tab) || tab == 'all').map((doc) => (
                    <FileTag
                        name={doc.id}
                        key={encodeURIComponent(doc.id)}
                        extension={doc.extension}
                        opened={openDl == doc.id}
                        onOpen={() => openDl == doc.id ? setOpenDl(null) : setOpenDl(doc.id)}
                    />
                ))}

                {docs.filter((doc) => doc.category.includes(tab) || tab == 'all').length == 0 && <>
                    <div className="text-white text-center w-full">No documents found</div>
                    {tab == 'custom' && (
                        <div className="text-white text-center w-full">You can upload your own templates in <code className="p-1 mx-1 bg-zinc-300/25">.vulnscout/templates</code></div>
                    )}
                </>}
            </div>

            <div className="grow"></div>
        </div>
    </>);
}

export default Exports;

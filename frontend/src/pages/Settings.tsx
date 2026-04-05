import { useState, useEffect, useRef, useCallback } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faPen,
  faFolderOpen,
  faFileImport,
  faPlus,
  faCheck,
  faXmark,
  faSpinner,
  faTriangleExclamation,
} from "@fortawesome/free-solid-svg-icons";
import Projects from "../handlers/project";
import type { Project } from "../handlers/project";
import Variants from "../handlers/variant";
import type { Variant } from "../handlers/variant";

type Props = {
  onDataChanged?: () => void;
};

function Settings({ onDataChanged }: Readonly<Props>) {
  // ---- Shared data ----
  const [projects, setProjects] = useState<Project[]>([]);

  const loadProjects = useCallback(() => {
    Projects.list()
      .then(setProjects)
      .catch(() => setProjects([]));
  }, []);

  useEffect(() => {
    loadProjects();
  }, [loadProjects]);

  // ---- Rename Project ----
  const [renameProjectId, setRenameProjectId] = useState<string>("");
  const [renameProjectName, setRenameProjectName] = useState<string>("");
  const [renameProjectBusy, setRenameProjectBusy] = useState(false);
  const [renameProjectMsg, setRenameProjectMsg] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);

  const handleRenameProject = async () => {
    if (!renameProjectId || !renameProjectName.trim()) return;
    setRenameProjectBusy(true);
    setRenameProjectMsg(null);
    try {
      await Projects.rename(renameProjectId, renameProjectName.trim());
      setRenameProjectMsg({ type: "success", text: "Project renamed successfully." });
      loadProjects();
      setRenameProjectName("");
      onDataChanged?.();
    } catch (e: any) {
      setRenameProjectMsg({ type: "error", text: e.message });
    } finally {
      setRenameProjectBusy(false);
    }
  };

  // ---- Rename Variant ----
  const [renameVariantProjectId, setRenameVariantProjectId] = useState<string>("");
  const [renameVariantProjectVariants, setRenameVariantProjectVariants] = useState<Variant[]>([]);
  const [renameVariantId, setRenameVariantId] = useState<string>("");
  const [renameVariantName, setRenameVariantName] = useState<string>("");
  const [renameVariantBusy, setRenameVariantBusy] = useState(false);
  const [renameVariantMsg, setRenameVariantMsg] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);

  useEffect(() => {
    if (!renameVariantProjectId) {
      setRenameVariantProjectVariants([]);
      return;
    }
    Variants.list(renameVariantProjectId)
      .then(setRenameVariantProjectVariants)
      .catch(() => setRenameVariantProjectVariants([]));
  }, [renameVariantProjectId]);

  const handleRenameVariant = async () => {
    if (!renameVariantId || !renameVariantName.trim()) return;
    setRenameVariantBusy(true);
    setRenameVariantMsg(null);
    try {
      await Variants.rename(renameVariantId, renameVariantName.trim());
      setRenameVariantMsg({ type: "success", text: "Variant renamed successfully." });
      Variants.list(renameVariantProjectId)
        .then(setRenameVariantProjectVariants)
        .catch(() => setRenameVariantProjectVariants([]));
      setRenameVariantName("");
      onDataChanged?.();
    } catch (e: any) {
      setRenameVariantMsg({ type: "error", text: e.message });
    } finally {
      setRenameVariantBusy(false);
    }
  };

  // ---- Import SBOM ----
  const [importProjectId, setImportProjectId] = useState<string>("");
  const [importVariantId, setImportVariantId] = useState<string>("");
  const [importVariants, setImportVariants] = useState<Variant[]>([]);
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importFormat, setImportFormat] = useState<string>("");
  const [importBusy, setImportBusy] = useState(false);
  const [importMsg, setImportMsg] = useState<{
    type: "success" | "error" | "info";
    text: string;
  } | null>(null);

  const [showNewProject, setShowNewProject] = useState(false);
  const [newProjectName, setNewProjectName] = useState("");
  const [showNewVariant, setShowNewVariant] = useState(false);
  const [newVariantName, setNewVariantName] = useState("");

  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!importProjectId) {
      setImportVariants([]);
      setImportVariantId("");
      return;
    }
    Variants.list(importProjectId)
      .then((v) => {
        setImportVariants(v);
        if (v.length > 0 && !v.find((x) => x.id === importVariantId)) {
          setImportVariantId(v[0].id);
        }
      })
      .catch(() => setImportVariants([]));
  }, [importProjectId]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleCreateProject = async () => {
    if (!newProjectName.trim()) return;
    try {
      const created = await Projects.create(newProjectName.trim());
      loadProjects();
      setImportProjectId(created.id);
      setShowNewProject(false);
      setNewProjectName("");
      onDataChanged?.();
    } catch (e: any) {
      setImportMsg({ type: "error", text: e.message });
    }
  };

  const handleCreateVariant = async () => {
    if (!newVariantName.trim() || !importProjectId) return;
    try {
      const created = await Variants.create(importProjectId, newVariantName.trim());
      Variants.list(importProjectId).then(setImportVariants);
      setImportVariantId(created.id);
      setShowNewVariant(false);
      setNewVariantName("");
      onDataChanged?.();
    } catch (e: any) {
      setImportMsg({ type: "error", text: e.message });
    }
  };

  const handleUploadSBOM = async () => {
    if (!importProjectId || !importVariantId || !importFile) return;
    setImportBusy(true);
    setImportMsg({ type: "info", text: "Uploading file..." });
    try {
      const result = await Variants.uploadSBOM(
        importProjectId,
        importVariantId,
        importFile,
        importFormat || undefined
      );
      setImportMsg({ type: "info", text: "Processing SBOM..." });

      const uploadId = result.upload_id;
      const poll = async () => {
        for (let i = 0; i < 600; i++) {
          await new Promise((r) => setTimeout(r, 1000));
          const status = await Variants.getUploadStatus(uploadId);
          if (status.status === "done") {
            setImportMsg({ type: "success", text: status.message });
            setImportFile(null);
            if (fileInputRef.current) fileInputRef.current.value = "";
            onDataChanged?.();
            return;
          }
          if (status.status === "error") {
            setImportMsg({ type: "error", text: status.message });
            return;
          }
          setImportMsg({ type: "info", text: status.message });
        }
        setImportMsg({ type: "error", text: "Upload processing timed out." });
      };
      await poll();
    } catch (e: any) {
      setImportMsg({ type: "error", text: e.message });
    } finally {
      setImportBusy(false);
    }
  };

  // ---- Styles matching Metrics.tsx (zinc-700 dark cards) ----
  const inputClass =
    "w-full rounded px-2 py-1.5 text-sm bg-zinc-800 border border-zinc-600 text-white focus:outline-none focus:border-cyan-400";
  const selectClass = inputClass;
  const btnPrimary =
    "px-4 py-2 rounded-lg bg-cyan-800 hover:bg-cyan-700 focus:ring-4 focus:outline-none focus:ring-blue-800 text-white text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-colors duration-150";
  const btnSecondary =
    "px-3 py-2 rounded-lg bg-zinc-600 hover:bg-zinc-500 text-white text-sm font-medium transition-colors duration-150";

  return (
    <div className="w-full flex justify-center pt-8">
      <div className="w-full max-w-3xl space-y-6">
        <h1 className="text-3xl font-bold text-white mb-2">Settings</h1>
        <p className="text-zinc-400 mb-4">
          Manage projects, variants, and import SBOM files.
        </p>

        {/* ======== Rename Project ======== */}
        <div>
          <div className="bg-zinc-700 px-4 py-2 flex items-center gap-2 rounded-t-md">
            <FontAwesomeIcon icon={faPen} className="text-cyan-400" />
            <h2 className="text-xl font-bold text-white">Rename Project</h2>
          </div>
          <div className="bg-zinc-700 p-4 rounded-b-md space-y-3">
            <div>
              <label className="block text-sm text-zinc-300 mb-1">Project</label>
              <select
                value={renameProjectId}
                onChange={(e) => {
                  setRenameProjectId(e.target.value);
                  setRenameProjectMsg(null);
                  const p = projects.find((x) => x.id === e.target.value);
                  setRenameProjectName(p?.name ?? "");
                }}
                className={selectClass}
              >
                <option value="">— select a project —</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm text-zinc-300 mb-1">New Name</label>
              <input
                type="text"
                value={renameProjectName}
                onChange={(e) => setRenameProjectName(e.target.value)}
                placeholder="Enter new project name"
                className={inputClass}
                disabled={!renameProjectId}
              />
            </div>

            <div className="flex items-center gap-3 pt-1">
              <button
                onClick={handleRenameProject}
                disabled={renameProjectBusy || !renameProjectId || !renameProjectName.trim()}
                className={btnPrimary}
              >
                {renameProjectBusy ? (
                  <FontAwesomeIcon icon={faSpinner} spin className="mr-1" />
                ) : (
                  <FontAwesomeIcon icon={faCheck} className="mr-1" />
                )}
                Rename
              </button>
              {renameProjectMsg && (
                <span className={renameProjectMsg.type === "success" ? "text-green-400 text-sm" : "text-red-400 text-sm"}>
                  <FontAwesomeIcon
                    icon={renameProjectMsg.type === "success" ? faCheck : faTriangleExclamation}
                    className="mr-1"
                  />
                  {renameProjectMsg.text}
                </span>
              )}
            </div>
          </div>
        </div>

        {/* ======== Rename Variant ======== */}
        <div>
          <div className="bg-zinc-700 px-4 py-2 flex items-center gap-2 rounded-t-md">
            <FontAwesomeIcon icon={faFolderOpen} className="text-cyan-400" />
            <h2 className="text-xl font-bold text-white">Rename Variant</h2>
          </div>
          <div className="bg-zinc-700 p-4 rounded-b-md space-y-3">
            <div>
              <label className="block text-sm text-zinc-300 mb-1">Project</label>
              <select
                value={renameVariantProjectId}
                onChange={(e) => {
                  setRenameVariantProjectId(e.target.value);
                  setRenameVariantId("");
                  setRenameVariantName("");
                  setRenameVariantMsg(null);
                }}
                className={selectClass}
              >
                <option value="">— select a project —</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm text-zinc-300 mb-1">Variant</label>
              <select
                value={renameVariantId}
                onChange={(e) => {
                  setRenameVariantId(e.target.value);
                  setRenameVariantMsg(null);
                  const v = renameVariantProjectVariants.find((x) => x.id === e.target.value);
                  setRenameVariantName(v?.name ?? "");
                }}
                disabled={!renameVariantProjectId}
                className={selectClass + " disabled:opacity-50 disabled:cursor-not-allowed"}
              >
                <option value="">— select a variant —</option>
                {renameVariantProjectVariants.map((v) => (
                  <option key={v.id} value={v.id}>{v.name}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm text-zinc-300 mb-1">New Name</label>
              <input
                type="text"
                value={renameVariantName}
                onChange={(e) => setRenameVariantName(e.target.value)}
                placeholder="Enter new variant name"
                className={inputClass}
                disabled={!renameVariantId}
              />
            </div>

            <div className="flex items-center gap-3 pt-1">
              <button
                onClick={handleRenameVariant}
                disabled={renameVariantBusy || !renameVariantId || !renameVariantName.trim()}
                className={btnPrimary}
              >
                {renameVariantBusy ? (
                  <FontAwesomeIcon icon={faSpinner} spin className="mr-1" />
                ) : (
                  <FontAwesomeIcon icon={faCheck} className="mr-1" />
                )}
                Rename
              </button>
              {renameVariantMsg && (
                <span className={renameVariantMsg.type === "success" ? "text-green-400 text-sm" : "text-red-400 text-sm"}>
                  <FontAwesomeIcon
                    icon={renameVariantMsg.type === "success" ? faCheck : faTriangleExclamation}
                    className="mr-1"
                  />
                  {renameVariantMsg.text}
                </span>
              )}
            </div>
          </div>
        </div>

        {/* ======== Import SBOM ======== */}
        <div>
          <div className="bg-zinc-700 px-4 py-2 flex items-center gap-2 rounded-t-md">
            <FontAwesomeIcon icon={faFileImport} className="text-cyan-400" />
            <h2 className="text-xl font-bold text-white">Import SBOM</h2>
          </div>
          <div className="bg-zinc-700 p-4 rounded-b-md space-y-3">

            {/* ---- Project selector + new ---- */}
            <div>
              <label className="block text-sm text-zinc-300 mb-1">Project</label>
              <div className="flex gap-2">
                <select
                  value={importProjectId}
                  onChange={(e) => {
                    setImportProjectId(e.target.value);
                    setImportVariantId("");
                    setImportMsg(null);
                  }}
                  className={selectClass + " flex-1"}
                  disabled={showNewProject}
                >
                  <option value="">— select a project —</option>
                  {projects.map((p) => (
                    <option key={p.id} value={p.id}>{p.name}</option>
                  ))}
                </select>
                {!showNewProject ? (
                  <button
                    onClick={() => setShowNewProject(true)}
                    className={btnSecondary}
                    title="Create new project"
                  >
                    <FontAwesomeIcon icon={faPlus} />
                  </button>
                ) : (
                  <div className="flex gap-1">
                    <input
                      type="text"
                      value={newProjectName}
                      onChange={(e) => setNewProjectName(e.target.value)}
                      placeholder="New project name"
                      className={inputClass + " !w-40"}
                      onKeyDown={(e) => e.key === "Enter" && handleCreateProject()}
                    />
                    <button onClick={handleCreateProject} className={btnPrimary + " !px-2"}>
                      <FontAwesomeIcon icon={faCheck} />
                    </button>
                    <button
                      onClick={() => { setShowNewProject(false); setNewProjectName(""); }}
                      className={btnSecondary + " !px-2"}
                    >
                      <FontAwesomeIcon icon={faXmark} />
                    </button>
                  </div>
                )}
              </div>
            </div>

            {/* ---- Variant selector + new ---- */}
            <div>
              <label className="block text-sm text-zinc-300 mb-1">Variant</label>
              <div className="flex gap-2">
                <select
                  value={importVariantId}
                  onChange={(e) => { setImportVariantId(e.target.value); setImportMsg(null); }}
                  disabled={!importProjectId || showNewVariant}
                  className={selectClass + " flex-1 disabled:opacity-50 disabled:cursor-not-allowed"}
                >
                  <option value="">— select a variant —</option>
                  {importVariants.map((v) => (
                    <option key={v.id} value={v.id}>{v.name}</option>
                  ))}
                </select>
                {!showNewVariant ? (
                  <button
                    onClick={() => setShowNewVariant(true)}
                    disabled={!importProjectId}
                    className={btnSecondary + " disabled:opacity-40 disabled:cursor-not-allowed"}
                    title="Create new variant"
                  >
                    <FontAwesomeIcon icon={faPlus} />
                  </button>
                ) : (
                  <div className="flex gap-1">
                    <input
                      type="text"
                      value={newVariantName}
                      onChange={(e) => setNewVariantName(e.target.value)}
                      placeholder="New variant name"
                      className={inputClass + " !w-40"}
                      onKeyDown={(e) => e.key === "Enter" && handleCreateVariant()}
                    />
                    <button onClick={handleCreateVariant} className={btnPrimary + " !px-2"}>
                      <FontAwesomeIcon icon={faCheck} />
                    </button>
                    <button
                      onClick={() => { setShowNewVariant(false); setNewVariantName(""); }}
                      className={btnSecondary + " !px-2"}
                    >
                      <FontAwesomeIcon icon={faXmark} />
                    </button>
                  </div>
                )}
              </div>
            </div>

            {/* ---- Format selector ---- */}
            <div>
              <label className="block text-sm text-zinc-300 mb-1">Format (optional)</label>
              <select
                value={importFormat}
                onChange={(e) => setImportFormat(e.target.value)}
                className={selectClass}
              >
                <option value="">Auto-detect</option>
                <option value="spdx">SPDX (2 or 3)</option>
                <option value="cdx">CycloneDX</option>
                <option value="openvex">OpenVEX</option>
                <option value="yocto_cve_check">Yocto CVE check</option>
                <option value="grype">Grype</option>
              </select>
            </div>

            {/* ---- File picker ---- */}
            <div>
              <label className="block text-sm text-zinc-300 mb-1">SBOM File</label>
              <input
                ref={fileInputRef}
                type="file"
                accept=".json,.spdx,.cdx,.xml"
                onChange={(e) => { setImportFile(e.target.files?.[0] ?? null); setImportMsg(null); }}
                className={
                  inputClass +
                  " file:mr-3 file:py-1 file:px-3 file:rounded-lg file:border-0 file:text-sm file:font-semibold file:bg-cyan-900 file:text-cyan-300 hover:file:bg-cyan-800"
                }
              />
            </div>

            {/* ---- Submit ---- */}
            <div className="flex items-center gap-3 pt-1">
              <button
                onClick={handleUploadSBOM}
                disabled={importBusy || !importProjectId || !importVariantId || !importFile}
                className={btnPrimary}
              >
                {importBusy ? (
                  <FontAwesomeIcon icon={faSpinner} spin className="mr-1" />
                ) : (
                  <FontAwesomeIcon icon={faFileImport} className="mr-1" />
                )}
                Import
              </button>
              {importMsg && (
                <span
                  className={
                    importMsg.type === "success"
                      ? "text-green-400 text-sm"
                      : importMsg.type === "error"
                        ? "text-red-400 text-sm"
                        : "text-cyan-400 text-sm"
                  }
                >
                  <FontAwesomeIcon
                    icon={
                      importMsg.type === "success"
                        ? faCheck
                        : importMsg.type === "error"
                          ? faTriangleExclamation
                          : faSpinner
                    }
                    spin={importMsg.type === "info"}
                    className="mr-1"
                  />
                  {importMsg.text}
                </span>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Settings;


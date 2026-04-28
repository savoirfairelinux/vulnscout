import { useState, useEffect, useCallback, useRef } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faFolderOpen,
  faFileImport,
  faPlus,
  faCheck,
  faSpinner,
  faTriangleExclamation,
  faTrash,
  faLayerGroup,
  faXmark,
} from "@fortawesome/free-solid-svg-icons";
import Projects from "../handlers/project";
import type { Project } from "../handlers/project";
import Variants from "../handlers/variant";
import type { Variant } from "../handlers/variant";
import ConfirmationModal from "../components/ConfirmationModal";

type Props = {
  onDataChanged?: (message?: string) => void;
  onLoadingMessage?: (message: string | null) => void;
};

function Settings({ onDataChanged, onLoadingMessage }: Readonly<Props>) {
  // ---- Unmount guard for async operations ----
  const unmountedRef = useRef(false);
  useEffect(() => {
    return () => { unmountedRef.current = true; };
  }, []);

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

  // ---- Manage Projects ----
  const [renameProjectId, setRenameProjectId] = useState<string>("");
  const [renameProjectName, setRenameProjectName] = useState<string>("");
  const [renameProjectBusy, setRenameProjectBusy] = useState(false);
  const [projectMsg, setProjectMsg] = useState<string | null>(null);
  const [newProjectName, setNewProjectName] = useState("");
  const [createProjectBusy, setCreateProjectBusy] = useState(false);
  const [deleteProjectId, setDeleteProjectId] = useState<string>("");
  const [confirmDeleteProject, setConfirmDeleteProject] = useState(false);
  const [deleteProjectBusy, setDeleteProjectBusy] = useState(false);

  const handleRenameProject = async () => {
    if (!renameProjectId || !renameProjectName.trim()) return;
    setRenameProjectBusy(true);
    setProjectMsg(null);
    try {
      await Projects.rename(renameProjectId, renameProjectName.trim());
      loadProjects();
      onDataChanged?.("Renaming project...");
    } catch (e: any) {
      setProjectMsg(e.message);
    } finally {
      setRenameProjectBusy(false);
    }
  };

  const handleCreateProject = async () => {
    if (!newProjectName.trim()) return;
    setCreateProjectBusy(true);
    setProjectMsg(null);
    try {
      await Projects.create(newProjectName.trim());
      setNewProjectName("");
      loadProjects();
      onDataChanged?.("Creating project...");
    } catch (e: any) {
      setProjectMsg(e.message);
    } finally {
      setCreateProjectBusy(false);
    }
  };

  const handleDeleteProject = async () => {
    if (!deleteProjectId || deleteProjectBusy) return;
    setDeleteProjectBusy(true);
    setProjectMsg(null);
    try {
      await Projects.delete(deleteProjectId);
      // Invalidate variant section if it references the deleted project
      if (variantProjectId === deleteProjectId) {
        setVariantProjectId("");
        setVariantProjectVariants([]);
        setRenameVariantId("");
        setRenameVariantName("");
        setDeleteVariantId("");
      }
      // Invalidate import section if it references the deleted project
      if (importProjectId === deleteProjectId) {
        setImportProjectId("");
        setImportVariantId("");
        setImportVariants([]);
      }
      if (renameProjectId === deleteProjectId) {
        setRenameProjectId("");
        setRenameProjectName("");
      }
      setDeleteProjectId("");
      setConfirmDeleteProject(false);
      loadProjects();
      onDataChanged?.("Deleting project...");
    } catch (e: any) {
      setProjectMsg(e.message);
      setConfirmDeleteProject(false);
    } finally {
      setDeleteProjectBusy(false);
    }
  };

  // ---- Manage Variants ----
  const [variantProjectId, setVariantProjectId] = useState<string>("");
  const [variantProjectVariants, setVariantProjectVariants] = useState<Variant[]>([]);
  const [renameVariantId, setRenameVariantId] = useState<string>("");
  const [renameVariantName, setRenameVariantName] = useState<string>("");
  const [renameVariantBusy, setRenameVariantBusy] = useState(false);
  const [variantMsg, setVariantMsg] = useState<string | null>(null);
  const [newVariantName, setNewVariantName] = useState("");
  const [createVariantBusy, setCreateVariantBusy] = useState(false);
  const [deleteVariantId, setDeleteVariantId] = useState<string>("");
  const [confirmDeleteVariant, setConfirmDeleteVariant] = useState(false);
  const [deleteVariantBusy, setDeleteVariantBusy] = useState(false);

  const reloadVariants = useCallback((projectId: string) => {
    if (!projectId) { setVariantProjectVariants([]); return; }
    Variants.list(projectId)
      .then(setVariantProjectVariants)
      .catch(() => setVariantProjectVariants([]));
  }, []);

  useEffect(() => {
    reloadVariants(variantProjectId);
  }, [variantProjectId, reloadVariants]);

  const handleRenameVariant = async () => {
    if (!renameVariantId || !renameVariantName.trim()) return;
    setRenameVariantBusy(true);
    setVariantMsg(null);
    try {
      await Variants.rename(renameVariantId, renameVariantName.trim());
      reloadVariants(variantProjectId);
      onDataChanged?.("Renaming variant...");
    } catch (e: any) {
      setVariantMsg(e.message);
    } finally {
      setRenameVariantBusy(false);
    }
  };

  const handleCreateVariant = async () => {
    if (!newVariantName.trim() || !variantProjectId) return;
    setCreateVariantBusy(true);
    setVariantMsg(null);
    try {
      await Variants.create(variantProjectId, newVariantName.trim());
      setNewVariantName("");
      reloadVariants(variantProjectId);
      onDataChanged?.("Creating variant...");
    } catch (e: any) {
      setVariantMsg(e.message);
    } finally {
      setCreateVariantBusy(false);
    }
  };

  const handleDeleteVariant = async () => {
    if (!deleteVariantId || deleteVariantBusy) return;
    setDeleteVariantBusy(true);
    setVariantMsg(null);
    try {
      await Variants.delete(deleteVariantId);
      if (renameVariantId === deleteVariantId) {
        setRenameVariantId("");
        setRenameVariantName("");
      }
      setDeleteVariantId("");
      setConfirmDeleteVariant(false);
      reloadVariants(variantProjectId);
      onDataChanged?.("Deleting variant...");
    } catch (e: any) {
      setVariantMsg(e.message);
      setConfirmDeleteVariant(false);
    } finally {
      setDeleteVariantBusy(false);
    }
  };

  // ---- Import SBOM ----
  const [importProjectId, setImportProjectId] = useState<string>("");
  const [importVariantId, setImportVariantId] = useState<string>("");
  const [importVariants, setImportVariants] = useState<Variant[]>([]);
  const [importFiles, setImportFiles] = useState<File[]>([]);
  const [importBusy, setImportBusy] = useState(false);
  const [importMsg, setImportMsg] = useState<string | null>(null);

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
  }, [importProjectId, importVariantId]);

  const handleFileSelected = (index: number, file: File | null) => {
    setImportMsg(null);
    if (!file) return;
    setImportFiles((prev) => {
      const next = [...prev];
      next[index] = file;
      return next;
    });
  };

  const handleRemoveFile = (index: number) => {
    setImportFiles((prev) => prev.filter((_, i) => i !== index));
    setImportMsg(null);
  };

  const handleUploadSBOM = async () => {
    if (!importProjectId || !importVariantId || importFiles.length === 0) return;
    setImportBusy(true);
    setImportMsg(null);
    const count = importFiles.length;
    onLoadingMessage?.(`Uploading ${count} file${count > 1 ? "s" : ""}...`);
    try {
      const result = await Variants.uploadSBOM(
        importProjectId,
        importVariantId,
        importFiles
      );
      onLoadingMessage?.("Processing SBOM...");

      const uploadId = result.upload_id;
      const poll = async () => {
        for (let i = 0; i < 600; i++) {
          if (unmountedRef.current) { onLoadingMessage?.(null); return; }
          await new Promise((r) => setTimeout(r, 1000));
          if (unmountedRef.current) { onLoadingMessage?.(null); return; }
          const status = await Variants.getUploadStatus(uploadId);
          if (status.status === "done") {
            setImportFiles([]);
            onLoadingMessage?.(null);
            onDataChanged?.("Importing SBOM...");
            return;
          }
          if (status.status === "error") {
            setImportMsg(status.message);
            onLoadingMessage?.(null);
            return;
          }
          onLoadingMessage?.(status.message);
        }
        setImportMsg("Upload processing timed out.");
        onLoadingMessage?.(null);
      };
      await poll();
    } catch (e: any) {
      setImportMsg(e.message);
      onLoadingMessage?.(null);
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

  return (
    <div className="w-full flex justify-center pt-8">
      <div className="w-full max-w-3xl space-y-6">
        <h1 className="text-3xl font-bold text-white mb-2">Settings</h1>
        <p className="text-zinc-400 mb-4">
          Manage projects, variants, and import SBOM files.
        </p>

        {/* ======== Manage Projects ======== */}
        <div>
          <div className="bg-zinc-700 px-4 py-2 flex items-center gap-2 rounded-t-md">
            <FontAwesomeIcon icon={faLayerGroup} className="text-cyan-400" />
            <h2 className="text-xl font-bold text-white">Manage Projects</h2>
          </div>
          <div className="bg-zinc-700 p-4 rounded-b-md space-y-4">

            {/* -- Create project -- */}
            <div className="space-y-2">
              <label className="block text-sm text-zinc-300 font-semibold">Add Project</label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={newProjectName}
                  onChange={(e) => { setNewProjectName(e.target.value); setProjectMsg(null); }}
                  placeholder="New project name"
                  className={inputClass + " flex-1"}
                  onKeyDown={(e) => e.key === "Enter" && handleCreateProject()}
                />
                <button
                  onClick={handleCreateProject}
                  disabled={createProjectBusy || !newProjectName.trim()}
                  className={btnPrimary}
                >
                  {createProjectBusy ? (
                    <FontAwesomeIcon icon={faSpinner} spin className="mr-1" />
                  ) : (
                    <FontAwesomeIcon icon={faPlus} className="mr-1" />
                  )}
                  Add
                </button>
              </div>
            </div>

            {/* -- Rename project -- */}
            <div className="border-t border-zinc-600 pt-4 space-y-2">
              <label className="block text-sm text-zinc-300 font-semibold">Rename Project</label>
              <select
                value={renameProjectId}
                onChange={(e) => {
                  setRenameProjectId(e.target.value);
                  setProjectMsg(null);
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

              <div className="flex gap-2">
                <input
                  type="text"
                  value={renameProjectName}
                  onChange={(e) => setRenameProjectName(e.target.value)}
                  placeholder="Enter new name"
                  className={inputClass + " flex-1"}
                  disabled={!renameProjectId}
                  onKeyDown={(e) => e.key === "Enter" && handleRenameProject()}
                />
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
              </div>
            </div>

            {/* -- Delete project -- */}
            <div className="border-t border-zinc-600 pt-4 space-y-2">
              <label className="block text-sm text-zinc-300 font-semibold">Delete Project</label>
              <div className="flex gap-2">
                <select
                  value={deleteProjectId}
                  onChange={(e) => { setDeleteProjectId(e.target.value); setProjectMsg(null); }}
                  className={selectClass + " flex-1"}
                >
                  <option value="">— select a project —</option>
                  {projects.map((p) => (
                    <option key={p.id} value={p.id}>{p.name}</option>
                  ))}
                </select>
                <button
                  onClick={() => setConfirmDeleteProject(true)}
                  disabled={!deleteProjectId}
                  className="px-4 py-2 rounded-lg bg-red-900 hover:bg-red-800 text-white text-sm font-medium disabled:opacity-40 disabled:cursor-not-allowed transition-colors duration-150"
                >
                  <FontAwesomeIcon icon={faTrash} className="mr-1" />
                  Delete
                </button>
              </div>
            </div>

            {/* -- Feedback -- */}
            {projectMsg && (
              <span className="text-red-400 text-sm">
                <FontAwesomeIcon icon={faTriangleExclamation} className="mr-1" />
                {projectMsg}
              </span>
            )}
          </div>
        </div>

        {/* ======== Manage Variants ======== */}
        <div>
          <div className="bg-zinc-700 px-4 py-2 flex items-center gap-2 rounded-t-md">
            <FontAwesomeIcon icon={faFolderOpen} className="text-cyan-400" />
            <h2 className="text-xl font-bold text-white">Manage Variants</h2>
          </div>
          <div className="bg-zinc-700 p-4 rounded-b-md space-y-4">

            {/* -- Project picker -- */}
            <div>
              <label className="block text-sm text-zinc-300 mb-1">Project</label>
              <select
                value={variantProjectId}
                onChange={(e) => {
                  setVariantProjectId(e.target.value);
                  setRenameVariantId("");
                  setRenameVariantName("");
                  setDeleteVariantId("");
                  setVariantMsg(null);
                  setConfirmDeleteVariant(false);
                }}
                className={selectClass}
              >
                <option value="">— select a project —</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>

            {/* -- Create variant -- */}
            {variantProjectId && (
              <div className="space-y-2">
                <label className="block text-sm text-zinc-300 font-semibold">Add Variant</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={newVariantName}
                    onChange={(e) => { setNewVariantName(e.target.value); setVariantMsg(null); }}
                    placeholder="New variant name"
                    className={inputClass + " flex-1"}
                    onKeyDown={(e) => e.key === "Enter" && handleCreateVariant()}
                  />
                  <button
                    onClick={handleCreateVariant}
                    disabled={createVariantBusy || !newVariantName.trim()}
                    className={btnPrimary}
                  >
                    {createVariantBusy ? (
                      <FontAwesomeIcon icon={faSpinner} spin className="mr-1" />
                    ) : (
                      <FontAwesomeIcon icon={faPlus} className="mr-1" />
                    )}
                    Add
                  </button>
                </div>
              </div>
            )}

            {/* -- Rename variant -- */}
            {variantProjectId && (
              <div className="border-t border-zinc-600 pt-4 space-y-2">
                <label className="block text-sm text-zinc-300 font-semibold">Rename Variant</label>
                <select
                  value={renameVariantId}
                  onChange={(e) => {
                    setRenameVariantId(e.target.value);
                    setVariantMsg(null);
                    const v = variantProjectVariants.find((x) => x.id === e.target.value);
                    setRenameVariantName(v?.name ?? "");
                  }}
                  className={selectClass}
                >
                  <option value="">— select a variant —</option>
                  {variantProjectVariants.map((v) => (
                    <option key={v.id} value={v.id}>{v.name}</option>
                  ))}
                </select>

                <div className="flex gap-2">
                  <input
                    type="text"
                    value={renameVariantName}
                    onChange={(e) => setRenameVariantName(e.target.value)}
                    placeholder="Enter new name"
                    className={inputClass + " flex-1"}
                    disabled={!renameVariantId}
                    onKeyDown={(e) => e.key === "Enter" && handleRenameVariant()}
                  />
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
                </div>
              </div>
            )}

            {/* -- Delete variant -- */}
            {variantProjectId && (
              <div className="border-t border-zinc-600 pt-4 space-y-2">
                <label className="block text-sm text-zinc-300 font-semibold">Delete Variant</label>
                <div className="flex gap-2">
                  <select
                    value={deleteVariantId}
                    onChange={(e) => { setDeleteVariantId(e.target.value); setVariantMsg(null); }}
                    className={selectClass + " flex-1"}
                  >
                    <option value="">— select a variant —</option>
                    {variantProjectVariants.map((v) => (
                      <option key={v.id} value={v.id}>{v.name}</option>
                    ))}
                  </select>
                  <button
                    onClick={() => setConfirmDeleteVariant(true)}
                    disabled={!deleteVariantId}
                    className="px-4 py-2 rounded-lg bg-red-900 hover:bg-red-800 text-white text-sm font-medium disabled:opacity-40 disabled:cursor-not-allowed transition-colors duration-150"
                  >
                    <FontAwesomeIcon icon={faTrash} className="mr-1" />
                    Delete
                  </button>
                </div>
              </div>
            )}

            {/* -- Feedback -- */}
            {variantMsg && (
              <span className="text-red-400 text-sm">
                <FontAwesomeIcon icon={faTriangleExclamation} className="mr-1" />
                {variantMsg}
              </span>
            )}
          </div>
        </div>

        {/* ======== Import SBOM ======== */}
        <div>
          <div className="bg-zinc-700 px-4 py-2 flex items-center gap-2 rounded-t-md">
            <FontAwesomeIcon icon={faFileImport} className="text-cyan-400" />
            <h2 className="text-xl font-bold text-white">Import SBOM</h2>
          </div>
          <div className="bg-zinc-700 p-4 rounded-b-md space-y-3">

            {/* ---- Project selector ---- */}
            <div>
              <label className="block text-sm text-zinc-300 mb-1">Project</label>
              <select
                value={importProjectId}
                onChange={(e) => {
                  setImportProjectId(e.target.value);
                  setImportVariantId("");
                  setImportMsg(null);
                }}
                className={selectClass}
              >
                <option value="">— select a project —</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>

            {/* ---- Variant selector ---- */}
            <div>
              <label className="block text-sm text-zinc-300 mb-1">Variant</label>
              <select
                value={importVariantId}
                onChange={(e) => { setImportVariantId(e.target.value); setImportMsg(null); }}
                disabled={!importProjectId}
                className={selectClass + " disabled:opacity-50 disabled:cursor-not-allowed"}
              >
                <option value="">— select a variant —</option>
                {importVariants.map((v) => (
                  <option key={v.id} value={v.id}>{v.name}</option>
                ))}
              </select>
            </div>

            {/* ---- File picker(s) ---- */}
            <div className="space-y-2">
              <label className="block text-sm text-zinc-300 mb-1">SBOM Files</label>
              {/* Existing files */}
              {importFiles.map((file, idx) => (
                <div key={idx} className="flex items-center gap-2">
                  <span className="flex-1 truncate text-sm text-zinc-200 bg-zinc-800 border border-zinc-600 rounded px-2 py-1.5">
                    {file.name}
                  </span>
                  <button
                    type="button"
                    onClick={() => handleRemoveFile(idx)}
                    disabled={importBusy}
                    className="p-1.5 rounded text-zinc-400 hover:text-red-400 hover:bg-zinc-600 disabled:opacity-40 transition-colors"
                    title="Remove file"
                  >
                    <FontAwesomeIcon icon={faXmark} />
                  </button>
                </div>
              ))}
              {/* New file browse row */}
              <input
                key={importFiles.length}
                type="file"
                accept=".json,.spdx,.cdx,.xml"
                onChange={(e) => handleFileSelected(importFiles.length, e.target.files?.[0] ?? null)}
                disabled={importBusy}
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
                disabled={importBusy || !importProjectId || !importVariantId || importFiles.length === 0}
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
                <span className="text-red-400 text-sm">
                  <FontAwesomeIcon icon={faTriangleExclamation} className="mr-1" />
                  {importMsg}
                </span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ======== Confirmation Modals ======== */}
      <ConfirmationModal
        isOpen={confirmDeleteProject}
        title="Delete Project"
        message={`Are you sure you want to delete this project and all its variants? This action cannot be undone.`}
        confirmText="Yes, delete"
        cancelText="Cancel"
        showTitleIcon={true}
        onConfirm={handleDeleteProject}
        onCancel={() => setConfirmDeleteProject(false)}
      />
      <ConfirmationModal
        isOpen={confirmDeleteVariant}
        title="Delete Variant"
        message={`Are you sure you want to delete this variant and all its data? This action cannot be undone.`}
        confirmText="Yes, delete"
        cancelText="Cancel"
        showTitleIcon={true}
        onConfirm={handleDeleteVariant}
        onCancel={() => setConfirmDeleteVariant(false)}
      />
    </div>
  );
}

export default Settings;


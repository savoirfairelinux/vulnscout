import { useState, useEffect, useCallback, useRef } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faFolderOpen,
  faFileImport,
  faFileLines,
  faPlus,
  faCheck,
  faSpinner,
  faTriangleExclamation,
  faTrash,
  faXmark,
  faKey,
  faPenToSquare,
} from "@fortawesome/free-solid-svg-icons";
import Projects from "../handlers/project";
import type { Project } from "../handlers/project";
import Variants from "../handlers/variant";
import type { Variant } from "../handlers/variant";
import Config from "../handlers/config";
import ConfirmationModal from "../components/ConfirmationModal";
import MessageBanner from "../components/MessageBanner";
import NvdApiKey from "../handlers/nvdApiKey";

type Props = {
  onDataChanged?: (message?: string) => void;
  onLoadingMessage?: (message: string | null) => void;
};

type SettingsTab = "general" | "projects" | "variants";

function Settings({ onDataChanged, onLoadingMessage }: Readonly<Props>) {
  // ---- Active category tab ----
  const [activeTab, setActiveTab] = useState<SettingsTab>("general");

  // ---- Unmount guard for async operations ----
  const unmountedRef = useRef(false);
  useEffect(() => {
    unmountedRef.current = false;
    return () => { unmountedRef.current = true; };
  }, []);

  // ---- Shared data ----
  const [projects, setProjects] = useState<Project[]>([]);

  const loadProjects = useCallback(() => {
    Projects.list()
      .then(setProjects)
      .catch(() => setProjects([]));
  }, []);

  const [configBusy, setConfigBusy] = useState(false);
  const [configError, setConfigError] = useState<string | null>(null);
  const [configSaved, setConfigSaved] = useState<string | null>(null);
  const [configForm, setConfigForm] = useState({
    product_name: "",
    author_name: "",
    client_name: "",
    contact_email: "",
  });

  useEffect(() => {
    Config.get()
      .then((config) => {
        if (unmountedRef.current) return;
        setConfigForm({
          product_name: config.product_name,
          author_name: config.author_name,
          client_name: config.client_name,
          contact_email: config.contact_email,
        });
      })
      .catch(() => {
        if (unmountedRef.current) return;
        setConfigError("Failed to load report metadata settings.");
      });
  }, []);

  const handleSaveConfig = async () => {
    if (configBusy) return;
    setConfigBusy(true);
    setConfigError(null);
    setConfigSaved(null);
    try {
      const updated = await Config.patch(configForm);
      if (unmountedRef.current) return;
      setConfigForm({
        product_name: updated.product_name,
        author_name: updated.author_name,
        client_name: updated.client_name,
        contact_email: updated.contact_email,
      });
      setConfigSaved("Report metadata settings saved.");
      onDataChanged?.("Updating default settings...");
    } catch (e: any) {
      if (unmountedRef.current) return;
      setConfigError(e?.message || "Failed to save report metadata settings.");
    } finally {
      if (!unmountedRef.current) {
        setConfigBusy(false);
      }
    }
  };

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

  // ---- NVD API Key ----
  const [nvdKeyInput, setNvdKeyInput] = useState("");
  const [nvdMaskedKey, setNvdMaskedKey] = useState("");
  const [nvdHasKey, setNvdHasKey] = useState(false);
  const [nvdBusy, setNvdBusy] = useState(false);
  const [nvdMsg, setNvdMsg] = useState<{ text: string; type: "success" | "error" } | null>(null);
  const [nvdEditing, setNvdEditing] = useState(false);
  const [confirmDeleteNvdKey, setConfirmDeleteNvdKey] = useState(false);

  useEffect(() => {
    NvdApiKey.get()
      .then(data => {
        setNvdHasKey(data.has_key);
        setNvdMaskedKey(data.masked_key);
      })
      .catch((e) => {
        console.error(e instanceof Error ? e.message : String(e));
      });
  }, []);

  const handleSaveNvdKey = async () => {
    setNvdBusy(true);
    setNvdMsg(null);
    try {
      const data = await NvdApiKey.set(nvdKeyInput);
      if (!data.ok) {
        setNvdMsg({ text: data.error || "Failed to save API key", type: "error" });
      } else {
        setNvdHasKey(data.has_key);
        setNvdMaskedKey(data.masked_key);
        setNvdKeyInput("");
        setNvdEditing(false);
        setNvdMsg({ text: data.has_key ? "API key saved." : "API key removed.", type: "success" });
      }
    } catch (e) {
      setNvdMsg({ text: e instanceof Error ? e.message : String(e), type: "error" });
    } finally {
      setNvdBusy(false);
    }
  };

  const handleRemoveNvdKey = async () => {
    setConfirmDeleteNvdKey(false);
    setNvdBusy(true);
    setNvdMsg(null);
    try {
      const data = await NvdApiKey.remove();
      if (data.ok) {
        setNvdHasKey(data.has_key);
        setNvdMaskedKey(data.masked_key);
        setNvdKeyInput("");
        setNvdMsg({ text: "API key removed.", type: "success" });
      } else {
        setNvdMsg({ text: data.error || "Failed to remove API key", type: "error" });
      }
    } catch (e) {
      setNvdMsg({ text: e instanceof Error ? e.message : String(e), type: "error" });
    } finally {
      setNvdBusy(false);
    }
  };

  // ---- Styles ----
  const inputClass =
    "w-full rounded px-2 py-1.5 text-sm bg-slate-900/60 border border-slate-600 text-white focus:outline-none focus:border-cyan-400";
  const selectClass = inputClass;
  const btnPrimary =
    "px-4 py-2 rounded-lg bg-cyan-800 hover:bg-cyan-700 focus:ring-4 focus:outline-none focus:ring-blue-800 text-white text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-colors duration-150";
  // ---- Card styles: gradient header + slate body with ring & shadow ----
  const cardHeader =
    "bg-gradient-to-r from-slate-700 to-slate-800 px-4 py-2.5 flex items-center gap-2 rounded-t-lg border-b border-slate-600/60";
  const cardBody =
    "bg-slate-800/60 p-4 rounded-b-lg ring-1 ring-slate-700/70 shadow-lg shadow-black/20";

  return (
    <div className="w-full">
      <div className="w-full space-y-6">
        <h1 className="text-3xl font-bold text-white mb-2">Settings</h1>

        {/* ======== Category tabs ======== */}
        <div className="mb-3 flex items-center gap-1 border-b border-gray-700">
          <button
            className={`px-4 py-2 text-sm font-medium rounded-t transition-colors ${
              activeTab === "general"
                ? "bg-sky-800 text-white border-b-2 border-sky-400"
                : "text-gray-400 hover:text-gray-200 hover:bg-gray-800"
            }`}
            onClick={() => setActiveTab("general")}
          >
            General Settings
          </button>
          <button
            className={`px-4 py-2 text-sm font-medium rounded-t transition-colors ${
              activeTab === "projects"
                ? "bg-sky-800 text-white border-b-2 border-sky-400"
                : "text-gray-400 hover:text-gray-200 hover:bg-gray-800"
            }`}
            onClick={() => setActiveTab("projects")}
          >
            Projects Settings
          </button>
          <button
            className={`px-4 py-2 text-sm font-medium rounded-t transition-colors ${
              activeTab === "variants"
                ? "bg-sky-800 text-white border-b-2 border-sky-400"
                : "text-gray-400 hover:text-gray-200 hover:bg-gray-800"
            }`}
            onClick={() => setActiveTab("variants")}
          >
            Variants Settings
          </button>
        </div>

        {/* ======== General Settings tab ======== */}
        {activeTab === "general" && (
        <>
        {/* ======== Report Metadata ======== */}
        <div>
          <div className={cardHeader}>
            <FontAwesomeIcon icon={faFileLines} className="text-cyan-400" />
            <h2 className="text-xl font-bold text-white">Report Metadata</h2>
          </div>
          <div className={cardBody + " space-y-3"}>
            <div>
              <label className="block text-sm text-zinc-300 mb-1">PRODUCT_NAME</label>
              <input
                type="text"
                value={configForm.product_name}
                onChange={(e) => {
                  setConfigForm((prev) => ({ ...prev, product_name: e.target.value }));
                  setConfigError(null);
                  setConfigSaved(null);
                }}
                placeholder="Product name embedded in reports and SBOMs"
                className={inputClass}
              />
            </div>

            <div>
              <label className="block text-sm text-zinc-300 mb-1">AUTHOR_NAME</label>
              <input
                type="text"
                value={configForm.author_name}
                onChange={(e) => {
                  setConfigForm((prev) => ({ ...prev, author_name: e.target.value }));
                  setConfigError(null);
                  setConfigSaved(null);
                }}
                placeholder="Author/company name embedded in reports"
                className={inputClass}
              />
            </div>

            <div>
              <label className="block text-sm text-zinc-300 mb-1">CLIENT_NAME</label>
              <input
                type="text"
                value={configForm.client_name}
                onChange={(e) => {
                  setConfigForm((prev) => ({ ...prev, client_name: e.target.value }));
                  setConfigError(null);
                  setConfigSaved(null);
                }}
                placeholder="Customer company name (optional)"
                className={inputClass}
              />
            </div>

            <div>
              <label className="block text-sm text-zinc-300 mb-1">CONTACT_EMAIL</label>
              <input
                type="email"
                value={configForm.contact_email}
                onChange={(e) => {
                  setConfigForm((prev) => ({ ...prev, contact_email: e.target.value }));
                  setConfigError(null);
                  setConfigSaved(null);
                }}
                placeholder="Contact email embedded in reports"
                className={inputClass}
              />
            </div>

            <div className="flex items-center gap-3 pt-1">
              <button
                onClick={handleSaveConfig}
                disabled={configBusy}
                className={btnPrimary}
              >
                {configBusy ? (
                  <FontAwesomeIcon icon={faSpinner} spin className="mr-1" />
                ) : (
                  <FontAwesomeIcon icon={faCheck} className="mr-1" />
                )}
                Save
              </button>
              {configSaved && <span className="text-emerald-400 text-sm">{configSaved}</span>}
              {configError && (
                <span className="text-red-400 text-sm">
                  <FontAwesomeIcon icon={faTriangleExclamation} className="mr-1" />
                  {configError}
                </span>
              )}
            </div>
          </div>
        </div>

        {/* ======== NVD API Key ======== */}
        <section aria-labelledby="settings-heading-nvd">
          <div className={cardHeader}>
            <FontAwesomeIcon icon={faKey} className="text-cyan-400" aria-hidden="true" />
            <h2 id="settings-heading-nvd" className="text-xl font-bold text-white">NVD API Key</h2>
          </div>
          <div className={cardBody + " space-y-4"}>
            <p id="nvd-key-description" className="text-zinc-400 text-sm">
              An NVD API key increases the rate limit for vulnerability enrichment from 5 to 50 requests per 30 seconds.
              Get a free key at{" "}
              <a
                href="https://nvd.nist.gov/developers/request-an-api-key"
                target="_blank"
                rel="noopener noreferrer"
                className="text-cyan-400 hover:text-cyan-300 underline"
              >
                nvd.nist.gov
              </a>.
            </p>

            {/* -- Feedback -- */}
            {nvdMsg && (
              <MessageBanner
                type={nvdMsg.type}
                message={nvdMsg.text}
                isVisible={true}
                onClose={() => setNvdMsg(null)}
              />
            )}

            {nvdHasKey && !nvdEditing ? (
              <>
                {/* -- Key is set: show masked key + modify / remove buttons -- */}
                <div className="flex items-center gap-2">
                  <span className="text-sm text-zinc-300">NVD API key:</span>
                  <code className="text-sm text-zinc-300 bg-slate-900 px-2 py-0.5 rounded font-mono">{nvdMaskedKey}</code>
                </div>

                <div className="flex items-center gap-3 pt-1">
                  <button
                    onClick={() => { setNvdEditing(true); setNvdKeyInput(""); setNvdMsg(null); }}
                    className={btnPrimary}
                  >
                    <FontAwesomeIcon icon={faPenToSquare} className="mr-1" aria-hidden="true" />
                    Modify
                  </button>
                  <button
                    onClick={() => setConfirmDeleteNvdKey(true)}
                    disabled={nvdBusy}
                    className="px-4 py-2 rounded-lg bg-red-900 hover:bg-red-800 text-white text-sm font-medium disabled:opacity-40 disabled:cursor-not-allowed transition-colors duration-150"
                  >
                    <FontAwesomeIcon icon={faTrash} className="mr-1" aria-hidden="true" />
                    Remove
                  </button>
                </div>
              </>
            ) : (
              <>
                {/* -- No key or editing: show input field -- */}
                <div className="space-y-2">
                  <label htmlFor="nvd-api-key-input" className="block text-sm text-zinc-300 font-semibold">
                    {nvdEditing ? "New API Key" : "API Key"}
                  </label>
                  <input
                    id="nvd-api-key-input"
                    type="password"
                    value={nvdKeyInput}
                    onChange={e => setNvdKeyInput(e.target.value)}
                    placeholder="Paste your NVD API key..."
                    className={inputClass}
                    disabled={nvdBusy}
                    autoComplete="off"
                    aria-required="true"
                    aria-describedby="nvd-key-description"
                  />
                </div>

                <div className="flex items-center gap-3 pt-1">
                  <button
                    onClick={handleSaveNvdKey}
                    disabled={nvdBusy || !nvdKeyInput.trim()}
                    className={btnPrimary}
                    aria-busy={nvdBusy}
                  >
                    {nvdBusy ? (
                      <FontAwesomeIcon icon={faSpinner} spin className="mr-1" aria-hidden="true" />
                    ) : (
                      <FontAwesomeIcon icon={faCheck} className="mr-1" aria-hidden="true" />
                    )}
                    Save
                  </button>
                  {nvdEditing && (
                    <button
                      onClick={() => { setNvdEditing(false); setNvdKeyInput(""); setNvdMsg(null); }}
                      className="px-4 py-2 rounded-lg bg-slate-600 hover:bg-slate-500 text-white text-sm font-medium transition-colors duration-150"
                    >
                      <FontAwesomeIcon icon={faXmark} className="mr-1" aria-hidden="true" />
                      Cancel
                    </button>
                  )}
                </div>
              </>
            )}
          </div>
        </section>
        </>
        )}

        {/* ======== Projects Settings tab ======== */}
        {activeTab === "projects" && (
        <>
        {/* ======== Add Project ======== */}
        <section aria-labelledby="settings-heading-project-add">
          <div className={cardHeader}>
            <FontAwesomeIcon icon={faPlus} className="text-cyan-400" aria-hidden="true" />
            <h2 id="settings-heading-project-add" className="text-xl font-bold text-white">Add Project</h2>
          </div>
          <div className={cardBody + " space-y-4"}>

            {/* -- Create project -- */}
            <div className="space-y-2">
              <label htmlFor="new-project-name" className="block text-sm text-zinc-300 font-semibold">Add Project</label>
              <div className="flex gap-2">
                <input
                  id="new-project-name"
                  type="text"
                  value={newProjectName}
                  onChange={(e) => { setNewProjectName(e.target.value); setProjectMsg(null); }}
                  placeholder="New project name"
                  className={inputClass + " flex-1"}
                  aria-required="true"
                  onKeyDown={(e) => e.key === "Enter" && handleCreateProject()}
                />
                <button
                  onClick={handleCreateProject}
                  disabled={createProjectBusy || !newProjectName.trim()}
                  className={btnPrimary}
                  aria-busy={createProjectBusy}
                >
                  {createProjectBusy ? (
                    <FontAwesomeIcon icon={faSpinner} spin className="mr-1" aria-hidden="true" />
                  ) : (
                    <FontAwesomeIcon icon={faPlus} className="mr-1" aria-hidden="true" />
                  )}
                  Add
                </button>
              </div>
            </div>

            {/* -- Feedback -- */}
            {projectMsg && (
              <span role="alert" className="text-red-400 text-sm">
                <FontAwesomeIcon icon={faTriangleExclamation} className="mr-1" aria-hidden="true" />
                {projectMsg}
              </span>
            )}
          </div>
        </section>

        {/* ======== Rename Project ======== */}
        <section aria-labelledby="settings-heading-project-rename">
          <div className={cardHeader}>
            <FontAwesomeIcon icon={faPenToSquare} className="text-cyan-400" aria-hidden="true" />
            <h2 id="settings-heading-project-rename" className="text-xl font-bold text-white">Rename Project</h2>
          </div>
          <div className={cardBody + " space-y-4"}>

            {/* -- Rename project -- */}
            <div className="space-y-2">
              <label htmlFor="rename-project-select" className="block text-sm text-zinc-300 font-semibold">Rename Project</label>
              <select
                id="rename-project-select"
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
                <label htmlFor="rename-project-name" className="sr-only">New project name</label>
                <input
                  id="rename-project-name"
                  type="text"
                  value={renameProjectName}
                  onChange={(e) => setRenameProjectName(e.target.value)}
                  placeholder="Enter new name"
                  className={inputClass + " flex-1"}
                  disabled={!renameProjectId}
                  aria-required="true"
                  onKeyDown={(e) => e.key === "Enter" && handleRenameProject()}
                />
                <button
                  onClick={handleRenameProject}
                  disabled={renameProjectBusy || !renameProjectId || !renameProjectName.trim()}
                  className={btnPrimary}
                  aria-busy={renameProjectBusy}
                >
                  {renameProjectBusy ? (
                    <FontAwesomeIcon icon={faSpinner} spin className="mr-1" aria-hidden="true" />
                  ) : (
                    <FontAwesomeIcon icon={faCheck} className="mr-1" aria-hidden="true" />
                  )}
                  Rename
                </button>
              </div>
            </div>

            {/* -- Feedback -- */}
            {projectMsg && (
              <span role="alert" className="text-red-400 text-sm">
                <FontAwesomeIcon icon={faTriangleExclamation} className="mr-1" aria-hidden="true" />
                {projectMsg}
              </span>
            )}
          </div>
        </section>

        {/* ======== Delete Project ======== */}
        <section aria-labelledby="settings-heading-project-delete">
          <div className={cardHeader}>
            <FontAwesomeIcon icon={faTrash} className="text-cyan-400" aria-hidden="true" />
            <h2 id="settings-heading-project-delete" className="text-xl font-bold text-white">Delete Project</h2>
          </div>
          <div className={cardBody + " space-y-4"}>

            {/* -- Delete project -- */}
            <div className="space-y-2">
              <label htmlFor="delete-project-select" className="block text-sm text-zinc-300 font-semibold">Delete Project</label>
              <div className="flex gap-2">
                <select
                  id="delete-project-select"
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
                  <FontAwesomeIcon icon={faTrash} className="mr-1" aria-hidden="true" />
                  Delete
                </button>
              </div>
            </div>

            {/* -- Feedback -- */}
            {projectMsg && (
              <span role="alert" className="text-red-400 text-sm">
                <FontAwesomeIcon icon={faTriangleExclamation} className="mr-1" aria-hidden="true" />
                {projectMsg}
              </span>
            )}
          </div>
        </section>
        </>
        )}

        {/* ======== Variants Settings tab ======== */}
        {activeTab === "variants" && (
        <>
        {/* ======== Select Project ======== */}
        <section aria-labelledby="settings-heading-variant-project">
          <div className={cardHeader}>
            <FontAwesomeIcon icon={faFolderOpen} className="text-cyan-400" aria-hidden="true" />
            <h2 id="settings-heading-variant-project" className="text-xl font-bold text-white">Select Project</h2>
          </div>
          <div className={cardBody + " space-y-4"}>

            {/* -- Project picker -- */}
            <div>
              <label htmlFor="variant-project-select" className="block text-sm text-zinc-300 mb-1">Project</label>
              <select
                id="variant-project-select"
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
              {!variantProjectId && (
                <p className="text-zinc-400 text-sm mt-2">
                  Select a project to manage its variants.
                </p>
              )}
            </div>
          </div>
        </section>

        {/* ======== Add Variant ======== */}
        <section
          aria-labelledby="settings-heading-variant-add"
          aria-disabled={!variantProjectId}
          className={!variantProjectId ? "opacity-50" : ""}
        >
          <div className={cardHeader}>
            <FontAwesomeIcon icon={faPlus} className="text-cyan-400" aria-hidden="true" />
            <h2 id="settings-heading-variant-add" className="text-xl font-bold text-white">Add Variant</h2>
          </div>
          <div className={cardBody + " space-y-4"}>
            <div className="space-y-2">
              <label htmlFor="new-variant-name" className="block text-sm text-zinc-300 font-semibold">Add Variant</label>
              <div className="flex gap-2">
                <input
                  id="new-variant-name"
                  type="text"
                  value={newVariantName}
                  onChange={(e) => { setNewVariantName(e.target.value); setVariantMsg(null); }}
                  placeholder="New variant name"
                  className={inputClass + " flex-1 disabled:opacity-50 disabled:cursor-not-allowed"}
                  disabled={!variantProjectId}
                  aria-required="true"
                  onKeyDown={(e) => e.key === "Enter" && handleCreateVariant()}
                />
                <button
                  onClick={handleCreateVariant}
                  disabled={!variantProjectId || createVariantBusy || !newVariantName.trim()}
                  className={btnPrimary}
                  aria-busy={createVariantBusy}
                >
                  {createVariantBusy ? (
                    <FontAwesomeIcon icon={faSpinner} spin className="mr-1" aria-hidden="true" />
                  ) : (
                    <FontAwesomeIcon icon={faPlus} className="mr-1" aria-hidden="true" />
                  )}
                  Add
                </button>
              </div>
            </div>

            {/* -- Feedback -- */}
            {variantMsg && (
              <span role="alert" className="text-red-400 text-sm">
                <FontAwesomeIcon icon={faTriangleExclamation} className="mr-1" aria-hidden="true" />
                {variantMsg}
              </span>
            )}
          </div>
        </section>

        {/* ======== Rename Variant ======== */}
        <section
          aria-labelledby="settings-heading-variant-rename"
          aria-disabled={!variantProjectId}
          className={!variantProjectId ? "opacity-50" : ""}
        >
          <div className={cardHeader}>
            <FontAwesomeIcon icon={faPenToSquare} className="text-cyan-400" aria-hidden="true" />
            <h2 id="settings-heading-variant-rename" className="text-xl font-bold text-white">Rename Variant</h2>
          </div>
          <div className={cardBody + " space-y-4"}>
            <div className="space-y-2">
              <label htmlFor="rename-variant-select" className="block text-sm text-zinc-300 font-semibold">Rename Variant</label>
              <select
                id="rename-variant-select"
                value={renameVariantId}
                onChange={(e) => {
                  setRenameVariantId(e.target.value);
                  setVariantMsg(null);
                  const v = variantProjectVariants.find((x) => x.id === e.target.value);
                  setRenameVariantName(v?.name ?? "");
                }}
                className={selectClass + " disabled:opacity-50 disabled:cursor-not-allowed"}
                disabled={!variantProjectId}
              >
                <option value="">— select a variant —</option>
                {variantProjectVariants.map((v) => (
                  <option key={v.id} value={v.id}>{v.name}</option>
                ))}
              </select>

              <div className="flex gap-2">
                <label htmlFor="rename-variant-name" className="sr-only">New variant name</label>
                <input
                  id="rename-variant-name"
                  type="text"
                  value={renameVariantName}
                  onChange={(e) => setRenameVariantName(e.target.value)}
                  placeholder="Enter new name"
                  className={inputClass + " flex-1 disabled:opacity-50 disabled:cursor-not-allowed"}
                  disabled={!variantProjectId || !renameVariantId}
                  aria-required="true"
                  onKeyDown={(e) => e.key === "Enter" && handleRenameVariant()}
                />
                <button
                  onClick={handleRenameVariant}
                  disabled={!variantProjectId || renameVariantBusy || !renameVariantId || !renameVariantName.trim()}
                  className={btnPrimary}
                  aria-busy={renameVariantBusy}
                >
                  {renameVariantBusy ? (
                    <FontAwesomeIcon icon={faSpinner} spin className="mr-1" aria-hidden="true" />
                  ) : (
                    <FontAwesomeIcon icon={faCheck} className="mr-1" aria-hidden="true" />
                  )}
                  Rename
                </button>
              </div>
            </div>

            {/* -- Feedback -- */}
            {variantMsg && (
              <span role="alert" className="text-red-400 text-sm">
                <FontAwesomeIcon icon={faTriangleExclamation} className="mr-1" aria-hidden="true" />
                {variantMsg}
              </span>
            )}
          </div>
        </section>

        {/* ======== Delete Variant ======== */}
        <section
          aria-labelledby="settings-heading-variant-delete"
          aria-disabled={!variantProjectId}
          className={!variantProjectId ? "opacity-50" : ""}
        >
          <div className={cardHeader}>
            <FontAwesomeIcon icon={faTrash} className="text-cyan-400" aria-hidden="true" />
            <h2 id="settings-heading-variant-delete" className="text-xl font-bold text-white">Delete Variant</h2>
          </div>
          <div className={cardBody + " space-y-4"}>
            <div className="space-y-2">
              <label htmlFor="delete-variant-select" className="block text-sm text-zinc-300 font-semibold">Delete Variant</label>
              <div className="flex gap-2">
                <select
                  id="delete-variant-select"
                  value={deleteVariantId}
                  onChange={(e) => { setDeleteVariantId(e.target.value); setVariantMsg(null); }}
                  className={selectClass + " flex-1 disabled:opacity-50 disabled:cursor-not-allowed"}
                  disabled={!variantProjectId}
                >
                  <option value="">— select a variant —</option>
                  {variantProjectVariants.map((v) => (
                    <option key={v.id} value={v.id}>{v.name}</option>
                  ))}
                </select>
                <button
                  onClick={() => setConfirmDeleteVariant(true)}
                  disabled={!variantProjectId || !deleteVariantId}
                  className="px-4 py-2 rounded-lg bg-red-900 hover:bg-red-800 text-white text-sm font-medium disabled:opacity-40 disabled:cursor-not-allowed transition-colors duration-150"
                >
                  <FontAwesomeIcon icon={faTrash} className="mr-1" aria-hidden="true" />
                  Delete
                </button>
              </div>
            </div>

            {/* -- Feedback -- */}
            {variantMsg && (
              <span role="alert" className="text-red-400 text-sm">
                <FontAwesomeIcon icon={faTriangleExclamation} className="mr-1" aria-hidden="true" />
                {variantMsg}
              </span>
            )}
          </div>
        </section>

        {/* ======== Import SBOM ======== */}
        <section aria-labelledby="settings-heading-import">
          <div className={cardHeader}>
            <FontAwesomeIcon icon={faFileImport} className="text-cyan-400" aria-hidden="true" />
            <h2 id="settings-heading-import" className="text-xl font-bold text-white">Import SBOM</h2>
          </div>
          <div className={cardBody + " space-y-3"}>

            {/* ---- Project selector ---- */}
            <div>
              <label htmlFor="import-project-select" className="block text-sm text-zinc-300 mb-1">Project</label>
              <select
                id="import-project-select"
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
              <label htmlFor="import-variant-select" className="block text-sm text-zinc-300 mb-1">Variant</label>
              <select
                id="import-variant-select"
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
              <label className="block text-sm text-zinc-300 mb-1" id="sbom-files-label">SBOM Files</label>
              {/* Existing files */}
              {importFiles.map((file, idx) => (
                <div key={idx} className="flex items-center gap-2">
                  <span className="flex-1 truncate text-sm text-zinc-200 bg-slate-900/60 border border-slate-600 rounded px-2 py-1.5">
                    {file.name}
                  </span>
                  <button
                    type="button"
                    onClick={() => handleRemoveFile(idx)}
                    disabled={importBusy}
                    className="p-1.5 rounded text-zinc-400 hover:text-red-400 hover:bg-slate-600 disabled:opacity-40 transition-colors"
                    aria-label={`Remove file ${file.name}`}
                  >
                    <FontAwesomeIcon icon={faXmark} aria-hidden="true" />
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
                aria-labelledby="sbom-files-label"
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
                aria-busy={importBusy}
              >
                {importBusy ? (
                  <FontAwesomeIcon icon={faSpinner} spin className="mr-1" aria-hidden="true" />
                ) : (
                  <FontAwesomeIcon icon={faFileImport} className="mr-1" aria-hidden="true" />
                )}
                Import
              </button>
              {importMsg && (
                <span role="alert" className="text-red-400 text-sm">
                  <FontAwesomeIcon icon={faTriangleExclamation} className="mr-1" aria-hidden="true" />
                  {importMsg}
                </span>
              )}
            </div>
          </div>
        </section>
        </>
        )}
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
      <ConfirmationModal
        isOpen={confirmDeleteNvdKey}
        title="Remove NVD API Key"
        message="Are you sure you want to remove the NVD API key? Vulnerability enrichment will fall back to the lower rate limit."
        confirmText="Yes, remove"
        cancelText="Cancel"
        showTitleIcon={true}
        onConfirm={handleRemoveNvdKey}
        onCancel={() => setConfirmDeleteNvdKey(false)}
      />
    </div>
  );
}

export default Settings;


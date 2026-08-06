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
  faPenToSquare,
  faBug,
  faChevronDown,
  faChevronRight,
  faFolder,
  faGear,
  faRightLeft,
} from "@fortawesome/free-solid-svg-icons";
import Projects from "../handlers/project";
import type { Project } from "../handlers/project";
import Variants from "../handlers/variant";
import type { Variant } from "../handlers/variant";
import Config from "../handlers/config";
import NvdApiKey from "../handlers/nvdApiKey";
import ScansHandler from "../handlers/scans";
import type { EmptyScanPreview, OrphanedVulnerabilityPreview, OutdatedDataPreview } from "../handlers/scans";
import ConfirmationModal from "../components/ConfirmationModal";
import MessageBanner from "../components/MessageBanner";
import Popup from "../components/Popup";
import Transfer from "./Transfer";

type Props = {
  onDataChanged?: (message?: string) => void;
  onLoadingMessage?: (message: string | null) => void;
  projectId?: string;
};

type SettingsTab = "general" | "transfer" | "projects" | "variants";
type FeedbackMsg = { text: string; type: "success" | "error" } | null;
type AdditionalCleanup =
  | { kind: "empty-scans"; scans: EmptyScanPreview[] }
  | { kind: "orphaned-vulnerabilities"; vulnerabilities: OrphanedVulnerabilityPreview[] };

function Settings({ onDataChanged, onLoadingMessage, projectId }: Readonly<Props>) {
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
  const [projectVariants, setProjectVariants] = useState<Record<string, Variant[]>>({});
  const [expandedProjectIds, setExpandedProjectIds] = useState<Set<string>>(new Set());

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

  // ---- Grype settings ----
  const [grypeMemlimitInput, setGrypeMemlimitInput] = useState("");
  const [grypeMemlimitBusy, setGrypeMemlimitBusy] = useState(false);
  const [grypeMemlimitMsg, setGrypeMemlimitMsg] = useState<{ text: string; type: "success" | "error" } | null>(null);

  // ---- NVD API Key ----
  const [nvdKeyInput, setNvdKeyInput] = useState("");
  const [nvdMaskedKey, setNvdMaskedKey] = useState("");
  const [nvdHasKey, setNvdHasKey] = useState(false);
  const [nvdBusy, setNvdBusy] = useState(false);
  const [nvdMsg, setNvdMsg] = useState<{ text: string; type: "success" | "error" } | null>(null);
  const [nvdEditing, setNvdEditing] = useState(false);
  const [confirmRemoveNvdKey, setConfirmRemoveNvdKey] = useState(false);

  // ---- Global data maintenance ----
  const [confirmDeleteOutdatedData, setConfirmDeleteOutdatedData] = useState(false);
  const [outdatedDataPreview, setOutdatedDataPreview] = useState<OutdatedDataPreview | null>(null);
  const [loadingOutdatedDataPreview, setLoadingOutdatedDataPreview] = useState(false);
  const [deletingOutdatedData, setDeletingOutdatedData] = useState(false);
  const [outdatedDataMessage, setOutdatedDataMessage] = useState<FeedbackMsg>(null);
  const [pendingCleanup, setPendingCleanup] = useState<AdditionalCleanup | null>(null);
  const [additionalCleanupBusy, setAdditionalCleanupBusy] = useState(false);
  const maintenanceBusy = loadingOutdatedDataPreview || deletingOutdatedData || additionalCleanupBusy;
  const maintenanceStatus = loadingOutdatedDataPreview || additionalCleanupBusy
    ? "Scanning..."
    : deletingOutdatedData
      ? "Deleting..."
      : null;

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
        setGrypeMemlimitInput(config.grype_memlimit ?? "");
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

  const handleSaveGrypeSetting = async () => {
    if (grypeMemlimitBusy) return;
    setGrypeMemlimitBusy(true);
    setGrypeMemlimitMsg(null);
    try {
      const updated = await Config.patch({ grype_memlimit: grypeMemlimitInput.trim() });
      if (unmountedRef.current) return;
      setGrypeMemlimitInput(updated.grype_memlimit ?? "");
      setGrypeMemlimitMsg({ text: "Grype memory limit saved.", type: "success" });
    } catch (e: any) {
      if (unmountedRef.current) return;
      setGrypeMemlimitMsg({ text: e?.message || "Failed to save Grype settings.", type: "error" });
    } finally {
      if (!unmountedRef.current) setGrypeMemlimitBusy(false);
    }
  };

  useEffect(() => {
    loadProjects();
  }, [loadProjects]);

  useEffect(() => {
    let cancelled = false;

    Promise.all(projects.map(async (project) => [project.id, await Variants.list(project.id)] as const))
      .then((entries) => {
        if (!cancelled) setProjectVariants(Object.fromEntries(entries));
      })
      .catch(() => {
        if (!cancelled) setProjectVariants({});
      });

    return () => { cancelled = true; };
  }, [projects]);

  const toggleProject = (projectId: string) => {
    setExpandedProjectIds((current) => {
      const next = new Set(current);
      if (next.has(projectId)) next.delete(projectId);
      else next.add(projectId);
      return next;
    });
  };

  const clearProjectMsgs = () => {
    setAddProjectMsg(null);
    setRenameProjectMsg(null);
    setDeleteProjectMsg(null);
  };

  const clearVariantMsgs = () => {
    setAddVariantMsg(null);
    setRenameVariantMsg(null);
    setDeleteVariantMsg(null);
  };

  const selectProjectFromTree = (project: Project) => {
    clearProjectMsgs();
    setRenameProjectId(project.id);
    setRenameProjectName(project.name);
    setActiveTab("projects");
  };

  const startNewProject = () => {
    clearProjectMsgs();
    setRenameProjectId("");
    setRenameProjectName("");
    setActiveTab("projects");
  };

  const selectVariantFromTree = (projectId: string, variant: Variant) => {
    clearVariantMsgs();
    clearImportState();
    setVariantProjectId(projectId);
    setRenameVariantId(variant.id);
    setRenameVariantName(variant.name);
    setActiveTab("variants");
  };

  const requestDeleteVariant = (projectId: string, variant: Variant) => {
    clearVariantMsgs();
    clearImportState();
    setVariantProjectId(projectId);
    setRenameVariantId(variant.id);
    setRenameVariantName(variant.name);
    setConfirmDeleteVariant(true);
  };

  const startNewVariant = (projectId: string) => {
    clearVariantMsgs();
    clearImportState();
    setVariantProjectId(projectId);
    setRenameVariantId("");
    setRenameVariantName("");
    setActiveTab("variants");
  };

  // Load NVD API key status on mount
  useEffect(() => {
    NvdApiKey.get()
      .then((data) => {
        if (unmountedRef.current) return;
        setNvdHasKey(data.has_key);
        setNvdMaskedKey(data.masked_key);
      })
      .catch(() => {});
  }, []);

  const handleSaveNvdKey = async () => {
    if (nvdBusy || !nvdKeyInput.trim()) return;
    setNvdBusy(true);
    setNvdMsg(null);
    try {
      const result = await NvdApiKey.set(nvdKeyInput.trim());
      if (unmountedRef.current) return;
      if (!result.ok) {
        setNvdMsg({ text: result.error ?? "Failed to save NVD API key.", type: "error" });
      } else {
        setNvdHasKey(result.has_key);
        setNvdMaskedKey(result.masked_key);
        setNvdKeyInput("");
        setNvdEditing(false);
        setNvdMsg({
          text: result.warning ?? "NVD API key saved.",
          type: result.warning ? "error" : "success",
        });
      }
    } catch {
      if (unmountedRef.current) return;
      setNvdMsg({ text: "Failed to save NVD API key.", type: "error" });
    } finally {
      if (!unmountedRef.current) setNvdBusy(false);
    }
  };

  const handleRemoveNvdKey = async () => {
    setConfirmRemoveNvdKey(false);
    setNvdBusy(true);
    setNvdMsg(null);
    try {
      const result = await NvdApiKey.remove();
      if (unmountedRef.current) return;
      if (!result.ok) {
        setNvdMsg({ text: result.error ?? "Failed to remove NVD API key.", type: "error" });
      } else {
        setNvdHasKey(false);
        setNvdMaskedKey("");
        setNvdKeyInput("");
        setNvdEditing(false);
        setNvdMsg({ text: "NVD API key removed.", type: "success" });
      }
    } catch {
      if (unmountedRef.current) return;
      setNvdMsg({ text: "Failed to remove NVD API key.", type: "error" });
    } finally {
      if (!unmountedRef.current) setNvdBusy(false);
    }
  };

  const openDeleteOutdatedDataConfirmation = async () => {
    setConfirmDeleteOutdatedData(true);
    setOutdatedDataPreview(null);
    setOutdatedDataMessage(null);
    setLoadingOutdatedDataPreview(true);
    try {
      const result = await ScansHandler.getOutdatedDataPreview();
      if (unmountedRef.current) return;
      if (result.ok) {
        setOutdatedDataPreview(result.preview ?? null);
      } else {
        setConfirmDeleteOutdatedData(false);
        setOutdatedDataMessage({ text: result.error ?? "Failed to load outdated data.", type: "error" });
      }
    } catch {
      if (!unmountedRef.current) {
        setConfirmDeleteOutdatedData(false);
        setOutdatedDataMessage({ text: "Failed to load outdated data.", type: "error" });
      }
    } finally {
      if (!unmountedRef.current) setLoadingOutdatedDataPreview(false);
    }
  };

  const handleDeleteOutdatedData = async () => {
    setConfirmDeleteOutdatedData(false);
    setDeletingOutdatedData(true);
    setOutdatedDataMessage(null);
    onLoadingMessage?.("Deleting outdated data...");
    let refreshStarted = false;
    try {
      const result = await ScansHandler.deleteOutdatedData(outdatedDataPreview?.candidate_ids ?? {
        observations: [], assessments: [], package_pairs: [],
      });
      if (unmountedRef.current) return;
      if (!result.ok) {
        setOutdatedDataMessage({ text: result.error ?? "Failed to delete outdated data.", type: "error" });
        return;
      }
      setOutdatedDataPreview(null);
      setOutdatedDataMessage({ text: "Outdated data removed from every project and variant.", type: "success" });
      onDataChanged?.("Removing outdated data...");
      refreshStarted = Boolean(onDataChanged);
    } catch {
      if (!unmountedRef.current) setOutdatedDataMessage({ text: "Failed to delete outdated data.", type: "error" });
    } finally {
      if (!unmountedRef.current) {
        setDeletingOutdatedData(false);
        if (!refreshStarted) onLoadingMessage?.(null);
      }
    }
  };

  const openAdditionalCleanupConfirmation = async (kind: AdditionalCleanup["kind"]) => {
    setAdditionalCleanupBusy(true);
    setOutdatedDataMessage(null);
    try {
      if (kind === "empty-scans") {
        const result = await ScansHandler.getEmptyScansPreview();
        if (unmountedRef.current) return;
        if (!result.ok) setOutdatedDataMessage({ text: result.error ?? "Failed to load cleanup preview.", type: "error" });
        else if (!result.scans?.length) setOutdatedDataMessage({ text: "No empty scans were found.", type: "success" });
        else setPendingCleanup({ kind, scans: result.scans });
      } else {
        const result = await ScansHandler.getOrphanedVulnerabilitiesPreview();
        if (unmountedRef.current) return;
        if (!result.ok) setOutdatedDataMessage({ text: result.error ?? "Failed to load cleanup preview.", type: "error" });
        else if (!result.vulnerabilities?.length) setOutdatedDataMessage({ text: "No orphaned CVEs were found.", type: "success" });
        else setPendingCleanup({ kind, vulnerabilities: result.vulnerabilities });
      }
    } catch {
      if (!unmountedRef.current) setOutdatedDataMessage({ text: "Failed to load cleanup preview.", type: "error" });
    } finally {
      if (!unmountedRef.current) setAdditionalCleanupBusy(false);
    }
  };

  const handleAdditionalCleanup = async () => {
    if (!pendingCleanup) return;
    const cleanup = pendingCleanup;
    setPendingCleanup(null);
    setAdditionalCleanupBusy(true);
    setOutdatedDataMessage(null);
    onLoadingMessage?.(cleanup.kind === "empty-scans" ? "Deleting empty scans..." : "Deleting orphaned CVEs...");
    let refreshStarted = false;
    try {
      const result = cleanup.kind === "empty-scans"
        ? await ScansHandler.deleteEmptyScans(cleanup.scans.map((scan) => scan.id))
        : await ScansHandler.deleteOrphanedVulnerabilities(cleanup.vulnerabilities.map((vulnerability) => vulnerability.id));
      if (unmountedRef.current) return;
      if (!result.ok) {
        setOutdatedDataMessage({ text: result.error ?? "Cleanup failed.", type: "error" });
        return;
      }
      setOutdatedDataMessage({
        text: cleanup.kind === "empty-scans"
          ? `${result.count ?? 0} empty scan${result.count === 1 ? "" : "s"} deleted.`
          : `${result.count ?? 0} orphaned CVE${result.count === 1 ? "" : "s"} and their assessments deleted.`,
        type: "success",
      });
      onDataChanged?.("Refreshing data...");
      refreshStarted = Boolean(onDataChanged);
    } catch {
      if (!unmountedRef.current) setOutdatedDataMessage({ text: "Cleanup failed.", type: "error" });
    } finally {
      if (!unmountedRef.current) {
        setAdditionalCleanupBusy(false);
        if (!refreshStarted) onLoadingMessage?.(null);
      }
    }
  };

  // ---- Manage Projects ----
  const [renameProjectId, setRenameProjectId] = useState<string>("");
  const [renameProjectName, setRenameProjectName] = useState<string>("");
  const [renameProjectBusy, setRenameProjectBusy] = useState(false);
  const [renameProjectMsg, setRenameProjectMsg] = useState<FeedbackMsg>(null);
  const [newProjectName, setNewProjectName] = useState("");
  const [createProjectBusy, setCreateProjectBusy] = useState(false);
  const [addProjectMsg, setAddProjectMsg] = useState<FeedbackMsg>(null);
  const [confirmDeleteProject, setConfirmDeleteProject] = useState(false);
  const [deleteProjectBusy, setDeleteProjectBusy] = useState(false);
  const [deleteProjectMsg, setDeleteProjectMsg] = useState<FeedbackMsg>(null);

  const handleRenameProject = async () => {
    if (!renameProjectId || !renameProjectName.trim()) return;
    setRenameProjectBusy(true);
    setRenameProjectMsg(null);
    try {
      const updated = await Projects.rename(renameProjectId, renameProjectName.trim());
      loadProjects();
      setRenameProjectName(updated.name);
      setRenameProjectMsg({ text: "Project renamed.", type: "success" });
      onDataChanged?.("Renaming project...");
    } catch (e: any) {
      setRenameProjectMsg({ text: e.message, type: "error" });
    } finally {
      setRenameProjectBusy(false);
    }
  };

  const handleCreateProject = async () => {
    if (!newProjectName.trim()) return;
    setCreateProjectBusy(true);
    setAddProjectMsg(null);
    try {
      const created = await Projects.create(newProjectName.trim());
      setNewProjectName("");
      loadProjects();
      // Select the newly created project; success feedback shows in the management view that replaces this form
      setRenameProjectId(created.id);
      setRenameProjectName(created.name);
      setRenameProjectMsg({ text: `Project "${created.name}" created.`, type: "success" });
      onDataChanged?.("Creating project...");
    } catch (e: any) {
      setAddProjectMsg({ text: e.message, type: "error" });
    } finally {
      setCreateProjectBusy(false);
    }
  };

  const handleDeleteProject = async () => {
    if (!renameProjectId || deleteProjectBusy) return;
    setDeleteProjectBusy(true);
    setDeleteProjectMsg(null);
    try {
      await Projects.delete(renameProjectId);
      // Invalidate variant section (and its Import SBOM context) if it references the deleted project
      if (variantProjectId === renameProjectId) {
        setVariantProjectId("");
        setVariantProjectVariants([]);
        setRenameVariantId("");
        setRenameVariantName("");
      }
      setRenameProjectId("");
      setRenameProjectName("");
      setConfirmDeleteProject(false);
      loadProjects();
      onDataChanged?.("Deleting project...");
    } catch (e: any) {
      setDeleteProjectMsg({ text: e.message, type: "error" });
      setConfirmDeleteProject(false);
    } finally {
      setDeleteProjectBusy(false);
    }
  };

  // ---- Manage Variants ----
  const [variantProjectId, setVariantProjectId] = useState<string>("");
  const variantProjectIdRef = useRef(variantProjectId);
  const [variantProjectVariants, setVariantProjectVariants] = useState<Variant[]>([]);
  const [renameVariantId, setRenameVariantId] = useState<string>("");
  const [renameVariantName, setRenameVariantName] = useState<string>("");
  const [renameVariantBusy, setRenameVariantBusy] = useState(false);
  const [renameVariantMsg, setRenameVariantMsg] = useState<FeedbackMsg>(null);
  const [newVariantName, setNewVariantName] = useState("");
  const [createVariantBusy, setCreateVariantBusy] = useState(false);
  const [addVariantMsg, setAddVariantMsg] = useState<FeedbackMsg>(null);
  const [confirmDeleteVariant, setConfirmDeleteVariant] = useState(false);
  const [deleteVariantBusy, setDeleteVariantBusy] = useState(false);
  const [deleteVariantMsg, setDeleteVariantMsg] = useState<FeedbackMsg>(null);

  useEffect(() => {
    variantProjectIdRef.current = variantProjectId;
  }, [variantProjectId]);

  const reloadVariants = useCallback((projectId: string) => {
    if (!projectId) { setVariantProjectVariants([]); return; }
    Variants.list(projectId)
      .then(setVariantProjectVariants)
      .catch(() => setVariantProjectVariants([]));
  }, []);

  // Keeps the sidebar tree and Projects tab "Variants overview" list in sync with variant changes
  const reloadProjectVariants = useCallback((projectId: string) => {
    if (!projectId) return;
    Variants.list(projectId)
      .then((list) => setProjectVariants((prev) => ({ ...prev, [projectId]: list })))
      .catch(() => {});
  }, []);

  useEffect(() => {
    reloadVariants(variantProjectId);
  }, [variantProjectId, reloadVariants]);

  const handleRenameVariant = async () => {
    if (!renameVariantId || !renameVariantName.trim()) return;
    setRenameVariantBusy(true);
    setRenameVariantMsg(null);
    try {
      const updated = await Variants.rename(renameVariantId, renameVariantName.trim());
      reloadVariants(variantProjectId);
      reloadProjectVariants(variantProjectId);
      setRenameVariantName(updated.name);
      setRenameVariantMsg({ text: "Variant renamed.", type: "success" });
      onDataChanged?.("Renaming variant...");
    } catch (e: any) {
      setRenameVariantMsg({ text: e.message, type: "error" });
    } finally {
      setRenameVariantBusy(false);
    }
  };

  const handleCreateVariant = async () => {
    if (!newVariantName.trim() || !variantProjectId) return;
    const projectId = variantProjectId;
    const variantName = newVariantName.trim();
    setCreateVariantBusy(true);
    setAddVariantMsg(null);
    try {
      const created = await Variants.create(projectId, variantName);
      reloadProjectVariants(projectId);
      if (variantProjectIdRef.current !== projectId) return;
      setNewVariantName("");
      reloadVariants(projectId);
      // Select the newly created variant; success feedback shows in the management view that replaces this form
      setRenameVariantId(created.id);
      setRenameVariantName(created.name);
      setRenameVariantMsg({ text: `Variant "${created.name}" created.`, type: "success" });
      onDataChanged?.("Creating variant...");
    } catch (e: any) {
      setAddVariantMsg({ text: e.message, type: "error" });
    } finally {
      setCreateVariantBusy(false);
    }
  };

  const handleDeleteVariant = async () => {
    if (!renameVariantId || deleteVariantBusy) return;
    setDeleteVariantBusy(true);
    setDeleteVariantMsg(null);
    try {
      await Variants.delete(renameVariantId);
      setRenameVariantId("");
      setRenameVariantName("");
      setConfirmDeleteVariant(false);
      reloadVariants(variantProjectId);
      reloadProjectVariants(variantProjectId);
      // Return to the parent project view rather than an orphaned variant view
      const parent = projects.find((p) => p.id === variantProjectId);
      if (parent) {
        setRenameProjectId(parent.id);
        setRenameProjectName(parent.name);
      }
      setActiveTab("projects");
      onDataChanged?.("Deleting variant...");
    } catch (e: any) {
      setDeleteVariantMsg({ text: e.message, type: "error" });
      setConfirmDeleteVariant(false);
    } finally {
      setDeleteVariantBusy(false);
    }
  };

  // ---- Import SBOM (scoped to the variant selected in the Variants tab) ----
  const [importFiles, setImportFiles] = useState<File[]>([]);
  const [importBusy, setImportBusy] = useState(false);
  const [importMsg, setImportMsg] = useState<string | null>(null);
  const [importRefreshSources, setImportRefreshSources] = useState<Set<string>>(new Set(["epss"]));

  const clearImportState = () => {
    setImportFiles([]);
    setImportMsg(null);
  };

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
    if (!variantProjectId || !renameVariantId || importFiles.length === 0) return;
    setImportBusy(true);
    setImportMsg(null);
    const count = importFiles.length;
    onLoadingMessage?.(`Uploading ${count} file${count > 1 ? "s" : ""}...`);
    try {
      const result = await Variants.uploadSBOM(
        variantProjectId,
        renameVariantId,
        importFiles,
        Array.from(importRefreshSources),
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

  // ---- Styles ----
  const inputClass =
    "w-full rounded px-2 py-1.5 text-sm bg-slate-900/60 border border-slate-600 text-white focus:outline-none focus:border-cyan-400";
  const btnPrimary =
    "px-4 py-2 rounded-lg bg-cyan-800 hover:bg-cyan-700 focus:ring-4 focus:outline-none focus:ring-blue-800 text-white text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-colors duration-150";
  // ---- Card styles: gradient header + slate body with ring & shadow ----
  const cardHeader =
    "bg-gradient-to-r from-slate-700 to-slate-800 px-4 py-2.5 flex items-center gap-2 rounded-t-lg border-b border-slate-600/60";
  const cardBody =
    "bg-slate-800/60 p-4 rounded-b-lg ring-1 ring-slate-700/70 shadow-lg shadow-black/20";
  // ---- Danger zone card styles: red-tinted header for destructive actions ----
  const dangerCardHeader =
    "bg-gradient-to-r from-red-950 to-slate-800 px-4 py-2.5 flex items-center gap-2 rounded-t-lg border-b border-red-900/60";
  const dangerCardBody =
    "bg-slate-800/60 p-4 rounded-b-lg ring-1 ring-red-900/50 shadow-lg shadow-black/20";

  // ---- Breadcrumb / title context, driven by whichever project or variant is in scope ----
  const contextProject = projects.find((p) => p.id === (activeTab === "variants" ? variantProjectId : renameProjectId));
  const contextVariant = variantProjectVariants.find((v) => v.id === renameVariantId);
  const crumbs: string[] = ["Settings"];
  let pageTitle = "General Settings";
  let pageTag: { label: string; className: string } | null = null;
  if (activeTab === "projects") {
    crumbs.push("Projects");
    pageTitle = contextProject?.name ?? "Add Project";
    if (contextProject) {
      crumbs.push(contextProject.name);
      pageTag = { label: "Project", className: "bg-cyan-950 text-cyan-300" };
    }
  } else if (activeTab === "variants") {
    crumbs.push(contextProject?.name ?? "Variants");
    if (contextVariant || renameVariantId) {
      pageTitle = contextVariant?.name ?? renameVariantName;
      crumbs.push(pageTitle);
      pageTag = { label: "Variant", className: "bg-violet-950 text-violet-300" };
    } else {
      pageTitle = variantProjectId ? "Add Variant" : "Variants";
      if (variantProjectId) crumbs.push("Add Variant");
    }
  } else if (activeTab === "transfer") {
    crumbs.push("Transfer");
    pageTitle = "Transfer Assessments";
  } else {
    crumbs.push("General Settings");
  }

  return (
    <div className="w-full">
      <div className="grid items-start gap-6 xl:grid-cols-[17.5rem_minmax(0,1fr)]">
        <aside className="overflow-hidden rounded-lg border border-slate-700 bg-slate-800 shadow-lg shadow-black/20 xl:sticky xl:top-4">
          <div className="flex items-center justify-between border-b border-slate-700 px-4 py-3">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Settings</span>
          </div>
          <nav aria-label="Settings navigation" className="p-2">
            <button
              type="button"
              onClick={() => setActiveTab("general")}
              aria-current={activeTab === "general" ? "page" : undefined}
              className={`flex w-full items-center gap-3 rounded-md px-3 py-2 text-left text-sm transition-colors ${
                activeTab === "general" ? "bg-sky-900 text-white" : "text-slate-300 hover:bg-slate-700 hover:text-white"
              }`}
            >
              <FontAwesomeIcon icon={faGear} className="w-4 text-sky-400" aria-hidden="true" />
              General Settings
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("transfer")}
              aria-current={activeTab === "transfer" ? "page" : undefined}
              className={`mt-1 flex w-full items-center gap-3 rounded-md px-3 py-2 text-left text-sm transition-colors ${
                activeTab === "transfer" ? "bg-sky-900 text-white" : "text-slate-300 hover:bg-slate-700 hover:text-white"
              }`}
            >
              <FontAwesomeIcon icon={faRightLeft} className="w-4 text-sky-400" aria-hidden="true" />
              Transfer Assessments
            </button>

            <div className="my-3 border-t border-slate-700" />
            <div className="flex items-center justify-between px-3 pb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-500">Projects</span>
              <button
                type="button"
                onClick={startNewProject}
                className="flex h-6 w-6 items-center justify-center rounded border border-dashed border-sky-500 text-sky-400 transition-colors hover:bg-sky-900"
                aria-label="Add project"
                title="Add project"
              >
                <FontAwesomeIcon icon={faPlus} aria-hidden="true" />
              </button>
            </div>

            <div className="space-y-1">
              {projects.map((project) => {
                const variants = projectVariants[project.id] ?? [];
                const isExpanded = expandedProjectIds.has(project.id);
                const isSelected =
                  (activeTab === "projects" && renameProjectId === project.id) ||
                  (activeTab === "variants" && variantProjectId === project.id && !renameVariantId);

                return (
                  <div key={project.id}>
                    <div className={`flex items-center rounded-md ${isSelected ? "bg-sky-900" : "hover:bg-slate-700"}`}>
                      <button
                        type="button"
                        onClick={() => toggleProject(project.id)}
                        className="flex h-8 w-8 shrink-0 items-center justify-center text-slate-400 hover:text-sky-300"
                        aria-label={`${isExpanded ? "Collapse" : "Expand"} ${project.name}`}
                        aria-expanded={isExpanded}
                      >
                        <FontAwesomeIcon icon={isExpanded ? faChevronDown : faChevronRight} className="text-xs" aria-hidden="true" />
                      </button>
                      <button
                        type="button"
                        onClick={() => selectProjectFromTree(project)}
                        className="flex min-w-0 flex-1 items-center gap-2 py-2 pr-3 text-left text-sm text-slate-200"
                      >
                        <FontAwesomeIcon icon={faFolder} className="text-sky-400" aria-hidden="true" />
                        <span className="truncate">{project.name}</span>
                        <span className="ml-auto rounded-full bg-slate-700 px-2 py-0.5 text-xs text-sky-200">{variants.length}</span>
                      </button>
                    </div>
                    {isExpanded && (
                      <div className="ml-4 border-l border-slate-700 pl-2">
                        {variants.map((variant) => (
                          <button
                            type="button"
                            key={variant.id}
                            onClick={() => selectVariantFromTree(project.id, variant)}
                            className={`mt-1 flex w-full items-center gap-2 rounded-md px-3 py-1.5 text-left text-sm transition-colors ${
                              activeTab === "variants" && variantProjectId === project.id && renameVariantId === variant.id
                                ? "bg-violet-950 text-white"
                                : "text-slate-400 hover:bg-slate-700 hover:text-white"
                            }`}
                          >
                            <span className="h-2 w-2 rounded-full bg-violet-400" aria-hidden="true" />
                            <span className="truncate">{variant.name}</span>
                          </button>
                        ))}
                        <button
                          type="button"
                          onClick={() => startNewVariant(project.id)}
                          className="mt-1 flex w-full items-center gap-2 rounded-md border border-dashed border-slate-600 px-3 py-1.5 text-left text-xs italic text-slate-500 transition-colors hover:border-sky-500 hover:text-sky-400"
                        >
                          <FontAwesomeIcon icon={faPlus} className="text-[10px]" aria-hidden="true" />
                          Add variant…
                        </button>
                      </div>
                    )}
                  </div>
                );
              })}
              <button
                type="button"
                onClick={startNewProject}
                className="mt-2 flex w-full items-center gap-2 rounded-md border border-dashed border-slate-600 px-3 py-2 text-left text-xs italic text-slate-500 transition-colors hover:border-sky-500 hover:text-sky-400"
              >
                <FontAwesomeIcon icon={faPlus} className="text-[10px]" aria-hidden="true" />
                New Project
              </button>
            </div>
          </nav>
        </aside>

        <main className="min-w-0 space-y-6">
          <header className="border-b border-slate-700 pb-4">
            <p className="text-xs font-medium text-slate-500">{crumbs.join(" / ")}</p>
            <h1 className="mt-1 flex items-center gap-3 text-2xl font-bold text-white">
              {pageTitle}
              {pageTag && (
                <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${pageTag.className}`}>
                  {pageTag.label}
                </span>
              )}
            </h1>
          </header>

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
            <FontAwesomeIcon icon={faFolderOpen} className="text-cyan-400" aria-hidden="true" />
            <h2 id="settings-heading-nvd" className="text-xl font-bold text-white">NVD API Key</h2>
          </div>
          <div className={cardBody + " space-y-3"}>
            <p id="nvd-key-description" className="text-zinc-400 text-sm">
              An NVD API key increases the rate limit for vulnerability enrichment from 5 to 50 requests per 30 seconds
              when using NVD REST API mode. Required only when NVD data source is set to <strong>NVD REST API</strong>.{' '}
              <a
                className="text-cyan-400 hover:text-cyan-300 underline"
                href="https://nvd.nist.gov/developers/request-an-api-key"
                target="_blank"
                rel="noopener noreferrer"
              >
                nvd.nist.gov
              </a>
            </p>
            {nvdMsg && (
              <div className={`text-sm rounded px-3 py-2 ${nvdMsg.type === "success" ? "bg-green-900/40 text-green-300" : "bg-red-900/40 text-red-300"}`}>
                {nvdMsg.text}
              </div>
            )}
            {nvdHasKey && !nvdEditing ? (
              <div className="flex items-center gap-3 flex-wrap">
                <span className="text-sm text-zinc-300">NVD API key:</span>
                <code className="text-sm text-zinc-300 bg-slate-900 px-2 py-0.5 rounded font-mono">{nvdMaskedKey}</code>
                <button
                  type="button"
                  onClick={() => { setNvdEditing(true); setNvdMsg(null); }}
                  disabled={nvdBusy}
                  className={btnPrimary + " text-xs py-1 px-3"}
                >
                  Change
                </button>
                <button
                  type="button"
                  onClick={() => setConfirmRemoveNvdKey(true)}
                  disabled={nvdBusy}
                  className="px-3 py-1 rounded text-xs font-semibold bg-red-800 hover:bg-red-700 text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  Remove
                </button>
              </div>
            ) : (
              <div className="space-y-2">
                <label htmlFor="nvd-api-key-input" className="block text-sm text-zinc-300 font-semibold">
                  {nvdEditing ? "New API Key" : "API Key"}
                </label>
                <input
                  id="nvd-api-key-input"
                  type="password"
                  value={nvdKeyInput}
                  onChange={(e) => setNvdKeyInput(e.target.value)}
                  placeholder="Paste your NVD API key..."
                  className={inputClass}
                  disabled={nvdBusy}
                  aria-describedby="nvd-key-description"
                />
                <div className="flex items-center gap-2">
                  <button
                    type="button"
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
                    Save key
                  </button>
                  {nvdEditing && (
                    <button
                      type="button"
                      onClick={() => { setNvdEditing(false); setNvdKeyInput(""); setNvdMsg(null); }}
                      disabled={nvdBusy}
                      className="px-4 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-white text-sm font-semibold disabled:opacity-40 transition-colors"
                    >
                      Cancel
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        </section>

        {/* ======== Grype Scanner ======== */}
        <section aria-labelledby="settings-heading-grype">
          <div className={cardHeader}>
            <FontAwesomeIcon icon={faBug} className="text-cyan-400" aria-hidden="true" />
            <h2 id="settings-heading-grype" className="text-xl font-bold text-white">Grype Scanner</h2>
          </div>
          <div className={cardBody + " space-y-4"}>

            {/* ---- GRYPE_MEMLIMIT ---- */}
            <div className="space-y-2">
              <label htmlFor="grype-memlimit-input" className="block text-sm text-zinc-300 font-semibold">
                Memory Limit <span className="font-normal text-zinc-500">(GRYPE_MEMLIMIT)</span>
              </label>
              <p className="text-zinc-400 text-sm">
                Caps the RAM used by the Grype binary via Go's soft memory limit (<code className="text-zinc-300 bg-slate-900 px-1 rounded text-xs">GOMEMLIMIT</code>).
                Leave blank to use the auto-default: <strong className="text-zinc-300">~80 % of the container/cgroup memory limit</strong>,
                which prevents OOM kills in CI without any configuration.
                Set to <code className="text-zinc-300 bg-slate-900 px-1 rounded text-xs">off</code> to disable the cap entirely.
              </p>
              <input
                id="grype-memlimit-input"
                type="text"
                value={grypeMemlimitInput}
                onChange={(e) => { setGrypeMemlimitInput(e.target.value); setGrypeMemlimitMsg(null); }}
                placeholder="auto (leave blank) · e.g. 4GiB · 512MiB · 1073741824 · off"
                className={inputClass}
                disabled={grypeMemlimitBusy}
                autoComplete="off"
                spellCheck={false}
                aria-describedby="grype-memlimit-hint"
              />
              <p id="grype-memlimit-hint" className="text-zinc-500 text-xs">
                Valid values: Go memory strings (<code className="bg-slate-900 px-0.5 rounded">4GiB</code>,{" "}
                <code className="bg-slate-900 px-0.5 rounded">512MiB</code>,{" "}
                <code className="bg-slate-900 px-0.5 rounded">1073741824</code>),{" "}
                <code className="bg-slate-900 px-0.5 rounded">off</code> / <code className="bg-slate-900 px-0.5 rounded">disabled</code> to remove the cap,
                or blank to restore the auto-default.
              </p>
            </div>

            {/* ---- Feedback ---- */}
            {grypeMemlimitMsg && (
              <MessageBanner
                type={grypeMemlimitMsg.type}
                message={grypeMemlimitMsg.text}
                isVisible={true}
                onClose={() => setGrypeMemlimitMsg(null)}
              />
            )}

            {/* ---- Submit ---- */}
            <div className="flex items-center gap-3 pt-1">
              <button
                onClick={handleSaveGrypeSetting}
                disabled={grypeMemlimitBusy}
                className={btnPrimary}
                aria-busy={grypeMemlimitBusy}
              >
                {grypeMemlimitBusy ? (
                  <FontAwesomeIcon icon={faSpinner} spin className="mr-1" aria-hidden="true" />
                ) : (
                  <FontAwesomeIcon icon={faCheck} className="mr-1" aria-hidden="true" />
                )}
                Save
              </button>
            </div>
          </div>
        </section>

        <section aria-labelledby="settings-heading-outdated-data" aria-busy={maintenanceBusy}>
          <div className={cardHeader}>
            <FontAwesomeIcon icon={faTrash} className="text-red-400" aria-hidden="true" />
            <h2 id="settings-heading-outdated-data" className="text-xl font-bold text-white">Data Maintenance</h2>
          </div>
          <div className={cardBody + " space-y-3"}>
            <p className="text-sm text-zinc-400">Permanently remove redundant or unreferenced records across every project and variant.</p>
            {outdatedDataMessage && (
              <MessageBanner type={outdatedDataMessage.type} message={outdatedDataMessage.text} isVisible={true} onClose={() => setOutdatedDataMessage(null)} />
            )}
            {maintenanceStatus && (
              <div role="status" aria-live="polite" className="flex items-center gap-2 text-sm font-medium text-cyan-300">
                <FontAwesomeIcon icon={faSpinner} spin aria-hidden="true" />
                <span>Maintenance Scan</span>
                <span className="text-zinc-400">{maintenanceStatus}</span>
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              <button type="button" onClick={openDeleteOutdatedDataConfirmation} disabled={maintenanceBusy} className="px-4 py-2 rounded-lg bg-red-800 hover:bg-red-700 focus:ring-4 focus:outline-none focus:ring-red-900 text-white text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                <FontAwesomeIcon icon={faTrash} className="mr-1" aria-hidden="true" /> Analyze outdated data
              </button>
              <button type="button" onClick={() => openAdditionalCleanupConfirmation("empty-scans")} disabled={maintenanceBusy} className="px-4 py-2 rounded-lg bg-red-800 hover:bg-red-700 focus:ring-4 focus:outline-none focus:ring-red-900 text-white text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                <FontAwesomeIcon icon={faTrash} className="mr-1" aria-hidden="true" /> Analyze empty scans
              </button>
              <button type="button" onClick={() => openAdditionalCleanupConfirmation("orphaned-vulnerabilities")} disabled={maintenanceBusy} className="px-4 py-2 rounded-lg bg-red-800 hover:bg-red-700 focus:ring-4 focus:outline-none focus:ring-red-900 text-white text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                <FontAwesomeIcon icon={faTrash} className="mr-1" aria-hidden="true" /> Analyze orphaned CVEs
              </button>
            </div>
          </div>
        </section>

        </>)
        }

        {/* ======== Projects Settings tab ======== */}
        {activeTab === "projects" && (
        <>
        {/* ======== Add Project (only when no project is selected) ======== */}
        {!contextProject && (
        <section aria-labelledby="settings-heading-project-add">
          <div className={cardHeader}>
            <FontAwesomeIcon icon={faPlus} className="text-cyan-400" aria-hidden="true" />
            <h2 id="settings-heading-project-add" className="text-xl font-bold text-white">Add Project</h2>
          </div>
          <div className={cardBody + " space-y-4"}>
            <div className="space-y-2">
              <label htmlFor="new-project-name" className="block text-sm text-zinc-300 font-semibold">Project name</label>
              <div className="flex gap-2">
                <input
                  id="new-project-name"
                  type="text"
                  value={newProjectName}
                  onChange={(e) => { setNewProjectName(e.target.value); setAddProjectMsg(null); }}
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
            {addProjectMsg && (
              <MessageBanner
                type={addProjectMsg.type}
                message={addProjectMsg.text}
                isVisible={true}
                onClose={() => setAddProjectMsg(null)}
              />
            )}
          </div>
        </section>
        )}

        {contextProject && (
        <>
        {/* ======== Variants overview ======== */}
        <section aria-labelledby="settings-heading-project-variants">
          <div className={cardHeader}>
            <FontAwesomeIcon icon={faFolder} className="text-cyan-400" aria-hidden="true" />
            <h2 id="settings-heading-project-variants" className="text-xl font-bold text-white">Variants</h2>
            <button
              type="button"
              onClick={() => startNewVariant(contextProject.id)}
              className={btnPrimary + " ml-auto py-1.5 text-xs"}
            >
              <FontAwesomeIcon icon={faPlus} className="mr-1" aria-hidden="true" />
              Add Variant
            </button>
          </div>
          <div className={cardBody + " space-y-2"}>
            {(projectVariants[contextProject.id] ?? []).map((v) => (
              <div
                key={v.id}
                className="flex items-center justify-between gap-3 rounded-lg border border-slate-600 bg-slate-900/60 px-3 py-2 text-sm text-zinc-200"
              >
                <span className="flex min-w-0 items-center gap-2">
                  <span className="h-2 w-2 shrink-0 rounded-full bg-violet-400" aria-hidden="true" />
                  <span className="truncate">{v.name}</span>
                </span>
                <div className="flex shrink-0 items-center gap-1">
                  <button
                    type="button"
                    onClick={() => selectVariantFromTree(contextProject.id, v)}
                    className="flex h-8 w-8 items-center justify-center rounded text-zinc-400 transition-colors hover:bg-slate-700 hover:text-sky-300"
                    aria-label={`Edit ${v.name}`}
                    title="Edit variant"
                  >
                    <FontAwesomeIcon icon={faPenToSquare} aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    onClick={() => requestDeleteVariant(contextProject.id, v)}
                    className="flex h-8 w-8 items-center justify-center rounded text-zinc-400 transition-colors hover:bg-red-950 hover:text-red-400"
                    aria-label={`Delete ${v.name}`}
                    title="Delete variant"
                  >
                    <FontAwesomeIcon icon={faTrash} aria-hidden="true" />
                  </button>
                </div>
              </div>
            ))}
            {(projectVariants[contextProject.id] ?? []).length === 0 && (
              <span className="text-sm text-zinc-500">No variants yet.</span>
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
            <div className="space-y-2">
              <label htmlFor="rename-project-name" className="block text-sm text-zinc-300 font-semibold">New name</label>
              <div className="flex gap-2">
                <input
                  id="rename-project-name"
                  type="text"
                  value={renameProjectName}
                  onChange={(e) => { setRenameProjectName(e.target.value); setRenameProjectMsg(null); }}
                  placeholder="Enter new name"
                  className={inputClass + " flex-1"}
                  aria-required="true"
                  onKeyDown={(e) => e.key === "Enter" && handleRenameProject()}
                />
                <button
                  onClick={handleRenameProject}
                  disabled={renameProjectBusy || !renameProjectName.trim() || renameProjectName.trim() === contextProject.name}
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
            {renameProjectMsg && (
              <MessageBanner
                type={renameProjectMsg.type}
                message={renameProjectMsg.text}
                isVisible={true}
                onClose={() => setRenameProjectMsg(null)}
              />
            )}
          </div>
        </section>

        {/* ======== Danger Zone ======== */}
        <section aria-labelledby="settings-heading-project-delete">
          <div className={dangerCardHeader}>
            <FontAwesomeIcon icon={faTrash} className="text-red-400" aria-hidden="true" />
            <h2 id="settings-heading-project-delete" className="text-xl font-bold text-red-300">Danger Zone</h2>
          </div>
          <div className={dangerCardBody + " space-y-3"}>
            <div className="flex items-center gap-4 flex-wrap">
              <div className="flex-1 min-w-[16rem]">
                <p className="text-sm font-semibold text-red-300">Delete Project</p>
                <p className="text-xs text-zinc-400">
                  Permanently removes <strong className="text-zinc-300">{contextProject.name}</strong> and all its variants.
                </p>
              </div>
              <button
                onClick={() => setConfirmDeleteProject(true)}
                className="px-4 py-2 rounded-lg bg-red-900 hover:bg-red-800 text-white text-sm font-medium transition-colors duration-150"
              >
                <FontAwesomeIcon icon={faTrash} className="mr-1" aria-hidden="true" />
                Delete Project
              </button>
            </div>

            {/* -- Feedback -- */}
            {deleteProjectMsg && (
              <MessageBanner
                type={deleteProjectMsg.type}
                message={deleteProjectMsg.text}
                isVisible={true}
                onClose={() => setDeleteProjectMsg(null)}
              />
            )}
          </div>
        </section>
        </>
        )}
        </>
        )}

        {activeTab === "transfer" && (
          <Transfer projectId={projectId} onDataChanged={onDataChanged} />
        )}

        {/* ======== Variants Settings tab ======== */}
        {activeTab === "variants" && !variantProjectId && (
        <section aria-labelledby="settings-heading-variant-empty">
          <div className={cardHeader}>
            <FontAwesomeIcon icon={faFolder} className="text-cyan-400" aria-hidden="true" />
            <h2 id="settings-heading-variant-empty" className="text-xl font-bold text-white">Variants</h2>
          </div>
          <div className={cardBody}>
            <p className="text-sm text-zinc-400">Select a variant from the sidebar, or expand a project and use “Add variant…” to create one.</p>
          </div>
        </section>
        )}

        {activeTab === "variants" && variantProjectId && !renameVariantId && (
        <>
        {/* ======== Add Variant ======== */}
        <section aria-labelledby="settings-heading-variant-add">
          <div className={cardHeader}>
            <FontAwesomeIcon icon={faPlus} className="text-cyan-400" aria-hidden="true" />
            <h2 id="settings-heading-variant-add" className="text-xl font-bold text-white">Add Variant</h2>
          </div>
          <div className={cardBody + " space-y-4"}>
            <p className="text-sm text-zinc-400">
              New variant in project <strong className="text-zinc-300">{contextProject?.name ?? ""}</strong>.
            </p>
            <div className="space-y-2">
              <label htmlFor="new-variant-name" className="block text-sm text-zinc-300 font-semibold">Variant name</label>
              <div className="flex gap-2">
                <input
                  id="new-variant-name"
                  type="text"
                  value={newVariantName}
                  onChange={(e) => { setNewVariantName(e.target.value); setAddVariantMsg(null); }}
                  placeholder="New variant name"
                  className={inputClass + " flex-1"}
                  aria-required="true"
                  onKeyDown={(e) => e.key === "Enter" && handleCreateVariant()}
                />
                <button
                  onClick={handleCreateVariant}
                  disabled={createVariantBusy || !newVariantName.trim()}
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
            {addVariantMsg && (
              <MessageBanner
                type={addVariantMsg.type}
                message={addVariantMsg.text}
                isVisible={true}
                onClose={() => setAddVariantMsg(null)}
              />
            )}
          </div>
        </section>
        </>
        )}

        {activeTab === "variants" && variantProjectId && renameVariantId && (
        <>
        {/* ======== Import SBOM ======== */}
        <section aria-labelledby="settings-heading-import">
          <div className={cardHeader}>
            <FontAwesomeIcon icon={faFileImport} className="text-cyan-400" aria-hidden="true" />
            <h2 id="settings-heading-import" className="text-xl font-bold text-white">Import SBOM</h2>
          </div>
          <div className={cardBody + " space-y-3"}>
            <p className="text-sm text-zinc-400">
              Files are imported into <strong className="text-zinc-300">{contextVariant?.name ?? renameVariantName}</strong>.
            </p>

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
                accept=".json,.spdx,.cdx,.xml,.tar,.tar.gz,.tgz,.tar.zst"
                onChange={(e) => handleFileSelected(importFiles.length, e.target.files?.[0] ?? null)}
                disabled={importBusy}
                aria-labelledby="sbom-files-label"
                className={
                  inputClass +
                  " disabled:opacity-50 disabled:cursor-not-allowed file:mr-3 file:py-1 file:px-3 file:rounded-lg file:border-0 file:text-sm file:font-semibold file:bg-cyan-900 file:text-cyan-300 hover:file:bg-cyan-800"
                }
              />
              <p className="text-xs text-zinc-400">
                Accepts JSON SBOMs (SPDX, CycloneDX, OpenVEX, Grype, Yocto) or tar archives
                (<code>.tar</code>, <code>.tar.gz</code>, <code>.tar.zst</code>) used for SPDX2.
              </p>
            </div>

            <fieldset className="space-y-2">
              <legend className="block text-sm text-zinc-300 mb-1">Refresh vulnerability data</legend>
              <div className="flex flex-wrap gap-x-5 gap-y-2">
                {(["epss", "nvd", "euvd", "ghsa"] as const).map((source) => (
                  <label key={source} className="flex items-center gap-2 text-sm text-zinc-200 cursor-pointer">
                    <input
                      type="checkbox"
                      aria-label={source.toUpperCase()}
                      checked={importRefreshSources.has(source)}
                      disabled={importBusy}
                      onChange={() => setImportRefreshSources((previous) => {
                        const next = new Set(previous);
                        if (next.has(source)) next.delete(source); else next.add(source);
                        return next;
                      })}
                      className="rounded accent-cyan-500"
                    />
                    {source.toUpperCase()}
                  </label>
                ))}
              </div>
            </fieldset>

            {/* ---- Submit ---- */}
            <div className="space-y-2 pt-1">
              <button
                onClick={handleUploadSBOM}
                disabled={importBusy || importFiles.length === 0}
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
                <MessageBanner
                  type="error"
                  message={importMsg}
                  isVisible={true}
                  onClose={() => setImportMsg(null)}
                />
              )}
            </div>
          </div>
        </section>

        {/* ======== Rename Variant ======== */}
        <section aria-labelledby="settings-heading-variant-rename">
          <div className={cardHeader}>
            <FontAwesomeIcon icon={faPenToSquare} className="text-cyan-400" aria-hidden="true" />
            <h2 id="settings-heading-variant-rename" className="text-xl font-bold text-white">Rename Variant</h2>
          </div>
          <div className={cardBody + " space-y-4"}>
            <div className="space-y-2">
              <label htmlFor="rename-variant-name" className="block text-sm text-zinc-300 font-semibold">New name</label>
              <div className="flex gap-2">
                <input
                  id="rename-variant-name"
                  type="text"
                  value={renameVariantName}
                  onChange={(e) => { setRenameVariantName(e.target.value); setRenameVariantMsg(null); }}
                  placeholder="Enter new name"
                  className={inputClass + " flex-1"}
                  aria-required="true"
                  onKeyDown={(e) => e.key === "Enter" && handleRenameVariant()}
                />
                <button
                  onClick={handleRenameVariant}
                  disabled={
                    renameVariantBusy ||
                    !renameVariantName.trim() ||
                    renameVariantName.trim() === contextVariant?.name
                  }
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
            {renameVariantMsg && (
              <MessageBanner
                type={renameVariantMsg.type}
                message={renameVariantMsg.text}
                isVisible={true}
                onClose={() => setRenameVariantMsg(null)}
              />
            )}
          </div>
        </section>

        {/* ======== Danger Zone ======== */}
        <section aria-labelledby="settings-heading-variant-delete">
          <div className={dangerCardHeader}>
            <FontAwesomeIcon icon={faTrash} className="text-red-400" aria-hidden="true" />
            <h2 id="settings-heading-variant-delete" className="text-xl font-bold text-red-300">Danger Zone</h2>
          </div>
          <div className={dangerCardBody + " space-y-3"}>
            <div className="flex items-center gap-4 flex-wrap">
              <div className="flex-1 min-w-[16rem]">
                <p className="text-sm font-semibold text-red-300">Delete Variant</p>
                <p className="text-xs text-zinc-400">
                  Permanently removes <strong className="text-zinc-300">{contextVariant?.name ?? renameVariantName}</strong> and all its data.
                </p>
              </div>
              <button
                onClick={() => setConfirmDeleteVariant(true)}
                className="px-4 py-2 rounded-lg bg-red-900 hover:bg-red-800 text-white text-sm font-medium transition-colors duration-150"
              >
                <FontAwesomeIcon icon={faTrash} className="mr-1" aria-hidden="true" />
                Delete Variant
              </button>
            </div>

            {/* -- Feedback -- */}
            {deleteVariantMsg && (
              <MessageBanner
                type={deleteVariantMsg.type}
                message={deleteVariantMsg.text}
                isVisible={true}
                onClose={() => setDeleteVariantMsg(null)}
              />
            )}
          </div>
        </section>

        </>
        )}
        </main>
      </div>


      {/* ======== Confirmation Modals ======== */}
      <ConfirmationModal
        isOpen={confirmDeleteProject}
        title="Delete Project"
        message={`Are you sure you want to delete "${contextProject?.name ?? "this project"}" and all its variants? This action cannot be undone.`}
        confirmText="Yes, delete"
        cancelText="Cancel"
        showTitleIcon={true}
        onConfirm={handleDeleteProject}
        onCancel={() => setConfirmDeleteProject(false)}
      />
      <ConfirmationModal
        isOpen={confirmDeleteVariant}
        title="Delete Variant"
        message={`Are you sure you want to delete "${contextVariant?.name ?? renameVariantName ?? "this variant"}" and all its data? This action cannot be undone.`}
        confirmText="Yes, delete"
        cancelText="Cancel"
        showTitleIcon={true}
        onConfirm={handleDeleteVariant}
        onCancel={() => setConfirmDeleteVariant(false)}
      />
      <ConfirmationModal
        isOpen={confirmRemoveNvdKey}
        title="Remove NVD API Key"
        message="Are you sure you want to remove the NVD API key? Vulnerability enrichment will fall back to the lower rate limit when using NVD REST API mode."
        confirmText="Remove"
        cancelText="Cancel"
        showTitleIcon={true}
        onConfirm={handleRemoveNvdKey}
        onCancel={() => setConfirmRemoveNvdKey(false)}
      />
      <Popup
        isOpen={pendingCleanup !== null}
        title={pendingCleanup?.kind === "empty-scans" ? "Delete Empty Scans" : "Delete Orphaned CVEs"}
        onClose={() => setPendingCleanup(null)}
      >
        {pendingCleanup?.kind === "empty-scans" ? (
          <div className="space-y-4">
            <p className="text-sm text-zinc-300">The following scans will be permanently deleted.</p>
            <ul className="max-h-[45vh] space-y-2 overflow-y-auto" aria-label="Empty scans deletion plan">
              {pendingCleanup.scans.map((scan) => (
                <li key={scan.id} className="rounded border border-slate-600 p-3 text-sm text-zinc-200">
                  <div className="font-semibold">{scan.project} / {scan.variant}</div>
                  <div className="mt-1 text-zinc-400">{scan.description || "No description"}</div>
                </li>
              ))}
            </ul>
            <div className="flex justify-end gap-3"><button type="button" onClick={() => setPendingCleanup(null)} className="px-4 py-2 text-sm text-zinc-300">Cancel</button><button type="button" onClick={handleAdditionalCleanup} className="rounded-lg bg-red-700 px-4 py-2 text-sm font-semibold text-white hover:bg-red-800">Delete empty scans</button></div>
          </div>
        ) : pendingCleanup ? (
          <div className="space-y-4">
            <p className="text-sm text-zinc-300">The following CVEs and their assessments will be permanently deleted.</p>
            <ul className="max-h-[45vh] space-y-2 overflow-y-auto" aria-label="Orphaned CVEs deletion plan">
              {pendingCleanup.vulnerabilities.map((vulnerability) => <li key={vulnerability.id} className="rounded border border-slate-600 p-3 text-sm text-zinc-200">{vulnerability.id} ({vulnerability.assessments} assessments)</li>)}
            </ul>
            <div className="flex justify-end gap-3"><button type="button" onClick={() => setPendingCleanup(null)} className="px-4 py-2 text-sm text-zinc-300">Cancel</button><button type="button" onClick={handleAdditionalCleanup} className="rounded-lg bg-red-700 px-4 py-2 text-sm font-semibold text-white hover:bg-red-800">Delete orphaned CVEs</button></div>
          </div>
        ) : null}
      </Popup>
      <ConfirmationModal
        isOpen={confirmDeleteOutdatedData}
        title="Delete Outdated Data"
        message={loadingOutdatedDataPreview ? "Loading deletion plan..." : outdatedDataPreview ? `Delete ${outdatedDataPreview.packages.length} outdated package records and ${outdatedDataPreview.assessments.length} outdated assessments?` : "No outdated data was found."}
        confirmText="Delete outdated data"
        cancelText="Cancel"
        showTitleIcon={true}
        onConfirm={handleDeleteOutdatedData}
        onCancel={() => { setConfirmDeleteOutdatedData(false); setOutdatedDataPreview(null); }}
      />
    </div>
  );
}

export default Settings;


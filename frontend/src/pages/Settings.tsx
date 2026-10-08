import { useState, useEffect, useCallback, useRef } from "react";
import { useLocation, useNavigate } from "react-router-dom";
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
  faCircleQuestion,
  faFileExport,
} from "@fortawesome/free-solid-svg-icons";
import Projects from "../handlers/project";
import type { Project } from "../handlers/project";
import Variants from "../handlers/variant";
import { waitForOperation } from "../handlers/operationStore";
import type { Variant } from "../handlers/variant";
import Config from "../handlers/config";
import NvdApiKey from "../handlers/nvdApiKey";
import ScansHandler from "../handlers/scans";
import type { EmptyScanPreview, OrphanedVulnerabilityPreview, OutdatedDataPreview } from "../handlers/scans";
import ConfirmationModal from "../components/ConfirmationModal";
import InlineAddInput from "../components/InlineAddInput";
import MessageBanner from "../components/MessageBanner";
import ModalShell from "../components/ModalShell";
import Transfer from "./Transfer";
import NotFound from "./NotFound";
import { ROUTES, SETTINGS_PATHS, parseSettingsPath, settingsProjectPath, settingsVariantPath } from "../routes";
import type { RefreshType } from "../helpers/refreshSources";
import {
  allVulnerabilityRefreshTypes,
  resolveRefreshSources,
  vulnerabilityRefreshSources,
} from "../helpers/refreshSources";
import type { RefreshMode } from "../helpers/refreshSources";
import CustomExportContentManager from "../components/CustomExportContentManager";
import type { AgentViewContext } from "../types/agent";

type Props = {
  onAgentContextChange?: (context: AgentViewContext) => void;
  onDataChanged?: (message?: string) => void;
  onLoadingMessage?: (message: string | null) => void;
  projectId?: string;
};

/** Navigation state understood by the Settings page. */
export type SettingsNavState = { settingsFlash?: string; openNewProject?: boolean };

type FeedbackMsg = { text: string; type: "success" | "error" } | null;
type AddKey = "project" | `tree-variant:${string}` | "page-variant" | null;
type AdditionalCleanup =
  | { kind: "empty-scans"; scans: EmptyScanPreview[] }
  | { kind: "orphaned-vulnerabilities"; vulnerabilities: OrphanedVulnerabilityPreview[] };

function nextRequest(seqs: Record<string, number>, key: string) {
  seqs[key] = (seqs[key] ?? 0) + 1;
  return seqs[key];
}

function Settings({ onDataChanged, onLoadingMessage, projectId, onAgentContextChange }: Readonly<Props>) {
  // ---- Section, project and variant come from the URL ----
  const location = useLocation();
  const navigate = useNavigate();
  const route = parseSettingsPath(location.pathname);
  const selectedProjectId = route.kind === "project" || route.kind === "variant" ? route.projectId : "";
  const selectedVariantId = route.kind === "variant" ? route.variantId : "";
  const navState = location.state as SettingsNavState | null;
  // Lets async continuations detect that the user moved to another project/variant meanwhile.
  const routeIdsRef = useRef({ projectId: selectedProjectId, variantId: selectedVariantId });
  routeIdsRef.current = { projectId: selectedProjectId, variantId: selectedVariantId };
  const locationKeyRef = useRef(location.key);
  locationKeyRef.current = location.key;

  useEffect(() => {
    onAgentContextChange?.({ section: route.kind, selectedProjectId: selectedProjectId || projectId });
  }, [route.kind, selectedProjectId, projectId, onAgentContextChange]);

  // ---- Unmount guard for async operations ----
  const unmountedRef = useRef(false);
  const uploadWaitRef = useRef<AbortController | null>(null);
  const loadingMessageRef = useRef(onLoadingMessage);
  loadingMessageRef.current = onLoadingMessage;
  useEffect(() => {
    unmountedRef.current = false;
    return () => {
      unmountedRef.current = true;
      uploadWaitRef.current?.abort();
      loadingMessageRef.current?.(null);
    };
  }, []);

  // ---- Shared data ----
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectsLoaded, setProjectsLoaded] = useState(false);
  const [projectsLoadFailed, setProjectsLoadFailed] = useState(false);
  const [projectVariants, setProjectVariants] = useState<Record<string, Variant[]>>({});
  const [variantLoadFailedIds, setVariantLoadFailedIds] = useState<Set<string>>(new Set());
  const [expandedProjectIds, setExpandedProjectIds] = useState<Set<string>>(new Set());
  const [openAddKey, setOpenAddKey] = useState<AddKey>(null);
  // Per-project request counter so an older Variants.list response never overwrites a newer one.
  const variantRequestSeqRef = useRef<Record<string, number>>({});

  const loadProjects = useCallback(() => {
    // A failed reload keeps the previous list; only a never-loaded list is an error.
    Projects.list()
      .then((list) => {
        setProjects(list);
        setProjectsLoaded(true);
        setProjectsLoadFailed(false);
      })
      .catch(() => setProjectsLoadFailed(true));
  }, []);

  const [configBusy, setConfigBusy] = useState(false);
  const [configError, setConfigError] = useState<string | null>(null);
  const [configSaved, setConfigSaved] = useState<string | null>(null);
  const [showAuthorHint, setShowAuthorHint] = useState(false);
  const authorHintRef = useRef<HTMLDivElement>(null);
  const [configForm, setConfigForm] = useState({
    product_name: "",
    author_name: "",
    client_name: "",
    contact_email: "",
  });

  useEffect(() => {
    if (!showAuthorHint) return;

    const closeHintOnOutsideClick = (event: MouseEvent) => {
      if (!authorHintRef.current?.contains(event.target as Node)) {
        setShowAuthorHint(false);
      }
    };

    document.addEventListener("mousedown", closeHintOnOutsideClick);
    return () => document.removeEventListener("mousedown", closeHintOnOutsideClick);
  }, [showAuthorHint]);

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

    const seqs = projects.map((project) => nextRequest(variantRequestSeqRef.current, project.id));
    Promise.allSettled(projects.map((project) => Variants.list(project.id))).then((results) => {
      if (cancelled) return;
      // A newer request for a project (create/reload) already owns its list.
      const isFresh = (index: number) => variantRequestSeqRef.current[projects[index].id] === seqs[index];
      // A failed fetch keeps that project's previous list; with none, it stays unloaded and is flagged.
      setProjectVariants((prev) => {
        const next: Record<string, Variant[]> = {};
        projects.forEach((project, index) => {
          const result = results[index];
          if (isFresh(index) && result.status === "fulfilled") next[project.id] = result.value;
          else if (prev[project.id]) next[project.id] = prev[project.id];
        });
        return next;
      });
      setVariantLoadFailedIds(new Set(projects
        .filter((_, index) => isFresh(index) && results[index].status === "rejected")
        .map((project) => project.id)));
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

  useEffect(() => {
    if (!selectedProjectId) return;
    setExpandedProjectIds((current) => current.has(selectedProjectId) ? current : new Set(current).add(selectedProjectId));
  }, [selectedProjectId]);

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
  const [renameProjectName, setRenameProjectName] = useState<string>("");
  const [renameProjectBusy, setRenameProjectBusy] = useState(false);
  const [renameProjectMsg, setRenameProjectMsg] = useState<FeedbackMsg>(null);
  const [confirmDeleteProject, setConfirmDeleteProject] = useState(false);
  const [deleteProjectBusy, setDeleteProjectBusy] = useState(false);
  const [deleteProjectMsg, setDeleteProjectMsg] = useState<FeedbackMsg>(null);

  const handleRenameProject = async () => {
    const targetId = selectedProjectId;
    if (!targetId || !renameProjectName.trim()) return;
    setRenameProjectBusy(true);
    setRenameProjectMsg(null);
    try {
      const updated = await Projects.rename(targetId, renameProjectName.trim());
      loadProjects();
      onDataChanged?.("Renaming project...");
      if (routeIdsRef.current.projectId !== targetId) return;
      setRenameProjectName(updated.name);
      setRenameProjectMsg({ text: "Project renamed.", type: "success" });
    } catch (e: any) {
      if (routeIdsRef.current.projectId === targetId) setRenameProjectMsg({ text: e.message, type: "error" });
    } finally {
      setRenameProjectBusy(false);
    }
  };

  // Only Projects.create failures reject: a failed list reload must not make
  // the user retry (and hit a duplicate name) for a project that now exists.
  const createProject = async (name: string) => {
    const submitKey = locationKeyRef.current;
    const created = await Projects.create(name);
    try {
      const list = await Projects.list();
      setProjects(list);
      setProjectsLoaded(true);
      setProjectsLoadFailed(false);
    } catch {
      setProjects((current) => current.some((p) => p.id === created.id) ? current : [...current, created]);
    }
    // Don't pull the user back if they left Settings or moved elsewhere meanwhile.
    if (!unmountedRef.current && locationKeyRef.current === submitKey) {
      navigate(settingsProjectPath(created.id), {
        state: { settingsFlash: `Project "${created.name}" created.` } satisfies SettingsNavState,
      });
    }
    onDataChanged?.("Creating project...");
  };

  const handleDeleteProject = async () => {
    const targetId = selectedProjectId;
    if (!targetId || deleteProjectBusy) return;
    setDeleteProjectBusy(true);
    setDeleteProjectMsg(null);
    try {
      await Projects.delete(targetId);
      setConfirmDeleteProject(false);
      loadProjects();
      if (routeIdsRef.current.projectId === targetId) navigate(ROUTES.settings);
      onDataChanged?.("Deleting project...");
    } catch (e: any) {
      if (routeIdsRef.current.projectId === targetId) setDeleteProjectMsg({ text: e.message, type: "error" });
      setConfirmDeleteProject(false);
    } finally {
      setDeleteProjectBusy(false);
    }
  };

  // ---- Manage Variants ----
  const [renameVariantName, setRenameVariantName] = useState<string>("");
  const [renameVariantBusy, setRenameVariantBusy] = useState(false);
  const [renameVariantMsg, setRenameVariantMsg] = useState<FeedbackMsg>(null);
  const [pendingDeleteVariant, setPendingDeleteVariant] =
    useState<{ projectId: string; id: string; name: string } | null>(null);
  const [deleteVariantBusy, setDeleteVariantBusy] = useState(false);
  const [deleteVariantMsg, setDeleteVariantMsg] = useState<FeedbackMsg>(null);

  // Keeps the sidebar tree and the project page's Variants list in sync with variant changes
  const reloadProjectVariants = useCallback((projectId: string) => {
    if (!projectId) return;
    const seq = nextRequest(variantRequestSeqRef.current, projectId);
    Variants.list(projectId)
      .then((list) => {
        if (variantRequestSeqRef.current[projectId] === seq) setProjectVariants((prev) => ({ ...prev, [projectId]: list }));
      })
      .catch(() => {});
  }, []);

  const handleRenameVariant = async () => {
    const targetProjectId = selectedProjectId;
    const targetId = selectedVariantId;
    if (!targetId || !renameVariantName.trim()) return;
    const isStillSelected = () => routeIdsRef.current.variantId === targetId;
    setRenameVariantBusy(true);
    setRenameVariantMsg(null);
    try {
      const updated = await Variants.rename(targetId, renameVariantName.trim());
      reloadProjectVariants(targetProjectId);
      onDataChanged?.("Renaming variant...");
      if (!isStillSelected()) return;
      setRenameVariantName(updated.name);
      setRenameVariantMsg({ text: "Variant renamed.", type: "success" });
    } catch (e: any) {
      if (isStillSelected()) setRenameVariantMsg({ text: e.message, type: "error" });
    } finally {
      setRenameVariantBusy(false);
    }
  };

  // Only Variants.create failures reject; see createProject.
  const createVariant = async (projectId: string, name: string) => {
    const submitKey = locationKeyRef.current;
    const created = await Variants.create(projectId, name);
    const seq = nextRequest(variantRequestSeqRef.current, projectId);
    try {
      const list = await Variants.list(projectId);
      if (variantRequestSeqRef.current[projectId] === seq) setProjectVariants((prev) => ({ ...prev, [projectId]: list }));
    } catch {
      setProjectVariants((prev) => {
        const current = prev[projectId] ?? [];
        return { ...prev, [projectId]: current.some((v) => v.id === created.id) ? current : [...current, created] };
      });
    }
    // Don't pull the user back if they left Settings or moved elsewhere meanwhile.
    if (!unmountedRef.current && locationKeyRef.current === submitKey) {
      navigate(settingsVariantPath(projectId, created.id), {
        state: { settingsFlash: `Variant "${created.name}" created.` } satisfies SettingsNavState,
      });
    }
    onDataChanged?.("Creating variant...");
  };

  const handleDeleteVariant = async () => {
    if (!pendingDeleteVariant || deleteVariantBusy) return;
    const { projectId: deletedProjectId, id: deletedId } = pendingDeleteVariant;
    setDeleteVariantBusy(true);
    setDeleteVariantMsg(null);
    try {
      await Variants.delete(deletedId);
      setPendingDeleteVariant(null);
      reloadProjectVariants(deletedProjectId);
      onDataChanged?.("Deleting variant...");
    } catch (e: any) {
      setDeleteVariantMsg({ text: e.message, type: "error" });
      setPendingDeleteVariant(null);
    } finally {
      setDeleteVariantBusy(false);
    }
  };

  // ---- Import SBOM (scoped to the variant selected in the Variants tab) ----
  const [importFiles, setImportFiles] = useState<File[]>([]);
  const [importBusy, setImportBusy] = useState(false);
  const [importMsg, setImportMsg] = useState<string | null>(null);
  const [importRefreshMode, setImportRefreshMode] = useState<RefreshMode>("complete");
  const [importCustomRefreshSources, setImportCustomRefreshSources] = useState<Set<RefreshType>>(
    () => new Set(allVulnerabilityRefreshTypes),
  );
  const importRefreshSources = resolveRefreshSources(importRefreshMode, importCustomRefreshSources);

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
    const targetVariantId = selectedVariantId;
    if (!selectedProjectId || !targetVariantId || importFiles.length === 0) return;
    const isStillSelected = () => routeIdsRef.current.variantId === targetVariantId;
    setImportBusy(true);
    setImportMsg(null);
    const count = importFiles.length;
    onLoadingMessage?.(`Uploading ${count} file${count > 1 ? "s" : ""}...`);
    try {
      const result = await Variants.uploadSBOM(
        selectedProjectId,
        targetVariantId,
        importFiles,
        Array.from(importRefreshSources),
      );
      if (unmountedRef.current) return;
      onLoadingMessage?.("Processing SBOM...");
      const controller = new AbortController();
      uploadWaitRef.current = controller;
      const operation = await waitForOperation(result.op_id, current => {
        if (!unmountedRef.current) onLoadingMessage?.(current.progress.message || "Processing SBOM...");
      }, controller.signal);
      if (unmountedRef.current) return;
      if (operation.status === "done") {
        if (isStillSelected()) setImportFiles([]);
        onDataChanged?.("Importing SBOM...");
      } else if (isStillSelected()) {
        setImportMsg(operation.error || operation.progress.message || "SBOM import did not complete.");
      }
    } catch (e: any) {
      if (!unmountedRef.current && isStillSelected()) setImportMsg(e.message);
    } finally {
      uploadWaitRef.current = null;
      if (!unmountedRef.current) {
        onLoadingMessage?.(null);
        setImportBusy(false);
      }
    }
  };

  // ---- Project / variant in scope, resolved from the URL ----
  const contextProject = projects.find((p) => p.id === selectedProjectId);
  const contextVariants: Variant[] | undefined = projectVariants[selectedProjectId];
  const contextVariant = contextVariants?.find((v) => v.id === selectedVariantId);
  const notFound =
    route.kind === "unknown" ||
    (projectsLoaded && !!selectedProjectId && !contextProject) ||
    (route.kind === "variant" && !!contextProject && contextVariants !== undefined && !contextVariant);
  const contextLoading =
    !!selectedProjectId && (!projectsLoaded || (route.kind === "variant" && contextVariants === undefined));
  let contextLoadError: string | null = null;
  if (contextLoading) {
    if (!projectsLoaded) {
      if (projectsLoadFailed) contextLoadError = "Could not load projects.";
    } else if (variantLoadFailedIds.has(selectedProjectId)) {
      contextLoadError = "Could not load variants.";
    }
  }

  useEffect(() => {
    setRenameProjectMsg(null);
    setDeleteProjectMsg(null);
    setRenameVariantMsg(null);
    setDeleteVariantMsg(null);
    setImportFiles([]);
    setImportMsg(null);
    setPendingDeleteVariant(null);
    setOpenAddKey(null);
  }, [route.kind, selectedProjectId, selectedVariantId]);

  // One-shot navigation state (flash, openNewProject) is moved out of history so
  // back/forward cannot replay it; the flash stays visible while the URL remains
  // the page it was created for. Declared after the clearing effect above so
  // opening the New Project input wins on the same navigation.
  const [flash, setFlash] = useState<{ message: string; pathname: string } | null>(null);
  useEffect(() => {
    const message = navState?.settingsFlash;
    if (message) setFlash({ message, pathname: location.pathname });
    else setFlash((current) => (current?.pathname === location.pathname ? current : null));
    if (navState?.openNewProject) setOpenAddKey("project");
    if (navState && (message || navState.openNewProject)) {
      const { settingsFlash: _flash, openNewProject: _open, ...rest } = navState;
      navigate(
        { pathname: location.pathname, search: location.search, hash: location.hash },
        { replace: true, state: Object.keys(rest).length ? rest : null },
      );
    }
  }, [location.key]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    setRenameProjectName(contextProject?.name ?? "");
  }, [contextProject?.id, contextProject?.name]);

  useEffect(() => {
    setRenameVariantName(contextVariant?.name ?? "");
  }, [contextVariant?.id, contextVariant?.name]);

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

  if (notFound) return <NotFound />;

  // ---- Breadcrumb / title context, driven by the route ----
  const crumbs: { label: string; to?: string }[] = [];
  let pageTitle = "General Settings";
  let pageTag: { label: string; className: string } | null = null;
  if (route.kind === "project" || route.kind === "variant") {
    crumbs.push({ label: "Settings", to: ROUTES.settings });
    if (route.kind === "project") {
      pageTitle = contextProject?.name ?? "";
      crumbs.push({ label: pageTitle });
      pageTag = { label: "Project", className: "bg-cyan-950 text-cyan-300" };
    } else {
      crumbs.push({ label: contextProject?.name ?? "", to: settingsProjectPath(route.projectId) });
      pageTitle = contextVariant?.name ?? "";
      crumbs.push({ label: pageTitle });
      pageTag = { label: "Variant", className: "bg-violet-950 text-violet-300" };
    }
  } else if (route.kind === "transfer") {
    crumbs.push({ label: "Settings" }, { label: "Transfer" });
    pageTitle = "Transfer Assessments";
  } else if (route.kind === "custom-export") {
    crumbs.push({ label: "Settings" }, { label: "Custom reports & assets" });
    pageTitle = "Custom reports & assets";
  } else {
    crumbs.push({ label: "Settings" }, { label: "General Settings" });
  }
  const sidebarItemClass = (active: boolean) => `flex w-full items-center gap-3 rounded-md px-3 py-2 text-left text-sm transition-colors ${
    active ? "bg-sky-900 text-white" : "text-slate-300 hover:bg-slate-700 hover:text-white"
  }`;

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
              onClick={() => navigate(ROUTES.settings)}
              aria-current={route.kind === "general" ? "page" : undefined}
              className={sidebarItemClass(route.kind === "general")}
            >
              <FontAwesomeIcon icon={faGear} className="w-4 text-sky-400" aria-hidden="true" />
              General Settings
            </button>
            <button
              type="button"
              onClick={() => navigate(SETTINGS_PATHS.transfer)}
              aria-current={route.kind === "transfer" ? "page" : undefined}
              className={"mt-1 " + sidebarItemClass(route.kind === "transfer")}
            >
              <FontAwesomeIcon icon={faRightLeft} className="w-4 text-sky-400" aria-hidden="true" />
              Transfer Assessments
            </button>
            <button
              type="button"
              onClick={() => navigate(SETTINGS_PATHS.customExport)}
              aria-current={route.kind === "custom-export" ? "page" : undefined}
              className={"mt-1 " + sidebarItemClass(route.kind === "custom-export")}
            >
              <FontAwesomeIcon icon={faFileExport} className="w-4 text-sky-400" aria-hidden="true" />
              Custom reports &amp; assets
            </button>

            <div className="my-3 border-t border-slate-700" />
            <div className="flex items-center justify-between px-3 pb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-500">Projects</span>
            </div>

            <div className="space-y-1">
              {projects.map((project) => {
                const variants = projectVariants[project.id] ?? [];
                const isExpanded = expandedProjectIds.has(project.id);
                const isSelected = route.kind === "project" && selectedProjectId === project.id;

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
                        onClick={() => navigate(settingsProjectPath(project.id))}
                        aria-current={isSelected ? "page" : undefined}
                        className="flex min-w-0 flex-1 items-center gap-2 py-2 pr-3 text-left text-sm text-slate-200"
                      >
                        <FontAwesomeIcon icon={faFolder} className="text-sky-400" aria-hidden="true" />
                        <span className="truncate">{project.name}</span>
                        <span className="ml-auto rounded-full bg-slate-700 px-2 py-0.5 text-xs text-sky-200">{variants.length}</span>
                      </button>
                    </div>
                    {isExpanded && (
                      <div className="ml-4 border-l border-slate-700 pl-2">
                        {variants.map((variant) => {
                          const isVariantSelected =
                            route.kind === "variant" && selectedProjectId === project.id && selectedVariantId === variant.id;
                          return (
                          <button
                            type="button"
                            key={variant.id}
                            onClick={() => navigate(settingsVariantPath(project.id, variant.id))}
                            aria-current={isVariantSelected ? "page" : undefined}
                            className={`mt-1 flex w-full items-center gap-2 rounded-md px-3 py-1.5 text-left text-sm transition-colors ${
                              isVariantSelected
                                ? "bg-violet-950 text-white"
                                : "text-slate-400 hover:bg-slate-700 hover:text-white"
                            }`}
                          >
                            <span className="h-2 w-2 rounded-full bg-violet-400" aria-hidden="true" />
                            <span className="truncate">{variant.name}</span>
                          </button>
                          );
                        })}
                        <InlineAddInput
                          isOpen={openAddKey === `tree-variant:${project.id}`}
                          onOpenChange={(open) => setOpenAddKey(open ? `tree-variant:${project.id}` : null)}
                          onSubmit={(name) => createVariant(project.id, name)}
                          inputAriaLabel="New variant name"
                          submitAriaLabel="Create variant"
                          placeholder="New variant name"
                          buttonClassName="mt-1 flex w-full items-center gap-2 rounded-md border border-dashed border-slate-600 px-3 py-1.5 text-left text-xs italic text-slate-500 transition-colors hover:border-sky-500 hover:text-sky-400"
                          className="mt-1"
                        >
                          <FontAwesomeIcon icon={faPlus} className="text-[10px]" aria-hidden="true" />
                          Add variant…
                        </InlineAddInput>
                      </div>
                    )}
                  </div>
                );
              })}
              <InlineAddInput
                isOpen={openAddKey === "project"}
                onOpenChange={(open) => setOpenAddKey(open ? "project" : null)}
                onSubmit={createProject}
                inputAriaLabel="New project name"
                submitAriaLabel="Create project"
                placeholder="New project name"
                buttonClassName="mt-2 flex w-full items-center gap-2 rounded-md border border-dashed border-slate-600 px-3 py-2 text-left text-xs italic text-slate-500 transition-colors hover:border-sky-500 hover:text-sky-400"
                className="mt-2"
              >
                <FontAwesomeIcon icon={faPlus} className="text-[10px]" aria-hidden="true" />
                New Project
              </InlineAddInput>
            </div>
          </nav>
        </aside>

        <main className="min-w-0 space-y-6">
          {flash && (
            <MessageBanner
              type="success"
              message={flash.message}
              isVisible={true}
              onClose={() => setFlash(null)}
            />
          )}
          {contextLoadError ? (
            <p role="alert" className="text-sm text-red-400">{contextLoadError}</p>
          ) : contextLoading ? (
            <div aria-busy="true" className="text-sm text-slate-400">
              <FontAwesomeIcon icon={faSpinner} spin className="mr-2" aria-hidden="true" />
              Loading…
            </div>
          ) : (
          <>
          <header className="border-b border-slate-700 pb-4">
            <p className="text-xs font-medium text-slate-500">
              {crumbs.map((crumb, index) => (
                <span key={index}>
                  {index > 0 && " / "}
                  {crumb.to ? (
                    <button
                      type="button"
                      aria-label={`Go to ${crumb.label}`}
                      onClick={() => navigate(crumb.to!)}
                      className="hover:text-sky-300 hover:underline"
                    >
                      {crumb.label}
                    </button>
                  ) : crumb.label}
                </span>
              ))}
            </p>
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
        {route.kind === "general" && (
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

            <div ref={authorHintRef}>
              <div className="flex items-center gap-1 mb-1">
                <label htmlFor="author-name" className="text-sm text-zinc-300">AUTHOR_NAME</label>
                <div className="relative">
                  <button
                    type="button"
                    aria-label="Author name helper"
                    title="Show author name hint"
                    className="text-cyan-300 hover:text-cyan-100 transition-colors"
                    onClick={() => setShowAuthorHint((current) => !current)}
                  >
                    <FontAwesomeIcon icon={faCircleQuestion} />
                  </button>
                  {showAuthorHint && (
                    <div
                      role="tooltip"
                      className="absolute top-full mt-1 left-0 bg-sky-900 border border-sky-700 rounded-lg shadow-lg p-3 z-50 w-[360px] text-sm text-left"
                      onClick={(event) => event.stopPropagation()}
                    >
                      <h3 className="font-bold text-white mb-2">Author Name</h3>
                      <div className="space-y-1 text-gray-100">
                        <p>Identifies the person or organization responsible for the report metadata.</p>
                        <p>Also defines the author of custom CVE data entries.</p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
              <input
                id="author-name"
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

        {/* ======== Project page ======== */}
        {route.kind === "project" && contextProject && (
        <>
        {/* ======== Variants overview ======== */}
        <section aria-labelledby="settings-heading-project-variants">
          <div className={cardHeader}>
            <FontAwesomeIcon icon={faFolder} className="text-cyan-400" aria-hidden="true" />
            <h2 id="settings-heading-project-variants" className="text-xl font-bold text-white">Variants</h2>
            <InlineAddInput
              isOpen={openAddKey === "page-variant"}
              onOpenChange={(open) => setOpenAddKey(open ? "page-variant" : null)}
              onSubmit={(name) => createVariant(contextProject.id, name)}
              inputAriaLabel="New variant name"
              submitAriaLabel="Create variant"
              placeholder="New variant name"
              buttonClassName={btnPrimary + " ml-auto py-1.5 text-xs"}
              className="ml-auto w-64"
            >
              <FontAwesomeIcon icon={faPlus} className="mr-1" aria-hidden="true" />
              Add Variant
            </InlineAddInput>
          </div>
          <div className={cardBody + " space-y-2"}>
            {deleteVariantMsg && (
              <MessageBanner
                type={deleteVariantMsg.type}
                message={deleteVariantMsg.text}
                isVisible={true}
                onClose={() => setDeleteVariantMsg(null)}
              />
            )}
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
                    onClick={() => navigate(settingsVariantPath(contextProject.id, v.id))}
                    className="flex h-8 w-8 items-center justify-center rounded text-zinc-400 transition-colors hover:bg-slate-700 hover:text-sky-300"
                    aria-label={`Edit ${v.name}`}
                    title="Edit variant"
                  >
                    <FontAwesomeIcon icon={faPenToSquare} aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    onClick={() => setPendingDeleteVariant({ projectId: contextProject.id, id: v.id, name: v.name })}
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

        {route.kind === "transfer" && (
          <Transfer projectId={projectId} onDataChanged={onDataChanged} />
        )}

        {route.kind === "custom-export" && (
          <CustomExportContentManager />
        )}

        {/* ======== Variant page ======== */}
        {route.kind === "variant" && contextVariant && (
        <>
        {/* ======== Import SBOM ======== */}
        <section aria-labelledby="settings-heading-import">
          <div className={cardHeader}>
            <FontAwesomeIcon icon={faFileImport} className="text-cyan-400" aria-hidden="true" />
            <h2 id="settings-heading-import" className="text-xl font-bold text-white">Import SBOM</h2>
          </div>
          <div className={cardBody + " space-y-3"}>
            <p className="text-sm text-zinc-400">
              Files are imported into <strong className="text-zinc-300">{contextVariant.name}</strong>.
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

            <fieldset className="space-y-3" disabled={importBusy}>
              <legend className="block text-sm text-zinc-300 mb-1">Refresh vulnerability data</legend>
              <p className="text-xs text-zinc-400">Optionally fetch current vulnerability data after the SBOM is imported.</p>
              <div className="grid gap-2 sm:grid-cols-2">
                {([
                  ["complete", "Complete refresh", "Refresh every supported data source."],
                  ["custom", "Custom refresh", "Choose which data sources to refresh."],
                ] as const).map(([mode, label, description]) => (
                  <label key={mode} className={[
                    "flex cursor-pointer items-start gap-2 rounded-lg border px-3 py-3 text-sm transition-colors",
                    importRefreshMode === mode
                      ? "border-cyan-500 bg-cyan-950/40 text-white"
                      : "border-slate-600 bg-slate-900/40 text-zinc-300 hover:border-slate-500",
                  ].join(" ")}>
                    <input
                      type="radio"
                      name="import-refresh-mode"
                      checked={importRefreshMode === mode}
                      onChange={() => setImportRefreshMode(mode)}
                      className="mt-0.5 accent-cyan-500"
                    />
                    <span className="flex flex-col">
                      <span className="font-medium">{label}</span>
                      <span className="mt-1 text-xs text-zinc-400">{description}</span>
                    </span>
                  </label>
                ))}
              </div>
              {importRefreshMode === "custom" && (
                <div className="grid gap-2 sm:grid-cols-2">
                  {vulnerabilityRefreshSources.map(({ source, label }) => (
                    <label key={source} className={[
                      "flex cursor-pointer items-center gap-2 rounded border px-3 py-2 text-sm transition-colors",
                      importCustomRefreshSources.has(source)
                        ? "border-cyan-600 bg-cyan-950/30 text-zinc-100"
                        : "border-slate-600 bg-slate-900/40 text-zinc-300 hover:border-slate-500",
                    ].join(" ")}>
                      <input
                        type="checkbox"
                        aria-label={label}
                        checked={importCustomRefreshSources.has(source)}
                        onChange={() => setImportCustomRefreshSources((previous) => {
                        const next = new Set(previous);
                        if (next.has(source)) next.delete(source); else next.add(source);
                        return next;
                      })}
                      className="rounded accent-cyan-500"
                    />
                      {label}
                    </label>
                  ))}
                </div>
              )}
              {importRefreshMode === "custom" && importRefreshSources.size === 0 && (
                <p className="text-xs text-zinc-400">The SBOM will be imported without refreshing vulnerability data.</p>
              )}
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

        </>
        )}
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
        isOpen={pendingDeleteVariant !== null}
        title="Delete Variant"
        message={`Are you sure you want to delete "${pendingDeleteVariant?.name ?? "this variant"}" and all its data? This action cannot be undone.`}
        confirmText="Yes, delete"
        cancelText="Cancel"
        showTitleIcon={true}
        onConfirm={handleDeleteVariant}
        onCancel={() => setPendingDeleteVariant(null)}
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
      <ModalShell
        isOpen={pendingCleanup !== null}
        title={pendingCleanup?.kind === "empty-scans" ? "Delete Empty Scans" : "Delete Orphaned CVEs"}
        onClose={() => setPendingCleanup(null)}
        size="compact"
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
      </ModalShell>
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


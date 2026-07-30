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

type Props = {
  onDataChanged?: (message?: string) => void;
  onLoadingMessage?: (message: string | null) => void;
};

type SettingsTab = "general" | "projects" | "variants" | "scan";

type OutdatedPackagePlan = {
  package: string;
  vulnerabilities: string[];
  assessments: string[];
  linkedData: { observations: number; sbomPackages: number; sbomObservations: number };
};

type OutdatedVariantPlan = { name: string; packages: Map<string, OutdatedPackagePlan> };
type OutdatedProjectPlan = { name: string; variants: Map<string, OutdatedVariantPlan> };
type AdditionalCleanup =
  | { kind: "empty-scans"; scans: EmptyScanPreview[] }
  | { kind: "orphaned-vulnerabilities"; vulnerabilities: OrphanedVulnerabilityPreview[] };

function buildOutdatedDataPlan(preview: OutdatedDataPreview): OutdatedProjectPlan[] {
  const projects = new Map<string, OutdatedProjectPlan>();
  const ensurePackage = (projectName: string, variantName: string, packageName: string) => {
    let project = projects.get(projectName);
    if (!project) {
      project = { name: projectName, variants: new Map() };
      projects.set(projectName, project);
    }
    let variant = project.variants.get(variantName);
    if (!variant) {
      variant = { name: variantName, packages: new Map() };
      project.variants.set(variantName, variant);
    }
    let packagePlan = variant.packages.get(packageName);
    if (!packagePlan) {
      packagePlan = {
        package: packageName,
        vulnerabilities: [],
        assessments: [],
        linkedData: { observations: 0, sbomPackages: 0, sbomObservations: 0 },
      };
      variant.packages.set(packageName, packagePlan);
    }
    return packagePlan;
  };

  for (const item of preview.packages) {
    const packagePlan = ensurePackage(item.project, item.variant, item.package);
    packagePlan.vulnerabilities.push(...item.vulnerabilities);
    packagePlan.linkedData = {
      observations: item.linked_data.observations,
      sbomPackages: item.linked_data.sbom_packages,
      sbomObservations: item.linked_data.sbom_observations,
    };
  }
  for (const item of preview.assessments) {
    const packagePlan = ensurePackage(item.project, item.variant, item.package);
    packagePlan.assessments.push(item.vulnerability);
  }
  return [...projects.values()];
}

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
  const [outdatedDataMessage, setOutdatedDataMessage] = useState<{ text: string; type: "success" | "error" } | null>(null);
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
      if (!unmountedRef.current) {
        setOutdatedDataMessage({ text: "Failed to delete outdated data.", type: "error" });
      }
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
        if (!result.ok) {
          setOutdatedDataMessage({ text: result.error ?? "Failed to load cleanup preview.", type: "error" });
        } else if (!result.scans?.length) {
          setOutdatedDataMessage({ text: "No empty scans were found.", type: "success" });
        } else {
          setPendingCleanup({ kind, scans: result.scans });
        }
      } else {
        const result = await ScansHandler.getOrphanedVulnerabilitiesPreview();
        if (unmountedRef.current) return;
        if (!result.ok) {
          setOutdatedDataMessage({ text: result.error ?? "Failed to load cleanup preview.", type: "error" });
        } else if (!result.vulnerabilities?.length) {
          setOutdatedDataMessage({ text: "No orphaned CVEs were found.", type: "success" });
        } else {
          setPendingCleanup({ kind, vulnerabilities: result.vulnerabilities });
        }
      }
    } catch {
      if (!unmountedRef.current) {
        setOutdatedDataMessage({ text: "Failed to load cleanup preview.", type: "error" });
      }
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
  const [importRefreshSources, setImportRefreshSources] = useState<Set<string>>(new Set(["epss"]));

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
          <button
            className={`px-4 py-2 text-sm font-medium rounded-t transition-colors ${
              activeTab === "scan"
                ? "bg-sky-800 text-white border-b-2 border-sky-400"
                : "text-gray-400 hover:text-gray-200 hover:bg-gray-800"
            }`}
            onClick={() => setActiveTab("scan")}
          >
            Scan Settings
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

        </>)
        }

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

        </>
        )}

        {/* ======== Scan Settings tab ======== */}
        {activeTab === "scan" && (
        <>
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
                accept=".json,.spdx,.cdx,.xml,.tar,.tar.gz,.tgz,.tar.zst"
                onChange={(e) => handleFileSelected(importFiles.length, e.target.files?.[0] ?? null)}
                disabled={importBusy}
                aria-labelledby="sbom-files-label"
                className={
                  inputClass +
                  " file:mr-3 file:py-1 file:px-3 file:rounded-lg file:border-0 file:text-sm file:font-semibold file:bg-cyan-900 file:text-cyan-300 hover:file:bg-cyan-800"
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
            <p className="text-sm text-zinc-400">
              Permanently remove redundant or unreferenced records across every project and variant.
            </p>
            {outdatedDataMessage && (
              <MessageBanner
                type={outdatedDataMessage.type}
                message={outdatedDataMessage.text}
                isVisible={true}
                onClose={() => setOutdatedDataMessage(null)}
              />
            )}
            {maintenanceStatus && (
              <div role="status" aria-live="polite" className="flex items-center gap-2 text-sm font-medium text-cyan-300">
                <FontAwesomeIcon icon={faSpinner} spin aria-hidden="true" />
                <span>Maintenance Scan</span>
                <span className="text-zinc-400">{maintenanceStatus}</span>
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={openDeleteOutdatedDataConfirmation}
                disabled={maintenanceBusy}
                className="px-4 py-2 rounded-lg bg-red-800 hover:bg-red-700 focus:ring-4 focus:outline-none focus:ring-red-900 text-white text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                <FontAwesomeIcon icon={faTrash} className="mr-1" aria-hidden="true" />
                Analyze outdated data
              </button>
              <button
                type="button"
                onClick={() => openAdditionalCleanupConfirmation("empty-scans")}
                disabled={maintenanceBusy}
                className="px-4 py-2 rounded-lg bg-red-800 hover:bg-red-700 focus:ring-4 focus:outline-none focus:ring-red-900 text-white text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                <FontAwesomeIcon icon={faTrash} className="mr-1" aria-hidden="true" />
                Analyze empty scans
              </button>
              <button
                type="button"
                onClick={() => openAdditionalCleanupConfirmation("orphaned-vulnerabilities")}
                disabled={maintenanceBusy}
                className="px-4 py-2 rounded-lg bg-red-800 hover:bg-red-700 focus:ring-4 focus:outline-none focus:ring-red-900 text-white text-sm font-semibold disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                <FontAwesomeIcon icon={faTrash} className="mr-1" aria-hidden="true" />
                Analyze orphaned CVEs
              </button>
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
            <p className="text-sm text-gray-600 dark:text-gray-300">
              The following scans have no package, CVE, finding, or assessment changes and will be permanently deleted.
            </p>
            <ul className="max-h-[45vh] space-y-2 overflow-y-auto" aria-label="Empty scans deletion plan">
              {pendingCleanup.scans.map((scan) => (
                <li key={scan.id} className="rounded border border-gray-200 p-3 text-sm dark:border-gray-600">
                  <div className="font-semibold text-gray-900 dark:text-white">{scan.project} / {scan.variant}</div>
                  <div className="mt-1 text-gray-600 dark:text-gray-300">{scan.description || "No description"}</div>
                  <div className="mt-1 text-xs text-gray-500 dark:text-gray-400">{scan.timestamp}</div>
                </li>
              ))}
            </ul>
            <div className="flex justify-end gap-3 border-t border-gray-200 pt-4 dark:border-gray-600">
              <button type="button" onClick={() => setPendingCleanup(null)} className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-semibold text-gray-700 hover:bg-gray-100 dark:border-gray-500 dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600">Cancel</button>
              <button type="button" onClick={handleAdditionalCleanup} className="rounded-lg bg-red-700 px-4 py-2 text-sm font-semibold text-white hover:bg-red-800 focus:outline-none focus:ring-4 focus:ring-red-300 dark:focus:ring-red-900">Delete empty scans</button>
            </div>
          </div>
        ) : pendingCleanup ? (
          <div className="space-y-4">
            <p className="text-sm text-gray-600 dark:text-gray-300">
              The following CVEs are absent from every project and variant and will be permanently deleted with their assessments.
            </p>
            <ul className="max-h-[45vh] space-y-2 overflow-y-auto" aria-label="Orphaned CVEs deletion plan">
              {pendingCleanup.vulnerabilities.map((vulnerability) => (
                <li key={vulnerability.id} className="flex items-center justify-between rounded border border-gray-200 p-3 text-sm dark:border-gray-600">
                  <span className="font-mono font-semibold text-gray-900 dark:text-white">{vulnerability.id}</span>
                  <span className="text-gray-600 dark:text-gray-300">{vulnerability.assessments} assessment{vulnerability.assessments === 1 ? "" : "s"}</span>
                </li>
              ))}
            </ul>
            <div className="flex justify-end gap-3 border-t border-gray-200 pt-4 dark:border-gray-600">
              <button type="button" onClick={() => setPendingCleanup(null)} className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-semibold text-gray-700 hover:bg-gray-100 dark:border-gray-500 dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600">Cancel</button>
              <button type="button" onClick={handleAdditionalCleanup} className="rounded-lg bg-red-700 px-4 py-2 text-sm font-semibold text-white hover:bg-red-800 focus:outline-none focus:ring-4 focus:ring-red-300 dark:focus:ring-red-900">Delete orphaned CVEs</button>
            </div>
          </div>
        ) : null}
      </Popup>
      <Popup
        isOpen={confirmDeleteOutdatedData}
        title="Delete Outdated Data"
        dialogClassName="max-w-3xl"
        onClose={() => {
          setConfirmDeleteOutdatedData(false);
          setOutdatedDataPreview(null);
        }}
      >
        {loadingOutdatedDataPreview ? (
          <div className="flex min-h-40 items-center justify-center gap-3 text-sm text-gray-500 dark:text-gray-400">
            <FontAwesomeIcon icon={faSpinner} spin aria-hidden="true" />
            Loading deletion plan...
          </div>
        ) : !outdatedDataPreview ? null : outdatedDataPreview.packages.length === 0 && outdatedDataPreview.assessments.length === 0 ? (
          <p className="text-sm text-gray-500 dark:text-gray-400">No outdated data was found.</p>
        ) : (
          <div className="space-y-4">
            <p className="text-sm text-gray-600 dark:text-gray-300">
              The following outdated records will be permanently removed across all projects and variants.
            </p>
            <div className="max-h-[55vh] overflow-y-auto pr-1" role="tree" aria-label="Outdated data deletion plan">
              {buildOutdatedDataPlan(outdatedDataPreview).map((project) => (
                <section key={project.name} className="relative pb-4 last:pb-0" role="treeitem" aria-level={1}>
                  <div className="flex items-center gap-2 text-sm font-semibold text-gray-900 dark:text-white">
                    <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded bg-amber-100 text-amber-700 dark:bg-amber-900/50 dark:text-amber-300">
                      <FontAwesomeIcon icon={faFolderOpen} aria-hidden="true" />
                    </span>
                    {project.name}
                  </div>
                  <div className="ml-3.5 mt-2 border-l border-gray-300 pl-5 dark:border-gray-600" role="group">
                    {[...project.variants.values()].map((variant) => (
                      <div key={variant.name} className="relative pb-4 last:pb-0" role="treeitem" aria-level={2}>
                        <span className="absolute -left-5 top-3 h-px w-4 bg-gray-300 dark:bg-gray-600" aria-hidden="true" />
                        <div className="flex items-center gap-2 text-sm font-semibold text-gray-800 dark:text-gray-100">
                          <span className="h-2.5 w-2.5 shrink-0 rounded-full bg-sky-500 ring-4 ring-sky-100 dark:ring-sky-950" aria-hidden="true" />
                          Variant: {variant.name}
                        </div>
                        <div className="ml-1.5 mt-2 border-l border-gray-300 pl-5 dark:border-gray-600" role="group">
                          {[...variant.packages.values()].map((packagePlan) => (
                            <div key={packagePlan.package} className="relative pb-4 last:pb-0" role="treeitem" aria-level={3}>
                              <span className="absolute -left-5 top-3 h-px w-4 bg-gray-300 dark:bg-gray-600" aria-hidden="true" />
                              <div className="flex items-center gap-2 text-sm font-semibold text-gray-800 dark:text-gray-100">
                                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300">
                                  <FontAwesomeIcon icon={faFileLines} aria-hidden="true" />
                                </span>
                                {packagePlan.package}
                              </div>
                              <div className="ml-3 mt-2 space-y-2 border-l border-gray-200 pl-4 text-xs dark:border-gray-600" role="group">
                                {packagePlan.vulnerabilities.map((vulnerability) => (
                                  <div key={vulnerability} className="relative flex items-center gap-2 text-gray-700 dark:text-gray-200" role="treeitem" aria-level={4}>
                                    <span className="absolute -left-4 top-2 h-px w-3 bg-gray-200 dark:bg-gray-600" aria-hidden="true" />
                                    <FontAwesomeIcon icon={faBug} className="text-red-500" aria-hidden="true" />
                                    Vulnerability to remove: <span className="font-mono font-semibold">{vulnerability}</span>
                                  </div>
                                ))}
                                {packagePlan.assessments.map((vulnerability) => (
                                  <div key={`assessment-${vulnerability}`} className="relative flex items-center gap-2 text-gray-600 dark:text-gray-300" role="treeitem" aria-level={4}>
                                    <span className="absolute -left-4 top-2 h-px w-3 bg-gray-200 dark:bg-gray-600" aria-hidden="true" />
                                    <FontAwesomeIcon icon={faCheck} className="text-amber-600" aria-hidden="true" />
                                    Custom assessment for <span className="font-mono">{vulnerability}</span>
                                  </div>
                                ))}
                                <div className="relative text-gray-500 dark:text-gray-400" role="treeitem" aria-level={4}>
                                  <span className="absolute -left-4 top-2 h-px w-3 bg-gray-200 dark:bg-gray-600" aria-hidden="true" />
                                  Linked records: {packagePlan.linkedData.observations} observation{packagePlan.linkedData.observations === 1 ? "" : "s"}, {packagePlan.linkedData.sbomPackages} SBOM package link{packagePlan.linkedData.sbomPackages === 1 ? "" : "s"}, {packagePlan.linkedData.sbomObservations} SBOM vulnerability record{packagePlan.linkedData.sbomObservations === 1 ? "" : "s"}.
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </section>
              ))}
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              Findings, packages, and vulnerabilities are removed only when no current or other-variant data still references them.
            </p>
            <div className="flex justify-end gap-3 border-t border-gray-200 pt-4 dark:border-gray-600">
              <button
                type="button"
                onClick={() => {
                  setConfirmDeleteOutdatedData(false);
                  setOutdatedDataPreview(null);
                }}
                className="rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-semibold text-gray-700 hover:bg-gray-100 dark:border-gray-500 dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDeleteOutdatedData}
                className="rounded-lg bg-red-700 px-4 py-2 text-sm font-semibold text-white hover:bg-red-800 focus:outline-none focus:ring-4 focus:ring-red-300 dark:focus:ring-red-900"
              >
                Delete outdated data
              </button>
            </div>
          </div>
        )}
      </Popup>
    </div>
  );
}

export default Settings;


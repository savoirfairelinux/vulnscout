import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";

import Settings from "../../src/pages/Settings";
import Projects from "../../src/handlers/project";
import Variants from "../../src/handlers/variant";
import Config from "../../src/handlers/config";
import NvdApiKey from "../../src/handlers/nvdApiKey";
import ScansHandler from "../../src/handlers/scans";

jest.mock("../../src/handlers/project", () => ({
  __esModule: true,
  default: { list: jest.fn(), create: jest.fn(), rename: jest.fn(), delete: jest.fn() },
}));

jest.mock("../../src/handlers/variant", () => ({
  __esModule: true,
  default: { list: jest.fn(), create: jest.fn(), rename: jest.fn(), delete: jest.fn(), uploadSBOM: jest.fn(), getUploadStatus: jest.fn() },
}));

jest.mock("../../src/handlers/config", () => ({
  __esModule: true,
  default: { get: jest.fn(), patch: jest.fn() },
}));

jest.mock("../../src/handlers/nvdApiKey", () => ({
  __esModule: true,
  default: { get: jest.fn(), set: jest.fn(), remove: jest.fn() },
}));

jest.mock("../../src/handlers/scans", () => ({
  __esModule: true,
  default: {
    getOutdatedDataPreview: jest.fn(),
    deleteOutdatedData: jest.fn(),
    getEmptyScansPreview: jest.fn(),
    deleteEmptyScans: jest.fn(),
    getOrphanedVulnerabilitiesPreview: jest.fn(),
    deleteOrphanedVulnerabilities: jest.fn(),
  },
}));

const projectsList = Projects.list as jest.MockedFunction<typeof Projects.list>;
const variantsList = Variants.list as jest.MockedFunction<typeof Variants.list>;
const configGet = Config.get as jest.MockedFunction<typeof Config.get>;
const configPatch = Config.patch as jest.MockedFunction<typeof Config.patch>;
const nvdApiKeyGet = NvdApiKey.get as jest.MockedFunction<typeof NvdApiKey.get>;
const nvdApiKeySet = NvdApiKey.set as jest.MockedFunction<typeof NvdApiKey.set>;
const nvdApiKeyRemove = NvdApiKey.remove as jest.MockedFunction<typeof NvdApiKey.remove>;
const projectsCreate = Projects.create as jest.MockedFunction<typeof Projects.create>;
const projectsRename = Projects.rename as jest.MockedFunction<typeof Projects.rename>;
const projectsDelete = Projects.delete as jest.MockedFunction<typeof Projects.delete>;
const variantsCreate = Variants.create as jest.MockedFunction<typeof Variants.create>;
const variantsRename = Variants.rename as jest.MockedFunction<typeof Variants.rename>;
const variantsDelete = Variants.delete as jest.MockedFunction<typeof Variants.delete>;
const variantsUploadSBOM = Variants.uploadSBOM as jest.MockedFunction<typeof Variants.uploadSBOM>;
const getEmptyScansPreview = ScansHandler.getEmptyScansPreview as jest.MockedFunction<typeof ScansHandler.getEmptyScansPreview>;
const deleteEmptyScans = ScansHandler.deleteEmptyScans as jest.MockedFunction<typeof ScansHandler.deleteEmptyScans>;
const getOutdatedDataPreview = ScansHandler.getOutdatedDataPreview as jest.MockedFunction<typeof ScansHandler.getOutdatedDataPreview>;
const deleteOutdatedData = ScansHandler.deleteOutdatedData as jest.MockedFunction<typeof ScansHandler.deleteOutdatedData>;
const getOrphanedVulnerabilitiesPreview = ScansHandler.getOrphanedVulnerabilitiesPreview as jest.MockedFunction<typeof ScansHandler.getOrphanedVulnerabilitiesPreview>;
const deleteOrphanedVulnerabilities = ScansHandler.deleteOrphanedVulnerabilities as jest.MockedFunction<typeof ScansHandler.deleteOrphanedVulnerabilities>;

const project = { id: "project-1", name: "Apollo" };
const variant = { id: "variant-1", name: "Release", project_id: project.id };

describe("Settings scoped project and variant views", () => {
  beforeEach(() => {
    projectsList.mockResolvedValue([project]);
    variantsList.mockResolvedValue([variant]);
    configGet.mockResolvedValue({
      project: null,
      variant: null,
      product_name: "",
      author_name: "vulnscout",
      client_name: "",
      contact_email: "",
      grype_memlimit: "",
    });
    nvdApiKeyGet.mockResolvedValue({ has_key: false, masked_key: "" });
    configPatch.mockImplementation(async (data) => ({
      project: null,
      variant: null,
      product_name: data.product_name ?? "",
      author_name: data.author_name ?? "vulnscout",
      client_name: data.client_name ?? "",
      contact_email: data.contact_email ?? "",
      grype_memlimit: data.grype_memlimit ?? "",
    }));
    nvdApiKeySet.mockResolvedValue({ ok: true, has_key: true, masked_key: "abcd...wxyz" });
    nvdApiKeyRemove.mockResolvedValue({ ok: true, has_key: false, masked_key: "" });
    projectsCreate.mockResolvedValue({ id: "project-2", name: "Zeus" });
    projectsRename.mockResolvedValue({ ...project, name: "Apollo Renamed" });
    projectsDelete.mockResolvedValue();
    variantsCreate.mockResolvedValue({ id: "variant-2", name: "Next", project_id: project.id });
    variantsRename.mockResolvedValue({ ...variant, name: "Release Renamed" });
    variantsDelete.mockResolvedValue();
    variantsUploadSBOM.mockRejectedValue(new Error("Upload rejected"));
    getEmptyScansPreview.mockResolvedValue({ ok: true, scans: [{ id: "scan-1", description: "Empty", timestamp: "", project: "Apollo", variant: "Release" }] });
    deleteEmptyScans.mockResolvedValue({ ok: true, count: 1 });
    getOutdatedDataPreview.mockResolvedValue({ ok: true, preview: { packages: [], assessments: [], candidate_ids: { observations: [], assessments: [], package_pairs: [] } } });
    deleteOutdatedData.mockResolvedValue({ ok: true });
    getOrphanedVulnerabilitiesPreview.mockResolvedValue({ ok: true, vulnerabilities: [{ id: "CVE-2026-0001", assessments: 2 }] });
    deleteOrphanedVulnerabilities.mockResolvedValue({ ok: true, count: 1 });
  });

  test("selecting a project shows its management view instead of the add-project form", async () => {
    render(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: /^Apollo/ }));

    expect(await screen.findByRole("heading", { name: "Rename Project" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Variants" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Delete Project" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Add Project" })).not.toBeInTheDocument();
  });

  test("the project add-variant action opens an add form scoped to that project", async () => {
    render(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: /^Apollo/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Add Variant" }));

    expect(await screen.findByLabelText("Variant name")).toBeInTheDocument();
    expect(screen.getByText(/New variant in project/i)).toHaveTextContent("Apollo");
  });

  test("selecting a sidebar variant shows its import and lifecycle controls", async () => {
    render(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: "Expand Apollo" }));
    fireEvent.click(await screen.findByRole("button", { name: "Release" }));

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Import SBOM" })).toBeInTheDocument();
    });
    expect(screen.getByRole("heading", { name: "Rename Variant" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Delete Variant" })).toBeInTheDocument();
    expect(screen.getByLabelText("SBOM Files")).toBeInTheDocument();
  });

  test("saves report metadata and Grype memory settings", async () => {
    render(<Settings />);

    fireEvent.change(await screen.findByPlaceholderText("Product name embedded in reports and SBOMs"), { target: { value: "VulnScout" } });
    fireEvent.change(screen.getByPlaceholderText("Author/company name embedded in reports"), { target: { value: "VulnScout Team" } });
    fireEvent.click(screen.getAllByRole("button", { name: "Save" })[0]);
    expect(await screen.findByText("Report metadata settings saved.")).toBeInTheDocument();
    expect(configPatch).toHaveBeenCalledWith(expect.objectContaining({
      product_name: "VulnScout",
      author_name: "VulnScout Team",
    }));

    fireEvent.change(screen.getByLabelText(/Memory Limit/), { target: { value: "4GiB" } });
    fireEvent.click(screen.getAllByRole("button", { name: "Save" })[1]);
    expect(await screen.findByText("Grype memory limit saved.")).toBeInTheDocument();
    expect(configPatch).toHaveBeenCalledWith({ grype_memlimit: "4GiB" });
  });

  test("shows a failed report metadata save", async () => {
    configPatch.mockRejectedValueOnce(new Error("Settings unavailable"));
    render(<Settings />);

    fireEvent.click(await screen.findAllByRole("button", { name: "Save" }).then((buttons) => buttons[0]));
    expect(await screen.findByText("Settings unavailable")).toBeInTheDocument();
  });

  test("saves and removes an NVD API key after confirmation", async () => {
    render(<Settings />);

    fireEvent.change(await screen.findByLabelText("API Key"), { target: { value: "new-key" } });
    fireEvent.click(screen.getByRole("button", { name: "Save key" }));
    expect(await screen.findByText("NVD API key saved.")).toBeInTheDocument();
    expect(nvdApiKeySet).toHaveBeenCalledWith("new-key");

    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    fireEvent.click((await screen.findAllByRole("button", { name: /^Remove$/ }))[1]);
    expect(await screen.findByText("NVD API key removed.")).toBeInTheDocument();
    expect(nvdApiKeyRemove).toHaveBeenCalled();
  });

  test("creates, renames, and deletes the selected project", async () => {
    const createdProject = { id: "project-2", name: "Zeus" };
    projectsList.mockResolvedValueOnce([]).mockResolvedValue([createdProject]);
    projectsCreate.mockResolvedValue(createdProject);
    render(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: "Add project" }));
    fireEvent.change(screen.getByLabelText("Project name"), { target: { value: "Zeus" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    expect(await screen.findByText('Project "Zeus" created.')).toBeInTheDocument();
    expect(projectsCreate).toHaveBeenCalledWith("Zeus");

    fireEvent.change(screen.getByLabelText("New name"), { target: { value: "Apollo Renamed" } });
    fireEvent.click(screen.getByRole("button", { name: "Rename" }));
    expect(await screen.findByText("Project renamed.")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Delete Project" }));
    fireEvent.click(await screen.findByRole("button", { name: "Yes, delete" }));
    await waitFor(() => expect(projectsDelete).toHaveBeenCalledWith("project-2"));
  });

  test("renames and deletes the selected variant", async () => {
    render(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: "Expand Apollo" }));
    fireEvent.click(screen.getByRole("button", { name: "Release" }));
    fireEvent.change(await screen.findByLabelText("New name"), { target: { value: "Release Renamed" } });
    fireEvent.click(screen.getByRole("button", { name: "Rename" }));
    expect(await screen.findByText("Variant renamed.")).toBeInTheDocument();
    expect(variantsRename).toHaveBeenCalledWith(variant.id, "Release Renamed");

    fireEvent.click(screen.getByRole("button", { name: "Delete Variant" }));
    fireEvent.click(await screen.findByRole("button", { name: "Yes, delete" }));
    await waitFor(() => expect(variantsDelete).toHaveBeenCalledWith(variant.id));
  });

  test("previews and deletes empty scans from data maintenance", async () => {
    render(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: /Analyze empty scans/ }));
    expect(await screen.findByRole("list", { name: "Empty scans deletion plan" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Delete empty scans" }));
    expect(await screen.findByText("1 empty scan deleted.")).toBeInTheDocument();
    expect(deleteEmptyScans).toHaveBeenCalledWith(["scan-1"]);
  });

  test("deletes the previewed outdated data", async () => {
    render(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: /Analyze outdated data/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Delete outdated data" }));

    expect(await screen.findByText("Outdated data removed from every project and variant.")).toBeInTheDocument();
    expect(deleteOutdatedData).toHaveBeenCalledWith({ observations: [], assessments: [], package_pairs: [] });
  });

  test("previews and deletes orphaned CVEs", async () => {
    render(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: /Analyze orphaned CVEs/ }));
    expect(await screen.findByRole("list", { name: "Orphaned CVEs deletion plan" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Delete orphaned CVEs" }));

    expect(await screen.findByText("1 orphaned CVE and their assessments deleted.")).toBeInTheDocument();
    expect(deleteOrphanedVulnerabilities).toHaveBeenCalledWith(["CVE-2026-0001"]);
  });

  test("creates a variant scoped to the selected project", async () => {
    render(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: /^Apollo/ }));
    fireEvent.click(screen.getByRole("button", { name: "Add Variant" }));
    fireEvent.change(await screen.findByLabelText("Variant name"), { target: { value: "Next" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));

    expect(await screen.findByText('Variant "Next" created.')).toBeInTheDocument();
    expect(variantsCreate).toHaveBeenCalledWith(project.id, "Next");
  });

  test("shows an SBOM upload failure for the selected variant", async () => {
    render(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: "Expand Apollo" }));
    fireEvent.click(screen.getByRole("button", { name: "Release" }));
    const file = new File(["{}"], "sbom.json", { type: "application/json" });
    fireEvent.change(await screen.findByLabelText("SBOM Files"), { target: { files: [file] } });
    fireEvent.click(screen.getByRole("button", { name: "Import" }));

    expect(await screen.findByText("Upload rejected")).toBeInTheDocument();
    expect(variantsUploadSBOM).toHaveBeenCalledWith(project.id, variant.id, [file], ["epss"]);
  });

  test("updates import refresh sources, removes selected files, and navigates settings sections", async () => {
    render(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: "Expand Apollo" }));
    fireEvent.click(screen.getByRole("button", { name: "Release" }));
    const file = new File(["{}"], "sbom.json", { type: "application/json" });
    fireEvent.change(await screen.findByLabelText("SBOM Files"), { target: { files: [file] } });
    fireEvent.click(screen.getByLabelText("NVD"));
    fireEvent.click(screen.getByLabelText("EUVD"));
    fireEvent.click(screen.getByLabelText("GHSA"));
    fireEvent.click(screen.getByRole("button", { name: "Remove file sbom.json" }));
    expect(screen.queryByText("sbom.json")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Transfer Assessments" }));
    expect(await screen.findByRole("heading", { name: "Copy Custom Assessments" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "General Settings" }));
    expect(await screen.findByRole("heading", { name: "Report Metadata" })).toBeInTheDocument();
  });

  test("opens and cancels editing an existing NVD API key", async () => {
    nvdApiKeyGet.mockResolvedValueOnce({ has_key: true, masked_key: "abcd...wxyz" });
    render(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: "Change" }));
    expect(screen.getByLabelText("New API Key")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("New API Key"), { target: { value: "replacement" } });
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(await screen.findByText("abcd...wxyz")).toBeInTheDocument();
  });

  test("reports failed Grype and NVD key updates", async () => {
    configPatch.mockRejectedValueOnce(new Error("Invalid memory limit"));
    nvdApiKeySet.mockResolvedValueOnce({ ok: false, has_key: false, masked_key: "", error: "Key rejected" });
    render(<Settings />);

    fireEvent.click(await screen.findAllByRole("button", { name: "Save" }).then((buttons) => buttons[1]));
    expect(await screen.findByText("Invalid memory limit")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("API Key"), { target: { value: "bad-key" } });
    fireEvent.click(screen.getByRole("button", { name: "Save key" }));
    expect(await screen.findByText("Key rejected")).toBeInTheDocument();
  });

  test("reports empty and unavailable cleanup previews", async () => {
    getEmptyScansPreview.mockResolvedValueOnce({ ok: true, scans: [] });
    getOrphanedVulnerabilitiesPreview.mockResolvedValueOnce({ ok: false, error: "Cleanup unavailable" });
    render(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: /Analyze empty scans/ }));
    expect(await screen.findByText("No empty scans were found.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Analyze orphaned CVEs/ }));
    expect(await screen.findByText("Cleanup unavailable")).toBeInTheDocument();
  });

  test("toggles the AUTHOR_NAME hint and closes it when clicking outside", async () => {
    render(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: "Author name helper" }));
    const hint = await screen.findByRole("tooltip");
    expect(hint).toHaveTextContent("Author Name");

    fireEvent.mouseDown(hint);
    fireEvent.click(hint);
    expect(screen.getByRole("tooltip")).toBeInTheDocument();

    fireEvent.mouseDown(document.body);
    await waitFor(() => expect(screen.queryByRole("tooltip")).not.toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: "Author name helper" }));
    expect(await screen.findByRole("tooltip")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Author name helper" }));
    await waitFor(() => expect(screen.queryByRole("tooltip")).not.toBeInTheDocument());
  });

  test("navigates project and variant controls without committing destructive actions", async () => {
    render(<Settings />);

    fireEvent.click(await screen.findByRole("button", { name: "New Project" }));
    expect(await screen.findAllByRole("heading", { name: "Add Project" })).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: "General Settings" }));
    fireEvent.click(await screen.findByRole("button", { name: "Expand Apollo" }));
    fireEvent.click(screen.getByRole("button", { name: "Collapse Apollo" }));
  });
});
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from "react-router-dom";

import Settings from "../../src/pages/Settings";
import Projects from "../../src/handlers/project";
import Variants from "../../src/handlers/variant";
import Config from "../../src/handlers/config";
import NvdApiKey from "../../src/handlers/nvdApiKey";
import ScansHandler from "../../src/handlers/scans";
import { __reset, __setEventSourceFactory } from "../../src/handlers/operationStore";

class TestEventSource {
  static current: TestEventSource;
  private handlers = new Map<string, (event: MessageEvent) => void>();
  constructor() { TestEventSource.current = this; }
  addEventListener(type: string, handler: EventListenerOrEventListenerObject) {
    this.handlers.set(type, handler as (event: MessageEvent) => void);
  }
  close() {}
  send(type: string, data: unknown) {
    act(() => this.handlers.get(type)?.({ data: JSON.stringify(data), lastEventId: "epoch:1" } as MessageEvent));
  }
}

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

function LocationProbe() {
  const location = useLocation();
  return <span data-testid="location">{location.pathname}</span>;
}

function renderSettings(path = "/settings", props: React.ComponentProps<typeof Settings> = {}, state?: unknown) {
  return render(
    <MemoryRouter initialEntries={[{ pathname: path, state }]}>
      <Routes>
        <Route path="/settings/*" element={<><Settings {...props} /><LocationProbe /></>} />
      </Routes>
    </MemoryRouter>,
  );
}

function FullLocationProbe() {
  const location = useLocation();
  return <span data-testid="full-location">{`${location.pathname}${location.search}${location.hash}`}</span>;
}

function StateProbe() {
  const location = useLocation();
  return <span data-testid="state">{JSON.stringify(location.state)}</span>;
}

function renderFull(pathname: string, search: string, hash: string, state: unknown) {
  return render(
    <MemoryRouter initialEntries={[{ pathname, search, hash, state }]}>
      <Routes>
        <Route path="/settings/*" element={<><Settings /><FullLocationProbe /><StateProbe /></>} />
      </Routes>
    </MemoryRouter>,
  );
}

function LeaveButton() {
  const navigate = useNavigate();
  return <button type="button" onClick={() => navigate("/elsewhere")}>Leave settings</button>;
}

function renderSettingsWithExit(path = "/settings") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/settings/*" element={<Settings />} />
        <Route path="/elsewhere" element={<p>Elsewhere page</p>} />
      </Routes>
      <LocationProbe />
      <LeaveButton />
    </MemoryRouter>,
  );
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

function HistoryControls() {
  const navigate = useNavigate();
  return (
    <>
      <button type="button" onClick={() => navigate(-1)}>History back</button>
      <button type="button" onClick={() => navigate(1)}>History forward</button>
    </>
  );
}

const project = { id: "project-1", name: "Apollo" };
const variant = { id: "variant-1", name: "Release", project_id: project.id };

describe("Settings scoped project and variant views", () => {
  let restoreStream: () => void;
  beforeEach(() => {
    restoreStream = __setEventSourceFactory(() => new TestEventSource() as unknown as EventSource);
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

  afterEach(() => {
    __reset();
    restoreStream();
  });

  test.each(["done", "error"])("tracks an SBOM upload until %s through SSE", async status => {
    variantsUploadSBOM.mockResolvedValue({ op_id: "upload:1", scan_id: "scan-1", message: "Accepted" });
    const onDataChanged = jest.fn();
    const onLoadingMessage = jest.fn();
    renderSettings("/settings", { onDataChanged, onLoadingMessage });

    fireEvent.click(await screen.findByRole("button", { name: "Expand Apollo" }));
    fireEvent.click(screen.getByRole("button", { name: "Release" }));
    fireEvent.change(await screen.findByLabelText("SBOM Files"), {
      target: { files: [new File(["{}"], "sbom.json", { type: "application/json" })] },
    });
    fireEvent.click(screen.getByRole("button", { name: "Import" }));
    await waitFor(() => expect(onLoadingMessage).toHaveBeenCalledWith("Processing SBOM..."));
    TestEventSource.current.send("operation", {
      op_id: "upload:1", status, error: status === "error" ? "Import failed" : null,
      progress: { current: 1, total: 1, message: "Processing complete" },
    });
    if (status === "done") {
      await waitFor(() => expect(onDataChanged).toHaveBeenCalledWith("Importing SBOM..."));
    } else {
      expect(await screen.findByText("Import failed")).toBeInTheDocument();
      expect(onDataChanged).not.toHaveBeenCalled();
    }
    expect(onLoadingMessage).toHaveBeenLastCalledWith(null);
  });

  test("clears the loading overlay when leaving Settings during an upload", async () => {
    variantsUploadSBOM.mockResolvedValue({ op_id: "upload:1", scan_id: "scan-1", message: "Accepted" });
    const onLoadingMessage = jest.fn();
    const view = renderSettings("/settings", { onLoadingMessage });
    fireEvent.click(await screen.findByRole("button", { name: "Expand Apollo" }));
    fireEvent.click(screen.getByRole("button", { name: "Release" }));
    fireEvent.change(await screen.findByLabelText("SBOM Files"), {
      target: { files: [new File(["{}"], "sbom.json", { type: "application/json" })] },
    });
    fireEvent.click(screen.getByRole("button", { name: "Import" }));
    await waitFor(() => expect(onLoadingMessage).toHaveBeenCalledWith("Processing SBOM..."));
    view.unmount();
    expect(onLoadingMessage).toHaveBeenLastCalledWith(null);
  });

  test("selecting a project in the tree shows its management view", async () => {
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: /^Apollo/ }));

    expect(await screen.findByRole("heading", { name: "Rename Project" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Variants" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Delete Project" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add project" })).not.toBeInTheDocument();
  });

  test("opens a project from its URL", async () => {
    renderSettings("/settings/project-1");

    expect(await screen.findByDisplayValue("Apollo")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Rename Project" })).toBeInTheDocument();
  });

  test.each([
    ["/settings", "Report Metadata"],
    ["/settings/transfer", "Copy Custom Assessments"],
    ["/settings/project-1", "Rename Project"],
    ["/settings/project-1/", "Rename Project"],
    ["/settings/project-1/variant-1", "Import SBOM"],
  ])("renders %s", async (path, heading) => {
    renderSettings(path);
    expect(await screen.findByRole("heading", { name: heading })).toBeInTheDocument();
  });

  test.each(["/settings/missing", "/settings/project-1/missing", "/settings/project-1/variant-1/extra"])(
    "shows the 404 page for %s", async (path) => {
      renderSettings(path);
      expect(await screen.findByText("Page not found")).toBeInTheDocument();
    });

  test("does not flash 404 while a deep-linked variant loads", async () => {
    let resolveProjects!: (value: typeof project[]) => void;
    projectsList.mockReturnValueOnce(new Promise((resolve) => { resolveProjects = resolve; }));
    renderSettings("/settings/project-1/variant-1");
    expect(screen.queryByText("Page not found")).not.toBeInTheDocument();
    await act(async () => resolveProjects([project]));
    expect(await screen.findByRole("heading", { name: "Import SBOM" })).toBeInTheDocument();
    expect(screen.queryByText("Page not found")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Release" })).toBeInTheDocument();
  });

  test("a failed initial projects load on a project deep link shows an error, not 404", async () => {
    projectsList.mockRejectedValue(new Error("boom"));
    renderSettings("/settings/project-1");
    expect(await screen.findByText("Could not load projects.")).toHaveAttribute("role", "alert");
    expect(screen.queryByText("Page not found")).not.toBeInTheDocument();
  });

  test("a failed variant list load on a variant deep link shows an error, not 404", async () => {
    variantsList.mockRejectedValue(new Error("boom"));
    renderSettings("/settings/project-1/variant-1");
    expect(await screen.findByText("Could not load variants.")).toHaveAttribute("role", "alert");
    expect(screen.queryByText("Page not found")).not.toBeInTheDocument();
  });

  test("a failed project list reload after a rename keeps the page", async () => {
    projectsList.mockResolvedValueOnce([project]).mockRejectedValue(new Error("boom"));
    renderSettings("/settings/project-1");
    fireEvent.change(await screen.findByLabelText("New name"), { target: { value: "Apollo Renamed" } });
    fireEvent.click(screen.getByRole("button", { name: "Rename" }));
    expect(await screen.findByText("Project renamed.")).toBeInTheDocument();
    await waitFor(() => expect(projectsList).toHaveBeenCalledTimes(2));
    expect(screen.queryByText("Page not found")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Rename Project" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Apollo/ })).toBeInTheDocument();
  });

  test("switching between same-named variants resets an unsaved rename", async () => {
    const zeus = { id: "project-2", name: "Zeus" };
    const zeusRelease = { id: "variant-3", name: "Release", project_id: zeus.id };
    projectsList.mockResolvedValue([project, zeus]);
    variantsList.mockImplementation(async (projectId) => (projectId === zeus.id ? [zeusRelease] : [variant]));
    renderSettings("/settings/project-1/variant-1");
    fireEvent.change(await screen.findByLabelText("New name"), { target: { value: "Stale edit" } });
    fireEvent.click(screen.getByRole("button", { name: "Expand Zeus" }));
    fireEvent.click(screen.getAllByRole("button", { name: "Release" })[1]);
    expect(screen.getByTestId("location")).toHaveTextContent("/settings/project-2/variant-3");
    await waitFor(() => expect(screen.getByLabelText("New name")).toHaveValue("Release"));
  });

  test("switching between same-named projects resets an unsaved rename", async () => {
    const twin = { id: "project-2", name: "Apollo" };
    projectsList.mockResolvedValue([project, twin]);
    renderSettings("/settings/project-1");
    fireEvent.change(await screen.findByLabelText("New name"), { target: { value: "Stale edit" } });
    fireEvent.click(screen.getAllByRole("button", { name: /^Apollo/ })[1]);
    expect(screen.getByTestId("location")).toHaveTextContent("/settings/project-2");
    await waitFor(() => expect(screen.getByLabelText("New name")).toHaveValue("Apollo"));
  });

  test("a create flash does not reappear on history navigation", async () => {
    projectsList.mockResolvedValueOnce([project]).mockResolvedValue([project, { id: "project-2", name: "Zeus" }]);
    render(
      <MemoryRouter initialEntries={["/settings"]}>
        <Routes>
          <Route path="/settings/*" element={<><Settings /><LocationProbe /><HistoryControls /></>} />
        </Routes>
      </MemoryRouter>,
    );
    fireEvent.click(await screen.findByRole("button", { name: "New Project" }));
    fireEvent.change(screen.getByLabelText("New project name"), { target: { value: "Zeus" } });
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
    expect(await screen.findByText('Project "Zeus" created.')).toBeInTheDocument();
    await act(async () => {});
    expect(screen.getByText('Project "Zeus" created.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "History back" }));
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent(/^\/settings$/));
    expect(screen.queryByText('Project "Zeus" created.')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "History forward" }));
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent("/settings/project-2"));
    expect(await screen.findByRole("heading", { name: "Rename Project" })).toBeInTheDocument();
    expect(screen.queryByText('Project "Zeus" created.')).not.toBeInTheDocument();
  });

  test("tree, sidebar and breadcrumbs drive the URL", async () => {
    renderSettings();
    fireEvent.click(await screen.findByRole("button", { name: /^Apollo/ }));
    expect(screen.getByTestId("location")).toHaveTextContent("/settings/project-1");
    fireEvent.click(await screen.findByRole("button", { name: "Release" }));
    expect(screen.getByTestId("location")).toHaveTextContent("/settings/project-1/variant-1");
    fireEvent.click(screen.getByRole("button", { name: "Go to Apollo" }));
    expect(screen.getByTestId("location")).toHaveTextContent(/^\/settings\/project-1$/);
    fireEvent.click(screen.getByRole("button", { name: "Go to Settings" }));
    expect(screen.getByTestId("location")).toHaveTextContent(/^\/settings$/);
    fireEvent.click(screen.getByRole("button", { name: "Transfer Assessments" }));
    expect(screen.getByTestId("location")).toHaveTextContent("/settings/transfer");
    expect(await screen.findByRole("heading", { name: "Copy Custom Assessments" })).toBeInTheDocument();
  });

  test("creating a project navigates to it with a flash message", async () => {
    projectsList.mockResolvedValueOnce([project]).mockResolvedValue([project, { id: "project-2", name: "Zeus" }]);
    renderSettings();
    fireEvent.click(await screen.findByRole("button", { name: "New Project" }));
    fireEvent.change(screen.getByLabelText("New project name"), { target: { value: "Zeus" } });
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
    expect(await screen.findByText('Project "Zeus" created.')).toBeInTheDocument();
    expect(screen.getByTestId("location")).toHaveTextContent("/settings/project-2");
    fireEvent.click(screen.getByText('Project "Zeus" created.').closest('[role="alert"]')!.querySelector("button")!);
    await waitFor(() => expect(screen.queryByText('Project "Zeus" created.')).not.toBeInTheDocument());
    expect(screen.getByTestId("location")).toHaveTextContent("/settings/project-2");
  });

  test("a created project is not reported as failed when the list reload fails", async () => {
    const onDataChanged = jest.fn();
    projectsList.mockResolvedValueOnce([project]).mockRejectedValue(new Error("List failed"));
    renderSettings("/settings", { onDataChanged });
    fireEvent.click(await screen.findByRole("button", { name: "New Project" }));
    fireEvent.change(screen.getByLabelText("New project name"), { target: { value: "Zeus" } });
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
    expect(await screen.findByText('Project "Zeus" created.')).toBeInTheDocument();
    expect(screen.getByTestId("location")).toHaveTextContent("/settings/project-2");
    expect(screen.queryByText("List failed")).not.toBeInTheDocument();
    expect(screen.queryByText("Page not found")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Rename Project" })).toBeInTheDocument();
    expect(onDataChanged).toHaveBeenCalledWith("Creating project...");
  });

  test("creating a variant from the tree navigates to it", async () => {
    variantsList.mockResolvedValueOnce([variant]).mockResolvedValue([variant, { id: "variant-2", name: "Next", project_id: project.id }]);
    renderSettings();
    fireEvent.click(await screen.findByRole("button", { name: "Expand Apollo" }));
    fireEvent.click(screen.getByRole("button", { name: "Add variant…" }));
    fireEvent.change(screen.getByLabelText("New variant name"), { target: { value: "Next" } });
    fireEvent.keyDown(screen.getByLabelText("New variant name"), { key: "Enter" });
    expect(await screen.findByText('Variant "Next" created.')).toBeInTheDocument();
    expect(screen.getByTestId("location")).toHaveTextContent("/settings/project-1/variant-2");
    expect(screen.queryByText("Page not found")).not.toBeInTheDocument();
  });

  test("a created variant is not reported as failed when the list reload fails", async () => {
    variantsList.mockResolvedValueOnce([variant]).mockRejectedValue(new Error("List failed"));
    renderSettings("/settings/project-1");
    fireEvent.click(await screen.findByRole("button", { name: "Add Variant" }));
    fireEvent.change(screen.getByLabelText("New variant name"), { target: { value: "Next" } });
    fireEvent.keyDown(screen.getByLabelText("New variant name"), { key: "Enter" });
    expect(await screen.findByText('Variant "Next" created.')).toBeInTheDocument();
    expect(screen.getByTestId("location")).toHaveTextContent("/settings/project-1/variant-2");
    expect(screen.queryByText("List failed")).not.toBeInTheDocument();
    expect(screen.queryByText("Page not found")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Import SBOM" })).toBeInTheDocument();
  });

  test("changing section closes an open inline add input", async () => {
    renderSettings();
    fireEvent.click(await screen.findByRole("button", { name: "New Project" }));
    expect(screen.getByLabelText("New project name")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Transfer Assessments" }));
    expect(await screen.findByRole("heading", { name: "Copy Custom Assessments" })).toBeInTheDocument();
    expect(screen.queryByLabelText("New project name")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /^Apollo/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Add Variant" }));
    expect(screen.getByLabelText("New variant name")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Release" }));
    expect(await screen.findByRole("heading", { name: "Import SBOM" })).toBeInTheDocument();
    expect(screen.queryByLabelText("New variant name")).not.toBeInTheDocument();
  });

  test("deleting a project returns to /settings", async () => {
    renderSettings("/settings/project-1");
    fireEvent.click(await screen.findByRole("button", { name: "Delete Project" }));
    fireEvent.click(await screen.findByRole("button", { name: "Yes, delete" }));
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent(/^\/settings$/));
  });

  test("openNewProject navigation state opens the New Project input", async () => {
    renderSettings("/settings", {}, { openNewProject: true });
    expect(await screen.findByLabelText("New project name")).toBeInTheDocument();
  });

  test("project page Add Variant turns into an inline input", async () => {
    variantsList.mockResolvedValueOnce([variant]).mockResolvedValue([variant, { id: "variant-2", name: "Next", project_id: project.id }]);
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: /^Apollo/ }));
    fireEvent.click(screen.getByRole("button", { name: "Add Variant" }));
    const input = screen.getByLabelText("New variant name");
    fireEvent.change(input, { target: { value: "Next" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(await screen.findByText('Variant "Next" created.')).toBeInTheDocument();
    expect(variantsCreate).toHaveBeenCalledWith(project.id, "Next");
    expect(screen.getByRole("heading", { name: "Import SBOM" })).toBeInTheDocument();
  });

  test("selecting a sidebar variant shows its import and lifecycle controls", async () => {
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: "Expand Apollo" }));
    fireEvent.click(await screen.findByRole("button", { name: "Release" }));

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: "Import SBOM" })).toBeInTheDocument();
    });
    expect(screen.getByRole("heading", { name: "Rename Variant" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete Variant" })).not.toBeInTheDocument();
    expect(screen.getByLabelText("SBOM Files")).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /Complete refresh/ })).toBeChecked();
    expect(screen.getByRole("radio", { name: /Custom refresh/ })).not.toBeChecked();
    expect(screen.queryByRole("checkbox", { name: "NVD" })).not.toBeInTheDocument();
  });

  test("saves report metadata and Grype memory settings", async () => {
    renderSettings();

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
    renderSettings();

    fireEvent.click(await screen.findAllByRole("button", { name: "Save" }).then((buttons) => buttons[0]));
    expect(await screen.findByText("Settings unavailable")).toBeInTheDocument();
  });

  test("saves and removes an NVD API key after confirmation", async () => {
    renderSettings();

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
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: "New Project" }));
    fireEvent.change(screen.getByLabelText("New project name"), { target: { value: "Zeus" } });
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
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
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: "Expand Apollo" }));
    fireEvent.click(screen.getByRole("button", { name: "Release" }));
    fireEvent.change(await screen.findByLabelText("New name"), { target: { value: "Release Renamed" } });
    fireEvent.click(screen.getByRole("button", { name: "Rename" }));
    expect(await screen.findByText("Variant renamed.")).toBeInTheDocument();
    expect(variantsRename).toHaveBeenCalledWith(variant.id, "Release Renamed");

    fireEvent.click(screen.getByRole("button", { name: /^Apollo/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Delete Release" }));
    fireEvent.click(await screen.findByRole("button", { name: "Yes, delete" }));
    await waitFor(() => expect(variantsDelete).toHaveBeenCalledWith(variant.id));
    expect(screen.getByRole("heading", { name: "Rename Project" })).toBeInTheDocument();
  });

  test("deleting a variant row keeps the project page open", async () => {
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: /^Apollo/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Delete Release" }));
    variantsList.mockResolvedValue([]);
    fireEvent.click(await screen.findByRole("button", { name: "Yes, delete" }));
    await waitFor(() => expect(variantsDelete).toHaveBeenCalledWith(variant.id));
    await waitFor(() => expect(screen.queryByRole("button", { name: "Delete Release" })).not.toBeInTheDocument());
    expect(screen.getByTestId("location")).toHaveTextContent(/^\/settings\/project-1$/);
    expect(screen.getByRole("heading", { name: "Rename Project" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Import SBOM" })).not.toBeInTheDocument();
  });

  test("previews and deletes empty scans from data maintenance", async () => {
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: /Analyze empty scans/ }));
    expect(await screen.findByRole("list", { name: "Empty scans deletion plan" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Delete empty scans" }));
    expect(await screen.findByText("1 empty scan deleted.")).toBeInTheDocument();
    expect(deleteEmptyScans).toHaveBeenCalledWith(["scan-1"]);
  });

  test("deletes the previewed outdated data", async () => {
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: /Analyze outdated data/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Delete outdated data" }));

    expect(await screen.findByText("Outdated data removed from every project and variant.")).toBeInTheDocument();
    expect(deleteOutdatedData).toHaveBeenCalledWith({ observations: [], assessments: [], package_pairs: [] });
  });

  test("previews and deletes orphaned CVEs", async () => {
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: /Analyze orphaned CVEs/ }));
    expect(await screen.findByRole("list", { name: "Orphaned CVEs deletion plan" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Delete orphaned CVEs" }));

    expect(await screen.findByText("1 orphaned CVE and their assessments deleted.")).toBeInTheDocument();
    expect(deleteOrphanedVulnerabilities).toHaveBeenCalledWith(["CVE-2026-0001"]);
  });

  test("creates a variant scoped to the selected project", async () => {
    variantsList.mockResolvedValueOnce([variant]).mockResolvedValue([variant, { id: "variant-2", name: "Next", project_id: project.id }]);
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: "Expand Apollo" }));
    fireEvent.click(screen.getByRole("button", { name: "Add variant…" }));
    fireEvent.change(screen.getByLabelText("New variant name"), { target: { value: "Next" } });
    fireEvent.click(screen.getByRole("button", { name: "Create variant" }));

    expect(await screen.findByText('Variant "Next" created.')).toBeInTheDocument();
    expect(variantsCreate).toHaveBeenCalledWith(project.id, "Next");
  });

  test("shows an SBOM upload failure for the selected variant", async () => {
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: "Expand Apollo" }));
    fireEvent.click(screen.getByRole("button", { name: "Release" }));
    const file = new File(["{}"], "sbom.json", { type: "application/json" });
    fireEvent.change(await screen.findByLabelText("SBOM Files"), { target: { files: [file] } });
    fireEvent.click(screen.getByRole("button", { name: "Import" }));

    expect(await screen.findByText("Upload rejected")).toBeInTheDocument();
    expect(variantsUploadSBOM).toHaveBeenCalledWith(
      project.id,
      variant.id,
      [file],
      ["nvd", "epss", "ghsa", "euvd"],
    );
  });

  test("custom import refresh submits only selected sources", async () => {
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: "Expand Apollo" }));
    fireEvent.click(screen.getByRole("button", { name: "Release" }));
    fireEvent.click(await screen.findByRole("radio", { name: /Custom refresh/ }));
    expect(screen.getByRole("checkbox", { name: "NVD" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "EPSS" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "GHSA" })).toBeChecked();
    expect(screen.getByRole("checkbox", { name: "ENISA EUVD" })).toBeChecked();

    fireEvent.click(screen.getByRole("checkbox", { name: "NVD" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "GHSA" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "ENISA EUVD" }));
    const file = new File(["{}"], "sbom.json", { type: "application/json" });
    fireEvent.change(screen.getByLabelText("SBOM Files"), { target: { files: [file] } });
    fireEvent.click(screen.getByRole("button", { name: "Import" }));

    await waitFor(() => expect(variantsUploadSBOM).toHaveBeenCalledWith(
      project.id,
      variant.id,
      [file],
      ["epss"],
    ));
  });

  test("custom import refresh can be disabled without disabling import", async () => {
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: "Expand Apollo" }));
    fireEvent.click(screen.getByRole("button", { name: "Release" }));
    fireEvent.click(await screen.findByRole("radio", { name: /Custom refresh/ }));
    for (const source of ["NVD", "EPSS", "GHSA", "ENISA EUVD"]) {
      fireEvent.click(screen.getByRole("checkbox", { name: source }));
    }
    expect(screen.getByText("The SBOM will be imported without refreshing vulnerability data.")).toBeInTheDocument();

    const file = new File(["{}"], "sbom.json", { type: "application/json" });
    fireEvent.change(screen.getByLabelText("SBOM Files"), { target: { files: [file] } });
    expect(screen.getByRole("button", { name: "Import" })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: "Import" }));

    await waitFor(() => expect(variantsUploadSBOM).toHaveBeenCalledWith(
      project.id,
      variant.id,
      [file],
      [],
    ));
  });

  test("removes selected import files and navigates settings sections", async () => {
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: "Expand Apollo" }));
    fireEvent.click(screen.getByRole("button", { name: "Release" }));
    const file = new File(["{}"], "sbom.json", { type: "application/json" });
    fireEvent.change(await screen.findByLabelText("SBOM Files"), { target: { files: [file] } });
    fireEvent.click(screen.getByRole("button", { name: "Remove file sbom.json" }));
    expect(screen.queryByText("sbom.json")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Transfer Assessments" }));
    expect(await screen.findByRole("heading", { name: "Copy Custom Assessments" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "General Settings" }));
    expect(await screen.findByRole("heading", { name: "Report Metadata" })).toBeInTheDocument();
  });

  test("manages custom reports and assets from its Settings tab", async () => {
    const fetchFunction = global.fetch as jest.Mock;
    fetchFunction.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve([
        { id: "custom.adoc", category: ["custom"], extension: "adoc" },
        { id: "logo.png", category: ["assets"], extension: "png" },
      ]),
    } as Response);
    const { container } = renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: "Custom reports & assets" }));

    expect(await screen.findByRole("heading", { name: "Custom reports (1)" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Custom assets (1)" })).toBeInTheDocument();
    expect(screen.getByText("custom.adoc")).toBeInTheDocument();
    expect(screen.getByText("logo.png")).toBeInTheDocument();

    fetchFunction
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ id: "new.adoc" }) } as Response)
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve([]) } as Response);
    fireEvent.change(container.querySelector('input[type="file"][accept*=".adoc"]')!, {
      target: { files: [new File(["report"], "new.adoc", { type: "text/asciidoc" })] },
    });

    expect(await screen.findByText(/Imported "new\.adoc"/)).toBeInTheDocument();
    expect(fetchFunction.mock.calls.some(([url, options]) =>
      String(url).includes("/api/documents/templates") && options?.method === "POST"
    )).toBe(true);
  });

  test("opens and cancels editing an existing NVD API key", async () => {
    nvdApiKeyGet.mockResolvedValueOnce({ has_key: true, masked_key: "abcd...wxyz" });
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: "Change" }));
    expect(screen.getByLabelText("New API Key")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("New API Key"), { target: { value: "replacement" } });
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(await screen.findByText("abcd...wxyz")).toBeInTheDocument();
  });

  test("reports failed Grype and NVD key updates", async () => {
    configPatch.mockRejectedValueOnce(new Error("Invalid memory limit"));
    nvdApiKeySet.mockResolvedValueOnce({ ok: false, has_key: false, masked_key: "", error: "Key rejected" });
    renderSettings();

    fireEvent.click(await screen.findAllByRole("button", { name: "Save" }).then((buttons) => buttons[1]));
    expect(await screen.findByText("Invalid memory limit")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("API Key"), { target: { value: "bad-key" } });
    fireEvent.click(screen.getByRole("button", { name: "Save key" }));
    expect(await screen.findByText("Key rejected")).toBeInTheDocument();
  });

  test("reports empty and unavailable cleanup previews", async () => {
    getEmptyScansPreview.mockResolvedValueOnce({ ok: true, scans: [] });
    getOrphanedVulnerabilitiesPreview.mockResolvedValueOnce({ ok: false, error: "Cleanup unavailable" });
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: /Analyze empty scans/ }));
    expect(await screen.findByText("No empty scans were found.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Analyze orphaned CVEs/ }));
    expect(await screen.findByText("Cleanup unavailable")).toBeInTheDocument();
  });

  test("toggles the AUTHOR_NAME hint and closes it when clicking outside", async () => {
    renderSettings();

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
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: "New Project" }));
    expect(screen.getByLabelText("New project name")).toBeInTheDocument();
    fireEvent.keyDown(screen.getByLabelText("New project name"), { key: "Escape" });
    expect(screen.getByRole("button", { name: "New Project" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "General Settings" }));
    fireEvent.click(await screen.findByRole("button", { name: "Expand Apollo" }));
    expect(screen.getByRole("button", { name: "Release" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Collapse Apollo" }));
    expect(screen.queryByRole("button", { name: "Release" })).not.toBeInTheDocument();
    expect(screen.getByTestId("location")).toHaveTextContent(/^\/settings$/);
    expect(projectsCreate).not.toHaveBeenCalled();
    expect(projectsDelete).not.toHaveBeenCalled();
    expect(variantsDelete).not.toHaveBeenCalled();
  });

  test("only one inline add input is open at a time", async () => {
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: "Expand Apollo" }));
    fireEvent.click(screen.getByRole("button", { name: "New Project" }));
    fireEvent.click(screen.getByRole("button", { name: "Add variant…" }));
    expect(screen.queryByLabelText("New project name")).not.toBeInTheDocument();
    expect(screen.getByLabelText("New variant name")).toBeInTheDocument();
  });

  test("uses keyboard submits and project variant overview actions", async () => {
    const createdProject = { id: "project-2", name: "Zeus" };
    projectsList.mockResolvedValueOnce([]).mockResolvedValue([createdProject, project]);
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: "New Project" }));
    const projectName = screen.getByLabelText("New project name");
    fireEvent.change(projectName, { target: { value: "Zeus" } });
    fireEvent.keyDown(projectName, { key: "Enter" });
    expect(await screen.findByText('Project "Zeus" created.')).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "General Settings" }));
    fireEvent.click(await screen.findByRole("button", { name: /^Apollo/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Edit Release" }));
    expect(await screen.findByRole("heading", { name: "Import SBOM" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /^Apollo/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Delete Release" }));
    fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(variantsDelete).not.toHaveBeenCalled();
  });

  test("dismisses settings feedback banners", async () => {
    configPatch.mockRejectedValueOnce(new Error("Invalid memory limit"));
    renderSettings();

    fireEvent.click(await screen.findAllByRole("button", { name: "Save" }).then((buttons) => buttons[1]));
    expect(await screen.findByText("Invalid memory limit")).toBeInTheDocument();
    const banner = screen.getByText("Invalid memory limit").closest('[role="alert"]');
    const close = banner?.querySelector<HTMLButtonElement>('button');
    expect(close).not.toBeNull();
    fireEvent.click(close!);
    await waitFor(() => expect(screen.queryByText("Invalid memory limit")).not.toBeInTheDocument());

    getOutdatedDataPreview.mockRejectedValueOnce(new Error("offline"));
    fireEvent.click(screen.getByRole("button", { name: /Analyze outdated data/ }));
    expect(await screen.findByText("Failed to load outdated data.")).toBeInTheDocument();
  });

  test("reports project lifecycle failures", async () => {
    projectsCreate.mockRejectedValueOnce(new Error("Create failed"));
    projectsRename.mockRejectedValueOnce(new Error("Rename failed"));
    projectsDelete.mockRejectedValueOnce(new Error("Delete failed"));
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: "New Project" }));
    const brokenInput = screen.getByLabelText("New project name");
    fireEvent.change(brokenInput, { target: { value: "Broken" } });
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Create failed");
    expect(brokenInput).toHaveValue("Broken");
    fireEvent.keyDown(brokenInput, { key: "Escape" });

    fireEvent.click(screen.getByRole("button", { name: "General Settings" }));
    fireEvent.click(await screen.findByRole("button", { name: /^Apollo/ }));
    fireEvent.change(screen.getByLabelText("New name"), { target: { value: "Renamed" } });
    fireEvent.keyDown(screen.getByLabelText("New name"), { key: "Enter" });
    expect(await screen.findByText("Rename failed")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Delete Project" }));
    fireEvent.click(await screen.findByRole("button", { name: "Yes, delete" }));
    expect(await screen.findByText("Delete failed")).toBeInTheDocument();
  });

  test("reports variant lifecycle failures", async () => {
    variantsCreate.mockRejectedValueOnce(new Error("Variant create failed"));
    variantsRename.mockRejectedValueOnce(new Error("Variant rename failed"));
    variantsDelete.mockRejectedValueOnce(new Error("Variant delete failed"));
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: /^Apollo/ }));
    fireEvent.click(screen.getByRole("button", { name: "Add Variant" }));
    const variantName = await screen.findByLabelText("New variant name");
    fireEvent.change(variantName, { target: { value: "Broken" } });
    fireEvent.keyDown(variantName, { key: "Enter" });
    expect(await screen.findByRole("alert")).toHaveTextContent("Variant create failed");
    fireEvent.keyDown(variantName, { key: "Escape" });

    fireEvent.click(screen.getByRole("button", { name: "General Settings" }));
    // The tree stays expanded after visiting the project page.
    fireEvent.click(await screen.findByRole("button", { name: "Release" }));
    const newName = await screen.findByLabelText("New name");
    fireEvent.change(newName, { target: { value: "Broken rename" } });
    fireEvent.keyDown(newName, { key: "Enter" });
    expect(await screen.findByText("Variant rename failed")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /^Apollo/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Delete Release" }));
    fireEvent.click(await screen.findByRole("button", { name: "Yes, delete" }));
    expect(await screen.findByText("Variant delete failed")).toBeInTheDocument();
  });

  test("reports API-key and cleanup deletion failures", async () => {
    nvdApiKeySet.mockRejectedValueOnce(new Error("offline"));
    deleteEmptyScans.mockResolvedValueOnce({ ok: false, error: "Empty cleanup failed" });
    deleteOrphanedVulnerabilities.mockRejectedValueOnce(new Error("offline"));
    renderSettings();

    fireEvent.change(await screen.findByLabelText("API Key"), { target: { value: "new-key" } });
    fireEvent.click(screen.getByRole("button", { name: "Save key" }));
    expect(await screen.findByText("Failed to save NVD API key.")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Analyze empty scans/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Delete empty scans" }));
    expect(await screen.findByText("Empty cleanup failed")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Analyze orphaned CVEs/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Delete orphaned CVEs" }));
    expect(await screen.findByText("Cleanup failed.")).toBeInTheDocument();
  });

  test("cancels project, variant, API-key, and maintenance confirmations", async () => {
    nvdApiKeyGet.mockResolvedValueOnce({ has_key: true, masked_key: "abcd...wxyz" });
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: /^Apollo/ }));
    fireEvent.click(screen.getByRole("button", { name: "Delete Project" }));
    fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(projectsDelete).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "General Settings" }));
    fireEvent.click(await screen.findByRole("button", { name: /^Apollo/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Delete Release" }));
    fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(variantsDelete).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "General Settings" }));
    fireEvent.click(await screen.findByRole("button", { name: "Remove" }));
    fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(nvdApiKeyRemove).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: /Analyze outdated data/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(deleteOutdatedData).not.toHaveBeenCalled();
  });

  test("closes a cleanup preview from the modal header", async () => {
    renderSettings();

    fireEvent.click(await screen.findByRole("button", { name: /Analyze empty scans/ }));
    expect(await screen.findByRole("list", { name: "Empty scans deletion plan" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Close modal" }));
    await waitFor(() => expect(screen.queryByRole("list", { name: "Empty scans deletion plan" })).not.toBeInTheDocument());
  });

  test("a project created after leaving Settings does not navigate back", async () => {
    const pending = deferred<{ id: string; name: string }>();
    const onDataChanged = jest.fn();
    projectsCreate.mockReturnValueOnce(pending.promise);
    render(
      <MemoryRouter initialEntries={["/settings"]}>
        <Routes>
          <Route path="/settings/*" element={<Settings onDataChanged={onDataChanged} />} />
          <Route path="/elsewhere" element={<p>Elsewhere page</p>} />
        </Routes>
        <LocationProbe />
        <LeaveButton />
      </MemoryRouter>,
    );
    fireEvent.click(await screen.findByRole("button", { name: "New Project" }));
    fireEvent.change(screen.getByLabelText("New project name"), { target: { value: "Zeus" } });
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
    fireEvent.click(screen.getByRole("button", { name: "Leave settings" }));
    expect(await screen.findByText("Elsewhere page")).toBeInTheDocument();
    await act(async () => pending.resolve({ id: "project-2", name: "Zeus" }));
    await act(async () => {});
    expect(screen.getByTestId("location")).toHaveTextContent("/elsewhere");
    expect(onDataChanged).toHaveBeenCalledWith("Creating project...");
  });

  test("a variant created after leaving Settings does not navigate back", async () => {
    const pending = deferred<typeof variant>();
    variantsCreate.mockReturnValueOnce(pending.promise);
    renderSettingsWithExit("/settings/project-1");
    fireEvent.click(await screen.findByRole("button", { name: "Add Variant" }));
    fireEvent.change(screen.getByLabelText("New variant name"), { target: { value: "Next" } });
    fireEvent.keyDown(screen.getByLabelText("New variant name"), { key: "Enter" });
    fireEvent.click(screen.getByRole("button", { name: "Leave settings" }));
    expect(await screen.findByText("Elsewhere page")).toBeInTheDocument();
    await act(async () => pending.resolve({ id: "variant-2", name: "Next", project_id: project.id }));
    await act(async () => {});
    expect(screen.getByTestId("location")).toHaveTextContent("/elsewhere");
  });

  test("a project created after moving to another Settings page updates the tree without navigating", async () => {
    const pending = deferred<{ id: string; name: string }>();
    projectsCreate.mockReturnValueOnce(pending.promise);
    projectsList.mockResolvedValueOnce([project]).mockResolvedValue([project, { id: "project-2", name: "Zeus" }]);
    renderSettings();
    fireEvent.click(await screen.findByRole("button", { name: "New Project" }));
    fireEvent.change(screen.getByLabelText("New project name"), { target: { value: "Zeus" } });
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
    fireEvent.click(screen.getByRole("button", { name: "Transfer Assessments" }));
    await act(async () => pending.resolve({ id: "project-2", name: "Zeus" }));
    expect(await screen.findByRole("button", { name: /^Zeus/ })).toBeInTheDocument();
    expect(screen.getByTestId("location")).toHaveTextContent("/settings/transfer");
    expect(screen.queryByText('Project "Zeus" created.')).not.toBeInTheDocument();
  });

  test("a variant created after moving to another Settings page updates the list without navigating", async () => {
    const pending = deferred<typeof variant>();
    variantsCreate.mockReturnValueOnce(pending.promise);
    variantsList.mockResolvedValueOnce([variant]).mockResolvedValue([variant, { id: "variant-2", name: "Next", project_id: project.id }]);
    renderSettings("/settings/project-1");
    fireEvent.click(await screen.findByRole("button", { name: "Add variant…" }));
    fireEvent.change(screen.getByLabelText("New variant name"), { target: { value: "Next" } });
    fireEvent.keyDown(screen.getByLabelText("New variant name"), { key: "Enter" });
    fireEvent.click(screen.getByRole("button", { name: "Release" }));
    await act(async () => pending.resolve({ id: "variant-2", name: "Next", project_id: project.id }));
    expect(await screen.findByRole("button", { name: "Next" })).toBeInTheDocument();
    expect(screen.getByTestId("location")).toHaveTextContent("/settings/project-1/variant-1");
    expect(screen.queryByText('Variant "Next" created.')).not.toBeInTheDocument();
  });

  test("a stale variant list batch does not overwrite a just-created variant", async () => {
    const initialList = deferred<typeof variant[]>();
    const next = { id: "variant-2", name: "Next", project_id: project.id };
    variantsList.mockReturnValueOnce(initialList.promise).mockResolvedValue([variant, next]);
    renderSettings("/settings/project-1");
    fireEvent.click(await screen.findByRole("button", { name: "Add variant…" }));
    fireEvent.change(screen.getByLabelText("New variant name"), { target: { value: "Next" } });
    fireEvent.keyDown(screen.getByLabelText("New variant name"), { key: "Enter" });
    expect(await screen.findByText('Variant "Next" created.')).toBeInTheDocument();
    await act(async () => initialList.resolve([variant]));
    expect(screen.getByTestId("location")).toHaveTextContent("/settings/project-1/variant-2");
    expect(screen.queryByText("Page not found")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Import SBOM" })).toBeInTheDocument();
  });

  test("a project created after a failed initial load opens its page", async () => {
    projectsList.mockRejectedValueOnce(new Error("boom")).mockResolvedValue([project, { id: "project-2", name: "Zeus" }]);
    renderSettings();
    fireEvent.click(await screen.findByRole("button", { name: "New Project" }));
    fireEvent.change(screen.getByLabelText("New project name"), { target: { value: "Zeus" } });
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
    expect(await screen.findByText('Project "Zeus" created.')).toBeInTheDocument();
    expect(screen.queryByText("Could not load projects.")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Rename Project" })).toBeInTheDocument();
  });

  test("openNewProject state is consumed so history navigation does not reopen the input", async () => {
    render(
      <MemoryRouter initialEntries={[{ pathname: "/settings", search: "?tab=1", hash: "#top", state: { openNewProject: true, other: 1 } }]}>
        <Routes>
          <Route path="/settings/*" element={<><Settings /><FullLocationProbe /><HistoryControls /><StateProbe /></>} />
        </Routes>
      </MemoryRouter>,
    );
    expect(await screen.findByLabelText("New project name")).toBeInTheDocument();
    expect(screen.getByTestId("full-location")).toHaveTextContent("/settings?tab=1#top");
    expect(screen.getByTestId("state")).toHaveTextContent('{"other":1}');
    fireEvent.keyDown(screen.getByLabelText("New project name"), { key: "Escape" });
    fireEvent.click(screen.getByRole("button", { name: "Transfer Assessments" }));
    expect(await screen.findByRole("heading", { name: "Copy Custom Assessments" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "History back" }));
    expect(await screen.findByRole("heading", { name: "Report Metadata" })).toBeInTheDocument();
    expect(screen.queryByLabelText("New project name")).not.toBeInTheDocument();
  });

  test("consuming a flash keeps the search and hash", async () => {
    renderFull("/settings/project-1", "?q=1", "#x", { settingsFlash: "Saved." });
    expect(await screen.findByText("Saved.")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByTestId("state")).toHaveTextContent("null"));
    expect(screen.getByTestId("full-location")).toHaveTextContent("/settings/project-1?q=1#x");
  });

  test("shows the 404 page for a variant that belongs to another project", async () => {
    const zeus = { id: "project-2", name: "Zeus" };
    projectsList.mockResolvedValue([project, zeus]);
    variantsList.mockImplementation(async (projectId) => (
      projectId === zeus.id ? [{ id: "variant-3", name: "Beta", project_id: zeus.id }] : [variant]
    ));
    renderSettings("/settings/project-1/variant-3");
    expect(await screen.findByText("Page not found")).toBeInTheDocument();
  });
});

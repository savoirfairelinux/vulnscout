import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";

import Settings from "../../src/pages/Settings";
import Projects from "../../src/handlers/project";
import Variants from "../../src/handlers/variant";
import Config from "../../src/handlers/config";
import NvdApiKey from "../../src/handlers/nvdApiKey";

jest.mock("../../src/handlers/project", () => ({
  __esModule: true,
  default: { list: jest.fn() },
}));

jest.mock("../../src/handlers/variant", () => ({
  __esModule: true,
  default: { list: jest.fn() },
}));

jest.mock("../../src/handlers/config", () => ({
  __esModule: true,
  default: { get: jest.fn() },
}));

jest.mock("../../src/handlers/nvdApiKey", () => ({
  __esModule: true,
  default: { get: jest.fn() },
}));

const projectsList = Projects.list as jest.MockedFunction<typeof Projects.list>;
const variantsList = Variants.list as jest.MockedFunction<typeof Variants.list>;
const configGet = Config.get as jest.MockedFunction<typeof Config.get>;
const nvdApiKeyGet = NvdApiKey.get as jest.MockedFunction<typeof NvdApiKey.get>;

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
});
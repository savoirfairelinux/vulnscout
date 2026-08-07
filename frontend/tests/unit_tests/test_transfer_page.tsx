import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";

import Transfer from "../../src/pages/Transfer";
import Variants from "../../src/handlers/variant";

jest.mock("../../src/handlers/variant", () => ({
  __esModule: true,
  default: {
    list: jest.fn(),
    previewCopyAssessments: jest.fn(),
    copyAssessments: jest.fn(),
  },
}));

const variantsList = Variants.list as jest.MockedFunction<typeof Variants.list>;
const previewCopyAssessments = Variants.previewCopyAssessments as jest.MockedFunction<typeof Variants.previewCopyAssessments>;
const copyAssessments = Variants.copyAssessments as jest.MockedFunction<typeof Variants.copyAssessments>;

const variants = [
  { id: "variant-1", name: "Release 1", project_id: "project-1" },
  { id: "variant-2", name: "Release 2", project_id: "project-1" },
];

describe("Transfer", () => {
  beforeEach(() => {
    variantsList.mockResolvedValue(variants);
    previewCopyAssessments.mockResolvedValue({
      count: 1,
      skipped: 0,
      message: "1 assessment can be copied.",
      mode: "ignore_version",
      groups: [{
        source_assessment_id: "assessment-1",
        source_finding_id: "finding-1",
        vulnerability_id: "CVE-2026-0001",
        source_package: "pkg@1.0.0",
        candidates: [{
          target_finding_id: "finding-2",
          target_package: "pkg@2.0.0",
          already_has_custom: false,
          selected: true,
        }],
      }],
    });
    copyAssessments.mockResolvedValue({ copied: 1, skipped: 0, message: "1 assessment copied." });
  });

  test("requires a project before assessment copying can be configured", () => {
    render(<Transfer />);

    expect(screen.getByText(/Select a project or variant/i)).toBeInTheDocument();
    expect(screen.getByLabelText("Variant")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Preview & Copy" })).toBeDisabled();
  });

  test("previews a within-variant copy and opens its review", async () => {
    render(<Transfer projectId="project-1" />);

    fireEvent.change(await screen.findByLabelText("Variant"), { target: { value: "variant-1" } });

    await waitFor(() => {
      expect(previewCopyAssessments).toHaveBeenCalledWith(
        "variant-1", "variant-1", "ignore_version", 1, "no_custom",
      );
    });
    expect(await screen.findByText("1 assessment can be copied.")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Preview & Copy" }));
    expect(await screen.findByText("CVE-2026-0001")).toBeInTheDocument();
  });

  test("switches to a between-variant preview and keeps source and target distinct", async () => {
    render(<Transfer projectId="project-1" />);

    fireEvent.click(screen.getByRole("radio", { name: /Between two variants/ }));
    await waitFor(() => {
      expect((screen.getByLabelText("Source") as HTMLSelectElement).options).toHaveLength(3);
    });
    fireEvent.change(screen.getByLabelText("Source"), { target: { value: "variant-1" } });
    fireEvent.change(screen.getByLabelText("Target"), { target: { value: "variant-2" } });

    await waitFor(() => {
      expect(previewCopyAssessments).toHaveBeenLastCalledWith(
        "variant-1", "variant-2", "exact", 1, "no_custom",
      );
    });

    fireEvent.click(screen.getByRole("button", { name: "Swap source and target variants" }));
    expect((screen.getByLabelText("Source") as HTMLSelectElement).value).toBe("variant-2");
    expect((screen.getByLabelText("Target") as HTMLSelectElement).value).toBe("variant-1");
  });

  test("shows an unavailable preview response without enabling the review action", async () => {
    previewCopyAssessments.mockResolvedValueOnce({
      unsupported: true,
      status: 501,
      message: "Preview is not available.",
    });
    render(<Transfer projectId="project-1" />);

    fireEvent.change(await screen.findByLabelText("Variant"), { target: { value: "variant-1" } });

    expect(await screen.findByText("Preview is not available.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Preview & Copy" })).toBeDisabled();
  });

  test("changes copy conditions and matching rules before previewing", async () => {
    render(<Transfer projectId="project-1" />);

    await screen.findByLabelText("Variant");
    fireEvent.click(screen.getByRole("radio", { name: /Target has a different status/ }));
    fireEvent.click(screen.getByRole("radio", { name: /Target differs in any value/ }));
    fireEvent.click(screen.getByRole("radio", { name: /Same Major and Minor Versions/ }));
    fireEvent.click(screen.getByRole("radio", { name: /Same Major Versions/ }));
    fireEvent.click(screen.getByRole("radio", { name: /Any Versions/ }));
    fireEvent.change(screen.getByLabelText("Variant"), { target: { value: "variant-1" } });

    await waitFor(() => {
      expect(previewCopyAssessments).toHaveBeenLastCalledWith(
        "variant-1", "variant-1", "ignore_version", 1, "different_value",
      );
    });
  });

  test("confirms an exact cross-variant review", async () => {
    previewCopyAssessments.mockResolvedValueOnce({
      count: 1,
      skipped: 0,
      message: "1 exact match.",
      mode: "exact",
      entries: [{
        source_assessment_id: "assessment-1",
        source_finding_id: "finding-1",
        target_finding_id: "finding-2",
        vulnerability_id: "CVE-2026-0001",
        source_package: "pkg@1.0.0",
        target_package: "pkg@1.0.0",
      }],
    });
    render(<Transfer projectId="project-1" />);

    fireEvent.click(screen.getByRole("radio", { name: /Between two variants/ }));
    await waitFor(() => expect((screen.getByLabelText("Source") as HTMLSelectElement).options).toHaveLength(3));
    fireEvent.change(screen.getByLabelText("Source"), { target: { value: "variant-1" } });
    fireEvent.change(screen.getByLabelText("Target"), { target: { value: "variant-2" } });
    expect(await screen.findByText("1 exact match.")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Preview & Copy" }));
    fireEvent.click(await screen.findByRole("button", { name: "Confirm Copy" }));
    expect(await screen.findByText("1 assessment copied.")).toBeInTheDocument();
    expect(copyAssessments).toHaveBeenCalledWith("variant-1", "variant-2", "exact", 1, [{ source_assessment_id: "assessment-1", target_finding_id: "finding-2" }], "no_custom");
  });
});
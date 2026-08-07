import { fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom";
import RunScansWizard from "../../src/components/RunScansWizard";
import { refreshSourcesForScans } from "../../src/helpers/refreshSources";

describe("RunScansWizard", () => {
    const defaultProps = {
        isOpen: true,
        variants: [{ id: "variant-1", name: "Production", project_id: "project-1" }],
        selectedVariantIds: new Set(["variant-1"]),
        selectedScanTypes: new Set(["grype"]),
        selectedRefreshTypes: new Set(["epss"]),
        refreshMode: "complete" as const,
        excludeKernel: true,
        onClose: jest.fn(),
        onToggleVariant: jest.fn(),
        onToggleScanType: jest.fn(),
        onToggleRefreshType: jest.fn(),
        onRefreshModeChange: jest.fn(),
        onSelectAllVariants: jest.fn(),
        onSelectNoVariants: jest.fn(),
        onExcludeKernelChange: jest.fn(),
        onLaunch: jest.fn(),
    };

    it("moves through scan, variant, kernel, refresh, and review steps before launching", () => {
        const onLaunch = jest.fn();
        render(
            <RunScansWizard
                {...defaultProps}
                onLaunch={onLaunch}
            />,
        );

        expect(screen.getByRole("heading", { name: "Select scans" })).toBeInTheDocument();
        expect(screen.getByText("Matches SBOM packages against Grype vulnerability databases.")).toBeInTheDocument();
        expect(screen.getByText("Matches package CPEs against National Vulnerability Database records.")).toBeInTheDocument();
        expect(screen.getByText("Queries the Open Source Vulnerabilities database for affected package versions.")).toBeInTheDocument();
        expect(screen.getByText("Checks the SBOM against CVE data using sbom-cve-check.")).toBeInTheDocument();
        fireEvent.click(screen.getByRole("button", { name: "Next" }));

        expect(screen.getByRole("heading", { name: "Select context variants" })).toBeInTheDocument();
        fireEvent.click(screen.getByRole("button", { name: "Next" }));

        expect(screen.getByRole("heading", { name: "Exclude kernel packages?" })).toBeInTheDocument();
        fireEvent.click(screen.getByRole("radio", { name: /no scan every kernel-related package/i }));
        fireEvent.click(screen.getByRole("button", { name: "Next" }));

        expect(screen.getByRole("heading", { name: "Refresh data" })).toBeInTheDocument();
        fireEvent.click(screen.getByRole("button", { name: "Next" }));

        expect(screen.getByRole("heading", { name: "Review and launch" })).toBeInTheDocument();
        expect(screen.getByText("Grype")).toBeInTheDocument();
        expect(screen.getByText("Production")).toBeInTheDocument();
        expect(screen.getByText("FKIE, EPSS, ENISA EUVD")).toBeInTheDocument();
        fireEvent.click(screen.getByRole("button", { name: "Edit vulnerability data refresh" }));
        expect(screen.getByRole("heading", { name: "Refresh data" })).toBeInTheDocument();
        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        fireEvent.click(screen.getByRole("button", { name: "Launch scans" }));
        expect(onLaunch).toHaveBeenCalledTimes(1);
    });

    it("requires scans and context variants before continuing", () => {
        const { rerender } = render(<RunScansWizard {...defaultProps} selectedScanTypes={new Set()} />);

        expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();

        rerender(<RunScansWizard {...defaultProps} />);
        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        rerender(<RunScansWizard {...defaultProps} selectedVariantIds={new Set()} />);
        expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
    });

    it("closes on Escape and a backdrop click", () => {
        const onClose = jest.fn();
        const { container } = render(<RunScansWizard {...defaultProps} onClose={onClose} />);

        fireEvent.keyDown(document, { key: "Escape" });
        fireEvent.mouseDown(container.firstElementChild!);

        expect(onClose).toHaveBeenCalledTimes(2);
    });

    it("updates scan, variant, kernel, and refresh selections", () => {
        const onToggleScanType = jest.fn();
        const onToggleVariant = jest.fn();
        const onSelectAllVariants = jest.fn();
        const onSelectNoVariants = jest.fn();
        const onExcludeKernelChange = jest.fn();
        const onToggleRefreshType = jest.fn();
        const onRefreshModeChange = jest.fn();
        const { rerender } = render(
            <RunScansWizard
                {...defaultProps}
                variants={[
                    ...defaultProps.variants,
                    { id: "variant-2", name: "Staging", project_id: "project-1" },
                ]}
                onToggleScanType={onToggleScanType}
                onToggleVariant={onToggleVariant}
                onSelectAllVariants={onSelectAllVariants}
                onSelectNoVariants={onSelectNoVariants}
                onExcludeKernelChange={onExcludeKernelChange}
                onToggleRefreshType={onToggleRefreshType}
                onRefreshModeChange={onRefreshModeChange}
            />,
        );

        fireEvent.click(screen.getByRole("checkbox", { name: /NVD CPE/i }));
        expect(onToggleScanType).toHaveBeenCalledWith("nvd");
        fireEvent.click(screen.getByRole("button", { name: "Next" }));

        fireEvent.click(screen.getByRole("checkbox", { name: "Staging" }));
        fireEvent.click(screen.getByRole("button", { name: "Select all" }));
        fireEvent.click(screen.getByRole("button", { name: "Select none" }));
        expect(onToggleVariant).toHaveBeenCalledWith("variant-2");
        expect(onSelectAllVariants).toHaveBeenCalledTimes(1);
        expect(onSelectNoVariants).toHaveBeenCalledTimes(1);

        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        fireEvent.click(screen.getByRole("radio", { name: /no scan every kernel-related package/i }));
        fireEvent.click(screen.getByRole("button", { name: /why exclude kernel packages/i }));
        expect(screen.getByText(/Yocto kernel recipes create many companion packages/i)).toBeInTheDocument();
        fireEvent.click(screen.getByRole("button", { name: /why exclude kernel packages/i }));
        expect(onExcludeKernelChange).toHaveBeenCalledWith(false);

        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        fireEvent.click(screen.getByRole("radio", { name: /custom refresh/i }));
        rerender(
            <RunScansWizard
                {...defaultProps}
                refreshMode="custom"
                variants={[
                    ...defaultProps.variants,
                    { id: "variant-2", name: "Staging", project_id: "project-1" },
                ]}
                onToggleScanType={onToggleScanType}
                onToggleVariant={onToggleVariant}
                onSelectAllVariants={onSelectAllVariants}
                onSelectNoVariants={onSelectNoVariants}
                onExcludeKernelChange={onExcludeKernelChange}
                onToggleRefreshType={onToggleRefreshType}
                onRefreshModeChange={onRefreshModeChange}
            />,
        );
        fireEvent.click(screen.getByRole("checkbox", { name: /ENISA EUVD/i }));
        expect(onRefreshModeChange).toHaveBeenCalledWith("custom");
        expect(onToggleRefreshType).toHaveBeenCalledWith("euvd");
    });

    it("supports backward and review-step navigation", () => {
        render(<RunScansWizard {...defaultProps} />);

        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        fireEvent.click(screen.getByRole("button", { name: "Back" }));
        expect(screen.getByRole("heading", { name: "Select scans" })).toBeInTheDocument();

        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        fireEvent.click(screen.getByRole("button", { name: "Next" }));

        for (const [buttonName, heading] of [
            ["Edit scans", "Select scans"],
            ["Edit context variants", "Select context variants"],
            ["Edit kernel package selection", "Exclude kernel packages?"],
        ]) {
            fireEvent.click(screen.getByRole("button", { name: buttonName }));
            expect(screen.getByRole("heading", { name: heading })).toBeInTheDocument();
            while (!screen.queryByRole("heading", { name: "Review and launch" })) {
                fireEvent.click(screen.getByRole("button", { name: "Next" }));
            }
        }
    });

    it("resets to the first step when reopened and stays hidden while closed", () => {
        const { rerender } = render(<RunScansWizard {...defaultProps} isOpen={false} />);
        expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

        rerender(<RunScansWizard {...defaultProps} />);
        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        expect(screen.getByRole("heading", { name: "Select context variants" })).toBeInTheDocument();

        rerender(<RunScansWizard {...defaultProps} isOpen={false} />);
        rerender(<RunScansWizard {...defaultProps} />);
        expect(screen.getByRole("heading", { name: "Select scans" })).toBeInTheDocument();
    });

    it("maps selected scan sources to their applicable refreshes", () => {
        expect([...refreshSourcesForScans(new Set(["grype"]))]).toEqual(["nvd", "epss", "euvd"]);
        expect([...refreshSourcesForScans(new Set(["nvd", "scc"]))]).toEqual(["epss", "euvd"]);
        expect([...refreshSourcesForScans(new Set(["osv"]))]).toEqual(["nvd", "epss", "euvd"]);
        expect([...refreshSourcesForScans(new Set())]).toEqual([]);
    });

    it("ignores custom refresh selections that the chosen scans cannot produce", () => {
        render(
            <RunScansWizard
                {...defaultProps}
                selectedScanTypes={new Set(["scc"])}
                refreshMode="custom"
                selectedRefreshTypes={new Set(["nvd", "epss"])}
            />,
        );

        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        expect(screen.queryByText("FKIE")).not.toBeInTheDocument();
        expect(screen.getByText("EPSS")).toBeInTheDocument();

        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        expect(screen.getByText("EPSS")).toBeInTheDocument();
        expect(screen.queryByText("No refresh selected")).not.toBeInTheDocument();
    });

    it("offers every CVE refresh source for an OSV-only selection", () => {
        render(
            <RunScansWizard
                {...defaultProps}
                selectedScanTypes={new Set(["osv"])}
                refreshMode="custom"
                selectedRefreshTypes={new Set(["nvd", "epss", "euvd"])}
            />,
        );

        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        expect(screen.queryByText("The selected scans do not produce CVEs that can be refreshed.")).not.toBeInTheDocument();
        expect(screen.getByText("FKIE")).toBeInTheDocument();
        expect(screen.getByText("EPSS")).toBeInTheDocument();
        expect(screen.getByText("ENISA EUVD")).toBeInTheDocument();

        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        expect(screen.getByText("FKIE, EPSS, ENISA EUVD")).toBeInTheDocument();
    });
});

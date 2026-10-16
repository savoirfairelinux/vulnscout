import { fireEvent, render, screen, within } from "@testing-library/react";
import { useState } from "react";
import type { ScanConfiguration } from "../../src/handlers/project";
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
        nativeConfigurations: {
            "project-1": {
                exclude_native: true,
                native_package_exceptions: ["gcc-native", "g++-native", "cmake-native"],
                native_packages: ["make-native", "gcc-native"],
            },
        },
        onNativeConfigurationChange: jest.fn(),
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

    function renderNativeWizard(
        configurations: Record<string, ScanConfiguration> = defaultProps.nativeConfigurations,
        variants = defaultProps.variants,
    ) {
        const onChange = jest.fn();
        function Wizard() {
            const [configuration, setConfiguration] = useState(configurations);
            return <RunScansWizard {...defaultProps}
                variants={variants}
                selectedVariantIds={new Set(variants.map(variant => variant.id))}
                nativeConfigurations={configuration}
                onNativeConfigurationChange={(id, value) => {
                    onChange(id, value);
                    setConfiguration(previous => ({ ...previous, [id]: value }));
                }} />;
        }
        render(<Wizard />);
        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        return onChange;
    }

    it("always shows native package checkboxes and keeps selections through navigation and review", () => {
        renderNativeWizard();
        expect(screen.getByRole("region", { name: "Native packages to scan" })).toBeVisible();
        expect(screen.queryByText("Ignore -native packages?")).not.toBeInTheDocument();
        expect(screen.queryByRole("radio", { name: /scan every native package/i })).not.toBeInTheDocument();
        for (const name of ["gcc-native", "g++-native", "cmake-native"]) {
            expect(screen.getByRole("checkbox", { name })).toBeChecked();
            expect(screen.getByRole("checkbox", { name })).toBeVisible();
        }
        expect(screen.getByRole("checkbox", { name: "make-native" })).not.toBeChecked();
        expect(screen.getByText("3 of 4 selected")).toBeInTheDocument();
        fireEvent.click(screen.getByRole("checkbox", { name: "make-native" }));
        fireEvent.click(screen.getByRole("checkbox", { name: "gcc-native" }));
        fireEvent.click(screen.getByRole("button", { name: "Back" }));
        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        expect(screen.getByRole("checkbox", { name: "make-native" })).toBeChecked();
        expect(screen.getByRole("checkbox", { name: "gcc-native" })).not.toBeChecked();
        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        expect(screen.getByText("Native packages to scan: cmake-native, g++-native, make-native")).toBeInTheDocument();
        fireEvent.click(screen.getByRole("button", { name: "Edit package filters" }));
        expect(screen.getByRole("checkbox", { name: "make-native" })).toBeChecked();
        expect(screen.getByRole("checkbox", { name: "gcc-native" })).not.toBeChecked();
    });

    it("shows one native package per list item", () => {
        renderNativeWizard();
        const list = within(screen.getByRole("list", { name: "Native packages" }));
        const items = list.getAllByRole("listitem");
        expect(items).toHaveLength(4);
        expect(items.map(item => within(item).getByRole("checkbox").getAttribute("type"))).toEqual([
            "checkbox", "checkbox", "checkbox", "checkbox",
        ]);
        expect(items.map(item => item.textContent)).toEqual([
            "cmake-native", "g++-native", "gcc-native", "make-native",
        ]);
    });

    it("selects and unselects all native packages without hiding the checklist", () => {
        const onChange = renderNativeWizard();
        fireEvent.click(screen.getByRole("button", { name: "Select all" }));
        expect(onChange).toHaveBeenLastCalledWith("project-1", expect.objectContaining({ exclude_native: false }));
        expect(screen.getByText("4 of 4 selected")).toBeInTheDocument();
        expect(screen.getByRole("button", { name: "Select all" })).toBeDisabled();
        for (const checkbox of screen.getAllByRole("checkbox")) expect(checkbox).toBeChecked();

        fireEvent.click(screen.getByRole("button", { name: "Unselect all" }));
        expect(onChange).toHaveBeenLastCalledWith("project-1", expect.objectContaining({
            exclude_native: true, native_package_exceptions: [],
        }));
        expect(screen.getByText("0 of 4 selected")).toBeInTheDocument();
        expect(screen.getByRole("button", { name: "Unselect all" })).toBeDisabled();
        for (const checkbox of screen.getAllByRole("checkbox")) {
            expect(checkbox).not.toBeChecked();
            expect(checkbox).toBeVisible();
        }
        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        expect(screen.getByText("Native packages to scan: None")).toBeInTheDocument();
        fireEvent.click(screen.getByRole("button", { name: "Edit package filters" }));
        fireEvent.click(screen.getByRole("button", { name: "Select all" }));
        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        expect(screen.getByText("Native packages to scan: All")).toBeInTheDocument();
    });

    it("restores scan-all preferences and preserves other checked packages when one is unchecked", () => {
        const onChange = renderNativeWizard({
            "project-1": { ...defaultProps.nativeConfigurations["project-1"], exclude_native: false },
        });
        expect(screen.getByText("4 of 4 selected")).toBeInTheDocument();
        expect(screen.getByRole("checkbox", { name: "make-native" })).toBeChecked();
        fireEvent.click(screen.getByRole("checkbox", { name: "gcc-native" }));
        expect(onChange).toHaveBeenLastCalledWith("project-1", expect.objectContaining({
            exclude_native: true,
            native_package_exceptions: ["cmake-native", "g++-native", "make-native"],
        }));
        expect(screen.getByText("3 of 4 selected")).toBeInTheDocument();
        expect(screen.getByRole("checkbox", { name: "make-native" })).toBeChecked();
        expect(screen.getByRole("checkbox", { name: "gcc-native" })).not.toBeChecked();
    });

    it("keeps bulk selections separate for each selected project", () => {
        const onChange = renderNativeWizard({
            ...defaultProps.nativeConfigurations,
            "project-2": {
                exclude_native: true, native_package_exceptions: [], native_packages: ["ninja-native"],
            },
        }, [...defaultProps.variants, { id: "variant-2", name: "Staging", project_id: "project-2" }]);
        const production = within(screen.getByRole("group", { name: "Production" }));
        const staging = within(screen.getByRole("group", { name: "Staging" }));
        fireEvent.click(staging.getByRole("button", { name: "Select all" }));
        expect(onChange).toHaveBeenLastCalledWith("project-2", expect.objectContaining({ exclude_native: false }));
        expect(staging.getByRole("checkbox", { name: "ninja-native" })).toBeChecked();
        expect(production.getByRole("checkbox", { name: "make-native" })).not.toBeChecked();
        fireEvent.click(production.getByRole("button", { name: "Unselect all" }));
        expect(onChange).toHaveBeenLastCalledWith("project-1", expect.objectContaining({
            exclude_native: true, native_package_exceptions: [],
        }));
        expect(staging.getByRole("checkbox", { name: "ninja-native" })).toBeChecked();
    });

    it("offers checklist selection without a custom package-name field", () => {
        renderNativeWizard();
        expect(screen.getByRole("list", { name: "Native packages" })).toBeVisible();
        expect(screen.queryByRole("textbox", { name: "Native package name" })).not.toBeInTheDocument();
        expect(screen.queryByRole("button", { name: "Add native package" })).not.toBeInTheDocument();
    });

    it("blocks filter completion when preferences are loading or unavailable", () => {
        const view = render(<RunScansWizard {...defaultProps} configurationLoading />);
        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        fireEvent.click(screen.getByRole("button", { name: "Next" }));
        expect(screen.getByRole("status")).toHaveTextContent("Loading native package preferences");
        expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
        view.rerender(<RunScansWizard {...defaultProps} configurationError="Failed to load scan configuration" />);
        expect(screen.getByRole("alert")).toHaveTextContent("Failed to load scan configuration");
        expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
    });

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

        expect(screen.getByRole("heading", { name: "Exclude kernel companion packages?" })).toBeInTheDocument();
        expect(screen.queryByText("Filter scanner inputs")).not.toBeInTheDocument();
        expect(screen.queryByText("Skip package types that usually add little value to vulnerability analysis.")).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole("radio", { name: /no scan every kernel-related package/i }));
        fireEvent.click(screen.getByRole("button", { name: "Next" }));

        expect(screen.getByRole("heading", { name: "Refresh data" })).toBeInTheDocument();
        fireEvent.click(screen.getByRole("button", { name: "Next" }));

        expect(screen.getByRole("heading", { name: "Review and launch" })).toBeInTheDocument();
        expect(screen.getByText("Grype")).toBeInTheDocument();
        expect(screen.getByText("Production")).toBeInTheDocument();
        expect(screen.getByText("Native packages to scan: gcc-native, g++-native, cmake-native")).toBeInTheDocument();
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
            ["Edit package filters", "Exclude kernel companion packages?"],
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

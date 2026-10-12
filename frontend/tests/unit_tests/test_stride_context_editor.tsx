import { useState } from "react";
// @ts-expect-error TS6133
import React from "react";
import { fireEvent, render, screen, within } from "@testing-library/react";
import "@testing-library/jest-dom";
import StrideContextEditor from "../../src/components/StrideContextEditor";
import {
    THREAT_MODEL_FIELDS, STRIDE_CATEGORIES, emptyRisk, emptyThreatModel, emptySystemComponent, emptySystemInteraction, parseRiskRegister,
    parseThreatModel, serializeRiskRegister, serializeThreatModel,
} from "../../src/helpers/strideContext";
import type { StrideContextText, ThreatModel } from "../../src/helpers/strideContext";

function mountEditor(initial: StrideContextText = { threatModel: "", risks: "" }, disabled = false, error?: string) {
    const changed = jest.fn();
    function ControlledEditor() {
        const [text, setText] = useState(initial);
        const [section, setSection] = useState<"context" | "system" | "threat_model" | "risks" | "summary">("threat_model");
        const [modeContainer, setModeContainer] = useState<HTMLDivElement | null>(null);
        return <>
            <div role="tablist" aria-label="Editor sections">
                <button role="tab" id="editor-context-tab" aria-controls="editor-context-panel"
                    aria-selected={section === "context"} onClick={() => setSection("context")}>Context</button>
                <button role="tab" id="editor-threat_model-tab" aria-controls="editor-threat_model-panel"
                    aria-selected={section === "threat_model"} onClick={() => setSection("threat_model")}>Threat model</button>
                <button role="tab" id="editor-system-tab" aria-controls="editor-system-panel"
                    aria-selected={section === "system"} onClick={() => setSection("system")}>System</button>
                <button role="tab" id="editor-risks-tab" aria-controls="editor-risks-panel"
                    aria-selected={section === "risks"} onClick={() => setSection("risks")}>Risks</button>
                <button role="tab" id="editor-summary-tab" aria-controls="editor-summary-panel"
                    aria-selected={section === "summary"} onClick={() => setSection("summary")}>Summary</button>
            </div>
            <div role="tabpanel" id="editor-context-panel" aria-labelledby="editor-context-tab"
                hidden={section !== "context"}>
                <div ref={setModeContainer} />
            </div>
            <div hidden={section === "context"}>
                <StrideContextEditor {...text} activeSection={section === "context" ? "threat_model" : section}
                    tabIdPrefix="editor" modeContainer={modeContainer}
                    disabled={disabled} error={error} onChange={next => {
                        changed(next);
                        setText(next);
                    }} />
            </div>
        </>;
    }
    render(<ControlledEditor />);
    return changed;
}

function switchMode(value: "stride" | "free") {
    const selectedTab = screen.getByRole("tab", { selected: true });
    selectPanel("Context");
    fireEvent.change(screen.getByRole("combobox", { name: "Editor mode" }), { target: { value } });
    fireEvent.click(selectedTab);
}

function selectPanel(name: "Context" | "System" | "Threat model" | "Risks" | "Summary") {
    fireEvent.click(screen.getByRole("tab", { name }));
}

function addThreat(category: string, description: string) {
    selectPanel("Threat model");
    expect(screen.queryByText(/STRIDE helps identify threats to your system/)).not.toBeInTheDocument();
    const last = screen.queryAllByRole("group", { name: /^Threat \d+$/ }).at(-1);
    if (!last || last.querySelector("select")?.value || last.querySelector("textarea")?.value || last.querySelector("ul"))
        fireEvent.click(screen.getByRole("button", { name: "Add threat" }));
    const threats = screen.getAllByRole("group", { name: /^Threat \d+$/ });
    const row = within(threats[threats.length - 1]);
    fireEvent.change(row.getByRole("combobox", { name: /STRIDE category/ }), { target: { value: category } });
    fireEvent.change(row.getByRole("textbox"), { target: { value: description } });
    selectPanel("Risks");
}

function addComponent(name: string) {
    selectPanel("System");
    fireEvent.click(screen.getByRole("button", { name: "Add component" }));
    const inputs = screen.getAllByRole("textbox", { name: /^Component \d+ name$/ });
    fireEvent.change(inputs[inputs.length - 1], { target: { value: name } });
}

function addInteraction(name: string, sourceId: string, destinationId: string) {
    selectPanel("System");
    fireEvent.click(screen.getByRole("button", { name: "Add interaction" }));
    const inputs = screen.getAllByRole("textbox", { name: /^Interaction \d+ name$/ });
    const number = inputs.length;
    fireEvent.change(inputs[number - 1], { target: { value: name } });
    fireEvent.change(screen.getByLabelText(`Interaction ${number} source component`), { target: { value: sourceId } });
    fireEvent.change(screen.getByLabelText(`Interaction ${number} destination component`), { target: { value: destinationId } });
}

describe("STRIDE context editor", () => {
    test("Summary reflects live drafts and risk edits without publishing or creating valid content", () => {
        const changed = mountEditor();
        fireEvent.change(screen.getByLabelText("Threat 1 STRIDE category"), { target: { value: "Spoofing" } });
        const calls = changed.mock.calls.length;
        selectPanel("Summary");
        const categories = screen.getByRole("table", { name: "Recorded threats by STRIDE category" });
        expect(within(categories).getByRole("row", { name: "S - Spoofing 0 1" })).toBeVisible();
        expect(screen.getByRole("table", { name: "Threats and linked risk evaluations" })).toHaveTextContent("Description missing (draft)");
        expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
        expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
        expect(changed).toHaveBeenCalledTimes(calls);
        expect(changed).toHaveBeenLastCalledWith({ threatModel: "", risks: "" });
        switchMode("free");
        expect(screen.getByText("No threat model text recorded.")).toBeVisible();
        expect(screen.getByText("No risk text recorded.")).toBeVisible();
        switchMode("stride");
        expect(within(screen.getByRole("table", { name: "Recorded threats by STRIDE category" }))
            .getByRole("row", { name: "S - Spoofing 0 1" })).toBeVisible();
        selectPanel("Threat model");
        fireEvent.change(screen.getByLabelText("Threat 1 description"), { target: { value: "Device impersonation" } });
        selectPanel("Risks");
        fireEvent.change(screen.getByLabelText("Risk 1 threat"), { target: { value: "T1" } });
        fireEvent.change(screen.getByLabelText("Risk 1 impact"), { target: { value: "High" } });
        selectPanel("Summary");
        expect(screen.getByRole("table", { name: "Threats and linked risk evaluations" })).toHaveTextContent("Device impersonation");
        expect(within(screen.getByRole("table", { name: "Recorded threats by STRIDE category" }))
            .getByRole("row", { name: "S - Spoofing 1 0" })).toBeVisible();
        expect(screen.getByRole("cell", { name: "High" })).toBeVisible();
    });

    test("Summary in Advanced free mode shows current edited text instead of stale structured data", () => {
        const changed = mountEditor();
        addThreat("Tampering", "Old structured scenario");
        switchMode("free");
        selectPanel("Threat model");
        fireEvent.change(screen.getByRole("textbox", { name: "Threat Model" }), { target: { value: "Updated free model\nCustom scope" } });
        selectPanel("Risks");
        fireEvent.change(screen.getByRole("textbox", { name: "Risks" }), { target: { value: "Updated free risks" } });
        const calls = changed.mock.calls.length;
        selectPanel("Summary");
        const panel = screen.getByRole("tabpanel", { name: "Summary" });
        expect(panel).toHaveTextContent("Advanced free mode has no structured STRIDE summary");
        expect(within(panel).getByText(/Updated free model/)).toBeVisible();
        expect(within(panel).getByText("Updated free risks")).toBeVisible();
        expect(screen.queryByRole("table")).not.toBeInTheDocument();
        expect(screen.queryByText("Old structured scenario")).not.toBeInTheDocument();
        expect(changed).toHaveBeenCalledTimes(calls);
    });

    test("Summary cannot present context from an unavailable variant", () => {
        mountEditor(undefined, true);
        selectPanel("Summary");
        expect(screen.getByText("Select a loaded variant to view its summary.")).toBeVisible();
        expect(screen.queryByRole("table")).not.toBeInTheDocument();
    });

    test("saved system architecture and threat references restore without rewriting and survive free-mode round trips", () => {
        const model: ThreatModel = {
            ...emptyThreatModel(), components: [{ ...emptySystemComponent("C4"), name: "OTA updater" }],
            interactions: [{ ...emptySystemInteraction("I2"), name: "Local update", sourceId: "C4", destinationId: "C4" }],
            threats: [{ id: "T3", category: "Tampering", description: "Unauthorized update", targetIds: ["C4", "I2"] }],
        };
        const initial = {
            threatModel: serializeThreatModel(model),
            risks: serializeRiskRegister({ risks: [{ ...emptyRisk(), threatId: "T3" }], notes: "" }),
        };
        const changed = mountEditor(initial);
        expect(screen.getByRole("list", { name: "Threat 1 affected system elements" })).toHaveTextContent("Component C4: OTA updater");
        selectPanel("System");
        expect(screen.getByLabelText("Component 1 name")).toHaveValue("OTA updater");
        expect(screen.getByLabelText("Interaction 1 source component")).toHaveValue("C4");
        expect(changed).not.toHaveBeenCalled();
        switchMode("free");
        selectPanel("Threat model");
        expect(screen.getByRole("textbox", { name: "Threat Model" })).toHaveValue(initial.threatModel);
        switchMode("stride");
        expect(screen.getByRole("list", { name: "Threat 1 affected system elements" })).toHaveTextContent("Interaction I2: Local update");
        selectPanel("Risks");
        expect(screen.getByLabelText("Risk 1 threat")).toHaveValue("T3");
        expect(changed).not.toHaveBeenCalled();
    });

    test("System edits named components, directed interactions and trust information without inventing threats", () => {
        const changed = mountEditor();
        addComponent("Update service");
        fireEvent.change(screen.getByLabelText("Component 1 description / role"), { target: { value: "Supplies signed firmware" } });
        fireEvent.change(screen.getByLabelText("Component 1 trust zone"), { target: { value: "External network" } });
        addComponent("OTA updater");
        addInteraction("Firmware download", "C1", "C2");
        fireEvent.change(screen.getByLabelText("Interaction 1 interface / protocol"), { target: { value: "HTTPS" } });
        fireEvent.change(screen.getByLabelText("Interaction 1 data / commands"), { target: { value: "Signed image\nUpdate metadata" } });
        fireEvent.change(screen.getByLabelText("Interaction 1 trust boundary"), { target: { value: "Network -> privileged firmware" } });
        const saved = parseThreatModel(changed.mock.lastCall![0].threatModel)!;
        expect(saved.components).toEqual([
            { id: "C1", name: "Update service", description: "Supplies signed firmware", trustZone: "External network" },
            { ...emptySystemComponent("C2"), name: "OTA updater" },
        ]);
        expect(saved.interactions).toEqual([{
            id: "I1", name: "Firmware download", sourceId: "C1", destinationId: "C2", protocol: "HTTPS",
            description: "Signed image\nUpdate metadata", trustBoundary: "Network -> privileged firmware",
        }]);
        expect(saved.threats).toEqual([]);
        expect(changed.mock.lastCall![0].risks).toBe("");
        expect(screen.getByRole("button", { name: "Remove component 1" })).toBeDisabled();
        expect(screen.getByRole("button", { name: "Remove component 2" })).toBeDisabled();
        fireEvent.click(screen.getByRole("button", { name: "Remove interaction 1" }));
        expect(screen.getByRole("button", { name: "Remove component 1" })).toBeEnabled();
        fireEvent.click(screen.getByRole("button", { name: "Remove component 1" }));
        expect(screen.getByLabelText("Component 1 name")).toHaveValue("OTA updater");
        expect(parseThreatModel(changed.mock.lastCall![0].threatModel)?.components[0].id).toBe("C2");
    });

    test("threats reference multiple system elements and risks inherit renamed targets without changing their link", () => {
        const changed = mountEditor();
        addComponent("Update service");
        addComponent("OTA updater");
        addInteraction("Firmware download", "C1", "C2");
        addThreat("Tampering", "Unauthorized firmware replacement");
        selectPanel("Threat model");
        const selector = screen.getByLabelText("Threat 1 affected system element");
        fireEvent.change(selector, { target: { value: "C2" } });
        fireEvent.change(selector, { target: { value: "I1" } });
        const calls = changed.mock.calls.length;
        fireEvent.change(selector, { target: { value: "C2" } });
        fireEvent.change(selector, { target: { value: "" } });
        expect(changed).toHaveBeenCalledTimes(calls);
        expect(parseThreatModel(changed.mock.lastCall![0].threatModel)?.threats[0].targetIds).toEqual(["C2", "I1"]);
        expect(screen.getByRole("list", { name: "Threat 1 affected system elements" })).toHaveTextContent("OTA updater");
        selectPanel("Risks");
        fireEvent.change(screen.getByLabelText("Risk 1 threat"), { target: { value: "T1" } });
        fireEvent.change(screen.getByLabelText("Risk 1 impact"), { target: { value: "High" } });
        const savedRisks = changed.mock.lastCall![0].risks;
        selectPanel("System");
        expect(screen.getByRole("button", { name: "Remove interaction 1" })).toBeDisabled();
        expect(screen.getByRole("button", { name: "Remove interaction 1" })).toHaveAccessibleDescription(/threat references/);
        fireEvent.change(screen.getByLabelText("Component 2 name"), { target: { value: "Privileged OTA agent" } });
        fireEvent.change(screen.getByLabelText("Interaction 1 name"), { target: { value: "Authenticated download" } });
        selectPanel("Risks");
        expect(screen.getByRole("list", { name: "Risk 1 affected system elements" })).toHaveTextContent("Privileged OTA agent");
        expect(screen.getByRole("list", { name: "Risk 1 affected system elements" })).toHaveTextContent("Authenticated download");
        expect(screen.getByLabelText("Risk 1 threat")).toHaveValue("T1");
        expect(changed.mock.lastCall![0].risks).toBe(savedRisks);
        selectPanel("Threat model");
        fireEvent.click(screen.getByRole("button", { name: "Remove I1 from threat 1" }));
        selectPanel("System");
        expect(screen.getByRole("button", { name: "Remove interaction 1" })).toBeEnabled();
        fireEvent.click(screen.getByRole("button", { name: "Remove interaction 1" }));
        expect(screen.getByRole("button", { name: "Remove component 2" })).toBeDisabled();
        expect(screen.getByRole("button", { name: "Remove component 2" })).toHaveAccessibleDescription(/threat references/);
        selectPanel("Threat model");
        fireEvent.click(screen.getByRole("button", { name: "Remove C2 from threat 1" }));
        selectPanel("System");
        expect(screen.getByRole("button", { name: "Remove component 2" })).toBeEnabled();
        fireEvent.click(screen.getByRole("button", { name: "Remove component 2" }));
        selectPanel("Risks");
        expect(screen.queryByRole("list", { name: "Risk 1 affected system elements" })).not.toBeInTheDocument();
        expect(screen.getByLabelText("Risk 1 threat")).toHaveValue("T1");
    });

    test("missing system targets and endpoints remain visible and are not assigned to new components", () => {
        const model: ThreatModel = {
            ...emptyThreatModel(), scope: "Device firmware",
            interactions: [{ ...emptySystemInteraction("I1"), name: "Saved flow", sourceId: "C1", destinationId: "C1" }],
            threats: [{ id: "T1", category: "Tampering", description: "Saved threat", targetIds: ["C1", "I2"] }],
        };
        const changed = mountEditor({
            threatModel: serializeThreatModel(model),
            risks: serializeRiskRegister({ risks: [{ ...emptyRisk(), threatId: "T1" }], notes: "" }),
        });
        expect(changed).not.toHaveBeenCalled();
        expect(screen.getAllByRole("status")).toHaveLength(2);
        expect(screen.getByText(/linked system element C1 is missing/)).toBeVisible();
        selectPanel("System");
        expect(screen.getByRole("status")).toHaveTextContent("Missing component references: C1.");
        expect(screen.getByLabelText("Interaction 1 source component")).toHaveValue("C1");
        addComponent("Unrelated component");
        expect(parseThreatModel(changed.mock.lastCall![0].threatModel)?.components[0].id).toBe("C2");
        addInteraction("New flow", "C2", "C2");
        expect(parseThreatModel(changed.mock.lastCall![0].threatModel)?.interactions[1].id).toBe("I3");
        fireEvent.change(screen.getByLabelText("Interaction 1 source component"), { target: { value: "C2" } });
        fireEvent.change(screen.getByLabelText("Interaction 1 destination component"), { target: { value: "C2" } });
        expect(screen.queryByRole("status")).not.toBeInTheDocument();
        selectPanel("Risks");
        expect(screen.getByRole("list", { name: "Risk 1 affected system elements" })).toHaveTextContent("Unavailable system element (C1)");
        selectPanel("Threat model");
        fireEvent.click(screen.getByRole("button", { name: "Remove C1 from threat 1" }));
        fireEvent.click(screen.getByRole("button", { name: "Remove I2 from threat 1" }));
        expect(screen.queryByRole("status")).not.toBeInTheDocument();
    });

    test("empty unnamed drafts are not selectable and survive System, Context and unchanged mode switches", () => {
        const changed = mountEditor();
        selectPanel("System");
        fireEvent.click(screen.getByRole("button", { name: "Add component" }));
        fireEvent.click(screen.getByRole("button", { name: "Add interaction" }));
        expect(changed).toHaveBeenLastCalledWith({ threatModel: "", risks: "" });
        selectPanel("Threat model");
        expect(screen.getByRole("option", { name: "Component C1: (name needed)" })).toBeDisabled();
        expect(screen.getByRole("option", { name: "Interaction I1: (name needed)" })).toBeDisabled();
        selectPanel("System");
        switchMode("free");
        expect(screen.getByRole("tabpanel", { name: "System" })).toHaveTextContent("In Advanced free mode");
        expect(screen.queryByRole("button", { name: "Add component" })).not.toBeInTheDocument();
        switchMode("stride");
        expect(screen.getByLabelText("Component 1 name")).toHaveValue("");
        expect(screen.getByLabelText("Interaction 1 name")).toHaveValue("");
        fireEvent.click(screen.getByRole("button", { name: "Remove interaction 1" }));
        fireEvent.click(screen.getByRole("button", { name: "Remove component 1" }));
        expect(screen.queryByLabelText("Component 1 name")).not.toBeInTheDocument();
        expect(screen.queryByLabelText("Interaction 1 name")).not.toBeInTheDocument();
    });

    test("clearing a referenced component name keeps its identity, flow and threat associations", () => {
        const changed = mountEditor();
        addComponent("OTA updater");
        addInteraction("Local update", "C1", "C1");
        addThreat("Tampering", "Image replacement");
        selectPanel("Threat model");
        fireEvent.change(screen.getByLabelText("Threat 1 affected system element"), { target: { value: "C1" } });
        selectPanel("System");
        fireEvent.change(screen.getByLabelText("Component 1 name"), { target: { value: "" } });
        expect(screen.getByLabelText("Interaction 1 source component")).toHaveValue("C1");
        const saved = parseThreatModel(changed.mock.lastCall![0].threatModel)!;
        expect(saved.components).toEqual([emptySystemComponent("C1")]);
        expect(saved.threats[0].targetIds).toEqual(["C1"]);
        selectPanel("Threat model");
        expect(screen.getByRole("list", { name: "Threat 1 affected system elements" })).toHaveTextContent("(name needed)");
    });

    test("new contexts show architecture, repeatable threats and an always-visible Additional notes area", () => {
        const changed = mountEditor();
        expect(screen.getByLabelText("Editor mode")).toHaveValue("stride");
        selectPanel("Context");
        expect(screen.getByRole("option", { name: "Advanced free mode" })).toBeInTheDocument();
        expect(screen.getByLabelText("Editor mode")).toHaveAccessibleDescription("Applies to System, Threat model and Risks.");
        selectPanel("System");
        for (const field of THREAT_MODEL_FIELDS) {
            const input = screen.getByLabelText(field.label);
            expect(input).toHaveValue("");
            expect(input).toHaveAccessibleDescription(field.help);
            expect(input).toBeVisible();
        }
        expect(screen.getByRole("button", { name: "Add component" })).toBeVisible();
        expect(screen.getByRole("button", { name: "Add interaction" })).toBeVisible();
        selectPanel("Threat model");
        for (const field of THREAT_MODEL_FIELDS) expect(screen.getByLabelText(field.label)).not.toBeVisible();
        expect(screen.queryByLabelText("Threat Model", { selector: "textarea" })).not.toBeInTheDocument();
        expect(screen.queryByLabelText("Risks", { selector: "textarea" })).not.toBeInTheDocument();
        expect(screen.getByRole("textbox", { name: "Additional notes" })).toBeVisible();
        expect(screen.getByLabelText("Additional notes")).toHaveValue("");
        expect(screen.getByRole("group", { name: "Threat 1" })).toBeVisible();
        expect(screen.getByLabelText("Threat 1 STRIDE category")).toHaveValue("");
        expect(screen.getByLabelText("Threat 1 description")).toHaveValue("");
        expect(screen.getByRole("button", { name: "Add threat" })).toBeInTheDocument();
        for (const category of STRIDE_CATEGORIES)
            expect(screen.queryByLabelText(`${category.letter} - ${category.name}`)).not.toBeInTheDocument();
        expect(screen.getByLabelText("Risk 1 threat")).toHaveValue("");
        expect(screen.getByLabelText("Risk 1 threat")).toBeDisabled();
        expect(screen.getByLabelText("Risk 1 threat")).not.toBeVisible();
        expect(screen.queryByLabelText("Risk 1 STRIDE category")).not.toBeInTheDocument();
        expect(screen.queryByLabelText("Risk 1 threat scenario")).not.toBeInTheDocument();
        expect(screen.getByLabelText("Risk 1 likelihood")).toHaveValue("");
        expect(screen.getByLabelText("Risk 1 impact")).toHaveValue("");
        expect(changed).not.toHaveBeenCalled();
    });

    test.each(["stride", "free"] as const)("all %s editor fields and buttons are disabled without a selected variant", mode => {
        mountEditor(mode === "stride" ? undefined : { threatModel: "Existing text", risks: "Existing risks" }, true);
        selectPanel("Context");
        expect(screen.getByRole("combobox", { name: "Editor mode" })).toBeDisabled();
        for (const panel of ["System", "Threat model", "Risks"] as const) {
            selectPanel(panel);
            for (const field of screen.queryAllByRole("textbox")) expect(field).toBeDisabled();
            for (const field of screen.queryAllByRole("combobox")) expect(field).toBeDisabled();
            for (const button of screen.queryAllByRole("button")) expect(button).toBeDisabled();
        }
    });

    test.each(["stride", "free"] as const)("%s panels show only their own controls and preserve edits on section switches", mode => {
        const changed = mountEditor(mode === "stride" ? undefined : { threatModel: "Existing model", risks: "Existing risks" });
        const modelField = mode === "stride" ? "Threat 1 description" : "Threat Model";
        const riskField = mode === "stride" ? "Risk 1 mitigation" : "Risks";
        const modelPanel = screen.getByRole("tabpanel", { name: "Threat model" });
        const modelTab = screen.getByRole("tab", { name: "Threat model" });
        expect(modelPanel).toHaveAttribute("id", modelTab.getAttribute("aria-controls"));
        expect(modelPanel).toHaveAttribute("aria-labelledby", modelTab.id);
        expect(screen.getAllByRole("tabpanel", { hidden: true })).toHaveLength(5);
        expect(screen.getAllByRole("tabpanel")).toHaveLength(1);
        const modelInput = screen.getByRole("textbox", { name: modelField });
        fireEvent.change(modelInput, { target: { value: "Draft model" } });
        selectPanel("Risks");
        expect(modelInput).not.toBeVisible();
        const riskPanel = screen.getByRole("tabpanel", { name: "Risks" });
        const riskTab = screen.getByRole("tab", { name: "Risks" });
        expect(riskPanel).toHaveAttribute("id", riskTab.getAttribute("aria-controls"));
        expect(riskPanel).toHaveAttribute("aria-labelledby", riskTab.id);
        expect(screen.getAllByRole("tabpanel")).toHaveLength(1);
        fireEvent.change(screen.getByRole("textbox", { name: riskField }), { target: { value: "Draft mitigation" } });
        selectPanel("Threat model");
        expect(screen.getByRole("textbox", { name: modelField })).toBe(modelInput);
        expect(modelInput).toHaveValue("Draft model");
        selectPanel("Risks");
        expect(screen.getByRole("textbox", { name: riskField })).toHaveValue("Draft mitigation");
        expect(changed).toHaveBeenCalledTimes(2);
    });

    test("edits serialize the model without filling in examples or inventing optional risks", () => {
        const changed = mountEditor();
        selectPanel("System");
        fireEvent.change(screen.getByLabelText("System scope and assets"), { target: { value: "Firmware and device credentials" } });
        const saved: StrideContextText = changed.mock.lastCall![0];
        expect(parseThreatModel(saved.threatModel)).toEqual({
            ...emptyThreatModel(), scope: "Firmware and device credentials",
        });
        expect(saved.risks).toBe("");
        selectPanel("Threat model");
        fireEvent.change(screen.getByLabelText("Threat 1 STRIDE category"), { target: { value: "Spoofing" } });
        fireEvent.change(screen.getByLabelText("Threat 1 description"), { target: { value: "Device impersonation is possible" } });
        expect(parseThreatModel(changed.mock.lastCall![0].threatModel)?.threats).toEqual([
            { id: "T1", category: "Spoofing", description: "Device impersonation is possible" },
        ]);
    });

    test("input whitespace is editable but blank templates and empty risk rows emit no saved content", () => {
        const changed = mountEditor();
        selectPanel("System");
        fireEvent.change(screen.getByLabelText("System scope and assets"), { target: { value: " " } });
        expect(screen.getByLabelText("System scope and assets")).toHaveValue(" ");
        expect(changed).toHaveBeenLastCalledWith({ threatModel: "", risks: "" });
        selectPanel("Risks");
        fireEvent.click(screen.getByRole("button", { name: "Add risk" }));
        expect(screen.getByRole("group", { name: "Risk 2" })).toBeInTheDocument();
        expect(changed).toHaveBeenLastCalledWith({ threatModel: "", risks: "" });
    });

    test("a risk selects an existing threat and records only its risk evaluation", () => {
        const changed = mountEditor();
        addThreat("Tampering", "Unsigned firmware replacement");
        fireEvent.change(screen.getByLabelText("Risk 1 threat"), { target: { value: "T1" } });
        expect(screen.getByRole("note", { name: "Risk 1 selected threat" })).toHaveTextContent("Unsigned firmware replacement");
        fireEvent.change(screen.getByLabelText("Risk 1 likelihood"), { target: { value: "Medium" } });
        fireEvent.change(screen.getByLabelText("Risk 1 impact"), { target: { value: "High" } });
        fireEvent.change(screen.getByLabelText("Risk 1 mitigation"), { target: { value: "Verify signed images" } });
        fireEvent.change(screen.getByLabelText("Risk 1 residual risk / decision"), { target: { value: "Investigate recovery path" } });
        fireEvent.change(screen.getByLabelText("Additional risk notes"), { target: { value: "Review after key rotation" } });
        const saved = parseRiskRegister(changed.mock.lastCall![0].risks);
        expect(saved).toEqual({
            risks: [{ threatId: "T1", likelihood: "Medium",
                impact: "High", mitigation: "Verify signed images", decision: "Investigate recovery path" }],
            notes: "Review after key rotation",
        });
        fireEvent.change(screen.getByLabelText("Risk 1 likelihood"), { target: { value: "" } });
        fireEvent.change(screen.getByLabelText("Risk 1 impact"), { target: { value: "Low" } });
        fireEvent.change(screen.getByLabelText("Risk 1 threat"), { target: { value: "" } });
        expect(parseRiskRegister(changed.mock.lastCall![0].risks)?.risks[0]).toMatchObject({
            threatId: "", likelihood: "", impact: "Low",
        });
    });

    test("risk rows can be added and removed without losing a different row's values", () => {
        const changed = mountEditor();
        addThreat("Spoofing", "First scenario");
        addThreat("Spoofing", "Second scenario");
        fireEvent.change(screen.getByLabelText("Risk 1 threat"), { target: { value: "T1" } });
        fireEvent.click(screen.getByRole("button", { name: "Add risk" }));
        fireEvent.change(screen.getByLabelText("Risk 2 threat"), { target: { value: "T2" } });
        fireEvent.click(screen.getByRole("button", { name: "Remove risk 1" }));
        expect(screen.getByLabelText("Risk 1 threat")).toHaveValue("T2");
        expect(parseRiskRegister(changed.mock.lastCall![0].risks)?.risks).toEqual([
            { ...emptyRisk(), threatId: "T2" },
        ]);
        fireEvent.click(screen.getByRole("button", { name: "Remove risk 1" }));
        expect(screen.queryByRole("group", { name: "Risk 1" })).not.toBeInTheDocument();
        expect(changed.mock.lastCall![0].risks).toBe("");
        fireEvent.click(screen.getByRole("button", { name: "Add risk" }));
        expect(screen.getByLabelText("Risk 1 threat")).toHaveValue("");
    });

    test("saved STRIDE context restores in template mode without rewriting or dirtying it", () => {
        const model: ThreatModel = {
            ...emptyThreatModel(), scope: "Device firmware",
            threats: [{ id: "T1", category: "Spoofing", description: "A client may impersonate an administrator" }],
        };
        const register = { risks: [{ ...emptyRisk(), threatId: "T1" }], notes: "Needs review" };
        const initial = { threatModel: serializeThreatModel(model), risks: serializeRiskRegister(register) };
        const changed = mountEditor(initial);
        expect(screen.getByLabelText("System scope and assets")).toHaveValue(model.scope);
        expect(screen.getByLabelText("Threat 1 STRIDE category")).toHaveValue("Spoofing");
        expect(screen.getByLabelText("Threat 1 description")).toHaveValue(model.threats[0].description);
        expect(screen.getByLabelText("Risk 1 threat")).toHaveValue("T1");
        expect(changed).not.toHaveBeenCalled();
        switchMode("free");
        expect(screen.getByRole("textbox", { name: "Threat Model" })).toHaveValue(initial.threatModel);
        selectPanel("Risks");
        expect(screen.getByRole("textbox", { name: "Risks" })).toHaveValue(initial.risks);
        switchMode("stride");
        expect(changed).not.toHaveBeenCalled();
    });

    test("advanced free edits remain verbatim and switching to STRIDE preserves both fields as notes", () => {
        const initial = { threatModel: " Existing model\nWith assumptions ", risks: "Known risk\nStill unquantified" };
        const changed = mountEditor(initial);
        expect(screen.getByLabelText("Editor mode")).toHaveValue("free");
        expect(changed).not.toHaveBeenCalled();
        expect(screen.getByRole("textbox", { name: "Threat Model" })).toHaveValue(initial.threatModel);
        fireEvent.change(screen.getByRole("textbox", { name: "Threat Model" }), { target: { value: "Edited free model\n\n## Arbitrary heading" } });
        selectPanel("Risks");
        expect(screen.getByRole("textbox", { name: "Risks" })).toHaveValue(initial.risks);
        fireEvent.change(screen.getByRole("textbox", { name: "Risks" }), { target: { value: "Edited free risk" } });
        expect(changed).toHaveBeenLastCalledWith({
            threatModel: "Edited free model\n\n## Arbitrary heading", risks: "Edited free risk",
        });
        switchMode("stride");
        expect(screen.getByLabelText("Additional notes")).toHaveValue("Edited free model\n\n## Arbitrary heading");
        expect(screen.getByLabelText("Additional risk notes")).toHaveValue("Edited free risk");
        const converted: StrideContextText = changed.mock.lastCall![0];
        expect(parseThreatModel(converted.threatModel)?.notes).toBe("Edited free model\n\n## Arbitrary heading");
        expect(parseRiskRegister(converted.risks)?.notes).toBe("Edited free risk");
    });

    test("manually edited advanced template text is kept as notes rather than partially parsed and discarded", () => {
        const changed = mountEditor();
        fireEvent.change(screen.getByLabelText("Threat 1 STRIDE category"), { target: { value: "Denial of service" } });
        fireEvent.change(screen.getByLabelText("Threat 1 description"), { target: { value: "Unbounded network requests" } });
        switchMode("free");
        const edited = changed.mock.lastCall![0].threatModel + "\n\nMore notes outside the template.";
        fireEvent.change(screen.getByRole("textbox", { name: "Threat Model" }), { target: { value: edited } });
        switchMode("stride");
        expect(screen.getByLabelText("Additional notes")).toHaveValue(edited);
        expect(parseThreatModel(changed.mock.lastCall![0].threatModel)?.notes).toBe(edited);
    });

    test("a blank mode switch cannot turn headings or placeholders into a filled model", () => {
        const changed = mountEditor();
        switchMode("free");
        expect(screen.getByRole("textbox", { name: "Threat Model" })).toHaveValue("");
        switchMode("stride");
        expect(screen.getByLabelText("Threat 1 STRIDE category")).toHaveValue("");
        expect(screen.getByLabelText("Threat 1 description")).toHaveValue("");
        expect(changed).not.toHaveBeenCalled();
    });

    test("mode switches retain incomplete threat drafts unless the free text was edited", () => {
        const changed = mountEditor();
        fireEvent.change(screen.getByLabelText("Threat 1 STRIDE category"), { target: { value: "Spoofing" } });
        fireEvent.change(screen.getByLabelText("Threat 1 description"), { target: { value: " " } });
        switchMode("free");
        expect(screen.getByRole("textbox", { name: "Threat Model" })).toHaveValue("");
        switchMode("stride");
        expect(screen.getByLabelText("Threat 1 STRIDE category")).toHaveValue("Spoofing");
        expect(screen.getByLabelText("Threat 1 description")).toHaveValue(" ");
        expect(changed).toHaveBeenLastCalledWith({ threatModel: "", risks: "" });
        switchMode("free");
        fireEvent.change(screen.getByRole("textbox", { name: "Threat Model" }), { target: { value: "New free model" } });
        switchMode("stride");
        expect(screen.getByRole("group", { name: "Threat 1" })).toBeVisible();
        expect(screen.getByLabelText("Threat 1 STRIDE category")).toHaveValue("");
        expect(screen.getByLabelText("Threat 1 description")).toHaveValue("");
        expect(screen.getByLabelText("Additional notes")).toHaveValue("New free model");
    });

    test("risks distinguish threats sharing a category and inherit subsequent edits without losing their link", () => {
        const changed = mountEditor();
        addThreat("Spoofing", "Device impersonation");
        addThreat("Spoofing", "Administrator impersonation");
        const select = screen.getByLabelText("Risk 1 threat");
        expect(within(select).getByRole("option", { name: "Threat 1 - Spoofing: Device impersonation" })).toHaveValue("T1");
        expect(within(select).getByRole("option", { name: "Threat 2 - Spoofing: Administrator impersonation" })).toHaveValue("T2");
        fireEvent.change(select, { target: { value: "T2" } });
        expect(screen.getByRole("note", { name: "Risk 1 selected threat" })).toHaveTextContent("Administrator impersonation");
        selectPanel("Threat model");
        fireEvent.change(screen.getByLabelText("Threat 2 STRIDE category"), { target: { value: "Tampering" } });
        fireEvent.change(screen.getByLabelText("Threat 2 description"), { target: { value: "Modified administrator credentials" } });
        selectPanel("Risks");
        expect(screen.getByRole("note", { name: "Risk 1 selected threat" })).toHaveTextContent("Tampering");
        expect(screen.getByRole("note", { name: "Risk 1 selected threat" })).toHaveTextContent("Modified administrator credentials");
        selectPanel("Threat model");
        fireEvent.click(screen.getByRole("button", { name: "Remove threat 1" }));
        selectPanel("Risks");
        expect(screen.getByLabelText("Risk 1 threat")).toHaveValue("T2");
        expect(parseRiskRegister(changed.mock.lastCall![0].risks)?.risks[0].threatId).toBe("T2");
        expect(parseThreatModel(changed.mock.lastCall![0].threatModel)?.threats[0].id).toBe("T2");
    });

    test("linked threats cannot be deleted until all their risks are reassigned or removed", () => {
        mountEditor();
        addThreat("Spoofing", "Device impersonation");
        addThreat("Spoofing", "Administrator impersonation");
        fireEvent.change(screen.getByLabelText("Risk 1 threat"), { target: { value: "T1" } });
        fireEvent.click(screen.getByRole("button", { name: "Add risk" }));
        fireEvent.change(screen.getByLabelText("Risk 2 threat"), { target: { value: "T1" } });
        selectPanel("Threat model");
        const remove = screen.getByRole("button", { name: "Remove threat 1" });
        expect(remove).toBeDisabled();
        expect(remove).toHaveAccessibleDescription(/Reassign or remove.*linked risks/);
        fireEvent.click(remove);
        expect(screen.getByLabelText("Threat 1 description")).toHaveValue("Device impersonation");
        selectPanel("Risks");
        fireEvent.change(screen.getByLabelText("Risk 1 threat"), { target: { value: "T2" } });
        expect(remove).toBeDisabled();
        fireEvent.click(screen.getByRole("button", { name: "Remove risk 2" }));
        expect(remove).toBeEnabled();
        selectPanel("Threat model");
        fireEvent.click(remove);
        expect(screen.getByLabelText("Risk 1 threat")).toHaveValue("T2");
        expect(screen.getByRole("button", { name: "Remove threat 1" })).toBeDisabled();
        selectPanel("Risks");
        fireEvent.click(screen.getByRole("button", { name: "Remove risk 1" }));
        selectPanel("Threat model");
        expect(screen.getByRole("button", { name: "Remove threat 1" })).toBeEnabled();
    });

    test("clearing a linked threat's fields retains its ID and risk association", () => {
        const changed = mountEditor();
        selectPanel("System");
        fireEvent.change(screen.getByLabelText("System scope and assets"), { target: { value: "Device firmware" } });
        addThreat("", "Uncategorized threat");
        fireEvent.change(screen.getByLabelText("Risk 1 threat"), { target: { value: "T1" } });
        selectPanel("Threat model");
        fireEvent.change(screen.getByLabelText("Threat 1 description"), { target: { value: "" } });
        selectPanel("Risks");
        expect(screen.getByLabelText("Risk 1 threat")).toHaveValue("T1");
        expect(screen.getByLabelText("Risk 1 threat")).toBeDisabled();
        expect(screen.getByRole("note", { name: "Risk 1 selected threat" })).toHaveTextContent("Complete this threat's description in Threat model.");
        expect(parseThreatModel(changed.mock.lastCall![0].threatModel)?.threats).toEqual([
            { id: "T1", category: "", description: "" },
        ]);
        expect(parseRiskRegister(changed.mock.lastCall![0].risks)?.risks[0].threatId).toBe("T1");
        selectPanel("Threat model");
        fireEvent.change(screen.getByLabelText("Threat 1 description"), { target: { value: "Completed threat" } });
        selectPanel("Risks");
        expect(screen.getByLabelText("Risk 1 threat")).toBeEnabled();
        expect(screen.getByRole("note", { name: "Risk 1 selected threat" })).toHaveTextContent("Completed threat");
    });

    test("legacy unlinked scenarios are retained and can be explicitly added as threats without retyping them", () => {
        const legacy = {
            ...emptyRisk(), impact: "High" as const, mitigation: "Authenticate devices",
            legacyThreat: { category: "Spoofing" as const, description: "Saved device impersonation scenario" },
        };
        const changed = mountEditor({ threatModel: "", risks: serializeRiskRegister({ risks: [legacy], notes: "" }) });
        selectPanel("Risks");
        expect(screen.getByRole("status")).toHaveTextContent("existing risk is not linked to a threat");
        expect(screen.getByText("Saved device impersonation scenario")).toBeInTheDocument();
        expect(changed).not.toHaveBeenCalled();
        fireEvent.click(screen.getByRole("button", { name: "Add risk 1 scenario as threat" }));
        expect(screen.getByLabelText("Threat 1 description")).toHaveValue("");
        expect(screen.getByLabelText("Threat 2 description")).toHaveValue(legacy.legacyThreat.description);
        expect(screen.getByLabelText("Threat 2 STRIDE category")).toHaveValue("Spoofing");
        expect(screen.getByLabelText("Risk 1 threat")).toHaveValue("T2");
        expect(screen.queryByRole("status")).not.toBeInTheDocument();
        expect(parseRiskRegister(changed.mock.lastCall![0].risks)?.risks[0]).toEqual({
            ...emptyRisk(), threatId: "T2", impact: "High", mitigation: "Authenticate devices",
        });
    });

    test("legacy matching risks inherit a unique threat without rewriting the saved text", () => {
        const model: ThreatModel = {
            ...emptyThreatModel(), threats: [{ id: "T1", category: "Tampering", description: "Unsigned updates" }],
        };
        const legacy = { ...emptyRisk(), legacyThreat: { category: "Tampering" as const, description: "Unsigned updates" } };
        const text = { threatModel: serializeThreatModel(model), risks: serializeRiskRegister({ risks: [legacy], notes: "" }) };
        const changed = mountEditor(text);
        selectPanel("Risks");
        expect(screen.getByLabelText("Risk 1 threat")).toHaveValue("T1");
        expect(screen.queryByRole("status")).not.toBeInTheDocument();
        switchMode("free");
        expect(screen.getByRole("textbox", { name: "Risks" })).toHaveValue(text.risks);
        switchMode("stride");
        expect(changed).not.toHaveBeenCalled();
    });

    test("a missing linked threat stays visible and its ID is not reused for a newly added threat", () => {
        const changed = mountEditor({
            threatModel: serializeThreatModel({ ...emptyThreatModel(), scope: "Device firmware" }),
            risks: serializeRiskRegister({ risks: [{ ...emptyRisk(), threatId: "T1", impact: "High" }], notes: "" }),
        });
        selectPanel("Risks");
        expect(screen.getByRole("status")).toHaveTextContent("linked threat T1 is missing");
        expect(screen.getByLabelText("Risk 1 threat")).toHaveValue("T1");
        addThreat("Tampering", "Unsigned updates");
        expect(screen.getByRole("status")).toBeInTheDocument();
        expect(screen.getByLabelText("Risk 1 threat")).toHaveValue("T1");
        expect(parseThreatModel(changed.mock.lastCall![0].threatModel)?.threats[0].id).toBe("T2");
        fireEvent.change(screen.getByLabelText("Risk 1 threat"), { target: { value: "T2" } });
        expect(screen.queryByRole("status")).not.toBeInTheDocument();
        expect(parseRiskRegister(changed.mock.lastCall![0].risks)?.risks[0]).toEqual({
            ...emptyRisk(), threatId: "T2", impact: "High",
        });
    });

    test("multiple Spoofing threats can be added, edited and removed independently", () => {
        const changed = mountEditor();
        fireEvent.change(screen.getByLabelText("Threat 1 STRIDE category"), { target: { value: "Spoofing" } });
        fireEvent.change(screen.getByLabelText("Threat 1 description"), { target: { value: "Device impersonation" } });
        fireEvent.click(screen.getByRole("button", { name: "Add threat" }));
        fireEvent.change(screen.getByLabelText("Threat 2 STRIDE category"), { target: { value: "Spoofing" } });
        fireEvent.change(screen.getByLabelText("Threat 2 description"), { target: { value: "Administrator impersonation" } });
        expect(parseThreatModel(changed.mock.lastCall![0].threatModel)?.threats).toEqual([
            { id: "T1", category: "Spoofing", description: "Device impersonation" },
            { id: "T2", category: "Spoofing", description: "Administrator impersonation" },
        ]);
        fireEvent.click(screen.getByRole("button", { name: "Remove threat 1" }));
        expect(screen.getByLabelText("Threat 1 STRIDE category")).toHaveValue("Spoofing");
        expect(screen.getByLabelText("Threat 1 description")).toHaveValue("Administrator impersonation");
        expect(parseThreatModel(changed.mock.lastCall![0].threatModel)?.threats).toEqual([
            { id: "T2", category: "Spoofing", description: "Administrator impersonation" },
        ]);
        fireEvent.click(screen.getByRole("button", { name: "Remove threat 1" }));
        expect(screen.queryByRole("group", { name: "Threat 1" })).not.toBeInTheDocument();
        expect(changed).toHaveBeenLastCalledWith({ threatModel: "", risks: "" });
    });

    test("category selection alone is not a completed model and guidance changes without losing the description", () => {
        const changed = mountEditor();
        const select = screen.getByLabelText("Threat 1 STRIDE category");
        const description = screen.getByLabelText("Threat 1 description");
        for (const category of STRIDE_CATEGORIES) {
            fireEvent.change(select, { target: { value: category.name } });
            expect(description).toHaveAccessibleDescription(category.question);
            expect(description).toHaveAttribute("placeholder", category.example);
            expect(changed).toHaveBeenLastCalledWith({ threatModel: "", risks: "" });
        }
        fireEvent.change(description, { target: { value: "Unprivileged actor gaining admin access" } });
        fireEvent.change(select, { target: { value: "Spoofing" } });
        expect(description).toHaveValue("Unprivileged actor gaining admin access");
        fireEvent.change(select, { target: { value: "" } });
        expect(parseThreatModel(changed.mock.lastCall![0].threatModel)?.threats).toEqual([
            { id: "T1", category: "", description: "Unprivileged actor gaining admin access" },
        ]);
    });

    test("Additional notes needs no toggle and retains content across sections and editor modes", () => {
        const changed = mountEditor();
        const notes = screen.getByRole("textbox", { name: "Additional notes" });
        expect(notes).toBeVisible();
        expect(screen.queryByRole("button", { name: /additional notes/i })).not.toBeInTheDocument();
        fireEvent.change(notes, { target: { value: "Production debug port is disabled" } });
        const saved: StrideContextText = changed.mock.lastCall![0];
        selectPanel("Risks");
        expect(notes).not.toBeVisible();
        selectPanel("Threat model");
        expect(screen.getByRole("textbox", { name: "Additional notes" })).toBe(notes);
        expect(notes).toHaveValue("Production debug port is disabled");
        switchMode("free");
        switchMode("stride");
        expect(screen.getByRole("textbox", { name: "Additional notes" })).toHaveValue("Production debug port is disabled");
        expect(changed).toHaveBeenCalledTimes(1);
        expect(parseThreatModel(saved.threatModel)?.notes).toBe("Production debug port is disabled");
        fireEvent.change(screen.getByLabelText("Additional notes"), { target: { value: "" } });
        expect(screen.getByRole("textbox", { name: "Additional notes" })).toBeVisible();
        expect(changed).toHaveBeenLastCalledWith({ threatModel: "", risks: "" });
    });

    test("previous per-category templates open as threats without rewriting text on mode changes", () => {
        const legacy = [
            "# STRIDE threat model",
            ...THREAT_MODEL_FIELDS.map(field => `## ${field.label}\n>`),
            ...STRIDE_CATEGORIES.map(category =>
                `## ${category.letter} - ${category.name}\n${category.name === "Spoofing" ? "> Impersonation" : ">"}`),
            "## Additional threat model notes\n> Assumption retained",
            "<!-- VulnScout STRIDE v1 -->",
        ].join("\n\n");
        const changed = mountEditor({ threatModel: legacy, risks: "" });
        expect(screen.getByLabelText("Threat 1 STRIDE category")).toHaveValue("Spoofing");
        expect(screen.getByLabelText("Threat 1 description")).toHaveValue("Impersonation");
        expect(screen.getByLabelText("Additional notes")).toHaveValue("Assumption retained");
        switchMode("free");
        expect(screen.getByRole("textbox", { name: "Threat Model" })).toHaveValue(legacy);
        switchMode("stride");
        expect(changed).not.toHaveBeenCalled();
    });

    test.each(["stride", "free"] as const)("required model errors remain visible and associated with the %s editor", mode => {
        mountEditor(mode === "stride" ? undefined : { threatModel: "Existing text", risks: "" }, false, "Threat Model is required.");
        expect(screen.getByRole("alert")).toHaveTextContent("Threat Model is required.");
        if (mode === "stride") expect(screen.getByRole("group", { name: "Threat Model *" }))
            .toHaveAccessibleDescription("Threat Model is required.");
        else expect(screen.getByRole("textbox", { name: "Threat Model" })).toHaveAccessibleDescription("Threat Model is required.");
        selectPanel("Risks");
        expect(screen.queryByRole("alert")).not.toBeInTheDocument();
        selectPanel("Threat model");
        expect(screen.getByRole("alert")).toHaveTextContent("Threat Model is required.");
    });
});

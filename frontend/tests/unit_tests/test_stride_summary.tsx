// @ts-expect-error TS6133
import React from "react";
import { render, screen, within } from "@testing-library/react";
import "@testing-library/jest-dom";
import StrideSummary from "../../src/components/StrideSummary";
import {
    emptyRisk, emptyThreat, emptyThreatModel, emptySystemComponent, emptySystemInteraction,
} from "../../src/helpers/strideContext";
import type { RiskRegister, ThreatModel } from "../../src/helpers/strideContext";

describe("STRIDE summary", () => {
    const model: ThreatModel = {
        ...emptyThreatModel(),
        components: [
            { ...emptySystemComponent("C2"), name: "Gateway" },
            { ...emptySystemComponent("C3"), name: "Device" },
        ],
        interactions: [{
            ...emptySystemInteraction("I1"), name: "Firmware download", sourceId: "C2", destinationId: "C3",
            protocol: "HTTPS", trustBoundary: "Network to privileged firmware",
        }],
        threats: [
            emptyThreat("T7"),
            { id: "T4", category: "Spoofing", description: "Gateway impersonation", targetIds: ["C2", "I1"] },
            { id: "T5", category: "Spoofing", description: " " },
            { id: "T6", category: "", description: "Unclassified scenario" },
        ],
        notes: "Verify production debug settings.",
    };
    const register: RiskRegister = {
        risks: [
            emptyRisk(),
            { ...emptyRisk(), threatId: "T4", likelihood: "High", impact: "Medium", mitigation: "Authenticate gateways", decision: "Verify provisioning" },
            { ...emptyRisk(), threatId: "T4" },
        ],
        notes: "Review after deployment.",
    };

    test("empty templates do not invent threats, risks or completed category reviews", () => {
        render(<StrideSummary model={{ ...emptyThreatModel(), threats: [emptyThreat("T1")] }}
            register={{ risks: [emptyRisk()], notes: "" }} />);
        const categories = screen.getByRole("table", { name: "Recorded threats by STRIDE category" });
        expect(within(categories).getAllByRole("row")).toHaveLength(7);
        for (const row of within(categories).getAllByRole("row").slice(1)) {
            expect(within(row).getAllByRole("cell").map(cell => cell.textContent)).toEqual(["0", "0"]);
        }
        expect(screen.getByText(/Zero recorded threats does not mean/)).toBeVisible();
        expect(screen.queryByRole("table", { name: "Threats and linked risk evaluations" })).not.toBeInTheDocument();
        expect(screen.queryByRole("table", { name: "Risks with unlinked or unavailable threats" })).not.toBeInTheDocument();
        expect(screen.getByText(/No threat entries recorded yet/)).toBeVisible();
        expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
        expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
        expect(screen.queryByRole("button")).not.toBeInTheDocument();
    });

    test("counts threats once, separates incomplete drafts, and shows each linked risk with its editor number", () => {
        render(<StrideSummary model={model} register={register} />);
        const categories = screen.getByRole("table", { name: "Recorded threats by STRIDE category" });
        expect(within(categories).getByRole("row", { name: "S - Spoofing 1 1" })).toBeVisible();
        expect(screen.getByRole("status")).toHaveTextContent("Threats without a STRIDE category: T6.");
        const table = screen.getByRole("table", { name: "Threats and linked risk evaluations" });
        expect(within(table).getByText("Threat 2 (T4)").closest("th")).toHaveAttribute("rowspan", "2");
        expect(within(table).getAllByRole("row")).toHaveLength(5);
        expect(within(table).getByRole("cell", { name: "Risk 2" })).toBeVisible();
        expect(within(table).getByRole("cell", { name: "Risk 3" })).toBeVisible();
        expect(within(table).queryByRole("cell", { name: "Risk 1" })).not.toBeInTheDocument();
        expect(within(table).getByRole("cell", { name: "High" })).toBeVisible();
        expect(within(table).getByRole("cell", { name: "Medium" })).toBeVisible();
        expect(table).toHaveTextContent("Authenticate gateways");
        expect(table).toHaveTextContent("Verify provisioning");
        expect(table).toHaveTextContent("Not rated");
        expect(table).toHaveTextContent("Not recorded");
        expect(table).toHaveTextContent("No linked risk");
        expect(table).toHaveTextContent("Not evaluated");
        expect(table).toHaveTextContent("No system reference");
        expect(table).toHaveTextContent("Component C2: Gateway -> Component C3: Device (HTTPS)");
        expect(table).toHaveTextContent("Trust boundary: Network to privileged firmware");
        expect(table).not.toHaveTextContent("T7");
        expect(screen.getByText(model.notes)).toBeVisible();
        expect(screen.getByText(register.notes)).toBeVisible();
        for (const region of screen.getAllByRole("region")) {
            expect(region).toHaveAttribute("tabindex", "0");
            expect(region).toHaveClass("overflow-x-auto");
        }
    });

    test("a blank threat referenced by a risk stays visible as incomplete", () => {
        render(<StrideSummary model={{ ...emptyThreatModel(), threats: [emptyThreat("T1")] }}
            register={{ risks: [{ ...emptyRisk(), threatId: "T1", impact: "High" }], notes: "" }} />);
        expect(screen.getByRole("table", { name: "Threats and linked risk evaluations" })).toHaveTextContent("Description missing (draft)");
        expect(screen.getByRole("status")).toHaveTextContent("Threats without a STRIDE category: T1.");
        expect(screen.getByRole("cell", { name: "High" })).toBeVisible();
    });

    test("unlinked, missing and legacy risks remain visible without being turned into recorded threats", () => {
        render(<StrideSummary model={emptyThreatModel()} register={{
            risks: [
                emptyRisk(),
                { ...emptyRisk(), legacyThreat: { category: "Tampering", description: "Saved legacy scenario" } },
                { ...emptyRisk(), threatId: "T9", decision: "Investigate missing threat" },
                { ...emptyRisk(), legacyThreat: { category: "", description: " " }, impact: "High" },
                { ...emptyRisk(), likelihood: "Low" },
            ], notes: "",
        }} />);
        const table = screen.getByRole("table", { name: "Risks with unlinked or unavailable threats" });
        expect(within(table).getAllByRole("row")).toHaveLength(5);
        expect(table).toHaveTextContent("Risk 2");
        expect(table).toHaveTextContent("Saved legacy scenario");
        expect(table).toHaveTextContent("Tampering");
        expect(table).toHaveTextContent("Description not recorded");
        expect(table).toHaveTextContent("Uncategorized");
        expect(table).toHaveTextContent("No saved scenario");
        expect(table).toHaveTextContent("Investigate missing threat");
        expect(screen.getByRole("status")).toHaveTextContent("Unavailable threat (T9)");
        expect(screen.queryByRole("table", { name: "Threats and linked risk evaluations" })).not.toBeInTheDocument();
        expect(within(screen.getByRole("table", { name: "Recorded threats by STRIDE category" }))
            .getByRole("row", { name: "T - Tampering 0 0" })).toBeVisible();
    });

    test("missing system references and unspecified flow endpoints are reported without guessed connections", () => {
        render(<StrideSummary model={{
            ...emptyThreatModel(),
            interactions: [
                { ...emptySystemInteraction("I1"), name: "Missing endpoints", sourceId: "C9", destinationId: "C10" },
                emptySystemInteraction("I2"),
            ],
            threats: [{ id: "T1", category: "Tampering", description: "System threat", targetIds: ["C8", "I1", "I2"] }],
        }} register={{ risks: [], notes: "" }} />);
        const table = screen.getByRole("table", { name: "Threats and linked risk evaluations" });
        expect(screen.getByRole("status")).toHaveTextContent("Unavailable system element (C8)");
        expect(table).toHaveTextContent("Unavailable component (C9) -> Unavailable component (C10)");
        expect(table).toHaveTextContent("Source not specified -> Destination not specified");
        expect(table).toHaveTextContent("Interaction I2: (name needed)");
    });

    test("updated system and risk props replace old labels and evaluations", () => {
        const { rerender } = render(<StrideSummary model={model} register={register} />);
        const updated: ThreatModel = {
            ...model, components: model.components.map(component => ({ ...component, name: `Updated ${component.name}` })),
            interactions: [{ ...model.interactions[0], name: "Authenticated download" }],
        };
        rerender(<StrideSummary model={updated} register={{
            ...register, risks: [{ ...register.risks[1], mitigation: "Rotate device credentials" }],
        }} />);
        const table = screen.getByRole("table", { name: "Threats and linked risk evaluations" });
        expect(table).toHaveTextContent("Component C2: Updated Gateway");
        expect(table).toHaveTextContent("Authenticated download");
        expect(table).toHaveTextContent("Rotate device credentials");
        expect(table).not.toHaveTextContent("Authenticate gateways");
    });
});

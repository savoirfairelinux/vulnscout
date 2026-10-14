import { render, screen, fireEvent, waitFor, act, within } from "@testing-library/react";
import "@testing-library/jest-dom";
import fetchMock from "jest-fetch-mock";
// @ts-expect-error TS6133
import React from "react";
import AIContext from "../../src/pages/AIContext";
import Assessments from "../../src/handlers/assessments";
import { AGENT_WRITE_EVENT } from "../../src/types/agent";
import { emptySharedContext, mergeSavedSection } from "../../src/helpers/sharedContext";
import type { SharedContext, SharedContextResponse, SharedSection } from "../../src/helpers/sharedContext";

fetchMock.enableMocks();
const choices = [{ id: "v1", name: "Alpha" }, { id: "v2", name: "Beta" }];
const copy = <T,>(value: T): T => JSON.parse(JSON.stringify(value));
const row = (id: string, value: string, targets = ["v1", "v2"]) => ({ id, value, variant_ids: targets });
const component = (id = "C1", targets = ["v1", "v2"]) => ({
    id, name: "Device", description: "", trustZone: "", variant_ids: targets,
});
const threat = (id = "T1", targets = ["v1", "v2"]) => ({
    id, category: "Tampering" as const, description: "Unsigned update", targetIds: [], variant_ids: targets,
});
const risk = (id = "R1", targets = ["v1", "v2"]) => ({
    id, threatId: "T1", likelihood: "" as const, impact: "" as const, mitigation: "", decision: "", variant_ids: targets,
});
type Patch = { section: SharedSection; context: SharedContext; description?: string | null;
    expected_revision: number; dry_run: boolean };

function fixture(context = emptySharedContext()) {
    const states = new Map<string, SharedContextResponse>([
        ["p1", { project_id: "p1", description: "Project", revision: 0, context: copy(context), variants: choices }],
        ["p2", { project_id: "p2", description: "Second", revision: 0, context: emptySharedContext(),
            variants: [{ id: "v3", name: "Gamma" }] }],
    ]);
    const writes: Patch[] = [];
    const previews: Patch[] = [];
    const f = {
        states, writes, previews, failGet: false, failSave: false, failPreview: false, failProjects: false,
        failExport: false, failImport: false, failVariants: false, failMode: false,
        ignored: false, modeCalls: 0, importBody: undefined as unknown, exportUrl: "",
        defer: undefined as Promise<string> | undefined,
    };
    fetchMock.mockResponse(async request => {
        const url = new URL(request.url);
        const answer = (body: unknown, status = 200) => ({ body: JSON.stringify(body), status });
        if (url.pathname === "/api/projects") {
            if (f.failProjects) return answer({ error: "Failed projects" }, 500);
            return answer([{ id: "p1", name: "Project A" }, { id: "p2", name: "Project B" }]);
        }
        if (url.pathname.endsWith("/context/shared")) {
            const state = states.get(url.pathname.split("/")[3])!;
            if (request.method === "GET") {
                if (f.failGet) return answer({ error: "Load failed" }, 500);
                if (f.defer && state.project_id === "p1") return { body: await f.defer };
                return answer(state);
            }
            const body = JSON.parse(await request.text());
            if (request.method === "POST") {
                f.modeCalls++;
                if (f.failMode) return answer({ error: "Conversion failed" }, 400);
                return answer({ context: { ...body.context, editor_mode: body.editor_mode } });
            }
            const patch: Patch = body;
            if (patch.dry_run) previews.push(patch); else writes.push(patch);
            if (patch.expected_revision !== state.revision || (patch.dry_run ? f.failPreview : f.failSave))
                return answer({ error: "Saved context changed. Keep your drafts." }, 409);
            const merged = patch.context.editor_mode !== state.context.editor_mode ? copy(patch.context)
                : mergeSavedSection(state.context, patch.context, patch.section);
            const changed = choices.filter(variant => {
                const native = (document: SharedContext) => [
                    ...Object.values(document.fields), document.components, document.interactions,
                    document.threats, document.risks, document.threat_notes, document.risk_notes,
                    document.free_threat_model, document.free_risks,
                ].map(rows => rows.filter(row => row.variant_ids.includes(variant.id)).map(({ variant_ids: _scope, ...value }) => value));
                return JSON.stringify(native(merged)) !== JSON.stringify(native(state.context));
            }).map(variant => variant.id);
            const descriptionChanged = patch.section === "context" && patch.description !== state.description;
            const preview = { changed_variant_ids: changed, description_changed: descriptionChanged };
            if (patch.dry_run) return answer(preview);
            state.context = merged; state.revision++;
            if (patch.section === "context") state.description = patch.description ?? null;
            return answer({ ...state, ...preview });
        }
        if (url.pathname === "/api/reviews/assessments") return answer([]);
        if (url.pathname === "/api/variants") {
            if (f.failVariants) return answer({ error: "Failed variants" }, 500);
            return answer(choices.map(variant => ({ ...variant, project_id: "p1" })));
        }
        if (url.pathname === "/api/context/export") {
            f.exportUrl = request.url;
            return f.failExport ? answer({ error: "Export failed" }, 500)
                : answer({ version: "3.0", projects: [], exported_at: "now" });
        }
        if (url.pathname === "/api/context/import") {
            f.importBody = JSON.parse(await request.text());
            if (f.failImport) return answer({ error: "Import failed" }, 500);
            return answer({ imported: [{ project_name: "Project A", variant_name: "Alpha" }],
                ignored: f.ignored ? [{ project_name: "Unknown", variant_name: "Missing", reason: "Project not found" }] : [],
                failed: f.ignored ? [{ project_name: "Project A", variant_name: "Beta", reason: "Invalid scope" }] : [] });
        }
        return answer({});
    });
    return f;
}

async function load() {
    await screen.findByRole("option", { name: "Project A" });
    fireEvent.change(screen.getByLabelText("Project"), { target: { value: "p1" } });
    await waitFor(() => expect(screen.getByLabelText("Project Description")).toBeEnabled());
}
const tab = (name: string) => fireEvent.click(screen.getByRole("tab", { name }));
const edit = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
async function save(name = "Context") {
    fireEvent.click(screen.getByRole("button", { name: `Save ${name}` }));
    await screen.findByText(`${name} saved successfully.`);
}
function importFile(value: unknown, invalid = false) {
    const file = new File(["data"], "context.json", { type: "application/json" });
    Object.defineProperty(file, "text", { value: () => Promise.resolve(invalid ? "not JSON" : JSON.stringify(value)) });
    fireEvent.change(screen.getByLabelText("Import context file"), { target: { files: [file] } });
}
beforeEach(() => { fetchMock.resetMocks(); jest.restoreAllMocks(); });

test("variant references preserve shared drafts and project-level agent scope", async () => {
    const f = fixture();
    const agent = jest.fn();
    render(<AIContext onAgentContextChange={agent} />);
    await load();
    edit("Project Description", "Unsaved project");
    expect(screen.queryByLabelText("Upload codebase references")).not.toBeInTheDocument();
    fetchMock.mockResponseOnce(JSON.stringify({ files: [] }));
    edit("Codebase reference variant", "v1");
    await screen.findByLabelText("Upload codebase references");
    expect(String(fetchMock.mock.calls.at(-1)?.[0])).toContain("project_id=p1&variant_id=v1");
    fetchMock.mockResponseOnce("[]");
    fetchMock.mockResponseOnce(JSON.stringify({ id: "f1", original_name: "source.zip", description: null }), { status: 201 });
    fireEvent.drop(screen.getByRole("region", { name: "Drop codebase files" }), {
        dataTransfer: { files: [new File(["source"], "source.zip")] },
    });
    await screen.findByRole("button", { name: "Delete reference source.zip" });
    expect(String(fetchMock.mock.calls.at(-1)?.[0])).toContain("/api/variants/v1/context/files");
    expect(screen.getByLabelText("Project Description")).toHaveValue("Unsaved project");
    expect(f.writes).toHaveLength(0);
    expect(agent.mock.calls.at(-1)?.[0]).not.toHaveProperty("selectedVariantId");
    fetchMock.mockResponseOnce(JSON.stringify({ files: [] }));
    edit("Codebase reference variant", "v2");
    await screen.findByText("No codebase references uploaded.");
    expect(screen.queryByRole("button", { name: "Delete reference source.zip" })).not.toBeInTheDocument();
    edit("Project", "p2");
    await waitFor(() => expect(screen.getByLabelText("Project Description")).toHaveValue("Second"));
    expect(screen.getByLabelText("Codebase reference variant")).toHaveValue("");
    expect(screen.queryByLabelText("Upload codebase references")).not.toBeInTheDocument();
});

test("failed reference loads require a successful retry before uploading", async () => {
    fixture(); render(<AIContext />); await load();
    fetchMock.mockResponseOnce(JSON.stringify({ error: "References unavailable" }), { status: 500 });
    edit("Codebase reference variant", "v1");
    await screen.findByText("References unavailable");
    expect(screen.queryByLabelText("Upload codebase references")).not.toBeInTheDocument();
    fetchMock.mockResponseOnce(JSON.stringify({ files: [{ id: "f1", original_name: "main.c", description: null }] }));
    fireEvent.click(screen.getByRole("button", { name: "Retry references" }));
    await screen.findByRole("button", { name: "Delete reference main.c" });
    expect(screen.getByLabelText("Upload codebase references")).toBeEnabled();
});

test("late reference responses cannot leak across variant selections", async () => {
    fixture(); render(<AIContext />); await load();
    let finish: ((response: string) => void) | undefined;
    fetchMock.mockResponseOnce(() => new Promise(resolve => { finish = resolve; }));
    edit("Codebase reference variant", "v1");
    await screen.findByText("Loading codebase references...");
    fetchMock.mockResponseOnce(JSON.stringify({ files: [] }));
    edit("Codebase reference variant", "v2");
    await screen.findByText("No codebase references uploaded.");
    await act(async () => {
        finish?.(JSON.stringify({ files: [{ id: "old", original_name: "old.zip", description: null }] }));
    });
    expect(screen.queryByRole("button", { name: "Delete reference old.zip" })).not.toBeInTheDocument();
    expect(screen.getByLabelText("Codebase reference variant")).toHaveValue("v2");
});

test("removes the top variant selector and retains accessible subtabs and project-level agent context", async () => {
    fixture();
    const agent = jest.fn();
    render(<AIContext onAgentContextChange={agent} />);
    await load();
    expect(screen.queryByLabelText("Variant")).not.toBeInTheDocument();
    expect(agent).toHaveBeenLastCalledWith({ section: "context", selectedProjectId: "p1", selectedProjectName: "Project A" });
    expect(screen.getByRole("tablist")).toHaveClass("flex-wrap", "p-1");
    for (const name of ["Context", "System", "Threat model", "Risks", "Summary"]) {
        tab(name);
        const selected = screen.getByRole("tab", { name });
        const panel = screen.getByRole("tabpanel", { name });
        expect(selected).toHaveAttribute("aria-selected", "true");
        expect(panel.id).toBe(selected.getAttribute("aria-controls"));
        expect(screen.getAllByRole("tabpanel", { hidden: true })).toHaveLength(5);
        if (name === "Summary") expect(screen.queryByRole("button", { name: /^Save / })).not.toBeInTheDocument();
        else expect(within(panel).getByRole("button", { name: `Save ${name}` })).toBeEnabled();
    }
    expect(agent.mock.calls.at(-1)[0]).not.toHaveProperty("selectedVariantId");
});

test("tabs support wrapping arrows and Home/End", async () => {
    fixture(); render(<AIContext />); await load();
    screen.getByRole("tab", { name: "Context" }).focus();
    for (const [key, name] of [["ArrowLeft", "Summary"], ["ArrowRight", "Context"], ["End", "Summary"], ["Home", "Context"]]) {
        fireEvent.keyDown(document.activeElement!, { key });
        expect(screen.getByRole("tab", { name })).toHaveFocus();
    }
    fireEvent.keyDown(document.activeElement!, { key: "x" });
    expect(screen.getByRole("tab", { name: "Context" })).toHaveFocus();
});

test("context text has explicit multiple-variant scopes and additional entries", async () => {
    const f = fixture(); render(<AIContext />); await load();
    edit("Variant Description", "Common device");
    const scope = screen.getByRole("group", { name: "Variant Description variants" });
    fireEvent.click(within(scope).getByLabelText("Variant Description applies to Beta"));
    fireEvent.click(screen.getByRole("button", { name: "Add Variant Description" }));
    edit("Variant Description 2", "Beta addition");
    const second = screen.getByRole("group", { name: "Variant Description 2 variants" });
    fireEvent.click(within(second).getByLabelText("Variant Description 2 applies to Alpha"));
    await save();
    expect(f.writes[0].context.fields.variant_description.map(row => [row.value, row.variant_ids])).toEqual([
        ["Common device", ["v1"]], ["Beta addition", ["v2"]],
    ]);
    fireEvent.click(screen.getByRole("button", { name: "Remove Variant Description 2" }));
    expect(screen.getByLabelText("Variant Description")).toHaveValue("Common device");
});

test("scope selectors offer All/None without inline warnings across the AI subtabs", async () => {
    const context = emptySharedContext();
    context.components = [component()];
    context.interactions = [{
        id: "I1", name: "Update", sourceId: "C1", destinationId: "C1", description: "",
        protocol: "", trustBoundary: "", variant_ids: ["v1", "v2"],
    }];
    context.threats = [threat()];
    context.risks = [risk()];
    fixture(context); render(<AIContext />); await load();
    edit("Environment", "Zephyr");
    for (const [section, label] of [
        ["Context", "Environment"], ["Context", "Codebase Path 1"],
        ["System", "Component 1"], ["System", "Interaction 1"],
        ["Threat model", "Threat 1"], ["Risks", "Risk 1"],
    ]) {
        tab(section);
        const scope = screen.getByRole("group", { name: `${label} variants` });
        const checked = () => within(scope).getAllByRole("checkbox", { hidden: true })
            .map(input => (input as HTMLInputElement).checked);
        expect(checked()).toEqual([true, true]);
        fireEvent.click(within(scope).getByRole("button", { name: `${label} clear variants`, hidden: true }));
        expect(checked()).toEqual([false, false]);
        expect(within(scope).getByText("Select variants")).toBeVisible();
        expect(within(scope).queryByRole("status")).not.toBeInTheDocument();
        expect(scope).not.toHaveAttribute("aria-describedby");
        fireEvent.click(within(scope).getByRole("button", { name: `${label} select all variants`, hidden: true }));
        expect(checked()).toEqual([true, true]);
    }
    expect(screen.queryByText("Select at least one variant before saving this entry.")).not.toBeInTheDocument();
});

test("codebase paths are individually scoped and can be added and removed", async () => {
    const f = fixture(); render(<AIContext />); await load();
    edit("Codebase Path 1", "/workspace/app");
    fireEvent.click(screen.getByRole("button", { name: "Add Codebase Path" }));
    edit("Codebase Path 2", "/workspace/board");
    fireEvent.click(screen.getByLabelText("Codebase Path 2 applies to Beta"));
    await save();
    expect(f.writes[0].context.fields.codebase_path.map(row => [row.value, row.variant_ids])).toEqual([
        ["/workspace/app", ["v1", "v2"]], ["/workspace/board", ["v1"]],
    ]);
    fireEvent.click(screen.getByRole("button", { name: "Remove Codebase Path 1" }));
    expect(screen.getByLabelText("Codebase Path 1")).toHaveValue("/workspace/board");
});

test("adding another empty text entry allocates distinct identifiers", async () => {
    const f = fixture(); render(<AIContext />); await load();
    fireEvent.click(screen.getByRole("button", { name: "Add Environment" }));
    edit("Environment 1", "First"); edit("Environment 2", "Second");
    await save();
    expect(new Set(f.writes[0].context.fields.environment.map(row => row.id)).size).toBe(2);
});

test("section saves leave other context and structured drafts unsaved", async () => {
    const f = fixture(); render(<AIContext />); await load();
    edit("Environment", "Local draft");
    tab("System"); fireEvent.click(screen.getByRole("button", { name: "Add component" }));
    edit("Component 1 name", "Firmware");
    tab("Threat model"); fireEvent.click(screen.getByRole("button", { name: "Add threat" }));
    edit("Threat 1 description", "Unsigned update");
    await save("Threat model");
    expect(f.states.get("p1")!.context.components).toEqual([]);
    expect(f.states.get("p1")!.context.fields.environment).toEqual([]);
    tab("System"); expect(screen.getByLabelText("Component 1 name")).toHaveValue("Firmware");
    tab("Context"); expect(screen.getByLabelText("Environment")).toHaveValue("Local draft");
    await save();
    tab("System"); expect(screen.getByLabelText("Component 1 name")).toHaveValue("Firmware");
});

test("system fields, components, interactions, threats, risks and notes all have scopes", async () => {
    const f = fixture(); render(<AIContext />); await load();
    tab("System"); edit("System scope and assets", "Credentials");
    fireEvent.click(screen.getByRole("button", { name: "Add component" }));
    edit("Component 1 name", "Device");
    fireEvent.click(screen.getByRole("button", { name: "Add interaction" }));
    edit("Interaction 1 name", "Update");
    edit("Interaction 1 source component", "C1"); edit("Interaction 1 destination component", "C1");
    expect(screen.getByRole("group", { name: "Component 1 variants" })).toBeVisible();
    expect(screen.getByRole("group", { name: "Interaction 1 variants" })).toBeVisible();
    await save("System");
    tab("Threat model"); fireEvent.click(screen.getByRole("button", { name: "Add threat" }));
    edit("Threat 1 description", "Unsigned update");
    edit("Threat 1 affected system element", "I1");
    edit("Additional notes", "Assumptions");
    expect(screen.getByRole("group", { name: "Threat 1 variants" })).toBeVisible();
    await save("Threat model");
    tab("Risks"); fireEvent.click(screen.getByRole("button", { name: "Add risk" }));
    edit("Risk 1 threat", "T1"); edit("Additional risk notes", "Review later");
    expect(screen.getByRole("group", { name: "Risk 1 variants" })).toBeVisible();
    await save("Risks");
    expect(f.states.get("p1")!.context.threats[0].targetIds).toEqual(["I1"]);
    expect(f.states.get("p1")!.context.risks[0].variant_ids).toEqual(["v1", "v2"]);
});

test("references cannot select an element unavailable to the entry's variants", async () => {
    const document = emptySharedContext();
    document.components = [component("C1", ["v1"])];
    document.threats = [{ ...threat(), targetIds: ["C1"] }];
    fixture(document); render(<AIContext />); await load();
    tab("Threat model");
    expect(screen.getByRole("option", { name: /Component C1/ })).toBeDisabled();
    expect(screen.getByText(/outside their variant scope/)).toBeVisible();
    fireEvent.click(screen.getByLabelText("Threat 1 applies to Beta"));
    fireEvent.click(screen.getByRole("button", { name: "Remove C1 from threat 1" }));
    expect(screen.getByRole("option", { name: /Component C1/ })).toBeEnabled();
    tab("System"); fireEvent.click(screen.getByRole("button", { name: "Add interaction" }));
    expect(within(screen.getByLabelText("Interaction 1 source component")).getByRole("option", { name: "C1: Device" })).toBeDisabled();
});

test("selecting a narrowly scoped threat narrows its new risk and retains risk identity after deletion", async () => {
    const document = emptySharedContext();
    document.threats = [threat("T1", ["v1"])];
    document.risks = [risk("R1"), risk("R2", ["v2"])];
    const f = fixture(document); render(<AIContext />); await load();
    tab("Risks"); fireEvent.click(screen.getByRole("button", { name: "Remove risk 1" }));
    fireEvent.click(screen.getByRole("button", { name: "Add risk" }));
    edit("Risk 2 threat", "T1");
    await save("Risks");
    expect(f.writes[0].context.risks.map(row => [row.id, row.variant_ids])).toEqual([
        ["R2", ["v2"]], ["R3", ["v1"]],
    ]);
});

test("new identifiers reserve saved elements and unavailable references", async () => {
    const document = emptySharedContext();
    document.components = [component()];
    document.threats = [{ ...threat("T2"), targetIds: ["C2"] }];
    fixture(document); render(<AIContext />); await load();
    tab("System");
    fireEvent.click(screen.getByRole("button", { name: "Remove component 1" }));
    fireEvent.click(screen.getByRole("button", { name: "Add component" }));
    expect(screen.getByText("Component 1 (C3)")).toBeVisible();
    tab("Threat model"); fireEvent.click(screen.getByRole("button", { name: "Add threat" }));
    expect(screen.getByRole("group", { name: "Threat 2 variants" })).toBeVisible();
});

test("summary counts shared entries once and displays recipient scopes", async () => {
    const document = emptySharedContext();
    document.components = [component()];
    document.threats = [threat()];
    document.risks = [risk("R1", ["v1"])];
    document.fields.environment = [row("X1", "RTOS")];
    fixture(document); render(<AIContext />); await load();
    tab("Summary");
    const summary = screen.getByRole("table", { name: "Threats and linked risk evaluations" });
    expect(within(summary).getByRole("columnheader", { name: "Threat variants" })).toBeVisible();
    expect(within(summary).getByRole("columnheader", { name: "Risk variants" })).toBeVisible();
    expect(within(summary).getByText("Alpha, Beta")).toBeVisible();
    expect(within(summary).getByText("Alpha")).toBeVisible();
    const scopes = screen.getByRole("region", { name: "Entry variant scopes" });
    expect(within(scopes).getByText("components (C1)")).toBeVisible();
    expect(screen.getByText("Zero recorded threats", { exact: false })).toBeVisible();
});

test("unlinked risk summary also shows its scope", async () => {
    const document = emptySharedContext();
    document.risks = [{ ...risk(), threatId: "T99" }];
    fixture(document); render(<AIContext />); await load(); tab("Summary");
    const table = screen.getByRole("table", { name: "Risks with unlinked or unavailable threats" });
    expect(within(table).getByRole("columnheader", { name: "Variants" })).toBeVisible();
    expect(within(table).getByText("Alpha, Beta")).toBeVisible();
});

test("conflicted saves keep drafts and the expected baseline revision", async () => {
    const f = fixture(); render(<AIContext />); await load();
    edit("Environment", "Keep me"); f.failSave = true;
    fireEvent.click(screen.getByRole("button", { name: "Save Context" }));
    await screen.findByText("Saved context changed. Keep your drafts.");
    expect(screen.getByLabelText("Environment")).toHaveValue("Keep me");
    expect(f.writes[0].expected_revision).toBe(0);
    f.failSave = false; await save();
    expect(f.writes[1].expected_revision).toBe(0);
});

test("failed previews never write or discard drafts", async () => {
    const f = fixture(); render(<AIContext />); await load();
    edit("Environment", "Keep"); f.failPreview = true;
    fireEvent.click(screen.getByRole("button", { name: "Save Context" }));
    await screen.findByText("Saved context changed. Keep your drafts.");
    expect(f.writes).toEqual([]);
    expect(screen.getByLabelText("Environment")).toHaveValue("Keep");
});

test("assessment confirmation is scoped to changed variants and has immutable save data", async () => {
    const f = fixture();
    jest.spyOn(Assessments, "listForReview").mockResolvedValue([{
        id: "a", vuln_id: "CVE-1", variant_ids: ["v1"], origin: "ai", packages: [],
        status: "under_investigation", simplified_status: "", timestamp: "", responses: [],
    }]);
    render(<AIContext />); await load(); edit("Environment", "Shared change");
    fireEvent.click(screen.getByRole("button", { name: "Save Context" }));
    await screen.findByText("Mark AI assessments as outdated?");
    expect(screen.getByLabelText("Environment")).toBeDisabled();
    expect(f.writes).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: "Save and mark outdated" }));
    await screen.findByText("Context saved successfully.");
    expect(f.writes[0].context.fields.environment[0].value).toBe("Shared change");
});

test("pending assessments of unchanged variants do not require confirmation", async () => {
    fixture();
    jest.spyOn(Assessments, "listForReview").mockResolvedValue([{
        id: "a", vuln_id: "CVE-1", variant_ids: ["v2"], origin: "ai", packages: [],
        status: "under_investigation", simplified_status: "", timestamp: "", responses: [],
    }]);
    render(<AIContext />); await load(); edit("Environment", "Only alpha");
    fireEvent.click(screen.getByLabelText("Environment applies to Beta"));
    await save();
    expect(screen.queryByText("Mark AI assessments as outdated?")).not.toBeInTheDocument();
});

test("failed assessment check warns and allows cancellation", async () => {
    const f = fixture();
    jest.spyOn(Assessments, "listForReview").mockRejectedValue(new Error("Review unavailable"));
    render(<AIContext />); await load(); edit("Environment", "Change");
    fireEvent.click(screen.getByRole("button", { name: "Save Context" }));
    await screen.findByText("Mark AI assessments as outdated?");
    expect(screen.getByText(/Could not check pending AI assessments/)).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(f.writes).toEqual([]);
    expect(screen.getByLabelText("Environment")).toHaveValue("Change");
});

test("switching projects cancels an old confirmation and does not save to the new project", async () => {
    const f = fixture();
    jest.spyOn(Assessments, "listForReview").mockRejectedValue(new Error("Review unavailable"));
    render(<AIContext />); await load(); edit("Environment", "Old draft");
    fireEvent.click(screen.getByRole("button", { name: "Save Context" }));
    await screen.findByText("Mark AI assessments as outdated?");
    edit("Project", "p2");
    await waitFor(() => expect(screen.getByLabelText("Project Description")).toHaveValue("Second"));
    expect(screen.queryByText("Mark AI assessments as outdated?")).not.toBeInTheDocument();
    expect(f.writes).toEqual([]);
});

test("late project loads do not replace another project's data", async () => {
    const f = fixture();
    let resolve!: (value: string) => void;
    f.defer = new Promise(done => { resolve = done; });
    render(<AIContext />);
    await screen.findByRole("option", { name: "Project A" });
    edit("Project", "p1"); edit("Project", "p2");
    await waitFor(() => expect(screen.getByLabelText("Project Description")).toHaveValue("Second"));
    await act(async () => resolve(JSON.stringify(f.states.get("p1"))));
    expect(screen.getByLabelText("Project Description")).toHaveValue("Second");
});

test("load failures disable saving until a successful retry", async () => {
    const f = fixture(); f.failGet = true;
    render(<AIContext />); await screen.findByRole("option", { name: "Project A" }); edit("Project", "p1");
    await screen.findByText("Load failed");
    expect(screen.getByRole("button", { name: "Save Context" })).toBeDisabled();
    f.failGet = false; fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Save Context" })).toBeEnabled());
});

test("project-list failures are surfaced and projects without variants show a scope warning", async () => {
    const f = fixture(); f.failProjects = true;
    const rendered = render(<AIContext />);
    await screen.findByText("Failed to load projects (500)");
    rendered.unmount(); f.failProjects = false; f.states.get("p1")!.variants = [];
    render(<AIContext />); await load();
    expect(screen.getByText("This project has no variants to receive shared entries.")).toBeVisible();
});

test("editor mode is selected once and must be saved in Context before other edits", async () => {
    const f = fixture(); render(<AIContext />); await load();
    edit("Editor mode", "free");
    await waitFor(() => expect(screen.getByLabelText("Editor mode")).toHaveValue("free"));
    tab("Threat model");
    expect(screen.getByText("Save Editor mode in Context before editing another section.")).toBeVisible();
    expect(screen.getByLabelText("Threat Model")).toBeDisabled();
    tab("Context"); await save();
    tab("Threat model"); edit("Threat Model", "Shared free text");
    fireEvent.click(screen.getByLabelText("Threat Model applies to Beta"));
    await save("Threat model");
    expect(f.writes.at(-1)!.context.free_threat_model[0].variant_ids).toEqual(["v1"]);
    tab("Risks");
    fireEvent.change(screen.getByRole("textbox", { name: "Risks" }), { target: { value: "Scoped risks" } });
    await save("Risks");
    tab("Summary"); expect(screen.getByText("Scoped risks", { selector: "p" })).toBeVisible();
    tab("Context"); expect(screen.getAllByLabelText("Editor mode")).toHaveLength(1);
});

test("mode changes cannot discard other section drafts and conversion errors preserve the mode", async () => {
    const f = fixture(); render(<AIContext />); await load();
    tab("System"); edit("Actors and access", "Local actors");
    tab("Context"); edit("Editor mode", "free");
    await screen.findByText("Save or discard System, Threat model and Risks drafts before changing Editor mode.");
    expect(f.modeCalls).toBe(0);
    tab("System"); await save("System"); tab("Context"); f.failMode = true;
    edit("Editor mode", "free"); await screen.findByText("Conversion failed");
    expect(screen.getByLabelText("Editor mode")).toHaveValue("stride");
});

test("an unsaved mode change can be undone without saving or discarding context edits", async () => {
    const f = fixture(); render(<AIContext />); await load();
    edit("Environment", "Keep draft");
    edit("Editor mode", "free");
    await waitFor(() => expect(screen.getByLabelText("Editor mode")).toHaveValue("free"));
    edit("Editor mode", "stride");
    expect(screen.getByLabelText("Editor mode")).toHaveValue("stride");
    expect(screen.getByLabelText("Environment")).toHaveValue("Keep draft");
    expect(f.modeCalls).toBe(1);
    expect(f.writes).toEqual([]);
    tab("System");
    expect(screen.getByRole("button", { name: "Add component" })).toBeEnabled();
});

test("agent writes reload only clean forms and explicit reload confirms draft loss", async () => {
    const f = fixture(); render(<AIContext />); await load();
    f.states.get("p1")!.description = "Agent";
    act(() => window.dispatchEvent(new CustomEvent(AGENT_WRITE_EVENT, { detail: { tool: "update_project_context" } })));
    await waitFor(() => expect(screen.getByLabelText("Project Description")).toHaveValue("Agent"));
    edit("Environment", "Keep draft");
    act(() => window.dispatchEvent(new CustomEvent(AGENT_WRITE_EVENT, { detail: { tool: "update_variant_context" } })));
    await screen.findByText(/The agent updated saved context/);
    expect(screen.getByLabelText("Environment")).toHaveValue("Keep draft");
    fireEvent.click(screen.getByRole("button", { name: "Reload saved context" }));
    await screen.findByText("Discard unsaved drafts?");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByLabelText("Environment")).toHaveValue("Keep draft");
    fireEvent.click(screen.getByRole("button", { name: "Reload saved context" }));
    fireEvent.click(screen.getByRole("button", { name: "Discard and reload" }));
    await waitFor(() => expect(screen.getByLabelText("Environment")).toHaveValue(""));
});

test("import accepts any supported payload and retains existing drafts with explicit feedback", async () => {
    const f = fixture(); render(<AIContext />); await load();
    edit("Environment", "Keep draft");
    const document = { version: "3.0", projects: [] };
    importFile(document);
    await screen.findByText(/Import complete:/);
    expect(f.importBody).toEqual(document);
    expect(screen.getByText(/Your unsaved drafts were kept/)).toBeVisible();
    expect(screen.getByLabelText("Environment")).toHaveValue("Keep draft");
});

test("clean imports reload saved context and show failed and ignored entry details", async () => {
    const f = fixture(); f.ignored = true;
    render(<AIContext />); await load();
    f.states.get("p1")!.description = "Imported";
    importFile([{ project_name: "Legacy" }]);
    await waitFor(() => expect(screen.getByLabelText("Project Description")).toHaveValue("Imported"));
    expect(screen.getByText("Failed (1)")).toBeVisible();
    expect(screen.getByText("Ignored (1)")).toBeVisible();
    expect(screen.getByText("Unknown / Missing: Project not found")).toBeVisible();
});

test("invalid JSON and import HTTP failures are reported", async () => {
    const f = fixture(); render(<AIContext />); await load();
    importFile(null, true); await screen.findByText("The selected file is not valid JSON.");
    f.failImport = true; importFile({});
    await screen.findByText("Import failed");
});

test("exports select recipients lazily, contain only saved context and download a versioned document", async () => {
    const f = fixture();
    const create = jest.fn(() => "blob:context"); const revoke = jest.fn();
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: create });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revoke });
    jest.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    render(<AIContext />); await load();
    fireEvent.click(screen.getByRole("button", { name: "Export context" }));
    await screen.findByLabelText("Export Project A / Alpha");
    const menu = screen.getByRole("menu");
    fireEvent.click(within(menu).getByRole("button", { name: "All" }));
    fireEvent.click(within(menu).getByRole("button", { name: "None" }));
    expect(screen.getByRole("button", { name: "Export selected (0)" })).toBeDisabled();
    fireEvent.click(screen.getByLabelText("Export Project A / Alpha"));
    fireEvent.click(screen.getByLabelText("Export Project A / Alpha"));
    fireEvent.click(screen.getByLabelText("Export Project A / Beta"));
    fireEvent.click(screen.getByRole("button", { name: "Export selected (1)" }));
    await waitFor(() => expect(create).toHaveBeenCalled());
    expect(new URL(f.exportUrl).searchParams.get("variant_ids")).toBe("v2");
    expect(revoke).toHaveBeenCalledWith("blob:context");
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
});

test("export variant failures can retry and export failures preserve the selector", async () => {
    const f = fixture(); f.failVariants = true;
    render(<AIContext />); await load();
    fireEvent.click(screen.getByRole("button", { name: "Export context" }));
    await screen.findByText(/Failed to load variants/);
    fireEvent.click(screen.getByRole("button", { name: "Export context" }));
    f.failVariants = false;
    fireEvent.click(screen.getByRole("button", { name: "Export context" }));
    await screen.findByLabelText("Export Project A / Alpha");
    fireEvent.click(screen.getByLabelText("Export Project A / Alpha")); f.failExport = true;
    fireEvent.click(screen.getByRole("button", { name: "Export selected (1)" }));
    await screen.findByText("Export failed");
    expect(screen.getByRole("menu")).toBeVisible();
});

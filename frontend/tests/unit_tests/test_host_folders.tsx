import { act, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import "@testing-library/jest-dom";
import fetchMock from "jest-fetch-mock";
import HostFolders from "../../src/components/aiContext/HostFolders";

fetchMock.enableMocks();
beforeEach(() => fetchMock.resetMocks());

const props = { variantId: "v1", projectName: "demo", variantName: "x86", disabled: false };
const helper = { available: true, message: null };
const available = { attachment_id: "3488d574-c2db-44e9-9ed1-34f413541295",
    approval_revision: "05000000-0000-5000-8000-000000000001",
    alias: "src", host_path: "/work/app", status: "available" };
const unavailable = { attachment_id: "bf19a62f-ac62-4534-a65d-c74251a1de0a",
    approval_revision: "05000000-0000-5000-8000-000000000002",
    alias: "build", host_path: "/work/build", status: "unavailable", message: "Host folder not found." };
const needsApproval = { ...unavailable, message: "No host approval; reattach this folder with the host CLI." };
const helperOffline = "Host folder helper is not running. On the container host, run './vulnscout ai-context helper start'. Operation: status (ConnectionRefusedError).";

test("lists attached folders and refreshes after detaching one", async () => {
    fetchMock.mockResponses(
        JSON.stringify({ helper, mounts: [available, unavailable] }),
        JSON.stringify({ detached: true, warning: "Cleanup pending." }),
        JSON.stringify({ helper, mounts: [available] }),
    );
    render(<HostFolders {...props} />);
    const table = await screen.findByRole("table", { name: "Attached folders" });
    expect(within(table).getAllByRole("columnheader").map(header => header.textContent))
        .toEqual(["Name", "Host folder", "Status", "Detach"]);
    const sourceRow = within(table).getByRole("row", { name: /^src / });
    expect(within(sourceRow).getByRole("cell", { name: "/work/app" })).toBeVisible();
    expect(within(sourceRow).getByRole("cell", { name: "Available" })).toBeVisible();
    const buildRow = within(table).getByRole("row", { name: /^build / });
    expect(within(buildRow).getByText("Unavailable")).toBeVisible();
    expect(screen.queryByText(unavailable.message)).not.toBeInTheDocument();
    const details = within(buildRow).getByRole("button", { name: "Unavailable: build status details" });
    fireEvent.click(details);
    expect(within(buildRow).getByRole("tooltip")).toHaveTextContent(unavailable.message);
    expect(details).toHaveAccessibleDescription(unavailable.message);

    fireEvent.click(screen.getByRole("button", { name: "Detach build" }));
    expect(await screen.findByText("Detached build. Cleanup pending.")).toBeVisible();
    expect(fetchMock).toHaveBeenNthCalledWith(2,
        `http://localhost/api/variants/v1/context/mounts/build?approval_revision=${unavailable.approval_revision}`,
        expect.objectContaining({ method: "DELETE" }));
    expect(screen.queryByRole("button", { name: "Detach build" })).not.toBeInTheDocument();
    expect(screen.queryByRole("group", { name: "Reconnect host folders" })).not.toBeInTheDocument();
});

test.each([
    ["start", helperOffline],
    ["restart", "Incompatible host folder helper. On the host, run './vulnscout ai-context helper restart'."],
])("suggests helper %s and preserves the offline diagnostic", async (action, diagnostic) => {
    fetchMock.mockResponseOnce(JSON.stringify({
        helper: { available: false, message: diagnostic }, mounts: [{ ...unavailable, message: diagnostic }],
    }));
    render(<HostFolders {...props} disabled />);
    expect(await screen.findByRole("alert")).toHaveTextContent(`Host folder helper unavailable: ${diagnostic}`);
    expect(screen.getByRole("button", { name: "Detach build" })).toBeDisabled();
    const recovery = screen.getByRole("group", { name: "Reconnect host folders" });
    expect(within(recovery).getByText(`./vulnscout ai-context helper ${action}`)).toBeVisible();
    expect(within(recovery).queryByText(/ai-context attach/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Unavailable: build status details" }));
    expect(screen.getByRole("tooltip")).toHaveTextContent(diagnostic);
});

test.each([
    "Permission denied connecting to the host folder helper socket. Check the container's UID mapping and SELinux socket label; use matching VulnScout launcher and image versions.",
    "Host helper status communication failed: unexpected reply mentioning './vulnscout ai-context helper restart'.",
])("shows non-actionable helper diagnostics without a recovery command", async diagnostic => {
    fetchMock.mockResponseOnce(JSON.stringify({
        helper: { available: false, message: diagnostic }, mounts: [{ ...unavailable, message: diagnostic }],
    }));
    render(<HostFolders {...props} />);
    expect(await screen.findByRole("alert")).toHaveTextContent(diagnostic);
    expect(screen.queryByRole("group", { name: "Reconnect host folders" })).not.toBeInTheDocument();
});

test("offers individual scoped commands without including a missing or already available folder", async () => {
    const user = userEvent.setup();
    const extra = { ...needsApproval, attachment_id: "extra-mount", alias: "meta", host_path: "/work/Bob's $(date); meta" };
    const other = { ...needsApproval, attachment_id: "other-mount", alias: "logs", host_path: "/work/logs" };
    fetchMock.mockResponses(
        JSON.stringify({ helper, mounts: [available, unavailable, extra, other] }),
        JSON.stringify({ helper, mounts: [available, unavailable, { ...extra, status: "available" }, { ...other, status: "available" }] }),
    );
    render(<HostFolders {...props} />);
    const recovery = await screen.findByRole("group", { name: "Reconnect host folders" });
    expect(within(recovery).getByText(/Missing folders: build\. Restore them/)).toBeVisible();
    expect(within(recovery).queryByRole("group", { name: "Reapprove build" })).not.toBeInTheDocument();
    expect(within(recovery).queryByRole("group", { name: "Reapprove src" })).not.toBeInTheDocument();
    const meta = within(recovery).getByRole("group", { name: "Reapprove meta" });
    const command = "./vulnscout ai-context attach -p 'demo' -v 'x86' 'meta=/work/Bob'\\''s $(date); meta'";
    expect(within(meta).getByText(command)).toBeVisible();
    expect(within(recovery).getByText("./vulnscout ai-context attach -p 'demo' -v 'x86' 'logs=/work/logs'")).toBeVisible();
    const refresh = screen.getByRole("button", { name: "Refresh folder status" });
    expect(recovery.nextElementSibling).toBe(refresh);
    await user.click(within(meta).getByRole("button", { name: "Copy code block" }));
    expect(await navigator.clipboard.readText()).toBe(command);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await user.click(refresh);
    expect(await screen.findAllByRole("cell", { name: "Available" })).toHaveLength(3);
    expect(within(recovery).queryByRole("button", { name: "Copy code block" })).not.toBeInTheDocument();
});

test("keeps a detached folder out of the list and recovery commands despite an older GET and a failed refresh", async () => {
    const snapshot = JSON.stringify({ helper, mounts: [available, needsApproval] });
    let finishOldGet!: (response: string) => void;
    const oldGet = new Promise<string>(resolve => { finishOldGet = resolve; });
    let failRefresh!: () => void;
    const refresh = new Promise<{ body: string; status: number }>(resolve => {
        failRefresh = () => resolve({ body: JSON.stringify({ error: "Server unavailable" }), status: 500 });
    });
    fetchMock.mockResponseOnce(snapshot)
        .mockResponseOnce(() => oldGet)
        .mockResponseOnce(JSON.stringify({ detached: true, warning: "Cleanup pending." }))
        .mockResponseOnce(() => refresh);

    render(<HostFolders {...props} />);
    const detach = await screen.findByRole("button", { name: "Detach build" });
    expect(screen.getByRole("group", { name: "Reapprove build" })).toBeVisible();
    act(() => {
        fireEvent.click(screen.getByRole("button", { name: "Refresh folder status" }));
        fireEvent.click(detach);
    });
    expect(await screen.findByText("Detached build. Cleanup pending.")).toBeVisible();
    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect(screen.getByText("Checking attached folders...")).toBeVisible();
    expect(detach).not.toBeInTheDocument();
    expect(screen.queryByRole("group", { name: "Reapprove build" })).not.toBeInTheDocument();

    await act(async () => { finishOldGet(snapshot); });
    expect(screen.getByText("Checking attached folders...")).toBeVisible();
    expect(screen.queryByRole("button", { name: "Detach build" })).not.toBeInTheDocument();
    expect(screen.queryByRole("group", { name: "Reapprove build" })).not.toBeInTheDocument();
    await act(async () => { failRefresh(); });
    expect(screen.getByRole("alert")).toHaveTextContent("Server unavailable");
    expect(screen.getByRole("cell", { name: "/work/app" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Detach build" })).not.toBeInTheDocument();
    expect(screen.queryByRole("group", { name: "Reapprove build" })).not.toBeInTheDocument();
});

test("keeps the attachment when detach is rejected", async () => {
    fetchMock.mockResponseOnce(JSON.stringify({ helper, mounts: [needsApproval] }))
        .mockResponseOnce(JSON.stringify({ error: "The attachment was reapproved. Refresh the folder list." }), { status: 409 });
    render(<HostFolders {...props} />);
    const detach = await screen.findByRole("button", { name: "Detach build" });
    fireEvent.click(detach);
    expect(await screen.findByRole("alert")).toHaveTextContent("The attachment was reapproved.");
    expect(detach).toBeEnabled();
    expect(screen.getByRole("group", { name: "Reapprove build" })).toBeVisible();
    expect(fetchMock).toHaveBeenCalledTimes(2);
});

test("refresh retries a failed list request", async () => {
    fetchMock.mockResponseOnce(JSON.stringify({ error: "Server unavailable" }), { status: 500 })
        .mockResponseOnce(JSON.stringify({ helper, mounts: [] }));
    render(<HostFolders {...props} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Server unavailable");
    fireEvent.click(screen.getByRole("button", { name: "Refresh folder status" }));
    expect(await screen.findByText("No host folders attached.")).toBeVisible();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

test("opens and dismisses the attach instructions next to the heading with the keyboard", async () => {
    const user = userEvent.setup();
    fetchMock.mockResponseOnce(JSON.stringify({ helper, mounts: [] }));
    render(<HostFolders {...props} />);
    await screen.findByText("No host folders attached.");
    expect(screen.getByRole("heading", { name: "Attached host folders" })).toBeVisible();
    expect(screen.queryByText(/Agents can read and search/)).not.toBeInTheDocument();
    const help = screen.getByRole("button", { name: "Attached host folders help" });
    await user.tab();
    expect(help).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(screen.getByRole("tooltip")).toHaveTextContent(/Agents can read and search.*mount:<alias>.*then refresh the list\./);
    expect(help).toHaveAccessibleDescription(/launcher directory on the container host/);
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("tooltip")).not.toBeInTheDocument();
    expect(help).toHaveFocus();
});

test("copies the scoped attach example as literal shell arguments without changing mounts", async () => {
    const user = userEvent.setup();
    fetchMock.mockResponseOnce(JSON.stringify({ helper, mounts: [] }));
    render(<HostFolders {...props} projectName="Bob's project" variantName="$(date); x86" />);
    await screen.findByText("No host folders attached.");
    const command = "./vulnscout ai-context attach -p 'Bob'\\''s project' -v '$(date); x86' 'src=/path/to/folder'";
    expect(screen.getByText(command)).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Copy code block" }));
    expect(await navigator.clipboard.readText()).toBe(command);
    expect(fetchMock).toHaveBeenCalledTimes(1);
});

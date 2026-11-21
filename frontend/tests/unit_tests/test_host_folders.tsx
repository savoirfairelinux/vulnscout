import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import "@testing-library/jest-dom";
import fetchMock from "jest-fetch-mock";
import HostFolders from "../../src/components/aiContext/HostFolders";

fetchMock.enableMocks();
beforeEach(() => fetchMock.resetMocks());

const props = { variantId: "v1", projectName: "demo", variantName: "x86", disabled: false };
const helper = { available: true, message: null };
const available = { attachment_id: "3488d574-c2db-44e9-9ed1-34f413541295",
    alias: "src", host_path: "/work/app", status: "available" };
const unavailable = { attachment_id: "bf19a62f-ac62-4534-a65d-c74251a1de0a",
    alias: "build", host_path: "/work/build", status: "unavailable", message: "Host folder not found." };

test("lists attached folders and refreshes after detaching one", async () => {
    fetchMock.mockResponses(
        JSON.stringify({ helper, mounts: [available, unavailable] }),
        JSON.stringify({ detached: true, warning: "Cleanup pending." }),
        JSON.stringify({ helper, mounts: [available] }),
    );
    render(<HostFolders {...props} />);
    const list = await screen.findByRole("list", { name: "Attached folders" });
    expect(within(list).getByText("/work/app")).toBeVisible();
    expect(within(list).getByText("Available")).toBeVisible();
    expect(within(list).getByText("Unavailable")).toBeVisible();
    expect(within(list).getByText("Host folder not found.")).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "Detach build" }));
    expect(await screen.findByText("Detached build. Cleanup pending.")).toBeVisible();
    expect(fetchMock).toHaveBeenNthCalledWith(2,
        `http://localhost/api/variants/v1/context/mounts/build?attachment_id=${unavailable.attachment_id}`,
        expect.objectContaining({ method: "DELETE" }));
    expect(screen.queryByRole("button", { name: "Detach build" })).not.toBeInTheDocument();
});

test("reports helper unavailability and disables detach in a locked editor", async () => {
    fetchMock.mockResponseOnce(JSON.stringify({
        helper: { available: false, message: "Offline." }, mounts: [unavailable],
    }));
    render(<HostFolders {...props} disabled />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Host folder helper unavailable: Offline.");
    expect(screen.getByRole("button", { name: "Detach build" })).toBeDisabled();
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

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom";
import fetchMock from "jest-fetch-mock";
import HostFolders from "../../src/components/aiContext/HostFolders";

fetchMock.enableMocks();

type Mount = { alias: string; file_id: string; host_path: string; created_at: string; status: string; message: string };
type Server = {
    helperAvailable: boolean;
    roots: string[];
    folders: Record<string, string[]>;
    mounts: Mount[];
    requests: { url: string; method: string; body: string | null }[];
    attachError?: { status: number; error: string };
    attachPending?: Promise<void>;
};

const json = (body: unknown, status = 200) => ({ status, body: JSON.stringify(body), headers: { "Content-Type": "application/json" } });
const UNAVAILABLE = "Host folder helper is not running.";

function serve(overrides: Partial<Server> = {}): Server {
    const server: Server = {
        helperAvailable: true,
        roots: ["/work"],
        folders: { "/work": ["app", "build"], "/work/app": ["src"], "/work/build": [] },
        mounts: [],
        requests: [],
        ...overrides,
    };
    fetchMock.mockResponse(async request => {
        const url = new URL(request.url, "http://localhost");
        const body = request.method === "GET" ? null : await request.text();
        server.requests.push({ url: url.pathname + url.search, method: request.method, body });
        if (url.pathname === "/api/context/host-roots") {
            return json({ available: server.helperAvailable, message: server.helperAvailable ? null : UNAVAILABLE,
                roots: server.helperAvailable ? server.roots : [] });
        }
        if (url.pathname === "/api/context/host-roots/browse") {
            const path = url.searchParams.get("path");
            if (!path) {
                return json({ path: null, root: null, parent: null, truncated: false,
                    directories: server.roots.map(root => ({ name: root, path: root })) });
            }
            if (!server.roots.some(root => path === root || path.startsWith(`${root}/`))) {
                return json({ error: "Host path is outside the operator-approved roots." }, 403);
            }
            const parent = server.roots.includes(path) ? null : path.slice(0, path.lastIndexOf("/"));
            return json({ path, root: "/work", parent, truncated: false,
                directories: (server.folders[path] ?? []).map(name => ({ name, path: `${path}/${name}` })) });
        }
        const mounts = /^\/api\/variants\/v1\/context\/mounts(?:\/([^/]+))?$/.exec(url.pathname);
        if (mounts && request.method === "GET") {
            return json({ helper: { available: server.helperAvailable, message: server.helperAvailable ? null : UNAVAILABLE },
                mounts: server.mounts.map(mount => server.helperAvailable ? mount
                    : { ...mount, status: "unavailable", message: UNAVAILABLE }) });
        }
        if (mounts && request.method === "POST") {
            await server.attachPending;
            if (server.attachError) return json({ error: server.attachError.error }, server.attachError.status);
            const { alias, host_path } = JSON.parse(body ?? "{}");
            const mount = { alias, file_id: `mount:${alias}`, host_path, created_at: "2026-01-01T00:00:00Z",
                status: "available", message: "Folder is available read-only." };
            server.mounts = [...server.mounts, mount];
            return json(mount, 201);
        }
        if (mounts && request.method === "DELETE") {
            server.mounts = server.mounts.filter(mount => mount.alias !== mounts[1]);
            return json({ alias: mounts[1], detached: true, warning: null });
        }
        return json({ error: "unexpected" }, 500);
    });
    return server;
}

const mount = (alias: string, host_path: string, status = "available", message = ""): Mount => ({
    alias, file_id: `mount:${alias}`, host_path, created_at: "2026-01-01T00:00:00Z", status, message,
});

beforeEach(() => fetchMock.resetMocks());

test("lists attached folders with their availability and detaches one", async () => {
    const server = serve({ mounts: [mount("build", "/work/build", "unavailable", "Host folder not found."), mount("src", "/work/app")] });
    render(<HostFolders variantId="v1" disabled={false} />);
    const list = await screen.findByRole("list", { name: "Attached folders" });
    expect(within(list).getByText("/work/app")).toBeVisible();
    expect(within(list).getByText("Available")).toBeVisible();
    expect(within(list).getByText("Unavailable")).toBeVisible();
    expect(within(list).getByText("Host folder not found.")).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "Detach build" }));
    expect(await screen.findByText("Detached build.")).toBeVisible();
    expect(server.requests.some(r => r.method === "DELETE" && r.url === "/api/variants/v1/context/mounts/build")).toBe(true);
    await waitFor(() => expect(screen.queryByRole("button", { name: "Detach build" })).not.toBeInTheDocument());
});

test("attach folder browses approved roots only and sends the chosen folder and alias", async () => {
    let complete!: () => void;
    const server = serve({ attachPending: new Promise<void>(resolve => { complete = resolve; }) });
    render(<HostFolders variantId="v1" disabled={false} />);
    expect(await screen.findByText("No host folders attached.")).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "Attach folder" }));
    const panel = await screen.findByRole("group", { name: "Attach folder" });
    const attach = within(panel).getByRole("button", { name: "Attach selected folder" });
    fireEvent.click(await within(panel).findByRole("button", { name: "/work" }));
    fireEvent.click(await within(panel).findByRole("button", { name: "app" }));
    await within(panel).findByRole("button", { name: "src" });
    expect(within(panel).getByText("/work/app")).toBeVisible();
    expect(within(panel).getByLabelText("Alias")).toHaveValue("app");

    fireEvent.change(within(panel).getByLabelText("Alias"), { target: { value: "Bad Alias" } });
    expect(within(panel).getByText(/lowercase letters/)).toBeVisible();
    expect(attach).toBeDisabled();
    fireEvent.change(within(panel).getByLabelText("Alias"), { target: { value: "src" } });
    await waitFor(() => expect(attach).toBeEnabled());
    fireEvent.click(attach);
    expect(within(panel).getByRole("button", { name: "Cancel" })).toBeDisabled();
    complete();
    expect(await screen.findByText("Attached src (mount:src).")).toBeVisible();
    const post = server.requests.find(r => r.method === "POST");
    expect(JSON.parse(post?.body ?? "{}")).toEqual({ alias: "src", host_path: "/work/app" });
    expect(await screen.findByRole("button", { name: "Detach src" })).toBeVisible();
    expect(screen.queryByRole("group", { name: "Attach folder" })).not.toBeInTheDocument();
    expect(server.requests.every(r => !r.url.includes("path=%2Fetc"))).toBe(true);
});

test("navigating up from an approved root returns to the root list", async () => {
    serve();
    render(<HostFolders variantId="v1" disabled={false} />);
    fireEvent.click(await screen.findByRole("button", { name: "Attach folder" }));
    const panel = await screen.findByRole("group", { name: "Attach folder" });
    fireEvent.click(await within(panel).findByRole("button", { name: "/work" }));
    fireEvent.click(await within(panel).findByRole("button", { name: "Up" }));
    expect(await within(panel).findByText("Approved host folders")).toBeVisible();
    expect(within(panel).queryByRole("button", { name: "Up" })).not.toBeInTheDocument();
    expect(within(panel).getByRole("button", { name: "Attach selected folder" })).toBeDisabled();
});

test("attach errors are shown and duplicate aliases are refused locally", async () => {
    serve({ mounts: [mount("src", "/work/app")], attachError: { status: 403, error: "Host path is outside the operator-approved roots." } });
    render(<HostFolders variantId="v1" disabled={false} />);
    fireEvent.click(await screen.findByRole("button", { name: "Attach folder" }));
    const panel = await screen.findByRole("group", { name: "Attach folder" });
    fireEvent.click(await within(panel).findByRole("button", { name: "/work" }));
    fireEvent.click(await within(panel).findByRole("button", { name: "build" }));
    fireEvent.change(within(panel).getByLabelText("Alias"), { target: { value: "src" } });
    expect(within(panel).getByText("Alias 'src' is already used by this variant.")).toBeVisible();
    fireEvent.change(within(panel).getByLabelText("Alias"), { target: { value: "build" } });
    const attach = within(panel).getByRole("button", { name: "Attach selected folder" });
    await waitFor(() => expect(attach).toBeEnabled());
    fireEvent.click(attach);
    expect(await within(panel).findByRole("alert")).toHaveTextContent("outside the operator-approved roots");
});

test("helper unavailability is reported in the list and the picker", async () => {
    serve({ helperAvailable: false, mounts: [mount("src", "/work/app")] });
    render(<HostFolders variantId="v1" disabled={false} />);
    expect(await screen.findByText(`Host folder helper unavailable: ${UNAVAILABLE}`)).toBeVisible();
    expect(await screen.findByText("Unavailable")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Attach folder" }));
    const panel = await screen.findByRole("group", { name: "Attach folder" });
    expect(await within(panel).findByRole("alert")).toHaveTextContent(UNAVAILABLE);
    expect(within(panel).getByRole("button", { name: "Attach selected folder" })).toBeDisabled();
});

test("disabled editors cannot attach or detach", async () => {
    serve({ mounts: [mount("src", "/work/app")] });
    render(<HostFolders variantId="v1" disabled />);
    expect(await screen.findByRole("button", { name: "Detach src" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Attach folder" })).toBeDisabled();
});

test("load failures are explicit and can be retried", async () => {
    fetchMock.mockResponseOnce(JSON.stringify({ error: "Server unavailable" }), { status: 500 });
    render(<HostFolders variantId="v1" disabled={false} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Server unavailable");
    serve();
    fireEvent.click(screen.getByRole("button", { name: "Refresh folder status" }));
    expect(await screen.findByText("No host folders attached.")).toBeVisible();
});

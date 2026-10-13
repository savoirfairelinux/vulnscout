import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import fetchMock from "jest-fetch-mock";
import CodebaseReferences from "../../src/components/CodebaseReferences";
import Assessments from "../../src/handlers/assessments";

fetchMock.enableMocks();
const notify = jest.fn();
const reference = { id: "f1", original_name: "source.zip", description: "Full source" };
const noFiles: typeof reference[] = [];

beforeEach(() => {
    fetchMock.resetMocks();
    notify.mockReset();
    jest.spyOn(Assessments, "listForReview").mockResolvedValue([]);
});
afterEach(() => jest.restoreAllMocks());

function show(disabled = false, initialFiles = noFiles) {
    return render(
        <CodebaseReferences variantId="v1" initialFiles={initialFiles} disabled={disabled} notify={notify} />
    );
}

test("picker uploads multipart source with description and shows the saved reference", async () => {
    fetchMock.mockResponseOnce(JSON.stringify(reference), { status: 201 });
    show();
    fireEvent.change(screen.getByLabelText("Codebase reference description"), { target: { value: "Full source" } });
    const file = new File(["source"], "source.zip");
    fireEvent.change(screen.getByLabelText("Upload codebase references"), { target: { files: [file] } });
    await screen.findByRole("button", { name: "Delete reference source.zip" });
    expect(Assessments.listForReview).toHaveBeenCalledWith("v1", undefined, "ai");
    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toContain("/api/variants/v1/context/files");
    expect(options?.method).toBe("POST");
    const body = options?.body as FormData;
    expect(body.get("file")).toBe(file);
    expect(body.get("description")).toBe("Full source");
    expect(options?.headers).toBeUndefined();
    expect(notify).toHaveBeenCalledWith(expect.stringContaining("1 reference(s) uploaded"), "success");
});

test("drop accepts multiple files and reports partial failures without hiding successes", async () => {
    fetchMock.mockResponseOnce(JSON.stringify(reference), { status: 201 });
    fetchMock.mockResponseOnce(JSON.stringify({ error: "Invalid archive" }), { status: 400 });
    show();
    const dropzone = screen.getByRole("region", { name: "Drop codebase files" });
    fireEvent.dragOver(dropzone);
    fireEvent.dragLeave(dropzone);
    fireEvent.drop(dropzone, { dataTransfer: { files: [new File(["x"], "source.zip"), new File(["bad"], "bad.zip")] } });
    await waitFor(() => expect(notify).toHaveBeenCalledWith(expect.stringContaining("bad.zip: Invalid archive"), "error"));
    expect(screen.getByRole("button", { name: "Delete reference source.zip" })).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(2);
});

test("uploads require confirmation when pending assessments exist and cancel does not upload", async () => {
    jest.spyOn(Assessments, "listForReview").mockResolvedValue([{
        id: "a1", vuln_id: "CVE-2026-1234", packages: ["component@1"], origin: "ai",
        status: "under_investigation", simplified_status: "under_investigation", timestamp: "", responses: [],
    }]);
    show();
    fireEvent.change(screen.getByLabelText("Upload codebase references"), { target: { files: [new File(["x"], "a.c")] } });
    await screen.findByRole("button", { name: "Upload and mark outdated" });
    expect(fetchMock).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByLabelText("Upload codebase references")).not.toBeDisabled();
    expect(fetchMock).not.toHaveBeenCalled();
});

test("failed pending checks surface an error and require confirmation", async () => {
    jest.spyOn(Assessments, "listForReview").mockRejectedValue(new Error("Review service offline"));
    fetchMock.mockResponseOnce(JSON.stringify(reference), { status: 201 });
    show();
    fireEvent.change(screen.getByLabelText("Upload codebase references"), { target: { files: [new File(["x"], "a.c")] } });
    await screen.findByRole("button", { name: "Upload and mark outdated" });
    expect(notify).toHaveBeenCalledWith(expect.stringContaining("Review service offline"), "error");
    fireEvent.click(screen.getByRole("button", { name: "Upload and mark outdated" }));
    await screen.findByRole("button", { name: "Delete reference source.zip" });
});

test("oversized files are rejected explicitly before uploading", async () => {
    show();
    const oversized = new File(["x"], "large.c");
    Object.defineProperty(oversized, "size", { value: 10 * 1024 * 1024 + 1 });
    fireEvent.change(screen.getByLabelText("Upload codebase references"), { target: { files: [oversized] } });
    await waitFor(() => expect(notify).toHaveBeenCalledWith(expect.stringContaining("maximum size of 10 MB"), "error"));
    expect(fetchMock).not.toHaveBeenCalled();
});

test("disabled drop zone does not submit requests", () => {
    show(true);
    expect(screen.getByLabelText("Upload codebase references")).toBeDisabled();
    fireEvent.drop(screen.getByRole("region", { name: "Drop codebase files" }), {
        dataTransfer: { files: [new File(["x"], "a.c")] },
    });
    expect(Assessments.listForReview).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
});

test("delete confirms and removes persisted metadata", async () => {
    fetchMock.mockResponseOnce("", { status: 204 });
    show(false, [reference]);
    fireEvent.click(screen.getByRole("button", { name: "Delete reference source.zip" }));
    expect(fetchMock).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Delete reference" }));
    await screen.findByText("No codebase references uploaded.");
    expect(fetchMock.mock.calls[0][0]).toContain("/api/variants/v1/context/files/f1");
    expect(fetchMock.mock.calls[0][1]?.method).toBe("DELETE");
});

test("failed deletion leaves the reference visible", async () => {
    fetchMock.mockResponseOnce(JSON.stringify({ error: "Storage unavailable" }), { status: 500 });
    show(false, [reference]);
    fireEvent.click(screen.getByRole("button", { name: "Delete reference source.zip" }));
    fireEvent.click(screen.getByRole("button", { name: "Delete reference" }));
    await waitFor(() => expect(notify).toHaveBeenCalledWith("Storage unavailable", "error"));
    expect(screen.getByRole("button", { name: "Delete reference source.zip" })).toBeInTheDocument();
});

test("selection changes do not leak late uploads into the new variant", async () => {
    let finish: ((response: string) => void) | undefined;
    fetchMock.mockResponseOnce(() => new Promise(resolve => { finish = resolve; }));
    const { rerender } = show();
    fireEvent.change(screen.getByLabelText("Upload codebase references"), { target: { files: [new File(["x"], "a.c")] } });
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    rerender(<CodebaseReferences key="v2" variantId="v2" initialFiles={noFiles} disabled={false} notify={notify} />);
    await act(async () => { finish?.(JSON.stringify(reference)); });
    expect(screen.queryByRole("button", { name: "Delete reference source.zip" })).not.toBeInTheDocument();
    expect(notify).not.toHaveBeenCalled();
});

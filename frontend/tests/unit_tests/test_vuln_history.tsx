import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from "react";

import VulnHistory from "../../src/components/VulnHistory";
import VulnerabilityHistory from "../../src/handlers/vulnerabilityHistory";
import type { HistoryEntry } from "../../src/handlers/vulnerabilityHistory";
import VulnerabilityRefreshRun from "../../src/handlers/vulnerabilityRefreshRun";
import type { RefreshRun } from "../../src/handlers/vulnerabilityRefreshRun";
import { getSnapshot, subscribe } from "../../src/handlers/operationStore";

jest.mock("../../src/handlers/operationStore", () => ({
    getSnapshot: jest.fn(() => []), subscribe: jest.fn(() => () => {}),
}));

const row = (field: string, old_value: unknown, value: unknown, source: string, changed_at: string): HistoryEntry => ({
    field, old_value, value, source, changed_at,
});

const rows: HistoryEntry[] = [
    row("epss_score", null, 0.1, "sbom", "2026-01-01T00:00:00+00:00"),
    row("epss_score", 0.1, 0.125, "epss", "2026-02-01T00:00:00+00:00"),
    row("epss_score", 0.125, null, "epss", "2026-03-01T00:00:00+00:00"),
    row("epss_score", null, 0.2, "epss", "2026-04-01T00:00:00+00:00"),
    row("description", "old text", "new text", "nvd", "2026-02-01T00:00:00+00:00"),
    row("cvss:3.1:nvd", { score: 7.5, vector: "AV:N" }, { score: 9.8, vector: "AV:N" }, "nvd", "2026-02-01T00:00:00+00:00"),
];

describe("VulnHistory", () => {
    let list: jest.SpyInstance;

    beforeEach(() => {
        list = jest.spyOn(VulnerabilityHistory, "list").mockResolvedValue(rows);
        jest.spyOn(VulnerabilityRefreshRun, "latest").mockResolvedValue(null);
    });

    afterEach(() => jest.restoreAllMocks());

    const expand = async () => {
        await userEvent.click(screen.getByRole("button", { name: "Expand data history" }));
    };

    test("loads nothing until expanded", () => {
        render(<VulnHistory vulnId="CVE-2026-0001" />);

        expect(screen.getByText("Data history")).toBeInTheDocument();
        expect(list).not.toHaveBeenCalled();
    });

    test("shows when each field was first added and every later change", async () => {
        render(<VulnHistory vulnId="CVE-2026-0001" />);
        await expand();

        expect(await screen.findByText("EPSS score")).toBeInTheDocument();
        expect(list).toHaveBeenCalledWith("CVE-2026-0001");

        const epss = screen.getByTestId("history-epss_score");
        expect(epss).toHaveTextContent("(4 changes)");
        expect(epss).not.toHaveTextContent("Before history tracking");
        expect(epss).toHaveTextContent("SBOM import · first added");
        expect(epss).toHaveTextContent("10.00%");
        expect(epss).toHaveTextContent("EPSS · +2.50 pts");
        expect(epss).toHaveTextContent("12.50%");
        expect(epss).toHaveTextContent("EPSS · cleared");
        expect(epss).toHaveTextContent("Cleared");
        expect(epss).toHaveTextContent("EPSS · added");

        const description = screen.getByTestId("history-description");
        expect(description).toHaveTextContent("Description(1 change)");
        expect(description).toHaveTextContent("Before history trackingold text");
        expect(description).toHaveTextContent("NVDnew text");

        const cvss = screen.getByTestId("history-cvss:3.1:nvd");
        expect(cvss).toHaveTextContent("CVSS 3.1 (nvd)(1 change)");
        expect(cvss).toHaveTextContent("7.5 (AV:N)");
        expect(cvss).toHaveTextContent("NVD · +2.3");
        expect(cvss).toHaveTextContent("9.8 (AV:N)");

        await userEvent.click(screen.getByRole("button", { name: "Collapse data history" }));
        expect(screen.queryByText("EPSS score")).not.toBeInTheDocument();
    });

    test("reloads an open history when the reload key changes", async () => {
        const { rerender } = render(<VulnHistory vulnId="CVE-2026-0001" reloadKey={0} />);
        await expand();
        await screen.findByText("EPSS score");

        rerender(<VulnHistory vulnId="CVE-2026-0001" reloadKey={1} />);

        await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    });

    test("shows a loading state, then an empty history", async () => {
        let resolve: (value: HistoryEntry[]) => void = () => {};
        list.mockReturnValue(new Promise(done => { resolve = done; }));
        render(<VulnHistory vulnId="CVE-2026-0001" />);
        await expand();

        expect(screen.getByText("Loading history…")).toBeInTheDocument();
        resolve([]);
        expect(await screen.findByText("No changes recorded yet.")).toBeInTheDocument();
    });

    test("reports a failed load", async () => {
        list.mockRejectedValue(new Error("HTTP 500"));
        render(<VulnHistory vulnId="CVE-2026-0001" />);
        await expand();

        expect(await screen.findByText("Failed to load history: Error: HTTP 500")).toBeInTheDocument();
    });

    test("ignores a response that lands after unmount", async () => {
        let resolve: (value: HistoryEntry[]) => void = () => {};
        list.mockReturnValue(new Promise(done => { resolve = done; }));
        const { unmount } = render(<VulnHistory vulnId="CVE-2026-0001" />);
        await expand();

        unmount();
        resolve(rows);
        await Promise.resolve();
        expect(list).toHaveBeenCalledTimes(1);
    });

    test("never fetches unscoped field history for a shared CVE and resets on scope changes", async () => {
        const latest = jest.mocked(VulnerabilityRefreshRun.latest);
        const makeRun = (id: string): RefreshRun => ({
            run_id: id, scope: { project_id: id, variant_id: null }, sources: [],
            started_at: '2026-01-01T00:00:00Z', finished_at: null, status: 'incomplete',
            coverage: [], changes: [], summary: { total_changes: 0, changed_vulnerabilities: 0, first_enrichments: 0 },
            total: 0, limit: 1000, offset: 0,
        });
        latest.mockResolvedValueOnce(makeRun('first-project'));
        const { rerender } = render(<VulnHistory vulnId="CVE-1" projectId="p1" variantId="v1" />);
        await expand();
        await screen.findByText('first-project');
        let resolve: (value: RefreshRun) => void = () => {};
        latest.mockReturnValueOnce(new Promise(done => { resolve = done; }));
        rerender(<VulnHistory vulnId="CVE-1" projectId="p2" variantId="v2" />);
        expect(screen.queryByText('first-project')).not.toBeInTheDocument();
        await expand();
        expect(screen.getByText('Loading refresh changes…')).toBeInTheDocument();
        expect(latest).toHaveBeenLastCalledWith('CVE-1', { projectId: 'p2', variantId: 'v2' }, expect.any(AbortSignal));
        rerender(<VulnHistory vulnId="CVE-2" projectId="p2" variantId="v2" />);
        await act(async () => resolve(makeRun('stale-project')));
        expect(screen.queryByText('stale-project')).not.toBeInTheDocument();
        await expand();
        await waitFor(() => expect(latest).toHaveBeenLastCalledWith('CVE-2', { projectId: 'p2', variantId: 'v2' }, expect.any(AbortSignal)));
        expect(list).not.toHaveBeenCalled();
    });

    test("reloads scoped changes after explicit refresh invalidation and queue status updates", async () => {
        const { rerender } = render(<VulnHistory vulnId="CVE-1" projectId="p" reloadKey={0} />);
        await expand();
        await screen.findByText(/No refresh baseline/);
        const latest = jest.mocked(VulnerabilityRefreshRun.latest);
        rerender(<VulnHistory vulnId="CVE-1" projectId="p" reloadKey={1} />);
        await waitFor(() => expect(latest).toHaveBeenCalledTimes(2));
        const calls = jest.mocked(subscribe).mock.calls;
        const listener = calls[calls.length - 1][0];
        jest.mocked(getSnapshot).mockReturnValueOnce([{
            op_id: 'refresh:nvd', kind: 'refresh', status: 'done', source: 'nvd',
            label: 'NVD', lane: 'pipeline', scope: null, progress: { current: 1, total: 1, message: '' },
            logs: [], error: null, queue_id: 'q-1', position: null, options: {}, cancellable: false,
            created_at: '', started_at: null, finished_at: null, result: null,
        }]);
        act(() => listener());
        await waitFor(() => expect(latest).toHaveBeenCalledTimes(3));
        expect(list).not.toHaveBeenCalled();
    });

    test("reports scoped request failure instead of claiming no changes", async () => {
        jest.mocked(VulnerabilityRefreshRun.latest).mockRejectedValue(new Error('HTTP 500'));
        render(<VulnHistory vulnId="CVE-1" projectId="p" />);
        await expand();
        expect(await screen.findByRole('alert')).toHaveTextContent('Unable to load the scoped refresh run');
        expect(screen.queryByText(/No data changed/)).not.toBeInTheDocument();
    });
});

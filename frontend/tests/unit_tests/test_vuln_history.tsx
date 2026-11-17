import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from "react";

import VulnHistory from "../../src/components/VulnHistory";
import VulnerabilityHistory from "../../src/handlers/vulnerabilityHistory";
import type { HistoryEntry } from "../../src/handlers/vulnerabilityHistory";

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
});

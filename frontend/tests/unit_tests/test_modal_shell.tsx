import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from "react";

import ModalShell, { ModalActions, ModalButton, ModalLink } from "../../src/components/ModalShell";

describe("ModalShell", () => {
    const defaultProps = {
        isOpen: true,
        title: "Shared dialog",
        onClose: jest.fn(),
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    test("does not render when closed", () => {
        render(<ModalShell {...defaultProps} isOpen={false}>Content</ModalShell>);

        expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });

    test("associates the title and description with the dialog", () => {
        render(
            <ModalShell {...defaultProps} titleId="dialog-title" descriptionId="dialog-description">
                <p id="dialog-description">Content</p>
            </ModalShell>
        );

        const dialog = screen.getByRole("dialog", { name: "Shared dialog" });
        expect(dialog).toHaveAttribute("aria-labelledby", "dialog-title");
        expect(dialog).toHaveAttribute("aria-describedby", "dialog-description");
        expect(dialog).toHaveAttribute("aria-modal", "true");
    });

    test("dismisses from Escape, backdrop, and close button", async () => {
        const user = userEvent.setup();
        render(<ModalShell {...defaultProps}>Content</ModalShell>);

        fireEvent.keyDown(document, { key: "Escape" });
        fireEvent.mouseDown(screen.getByTestId("modal-backdrop"));
        await user.click(screen.getByRole("button", { name: "Close modal" }));

        expect(defaultProps.onClose).toHaveBeenCalledTimes(3);
    });

    test("does not dismiss from panel interaction", () => {
        render(<ModalShell {...defaultProps}>Content</ModalShell>);

        fireEvent.mouseDown(screen.getByRole("dialog"));

        expect(defaultProps.onClose).not.toHaveBeenCalled();
    });

    test("supports disabling Escape and backdrop dismissal", () => {
        render(
            <ModalShell {...defaultProps} closeOnEscape={false} closeOnBackdrop={false}>
                Content
            </ModalShell>
        );

        fireEvent.keyDown(document, { key: "Escape" });
        fireEvent.mouseDown(screen.getByTestId("modal-backdrop"));

        expect(defaultProps.onClose).not.toHaveBeenCalled();
    });

    test("traps focus, locks scrolling, and restores focus when closed", () => {
        const opener = document.createElement("button");
        document.body.appendChild(opener);
        opener.focus();

        const { rerender } = render(
            <ModalShell {...defaultProps}>
                <button type="button">First</button>
                <button type="button">Last</button>
            </ModalShell>
        );

        const dialog = screen.getByRole("dialog");
        const first = screen.getByRole("button", { name: "Close modal" });
        const last = screen.getByRole("button", { name: "Last" });
        expect(dialog).toHaveFocus();
        expect(document.body).toHaveStyle({ overflow: "hidden" });

        last.focus();
        fireEvent.keyDown(document, { key: "Tab" });
        expect(first).toHaveFocus();
        first.focus();
        fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
        expect(last).toHaveFocus();

        rerender(<ModalShell {...defaultProps} isOpen={false}>Content</ModalShell>);
        expect(opener).toHaveFocus();
        expect(document.body).not.toHaveStyle({ overflow: "hidden" });
        opener.remove();
    });

    test("keeps the focus lifecycle stable when onClose changes", () => {
        const firstOnClose = jest.fn();
        const { rerender } = render(<ModalShell {...defaultProps} onClose={firstOnClose}>Content</ModalShell>);
        const dialog = screen.getByRole("dialog");
        const secondOnClose = jest.fn();

        rerender(<ModalShell {...defaultProps} onClose={secondOnClose}>Updated content</ModalShell>);
        expect(dialog).toHaveFocus();

        fireEvent.keyDown(document, { key: "Escape" });
        expect(firstOnClose).not.toHaveBeenCalled();
        expect(secondOnClose).toHaveBeenCalledTimes(1);
    });

    test("renders standardized framing with header details, actions, and footer", () => {
        render(
            <ModalShell
                {...defaultProps}
                subtitle="Dialog subtitle"
                icon={<span>Icon</span>}
                headerActions={<button type="button">Action</button>}
                footer={<button type="button">Save</button>}
                closeLabel="Close shared dialog"
                contentClassName="custom-content"
                size="large"
            >
                Content
            </ModalShell>
        );

        expect(screen.getByText("Dialog subtitle")).toBeInTheDocument();
        expect(screen.getByText("Icon")).toBeInTheDocument();
        expect(screen.getByRole("button", { name: "Action" })).toBeInTheDocument();
        expect(screen.getByRole("button", { name: "Save" })).toBeInTheDocument();
        expect(screen.getByRole("button", { name: "Close shared dialog" })).toBeInTheDocument();
        expect(screen.getByTestId("modal-backdrop")).toHaveClass("bg-black/70");
        expect(screen.getByRole("dialog")).toHaveClass("max-w-3xl");
        expect(screen.getByRole("dialog")).toHaveClass("border-neutral-700", "bg-neutral-900");
        expect(screen.getByText("Content")).toHaveClass("custom-content", "overflow-y-auto");
        expect(screen.getByRole("contentinfo")).toHaveClass("border-neutral-700", "bg-neutral-950/60");
    });

    test("renders the fullscreen preset", () => {
        render(<ModalShell {...defaultProps} size="fullscreen">Content</ModalShell>);

        expect(screen.getByRole("dialog")).toHaveClass("h-[calc(100vh-2rem)]", "max-w-[calc(100vw-2rem)]");
    });

    test("renders standardized modal actions", () => {
        render(
            <ModalActions align="between">
                <ModalButton>Cancel</ModalButton>
                <ModalButton variant="primary" disabled>Save</ModalButton>
                <ModalButton variant="danger">Delete</ModalButton>
                <ModalLink href="/download">Download</ModalLink>
            </ModalActions>
        );

        expect(screen.getByRole("button", { name: "Cancel" })).toHaveClass("bg-neutral-800");
        expect(screen.getByRole("button", { name: "Save" })).toHaveClass("bg-cyan-700", "disabled:opacity-50");
        expect(screen.getByRole("button", { name: "Delete" })).toHaveClass("bg-red-700");
        expect(screen.getByRole("link", { name: "Download" })).toHaveClass("bg-cyan-700");
    });
});
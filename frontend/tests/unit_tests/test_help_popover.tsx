import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React, { useState } from "react";

import HelpPopover from "../../src/components/HelpPopover";

describe("HelpPopover", () => {
    test("toggles an accessible help surface", async () => {
        const user = userEvent.setup();
        render(<HelpPopover ariaLabel="Search help" heading="Search syntax">Help text</HelpPopover>);

        const trigger = screen.getByRole("button", { name: "Search help" });
        expect(trigger).toHaveAttribute("aria-expanded", "false");
        await user.click(trigger);

        expect(trigger).toHaveAttribute("aria-expanded", "true");
        expect(screen.getByRole("dialog")).toHaveTextContent("Search syntaxHelp text");
        await user.click(trigger);
        expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });

    test("stays open for inside interaction and closes outside", async () => {
        const user = userEvent.setup();
        render(
            <div>
                <HelpPopover ariaLabel="Help"><button type="button">Inside</button></HelpPopover>
                <button type="button">Outside</button>
            </div>
        );

        await user.click(screen.getByRole("button", { name: "Help" }));
        await user.click(screen.getByRole("button", { name: "Inside" }));
        expect(screen.getByRole("dialog")).toBeInTheDocument();
        fireEvent.mouseDown(screen.getByRole("button", { name: "Outside" }));
        expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });

    test("closes on Escape", async () => {
        const user = userEvent.setup();
        render(<HelpPopover ariaLabel="Help">Help text</HelpPopover>);

        await user.click(screen.getByRole("button", { name: "Help" }));
        fireEvent.keyDown(document, { key: "Escape" });

        expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });

    test("supports controlled state", async () => {
        const user = userEvent.setup();
        function ControlledHelp() {
            const [open, setOpen] = useState(false);
            return <HelpPopover ariaLabel="Controlled help" open={open} onOpenChange={setOpen}>Help text</HelpPopover>;
        }
        render(<ControlledHelp />);

        await user.click(screen.getByRole("button", { name: "Controlled help" }));
        expect(screen.getByRole("dialog")).toBeInTheDocument();
    });
});
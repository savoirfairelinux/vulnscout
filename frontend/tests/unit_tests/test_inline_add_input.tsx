import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import { useState } from "react";
import InlineAddInput from "../../src/components/InlineAddInput";

function Harness({ onSubmit, initialOpen = false, onOpenChange }: Readonly<{
  onSubmit: (name: string) => Promise<void>;
  initialOpen?: boolean;
  onOpenChange?: (open: boolean) => void;
}>) {
  const [open, setOpen] = useState(initialOpen);
  return (
    <InlineAddInput isOpen={open} onOpenChange={(next) => { onOpenChange?.(next); setOpen(next); }} onSubmit={onSubmit}
      inputAriaLabel="New project name" submitAriaLabel="Create project" buttonClassName="btn">
      New Project
    </InlineAddInput>
  );
}

describe("InlineAddInput", () => {
  test("opens on click and focuses the input", () => {
    render(<Harness onSubmit={jest.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "New Project" }));
    expect(screen.getByLabelText("New project name")).toHaveFocus();
  });

  test("submits the trimmed name with Enter and collapses on success", async () => {
    const onSubmit = jest.fn().mockResolvedValue(undefined);
    render(<Harness onSubmit={onSubmit} initialOpen />);
    fireEvent.change(screen.getByLabelText("New project name"), { target: { value: "  Zeus " } });
    fireEvent.keyDown(screen.getByLabelText("New project name"), { key: "Enter" });
    await waitFor(() => expect(onSubmit).toHaveBeenCalledWith("Zeus"));
    expect(await screen.findByRole("button", { name: "New Project" })).toBeInTheDocument();
  });

  test("submits with the button and disables controls while blank or busy", async () => {
    let resolve!: () => void;
    const onSubmit = jest.fn(() => new Promise<void>((r) => { resolve = r; }));
    render(<Harness onSubmit={onSubmit} initialOpen />);
    expect(screen.getByRole("button", { name: "Create project" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("New project name"), { target: { value: "Zeus" } });
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
    expect(screen.getByLabelText("New project name")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Create project" })).toBeDisabled();
    resolve();
    expect(await screen.findByRole("button", { name: "New Project" })).toBeInTheDocument();
  });

  test("ignores Enter on a blank name", () => {
    const onSubmit = jest.fn();
    render(<Harness onSubmit={onSubmit} initialOpen />);
    fireEvent.change(screen.getByLabelText("New project name"), { target: { value: "   " } });
    fireEvent.keyDown(screen.getByLabelText("New project name"), { key: "Enter" });
    expect(onSubmit).not.toHaveBeenCalled();
  });

  test("shows a rejection, keeps the name, and clears the error on typing", async () => {
    const onSubmit = jest.fn().mockRejectedValue(new Error("Duplicate name"));
    render(<Harness onSubmit={onSubmit} initialOpen />);
    const input = screen.getByLabelText("New project name");
    fireEvent.change(input, { target: { value: "Zeus" } });
    fireEvent.keyDown(input, { key: "Enter" });
    expect(await screen.findByRole("alert")).toHaveTextContent("Duplicate name");
    expect(input).toHaveValue("Zeus");
    expect(input).toBeEnabled();
    fireEvent.change(input, { target: { value: "Zeus2" } });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  test("Escape cancels and resets; blur collapses only when empty", () => {
    render(<Harness onSubmit={jest.fn()} initialOpen />);
    const input = screen.getByLabelText("New project name");
    fireEvent.change(input, { target: { value: "draft" } });
    fireEvent.blur(input);
    expect(screen.getByLabelText("New project name")).toBeInTheDocument();
    fireEvent.keyDown(input, { key: "Escape" });
    fireEvent.click(screen.getByRole("button", { name: "New Project" }));
    expect(screen.getByLabelText("New project name")).toHaveValue("");
    fireEvent.blur(screen.getByLabelText("New project name"));
    expect(screen.getByRole("button", { name: "New Project" })).toBeInTheDocument();
  });

  test("blur toward the submit button keeps the input open", () => {
    render(<Harness onSubmit={jest.fn()} initialOpen />);
    fireEvent.blur(screen.getByLabelText("New project name"), {
      relatedTarget: screen.getByRole("button", { name: "Create project" }),
    });
    expect(screen.getByLabelText("New project name")).toBeInTheDocument();
  });

  test("a submit that settles after the input was closed and reopened leaves it open", async () => {
    let resolve!: () => void;
    const onOpenChange = jest.fn();
    render(<Harness onSubmit={() => new Promise<void>((r) => { resolve = r; })} onOpenChange={onOpenChange} initialOpen />);
    fireEvent.change(screen.getByLabelText("New project name"), { target: { value: "Zeus" } });
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
    fireEvent.keyDown(screen.getByLabelText("New project name"), { key: "Escape" });
    fireEvent.click(screen.getByRole("button", { name: "New Project" }));
    onOpenChange.mockClear();
    await act(async () => resolve());
    expect(onOpenChange).not.toHaveBeenCalled();
    expect(screen.getByLabelText("New project name")).toBeInTheDocument();
  });

  test("a failure that settles after the input was closed does not reappear on reopen", async () => {
    let reject!: (error: Error) => void;
    render(<Harness onSubmit={() => new Promise<void>((_, r) => { reject = r; })} initialOpen />);
    fireEvent.change(screen.getByLabelText("New project name"), { target: { value: "Zeus" } });
    fireEvent.click(screen.getByRole("button", { name: "Create project" }));
    fireEvent.keyDown(screen.getByLabelText("New project name"), { key: "Escape" });
    await act(async () => reject(new Error("Duplicate name")));
    fireEvent.click(screen.getByRole("button", { name: "New Project" }));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  test("links the input to its error and refocuses it after a failed submit", async () => {
    render(<Harness onSubmit={jest.fn().mockRejectedValue(new Error("Duplicate name"))} initialOpen />);
    const input = screen.getByLabelText("New project name");
    expect(input).not.toHaveAttribute("aria-invalid", "true");
    fireEvent.change(input, { target: { value: "Zeus" } });
    fireEvent.keyDown(input, { key: "Enter" });
    const alert = await screen.findByRole("alert");
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(input).toHaveAccessibleDescription("Duplicate name");
    expect(alert.id).toBeTruthy();
    await waitFor(() => expect(input).toHaveFocus());
  });

  test("ignores Enter while an IME composition is in progress", () => {
    const onSubmit = jest.fn().mockResolvedValue(undefined);
    render(<Harness onSubmit={onSubmit} initialOpen />);
    const input = screen.getByLabelText("New project name");
    fireEvent.change(input, { target: { value: "Zeus" } });
    fireEvent.keyDown(input, { key: "Enter", isComposing: true });
    expect(onSubmit).not.toHaveBeenCalled();
  });

  test("Escape returns focus to the collapsed button", () => {
    render(<Harness onSubmit={jest.fn()} initialOpen />);
    fireEvent.keyDown(screen.getByLabelText("New project name"), { key: "Escape" });
    expect(screen.getByRole("button", { name: "New Project" })).toHaveFocus();
  });
});

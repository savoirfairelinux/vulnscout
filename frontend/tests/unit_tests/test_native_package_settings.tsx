import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom";
import NativePackageSettings from "../../src/components/NativePackageSettings";
import Config from "../../src/handlers/config";

jest.mock("../../src/handlers/config", () => ({
    __esModule: true, default: { nativePackages: jest.fn() },
}));

const nativePackages = Config.nativePackages as jest.MockedFunction<typeof Config.nativePackages>;
const defaults = { exclude_native: true, native_package_exceptions: ["gcc-native", "cmake-native"] };

beforeEach(() => {
    nativePackages.mockReset();
    nativePackages.mockResolvedValue(defaults);
});

it("loads global settings and saves normalized exceptions", async () => {
    render(<NativePackageSettings />);
    const input = await screen.findByRole("textbox", { name: "Native packages to scan by default" });
    expect(input).toHaveValue("gcc-native\ncmake-native");
    expect(screen.getByRole("checkbox")).toBeChecked();
    fireEvent.change(input, { target: { value: " Make-Native, gcc-native\nmake-native " } });
    fireEvent.click(screen.getByRole("checkbox"));
    nativePackages.mockResolvedValueOnce({
        exclude_native: false, native_package_exceptions: ["gcc-native", "make-native"],
    });
    fireEvent.click(screen.getByRole("button", { name: "Save native-package defaults" }));
    await screen.findByText("Global native-package defaults saved.");
    expect(nativePackages).toHaveBeenLastCalledWith({
        exclude_native: false, native_package_exceptions: ["gcc-native", "make-native"],
    });
    expect(input).toHaveValue("gcc-native\nmake-native");
});

it("allows an empty exception list", async () => {
    render(<NativePackageSettings />);
    const input = await screen.findByRole("textbox");
    fireEvent.change(input, { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "Save native-package defaults" }));
    await waitFor(() => expect(nativePackages).toHaveBeenLastCalledWith({
        exclude_native: true, native_package_exceptions: [],
    }));
});

it.each(["openssl", `${"a".repeat(249)}-native`, Array.from({ length: 1001 }, (_, i) => `${i}-native`).join("\n")])(
    "rejects invalid or oversized exception lists", async value => {
        render(<NativePackageSettings />);
        fireEvent.change(await screen.findByRole("textbox"), { target: { value } });
        fireEvent.click(screen.getByRole("button", { name: "Save native-package defaults" }));
        expect(screen.getByRole("alert")).toHaveTextContent("Enter up to 1000 package names ending in -native");
        expect(nativePackages).toHaveBeenCalledTimes(1);
    },
);

it("reports load errors without offering a save", async () => {
    nativePackages.mockRejectedValueOnce(new Error("Cannot load defaults"));
    render(<NativePackageSettings />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Cannot load defaults");
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
});

it("reports save errors and lets the user retry", async () => {
    render(<NativePackageSettings />);
    await screen.findByRole("textbox");
    nativePackages.mockRejectedValueOnce(new Error("Cannot save defaults"));
    fireEvent.click(screen.getByRole("button", { name: "Save native-package defaults" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Cannot save defaults");
    expect(screen.queryByText("Global native-package defaults saved.")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Save native-package defaults" }));
    await screen.findByText("Global native-package defaults saved.");
});

import "@testing-library/jest-dom";
import { fireEvent, render, screen } from "@testing-library/react";
import Context from "../../src/handlers/context";
import HostFolders from "../../src/components/aiContext/HostFolders";

afterEach(() => jest.restoreAllMocks());

describe("HostFolders", () => {
    it("keeps a detach error visible without reloading mounts", async () => {
        const listMounts = jest.spyOn(Context, "listMounts").mockResolvedValue({
            helper: { available: true, message: null },
            mounts: [{
                attachment_id: "7fa695e4-8872-45fd-a244-1d4e956a6021",
                alias: "src",
                file_id: "mount:src",
                host_path: "/work/app",
                created_at: null,
                status: "available",
                message: "",
            }],
        });
        jest.spyOn(Context, "detachMount").mockRejectedValue(new Error("Detach failed."));

        render(<HostFolders variantId="variant-1" projectName="demo" variantName="default" disabled={false} />);
        fireEvent.click(await screen.findByRole("button", { name: "Detach src" }));

        expect(await screen.findByRole("alert")).toHaveTextContent("Detach failed.");
        expect(listMounts).toHaveBeenCalledTimes(1);
    });
});

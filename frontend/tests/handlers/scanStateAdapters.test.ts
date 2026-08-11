import * as grypeState from "../../src/handlers/grypeScanState";
import * as nvdState from "../../src/handlers/nvdScanState";
import * as osvState from "../../src/handlers/osvScanState";
import * as sccState from "../../src/handlers/sccScanState";

const fetchSpy = jest.fn();
global.fetch = fetchSpy as typeof fetch;

beforeEach(() => {
  fetchSpy.mockReset();
});

test("scan state adapters trigger their corresponding engine", async () => {
  for (let index = 0; index < 4; index += 1) {
    fetchSpy.mockResolvedValueOnce({ ok: false, status: 503, json: async () => ({}) } as unknown as Response);
  }

  for (const state of [grypeState, nvdState, osvState, sccState]) {
    await state.triggerScan([{ id: "variant-1", name: "Variant 1" }]);
    state.dismissAll();
  }

  expect(fetchSpy).toHaveBeenCalledTimes(4);
});

test("scan state adapters poll their corresponding engine", async () => {
  jest.useFakeTimers();
  try {
    for (let index = 0; index < 4; index += 1) {
      fetchSpy.mockResolvedValueOnce({ ok: true, status: 202, json: async () => ({}) } as unknown as Response);
      fetchSpy.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ status: "done" }) } as unknown as Response);
    }

    for (const state of [grypeState, nvdState, osvState, sccState]) {
      await state.triggerScan([{ id: "variant-1", name: "Variant 1" }]);
      await jest.advanceTimersByTimeAsync(3000);
      state.dismissAll();
    }
  } finally {
    jest.useRealTimers();
  }

  expect(fetchSpy).toHaveBeenCalledTimes(8);
});
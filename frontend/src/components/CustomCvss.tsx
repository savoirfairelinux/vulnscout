import { useState } from "react";
import type { Variant } from "../handlers/variant";

type Props = {
  onCancel: () => void;
  onAddCvss: (vector: string) => void;
  triggerBanner: (message: string, type: "error" | "success") => void;
  variants?: Variant[];
  selectedVariantIds?: string[];
  onSelectedVariantIdsChange?: (variantIds: string[]) => void;
};

function CustomCvss({
  onCancel,
  onAddCvss,
  triggerBanner,
  variants,
  selectedVariantIds,
  onSelectedVariantIdsChange,
}: Props) {
  const [vectorString, setVectorString] = useState("");

  const handleAdd = () => {
    if (!vectorString.trim()) {
      triggerBanner("Please provide a valid CVSS vector string", "error");
      return;
    }
    onAddCvss(vectorString.trim());
    onCancel();
  };

  return (
    <div className="bg-sfl-dark p-3 rounded-lg mt-2 space-y-3">
      <h3 className="text-lg font-semibold text-white">Custom CVSS</h3>
      <p className="text-sm text-gray-400">
        You can enter a custom CVSS vector to assess the vulnerability with your own parameters. 
        You can use an online CVSS calculator to help you generate the vector.
      </p>

      {variants && variants.length > 0 && selectedVariantIds && onSelectedVariantIdsChange && (
        <div className="mt-2 mb-1">
          <p className="text-sm font-medium text-gray-300 mb-1">Select variants:</p>
          <div className="flex flex-wrap gap-x-4 gap-y-1">
            {variants.map(v => (
              <label key={v.id} className="flex items-center gap-1.5 text-sm cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={selectedVariantIds.includes(v.id)}
                  onChange={(e) => {
                    if (e.target.checked) {
                      onSelectedVariantIdsChange([...selectedVariantIds, v.id]);
                    } else {
                      onSelectedVariantIdsChange(selectedVariantIds.filter(id => id !== v.id));
                    }
                  }}
                  className="accent-blue-500"
                />
                <span className="text-gray-200">{v.name}</span>
              </label>
            ))}
          </div>
        </div>
      )}

      <div>
        <label className="block text-sm text-gray-300 mb-1">Vector String</label>
        <input
          type="text"
          value={vectorString}
          onChange={(e) => setVectorString(e.target.value)}
          className="w-full p-2 rounded bg-gray-700 text-white"
          placeholder="e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        />
      </div>

      <div className="flex space-x-2 pt-2">
        <button
          onClick={handleAdd}
          className="px-3 py-1 rounded-lg bg-blue-600 hover:bg-blue-700 text-white"
        >
          Add
        </button>
        <button
          onClick={onCancel}
          className="px-3 py-1 rounded-lg bg-slate-600 hover:bg-slate-700 text-white"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

export default CustomCvss;

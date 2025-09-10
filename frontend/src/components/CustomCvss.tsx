import { useState } from "react";

type Props = {
  onCancel: () => void;
  onAddCvss: (vector: string) => void;
};

function CustomCvss({ onCancel, onAddCvss }: Props) {
  const [vectorString, setVectorString] = useState("");

  const handleAdd = () => {
    if (!vectorString.trim()) {
      alert("Please provide a valid CVSS vector string");
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

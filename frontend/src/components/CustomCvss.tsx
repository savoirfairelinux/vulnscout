import { useState } from "react";
import type { CVSS } from "../handlers/vulnerabilities";

type Props = {
  onCancel: () => void;
  onAddCvss: (cvss: CVSS) => void;};

function CustomCvss({ onCancel, onAddCvss }: Props) {
  const [version, setVersion] = useState("3.1");
  const [baseScore, setBaseScore] = useState<number | "">("");
  const [author, setAuthor] = useState("custom");
  const [vectorString, setVectorString] = useState("");

  const handleAdd = () => {
    if (baseScore === "" || isNaN(Number(baseScore))) {
      alert("Please provide a valid base score between 0.0 and 10.0");
      return;
    }

    const cvss: CVSS = {
      version,
      base_score: Number(baseScore),
      author,
      vector_string: vectorString || `CVSS:${version} (manual)`
    };

    onAddCvss(cvss);
  };

  return (
    <div className="bg-sfl-dark p-3 rounded-lg mt-2 space-y-3">
        <h3 className="text-lg font-semibold text-white">Custom CVSS</h3>
        <p className="text-sm text-gray-400">
            You can enter a custom CVSS vector to assess the vulnerability with your own parameters. 
            You can use an online CVSS calculator to help you generate the vector.
        </p>


      <div>
        <label className="block text-sm text-gray-300 mb-1">Version</label>
        <input
          type="text"
          value={version}
          onChange={(e) => setVersion(e.target.value)}
          className="w-full p-2 rounded bg-gray-700 text-white"
          placeholder="e.g., 3.1"
        />
      </div>

      <div>
        <label className="block text-sm text-gray-300 mb-1">Base Score (0.0–10.0)</label>
        <input
          type="number"
          step="0.1"
          min="0"
          max="10"
          value={baseScore}
          onChange={(e) => setBaseScore(e.target.value === "" ? "" : Number(e.target.value))}
          className="w-full p-2 rounded bg-gray-700 text-white"
          placeholder="e.g., 7.5"
        />
      </div>

      <div>
        <label className="block text-sm text-gray-300 mb-1">Author</label>
        <input
          type="text"
          value={author}
          onChange={(e) => setAuthor(e.target.value)}
          className="w-full p-2 rounded bg-gray-700 text-white"
          placeholder="e.g., Analyst Name"
        />
      </div>

      <div>
        <label className="block text-sm text-gray-300 mb-1">Vector String (optional)</label>
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

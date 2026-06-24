"use client";

import { useState, useEffect } from "react";
import Link from "next/link";

const API_URL = "http://127.0.0.1:8000";

const SAMPLE = "A phishing campaign targets finance users. Domain: secure-login-update.com, IP: 185.199.108.153, Exploited Vulnerability: CVE-2023-3519, Goal: Credential Theft";

type Any = Record<string, any>;

export default function Dashboard() {
  const [content, setContent] = useState("");
  const [inputType, setInputType] = useState("text");
  const [options, setOptions] = useState({ mitre: true, risk: true, sigma: true });
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState<Any[]>([]);
  const [error, setError] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  useEffect(() => {
    fetchHistory();
  }, []);

  async function fetchHistory() {
    try {
      const res = await fetch(`${API_URL}/api/analyses`);
      if (res.ok) {
        const data = await res.json();
        setHistory(data.analyses || []);
      }
    } catch (error) {
      console.error("Error fetching analysis history:", error);
    }
  }

  async function analyze() {
    setLoading(true);
    setError("");
    try {
      const res = await fetch(`${API_URL}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          input_type: inputType,
          content: content || SAMPLE,
          options: {
            mitre_mapping: options.mitre,
            generate_rules: options.sigma,
            risk_scoring: options.risk,
          },
        }),
      });
      if (!res.ok) throw new Error("Failed");
      const data = await res.json();
      window.location.href = `/analysis/${data.analysis_id}`;
    } catch {
      setError("Analysis failed. Check backend.");
      setLoading(false);
    }
  }

  async function uploadFile() {
  if (!selectedFile) {
    setError("Please select a file first.");
    return;
  }

  setLoading(true);
  setError("");

  try {
    const formData = new FormData();
    formData.append("file", selectedFile);

    const res = await fetch(`${API_URL}/api/analyze/upload`, {
      method: "POST",
      body: formData,
    });

    if (!res.ok) {
      throw new Error("Upload failed");
    }

    const data = await res.json();

    window.location.href = `/analysis/${data.analysis_id}`;
  } catch {
    setError("File upload failed. Check backend.");
  } finally {
    setLoading(false);
  }
  }

  function timeAgo(timestamp: string) {
    const diff = Date.now() - new Date(timestamp).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 60) return `${mins}m ago`;
    return `${Math.floor(mins / 60)}h ago`;
  }

  const levelColor = (level: string) => {
    const map: Record<string, string> = {
      critical: "#ef4444",
      high: "#f97316",
      medium: "#eab308",
      low: "#22c55e",
    };
    return map[level?.toLowerCase()] || "#6b7280";
  };

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-gray-100">
      {/* Header */}
      <header className="border-b border-gray-800 px-8 py-5">
    <div>
        <h1 className="text-2xl font-bold tracking-wider text-white">
            THREAT INTELLIGENCE PLATFORM
        </h1>

        <p className="text-sm text-gray-400 mt-1 tracking-wide">
            AI-Powered Threat Detection • IOC Extraction • MITRE ATT&amp;CK Mapping
        </p>
    </div>
</header>

      <main className="max-w-6xl mx-auto px-8 py-8">
        {/* Input Panel */}
        <div className="border border-gray-700 rounded-lg bg-[#111118] p-6 mb-8">
          <h2 className="text-xl font-semibold mb-4">ANALYZE A THREAT</h2>

          {/* Input Type Tabs */}
          <div className="flex gap-2 mb-4">
            {["Text", "CVE", "URL", "File Upload"].map((type) => (
              <button
                key={type}
                onClick={() => setInputType(type.toLowerCase().replace(" ", "_"))}
                className={`px-4 py-2 rounded text-sm font-medium transition-colors ${
                  inputType === type.toLowerCase().replace(" ", "_")
                    ? "bg-blue-600 text-white"
                    : "bg-gray-800 text-gray-400 hover:text-white"
                }`}
              >
                {type}
              </button>
            ))}
          </div>

          {/* Textarea */}
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder={inputType === "text" ? "Paste threat report, enter CVE ID, or describe the threat here..." : `Enter ${inputType}...`}
            className="w-full h-32 bg-[#0a0a0f] border border-gray-700 rounded-lg p-4 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-blue-500 resize-none mb-4"
          />

          {/* Options */}
          <div className="flex gap-6 mb-4 text-sm">
            {[
              { key: "mitre", label: "MITRE Mapping" },
              { key: "risk", label: "Risk Score" },
              { key: "sigma", label: "Sigma Rules" },
            ].map((opt) => (
              <label key={opt.key} className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={options[opt.key as keyof typeof options]}
                  onChange={(e) => setOptions({ ...options, [opt.key]: e.target.checked })}
                  className="w-4 h-4 rounded border-gray-600 bg-gray-800 text-blue-600"
                />
                <span className="text-gray-300">{opt.label}</span>
              </label>
            ))}
          </div>

          {/* Buttons */}
          <div className="flex flex-wrap gap-4 items-center">
  <button
    onClick={analyze}
    disabled={loading}
    className="bg-blue-600 hover:bg-blue-500 text-white font-semibold px-6 py-3 rounded-lg disabled:opacity-50"
  >
    {loading ? "Analyzing..." : "ANALYZE THREAT"}
  </button>

  <label className="bg-gray-800 hover:bg-gray-700 text-gray-300 font-semibold px-6 py-3 rounded-lg cursor-pointer">
    Choose File
    <input
      type="file"
      accept=".txt,.pdf,.docx,.csv,.json"
      className="hidden"
      onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
    />
  </label>

  <button
    onClick={uploadFile}
    disabled={loading || !selectedFile}
    className="bg-gray-800 hover:bg-gray-700 text-gray-300 font-semibold px-6 py-3 rounded-lg disabled:opacity-50"
  >
    Upload File
  </button>

  {selectedFile && (
    <span className="text-sm text-gray-400">
      Selected: {selectedFile.name}
    </span>
  )}
</div>

          {error && <div className="mt-4 text-red-400 text-sm">{error}</div>}
        </div>

        {/* Recent Analyses */}
        <div className="border border-gray-700 rounded-lg bg-[#111118] overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-700 bg-[#16161f]">
            <h2 className="text-sm font-semibold text-gray-400">Recent Analyses</h2>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700 text-gray-500 text-left">
                <th className="px-6 py-3 font-medium">ID</th>
                <th className="px-6 py-3 font-medium">Input</th>
                <th className="px-6 py-3 font-medium">Risk</th>
                <th className="px-6 py-3 font-medium">Level</th>
                <th className="px-6 py-3 font-medium">Time</th>
              </tr>
            </thead>
            <tbody>
              {history.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-6 py-8 text-center text-gray-600">
                    No analyses yet. Run your first analysis above.
                  </td>
                </tr>
              )}
              {history.map((item: Any) => (
                <tr key={item.analysis_id} className="border-b border-gray-800 hover:bg-[#16161f] transition-colors">
                  <td className="px-6 py-3 font-mono text-blue-400">
                    <Link href={`/analysis/${item.analysis_id}`} className="hover:underline">
                      {item.analysis_id}
                    </Link>
                  </td>
                  <td className="px-6 py-3 text-gray-300 max-w-xs truncate">
                    {item.input_preview || "Analysis"}
                  </td>
                  <td className="px-6 py-3 font-mono">{item.risk_score}</td>
                  <td className="px-6 py-3">
                    <span
                      className="px-2 py-1 rounded text-xs font-bold uppercase"
                      style={{
                        color: levelColor(item.risk_level),
                        background: `${levelColor(item.risk_level)}20`,
                      }}
                    >
                      {item.risk_level}
                    </span>
                  </td>
                  <td className="px-6 py-3 text-gray-500">{timeAgo(item.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </main>
    </div>
  );
}
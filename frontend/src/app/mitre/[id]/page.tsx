"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";

const API_URL = "https://threat-intel-platform-cwgw.onrender.com";

type Any = Record<string, any>;

export default function MitreMatrix() {
  const { id } = useParams();
  const [result, setResult] = useState<Any | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedTechnique, setSelectedTechnique] = useState<Any | null>(null);

  useEffect(() => {
    if (id) fetchAnalysis();
  }, [id]);

  async function fetchAnalysis() {
    try {
      const res = await fetch(`${API_URL}/api/analyses/${id}`);
      if (res.ok) setResult(await res.json());
    } catch {}
    setLoading(false);
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

  if (loading) return (
    <div className="min-h-screen bg-[#0a0a0f] flex items-center justify-center text-gray-400">
      Loading...
    </div>
  );

  if (!result) return (
    <div className="min-h-screen bg-[#0a0a0f] flex items-center justify-center text-gray-400">
      Analysis not found
    </div>
  );

  const attackChain = result.mitre_mapping || [];

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-gray-100">
      {/* Header */}
      <header className="border-b border-gray-800 px-8 py-4 flex items-center gap-4">
        <Link href={`/analysis/${id}`} className="text-blue-400 hover:text-blue-300 text-sm">
          ← Back
        </Link>
        <span className="text-gray-500">|</span>
        <span className="text-sm font-semibold">MITRE ATT&CK Mapping</span>
        <span className="text-gray-500">|</span>
        <span className="font-mono text-sm">{result.analysis_id}</span>
      </header>

      <main className="max-w-6xl mx-auto px-8 py-8">
        {/* Attack Chain Visualization */}
        <div className="border border-gray-700 rounded-lg bg-[#111118] p-6 mb-6">
          <h2 className="text-sm font-semibold text-gray-400 mb-6">Attack Chain Visualization</h2>
          <div className="flex items-start gap-2 overflow-x-auto pb-4">
            {attackChain.map((item: Any, i: number) => (
              <div key={i} className="flex items-center gap-2">
                <div className="border border-gray-600 rounded-lg p-4 bg-[#0a0a0f] min-w-[160px] text-center">
                  <div className="text-xs text-gray-500 uppercase mb-2">{item.tactic}</div>
                  <div className="text-sm font-medium mb-1">{item.technique}</div>
                  <div className="text-xs font-mono text-blue-400">{item.technique_id}</div>
                </div>
                {i < attackChain.length - 1 && (
                  <div className="text-gray-600 text-2xl pt-4">→</div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Technique Detail Table */}
        <div className="border border-gray-700 rounded-lg bg-[#111118] overflow-hidden mb-6">
          <div className="px-6 py-4 border-b border-gray-700 bg-[#16161f]">
            <h2 className="text-sm font-semibold text-gray-400">Technique Detail (click to expand)</h2>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700 text-gray-500 text-left">
                <th className="px-6 py-3 font-medium">TACTIC</th>
                <th className="px-6 py-3 font-medium">TECHNIQUE</th>
                <th className="px-6 py-3 font-medium">ID</th>
                <th className="px-6 py-3 font-medium">CONF</th>
              </tr>
            </thead>
            <tbody>
              {attackChain.map((item: Any, i: number) => (
                <tr
                  key={i}
                  className="border-b border-gray-800 hover:bg-[#16161f] cursor-pointer transition-colors"
                  onClick={() => setSelectedTechnique(
                    selectedTechnique?.technique_id === item.technique_id ? null : item
                  )}
                >
                  <td className="px-6 py-3">{item.tactic}</td>
                  <td className="px-6 py-3">{item.technique}</td>
                  <td className="px-6 py-3 font-mono text-blue-400">{item.technique_id}</td>
                  <td className="px-6 py-3">
                    <span
                      className="px-2 py-1 rounded text-xs font-bold uppercase"
                      style={{
                        color: levelColor(item.confidence >= 50 ? "high" : "medium"),
                        background: `${levelColor(item.confidence >= 50 ? "high" : "medium")}20`,
                      }}
                    >
                      {item.confidence >= 50 ? "HIGH" : "MED"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Expanded Technique Detail */}
        {selectedTechnique && (
          <div className="border border-gray-700 rounded-lg bg-[#111118] p-6 mb-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-gray-400">
                {selectedTechnique.technique} — {selectedTechnique.technique_id}
              </h2>
              <button
                onClick={() => setSelectedTechnique(null)}
                className="text-gray-500 hover:text-gray-300 text-sm"
              >
                Close
              </button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-sm">
              <div>
                <h3 className="text-xs font-bold text-gray-500 uppercase mb-2">Description</h3>
                <p className="text-gray-300 leading-relaxed">
                  {selectedTechnique.description || "Adversaries may use phishing messages to gain access to victim systems. This is a commonly used and highly effective technique for initial access."}
                </p>
              </div>
              <div>
                <h3 className="text-xs font-bold text-gray-500 uppercase mb-2">Detection Opportunities</h3>
                <p className="text-gray-300 leading-relaxed">
                  Monitor for suspicious email attachments, URLs, and network traffic. Implement email filtering and user awareness training to reduce success rate.
                </p>
              </div>
              <div>
                <h3 className="text-xs font-bold text-gray-500 uppercase mb-2">Mitigation Recommendations</h3>
                <p className="text-gray-300 leading-relaxed">
                  Implement multi-factor authentication, email authentication protocols (SPF, DKIM, DMARC), and conduct regular security awareness training.
                </p>
              </div>
              <div>
                <h3 className="text-xs font-bold text-gray-500 uppercase mb-2">Related IOCs from this analysis</h3>
                <div className="space-y-1">
                  {result.iocs?.slice(0, 3).map((ioc: Any, i: number) => (
                    <div key={i} className="font-mono text-xs text-gray-400">{ioc.value}</div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Click hint */}
        {!selectedTechnique && (
          <div className="text-center text-gray-600 text-sm py-4">
            Click a technique in the table above for: Description, Detection opportunities, Mitigation recommendations, Related IOCs
          </div>
        )}
      </main>
    </div>
  );
}
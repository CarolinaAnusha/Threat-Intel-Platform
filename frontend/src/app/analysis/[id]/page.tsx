"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";

const API_URL = "https://threat-intel-platform-cwgw.onrender.com";

type Any = Record<string, any>;

export default function AnalysisResult() {
  const { id } = useParams();
  const [result, setResult] = useState<Any | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeRule, setActiveRule] = useState("sigma");
  const [copied, setCopied] = useState(false);

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

  async function copy(text: string) {
  await navigator.clipboard.writeText(text);

  setCopied(true);

  setTimeout(() => {
    setCopied(false);
  }, 2000);
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

  if (loading) return <div className="min-h-screen bg-[#0a0a0f] flex items-center justify-center text-gray-400">Loading...</div>;
  if (!result) return <div className="min-h-screen bg-[#0a0a0f] flex items-center justify-center text-gray-400">Analysis not found</div>;

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-gray-100">
      {/* Header */}
      <header className="border-b border-gray-800 px-8 py-4 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link href="/dashboard" className="text-blue-400 hover:text-blue-300 text-sm">← Back</Link>
          <span className="text-gray-500">|</span>
          <span className="font-mono text-lg">{result.analysis_id}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-gray-400">Risk:</span>
          <span className="font-mono text-xl font-bold">{result.risk_score}/100</span>
          <span
            className="px-2 py-1 rounded text-xs font-bold uppercase"
            style={{
              color: levelColor(result.risk_level),
              background: `${levelColor(result.risk_level)}20`,
            }}
          >
            {result.risk_level}
          </span>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-8 py-8">
        {/* Top Row: Risk Gauge + Risk Factors */}
        <div className="grid grid-cols-2 gap-6 mb-6">
          {/* Risk Score Gauge */}
          <div className="border border-gray-700 rounded-lg bg-[#111118] p-6 flex flex-col items-center justify-center">
            <h2 className="text-sm font-semibold text-gray-400 mb-4">RISK SCORE</h2>
            <div className="relative w-40 h-40 flex items-center justify-center">
              <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                <circle cx="50" cy="50" r="42" fill="none" stroke="#1a1a2e" strokeWidth="8" />
                <circle
                  cx="50"
                  cy="50"
                  r="42"
                  fill="none"
                  stroke={levelColor(result.risk_level)}
                  strokeWidth="8"
                  strokeDasharray={`${(result.risk_score / 100) * 264} 264`}
                  strokeLinecap="round"
                />
              </svg>
              <div className="absolute text-center">
                <div className="text-4xl font-bold">{result.risk_score}</div>
                <div className="text-sm uppercase font-bold" style={{ color: levelColor(result.risk_level) }}>
                  {result.risk_level}
                </div>
              </div>
            </div>
          </div>

          {/* Risk Factors */}
          <div className="border border-gray-700 rounded-lg bg-[#111118] p-6">
            <h2 className="text-sm font-semibold text-gray-400 mb-4">RISK FACTORS</h2>
            <div className="space-y-3">
              {result.risk_factors?.map((factor: Any, i: number) => (
                <div key={i}>
                  <div className="flex justify-between text-sm mb-1">
                    <span>{factor.factor}</span>
                    <span className="text-gray-400">{factor.score}</span>
                  </div>
                  <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{
                        width: `${Math.min((factor.score / 30) * 100, 100)}%`,
                        background: levelColor(result.risk_level),
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* IOCs */}
        <div className="border border-gray-700 rounded-lg bg-[#111118] overflow-hidden mb-6">
          <div className="px-6 py-4 border-b border-gray-700 bg-[#16161f]">
            <h2 className="text-sm font-semibold text-gray-400">EXTRACTED IOCs</h2>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700 text-gray-500 text-left">
                <th className="px-6 py-3 font-medium">Type</th>
                <th className="px-6 py-3 font-medium">Value</th>
                <th className="px-6 py-3 font-medium">Reputation</th>
                <th className="px-6 py-3 font-medium">Enriched</th>
              </tr>
            </thead>
            <tbody>
              {result.iocs?.map((ioc: Any, i: number) => (
                <tr key={i} className="border-b border-gray-800">
                  <td className="px-6 py-3">
                    <span className="px-2 py-1 rounded bg-gray-800 text-xs">{ioc.type}</span>
                  </td>
                  <td className="px-6 py-3 font-mono">{ioc.value}</td>
                  <td className="px-6 py-3">
                    <span
                      className="px-2 py-1 rounded text-xs font-bold uppercase"
                      style={{
                        color: levelColor(ioc.reputation || "suspicious"),
                        background: `${levelColor(ioc.reputation || "suspicious")}20`,
                      }}
                    >
                      {ioc.reputation || "suspicious"}
                    </span>
                  </td>
                  <td className="px-6 py-3 text-green-400">Yes</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* MITRE Mapping */}
        <div className="border border-gray-700 rounded-lg bg-[#111118] p-6 mb-6">
          <h2 className="text-sm font-semibold text-gray-400 mb-4">MITRE ATT&CK MAPPING</h2>
          <div className="flex gap-4 items-start">
            {result.mitre_mapping?.map((item: Any, i: number) => (
              <div key={i} className="flex items-center gap-4">
                <div className="border border-gray-600 rounded-lg p-4 bg-[#0a0a0f] min-w-[180px]">
                  <div className="text-xs text-gray-500 uppercase mb-1">{item.tactic}</div>
                  <div className="text-sm font-medium mb-1">{item.technique}</div>
                  <div className="text-xs font-mono text-blue-400">{item.technique_id}</div>
                </div>
                {i < result.mitre_mapping.length - 1 && (
                  <div className="text-gray-600 text-2xl">→</div>
                )}
              </div>
            ))}
          </div>
          <div className="mt-4">
            <Link href={`/mitre/${result.analysis_id}`} className="text-blue-400 hover:text-blue-300 text-sm">
              View full MITRE matrix →
            </Link>
          </div>
        </div>

        {/* AI Report */}
        <div className="border border-gray-700 rounded-lg bg-[#111118] p-6 mb-6">
          <h2 className="text-sm font-semibold text-gray-400 mb-4">AI THREAT INTELLIGENCE</h2>
          
        <div className="mb-6">
            <h3 className="text-xs font-bold text-gray-500 uppercase mb-2">AI ANALYST ASSESSMENT</h3>
            <p className="text-gray-300 leading-relaxed">
                {result.ai_report?.analyst_assessment}
            </p>
        </div>

          <div className="mb-6">
            <h3 className="text-xs font-bold text-gray-500 uppercase mb-2">SUMMARY</h3>
            <p className="text-gray-300 leading-relaxed">{result.ai_report?.summary}</p>
          </div>

          <div className="mb-6">
            <h3 className="text-xs font-bold text-gray-500 uppercase mb-2">ATTACK SCENARIO</h3>
            <p className="text-gray-300 leading-relaxed">{result.ai_report?.attack_scenario}</p>
          </div>

          <div className="mb-6">
            <h3 className="text-xs font-bold text-gray-500 uppercase mb-2">BUSINESS IMPACT</h3>
            <p className="text-gray-300 leading-relaxed">{result.ai_report?.business_impact}</p>
          </div>

          <div className="grid grid-cols-2 gap-6">
            <div>
              <h3 className="text-xs font-bold text-gray-500 uppercase mb-2">IMMEDIATE ACTIONS</h3>
              <ol className="list-decimal list-inside space-y-1 text-gray-300">
                {result.ai_report?.immediate_actions?.map((item: string, i: number) => (
                  <li key={i}>{item}</li>
                ))}
              </ol>
            </div>
            <div>
              <h3 className="text-xs font-bold text-gray-500 uppercase mb-2">LONG-TERM REMEDIATION</h3>
              <ol className="list-decimal list-inside space-y-1 text-gray-300">
                {result.ai_report?.long_term_remediation?.map((item: string, i: number) => (
                  <li key={i}>{item}</li>
                ))}
              </ol>
            </div>
          </div>
        </div>

        {/* Detection Rules */}
        <div className="border border-gray-700 rounded-lg bg-[#111118] p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-gray-400">DETECTION RULES</h2>
            <button
  onClick={() =>
    copy(
      typeof result.detection_rules?.[activeRule] === "string"
        ? result.detection_rules[activeRule]
        : JSON.stringify(result.detection_rules?.[activeRule], null, 2)
    )
  }
  className={`px-4 py-2 rounded text-sm transition-all ${
    copied
      ? "bg-green-600 text-white"
      : "bg-gray-800 hover:bg-gray-700 text-gray-300"
  }`}
>
  {copied ? "✓ Copied!" : "Copy to Clipboard"}
</button>
          </div>

          <div className="flex gap-2 mb-4">
            {["sigma", "yara", "splunk"].map((rule) => (
              <button
                key={rule}
                onClick={() => setActiveRule(rule)}
                className={`px-4 py-2 rounded text-sm font-medium ${
                  activeRule === rule
                    ? "bg-blue-600 text-white"
                    : "bg-gray-800 text-gray-400 hover:text-white"
                }`}
              >
                {rule === "sigma" ? "Sigma" : rule === "yara" ? "YARA" : "Splunk"}
              </button>
            ))}
          </div>

          <pre className="bg-[#0a0a0f] border border-gray-800 rounded-lg p-4 text-sm font-mono text-gray-400 overflow-x-auto max-h-[400px]">
            {typeof result.detection_rules?.[activeRule] === "string"
              ? result.detection_rules[activeRule]
              : JSON.stringify(result.detection_rules?.[activeRule], null, 2)}
          </pre>
        </div>
      </main>
    </div>
  );
}
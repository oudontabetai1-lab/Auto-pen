"use client";

import type { FindingRead, Severity } from "@/lib/types";
import { useState } from "react";

const SEV_ORDER: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

const SEV_STYLE: Record<Severity, string> = {
  critical: "bg-red-600 text-white",
  high:     "bg-orange-500 text-white",
  medium:   "bg-yellow-400 text-gray-900",
  low:      "bg-blue-400 text-white",
  info:     "bg-gray-200 text-gray-700",
};

const SEV_EMOJI: Record<Severity, string> = {
  critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", info: "⚪",
};

export function FindingsTable({ findings }: { findings: FindingRead[] }) {
  const [filter, setFilter] = useState<Severity | "all">("all");
  const [expanded, setExpanded] = useState<string | null>(null);

  const sorted = [...findings].sort(
    (a, b) => (SEV_ORDER[a.severity as Severity] ?? 99) - (SEV_ORDER[b.severity as Severity] ?? 99)
  );
  const filtered = filter === "all" ? sorted : sorted.filter((f) => f.severity === filter);

  const counts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});

  if (findings.length === 0) {
    return (
      <div className="text-center text-gray-400 py-12 text-sm">
        No findings recorded yet.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Summary chips */}
      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => setFilter("all")}
          className={`text-xs px-3 py-1 rounded-full border transition-colors ${filter === "all" ? "bg-gray-900 text-white" : "text-gray-600 hover:bg-gray-100"}`}
        >
          All ({findings.length})
        </button>
        {(["critical", "high", "medium", "low", "info"] as Severity[]).map((s) =>
          counts[s] ? (
            <button
              key={s}
              onClick={() => setFilter(s)}
              className={`text-xs px-3 py-1 rounded-full border transition-colors ${filter === s ? "border-gray-900 font-semibold" : "text-gray-600 hover:bg-gray-100"}`}
            >
              {SEV_EMOJI[s]} {s.toUpperCase()} ({counts[s]})
            </button>
          ) : null
        )}
      </div>

      {/* Table */}
      <div className="space-y-2">
        {filtered.map((f) => (
          <div key={f.id} className="border border-gray-200 rounded-lg overflow-hidden bg-white">
            <button
              className="w-full text-left px-4 py-3 flex items-center gap-3 hover:bg-gray-50 transition-colors"
              onClick={() => setExpanded(expanded === f.id ? null : f.id)}
            >
              <span className={`text-xs px-2 py-0.5 rounded font-bold ${SEV_STYLE[f.severity as Severity]}`}>
                {f.severity.toUpperCase()}
              </span>
              <span className="flex-1 font-medium text-gray-900 text-sm">{f.title}</span>
              <span className="text-xs text-gray-400">{f.tool_name}</span>
              {f.cvss_score !== null && (
                <span className="text-xs font-mono text-gray-500">CVSS {f.cvss_score}</span>
              )}
              <span className="text-gray-400">{expanded === f.id ? "▲" : "▼"}</span>
            </button>

            {expanded === f.id && (
              <div className="px-4 pb-4 space-y-3 border-t border-gray-100">
                <div className="text-xs text-gray-500 flex gap-4 mt-3">
                  <span>Target: <span className="font-mono text-gray-700">{f.target}</span></span>
                  <span>{new Date(f.timestamp).toLocaleString()}</span>
                </div>

                <div>
                  <p className="text-xs font-semibold text-gray-500 uppercase mb-1">Description</p>
                  <p className="text-sm text-gray-700">{f.description}</p>
                </div>

                {f.evidence && (
                  <div>
                    <p className="text-xs font-semibold text-gray-500 uppercase mb-1">Evidence</p>
                    <pre className="text-xs bg-gray-50 rounded p-3 overflow-x-auto whitespace-pre-wrap">
                      {f.evidence.slice(0, 1000)}
                    </pre>
                  </div>
                )}

                {f.remediation && (
                  <div>
                    <p className="text-xs font-semibold text-gray-500 uppercase mb-1">Remediation</p>
                    <p className="text-sm text-green-800 bg-green-50 rounded p-3">{f.remediation}</p>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

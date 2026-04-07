"use client";

import { useEffect, useState } from "react";
import { listTools } from "@/lib/api";
import type { ToolInfo } from "@/lib/types";

const RISK_STYLE: Record<string, string> = {
  low:      "bg-green-100 text-green-700",
  medium:   "bg-yellow-100 text-yellow-700",
  high:     "bg-red-100 text-red-700",
  critical: "bg-red-200 text-red-800 font-bold",
};

export default function ToolsPage() {
  const [tools, setTools] = useState<ToolInfo[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    listTools()
      .then(setTools)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Security Tools</h1>

      {loading ? (
        <div className="text-gray-400 text-sm text-center py-12">Loading…</div>
      ) : (
        <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-4 py-3 font-medium text-gray-500">Tool</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500">Risk</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500">Status</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500">Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {tools.map((t) => (
                <tr key={t.name} className="hover:bg-gray-50 transition-colors">
                  <td className="px-4 py-3 font-mono font-medium text-gray-900">{t.name}</td>
                  <td className="px-4 py-3">
                    <span className={`text-xs px-2 py-0.5 rounded-full ${RISK_STYLE[t.risk_level] ?? ""}`}>
                      {t.risk_level.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {t.available ? (
                      <span className="text-xs text-green-700 font-medium">✓ installed</span>
                    ) : (
                      <span className="text-xs text-gray-400">✗ not found</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-gray-600 text-xs">{t.description.slice(0, 100)}…</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

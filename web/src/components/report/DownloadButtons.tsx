"use client";

import { getReport } from "@/lib/api";
import { useState } from "react";

export function DownloadButtons({ sessionId }: { sessionId: string }) {
  const [loading, setLoading] = useState<"markdown" | "json" | null>(null);

  const download = async (format: "markdown" | "json") => {
    setLoading(format);
    try {
      const content = await getReport(sessionId, format);
      const ext = format === "json" ? "json" : "md";
      const mime = format === "json" ? "application/json" : "text/markdown";
      const blob = new Blob([content], { type: mime });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `auto-pen-report-${sessionId.slice(0, 8)}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      alert(`Download failed: ${e}`);
    } finally {
      setLoading(null);
    }
  };

  return (
    <div className="flex gap-2">
      <button
        onClick={() => download("markdown")}
        disabled={!!loading}
        className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50 transition-colors"
      >
        {loading === "markdown" ? "..." : "⬇ Markdown"}
      </button>
      <button
        onClick={() => download("json")}
        disabled={!!loading}
        className="px-3 py-1.5 text-sm border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50 transition-colors"
      >
        {loading === "json" ? "..." : "⬇ JSON"}
      </button>
    </div>
  );
}

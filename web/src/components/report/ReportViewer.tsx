"use client";

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

export function ReportViewer({ markdown }: { markdown: string }) {
  if (!markdown) {
    return (
      <div className="text-center text-gray-400 py-12 text-sm">
        No report available yet.
      </div>
    );
  }

  return (
    <div className="prose prose-sm max-w-none prose-headings:font-bold prose-code:text-xs">
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{markdown}</ReactMarkdown>
    </div>
  );
}

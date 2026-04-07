"use client";

import { use, useEffect, useState } from "react";
import { getSession, listFindings, getReport, stopSession } from "@/lib/api";
import { useSessionWebSocket } from "@/hooks/useSessionWebSocket";
import { LogStream } from "@/components/logs/LogStream";
import { ApprovalDialog } from "@/components/confirmation/ApprovalDialog";
import { FindingsTable } from "@/components/findings/FindingsTable";
import { ReportViewer } from "@/components/report/ReportViewer";
import { DownloadButtons } from "@/components/report/DownloadButtons";
import type { FindingRead, SessionRead } from "@/lib/types";

type Tab = "logs" | "findings" | "report";

const STATUS_DOT: Record<string, string> = {
  running:   "bg-blue-500 animate-pulse",
  completed: "bg-green-500",
  failed:    "bg-red-500",
  paused:    "bg-yellow-400",
  pending:   "bg-gray-400",
};

export default function SessionDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const [session, setSession] = useState<SessionRead | null>(null);
  const [tab, setTab] = useState<Tab>("logs");
  const [findings, setFindings] = useState<FindingRead[]>([]);
  const [report, setReport] = useState("");
  const [loadingReport, setLoadingReport] = useState(false);
  const [stopping, setStopping] = useState(false);

  // Load session metadata
  useEffect(() => {
    getSession(id).then(setSession).catch(console.error);
  }, [id]);

  // WebSocket connection
  const { logs, status, pendingConfirmation, isConnected, approve, deny } =
    useSessionWebSocket(id, session?.status ?? "pending");

  // Refresh findings when tab changes or finding_discovered events come in
  useEffect(() => {
    if (tab === "findings") {
      listFindings(id).then(setFindings).catch(console.error);
    }
  }, [id, tab, logs.filter((l) => l.type === "finding_discovered").length]);

  // Load report lazily
  useEffect(() => {
    if (tab === "report" && !report) {
      setLoadingReport(true);
      getReport(id, "markdown")
        .then(setReport)
        .catch(console.error)
        .finally(() => setLoadingReport(false));
    }
  }, [tab, id, report]);

  const handleStop = async () => {
    setStopping(true);
    try {
      await stopSession(id);
    } finally {
      setStopping(false);
    }
  };

  const dotStyle = STATUS_DOT[status] ?? "bg-gray-400";

  return (
    <div className="space-y-4">
      {/* Approval dialog (rendered over everything) */}
      {pendingConfirmation && (
        <ApprovalDialog
          confirmation={pendingConfirmation}
          onApprove={approve}
          onDeny={deny}
        />
      )}

      {/* Header */}
      <div className="bg-white border border-gray-200 rounded-xl px-5 py-4 flex items-center gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${dotStyle}`} />
            <p className="font-mono text-xs text-gray-400">{id.slice(0, 8)}</p>
            <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
              isConnected ? "bg-green-50 text-green-700" : "bg-gray-100 text-gray-500"
            }`}>
              {isConnected ? "WS connected" : "WS disconnected"}
            </span>
          </div>
          <p className="font-semibold text-gray-900 text-lg mt-0.5 truncate">
            {session?.target ?? "…"}
          </p>
          <p className="text-sm text-gray-500">
            {session?.profile.toUpperCase()} · {session?.llm_provider}/{session?.llm_model}
          </p>
        </div>

        {status === "running" && (
          <button
            onClick={handleStop}
            disabled={stopping}
            className="shrink-0 px-3 py-1.5 border border-red-300 text-red-600 text-sm rounded-lg hover:bg-red-50 transition-colors disabled:opacity-50"
          >
            {stopping ? "Stopping…" : "■ Stop"}
          </button>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-gray-100 rounded-lg p-1 w-fit">
        {(["logs", "findings", "report"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
              tab === t ? "bg-white shadow text-gray-900" : "text-gray-500 hover:text-gray-700"
            }`}
          >
            {t === "logs" && "📋 Logs"}
            {t === "findings" && `🚨 Findings (${findings.length})`}
            {t === "report" && "📄 Report"}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
        {tab === "logs" && (
          <div className="h-[70vh]">
            <LogStream logs={logs} />
          </div>
        )}

        {tab === "findings" && (
          <div className="p-5">
            <FindingsTable findings={findings} />
          </div>
        )}

        {tab === "report" && (
          <div className="p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-semibold text-gray-900">Penetration Test Report</h2>
              <DownloadButtons sessionId={id} />
            </div>
            {loadingReport ? (
              <div className="text-gray-400 text-sm text-center py-12">Loading report…</div>
            ) : (
              <ReportViewer markdown={report} />
            )}
          </div>
        )}
      </div>
    </div>
  );
}

import type { SessionRead } from "@/lib/types";
import Link from "next/link";

const STATUS_STYLES: Record<string, string> = {
  pending:    "bg-gray-100 text-gray-700",
  running:    "bg-blue-100 text-blue-700 animate-pulse",
  paused:     "bg-yellow-100 text-yellow-700",
  completed:  "bg-green-100 text-green-700",
  failed:     "bg-red-100 text-red-700",
  incomplete: "bg-purple-100 text-purple-700",
  timed_out:  "bg-orange-100 text-orange-700",
};

const TIME_FMT = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
});

export function SessionCard({ session }: { session: SessionRead }) {
  const style = STATUS_STYLES[session.status] ?? "bg-gray-100 text-gray-700";
  // Backend timestamps come from datetime.utcnow().isoformat() with no tz suffix.
  // Treat them as UTC so the displayed local time is correct.
  const isoUtc = session.created_at.endsWith("Z")
    ? session.created_at
    : `${session.created_at}Z`;
  const created = TIME_FMT.format(new Date(isoUtc));

  return (
    <Link href={`/sessions/${session.id}`}>
      <div className="border border-gray-200 rounded-lg p-4 hover:border-blue-400 hover:shadow-sm transition-all cursor-pointer bg-white">
        <div className="flex items-start justify-between gap-2">
          <div className="flex-1 min-w-0">
            <p className="font-mono text-sm text-gray-500">{session.id.slice(0, 8)}</p>
            <p className="font-semibold text-gray-900 truncate mt-0.5">{session.target}</p>
            <p className="text-sm text-gray-500 mt-1">
              {session.profile.toUpperCase()} · {session.llm_provider}/{session.llm_model}
            </p>
          </div>
          <span className={`text-xs px-2 py-1 rounded-full font-medium whitespace-nowrap ${style}`}>
            {session.status}
          </span>
        </div>
        <div className="mt-3 flex items-center gap-4 text-xs text-gray-500">
          <span>{session.step_count} steps</span>
          <span>{created}</span>
        </div>
      </div>
    </Link>
  );
}

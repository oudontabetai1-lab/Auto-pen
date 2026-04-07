"use client";

import Link from "next/link";
import { SessionCard } from "@/components/sessions/SessionCard";
import { useSessions } from "@/hooks/useSessions";

export default function SessionsPage() {
  const { sessions, loading, error } = useSessions(5000);

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Sessions</h1>
        <Link
          href="/sessions/new"
          className="bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
        >
          + New Scan
        </Link>
      </div>

      {loading && (
        <div className="text-gray-400 text-sm text-center py-12">Loading sessions…</div>
      )}

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm">
          Failed to connect to API server: {error}
        </div>
      )}

      {!loading && sessions.length === 0 && (
        <div className="text-center py-16 text-gray-400">
          <p className="text-4xl mb-3">🔍</p>
          <p className="text-lg font-medium text-gray-600">No sessions yet</p>
          <p className="text-sm mt-1">
            <Link href="/sessions/new" className="text-blue-600 hover:underline">
              Start your first penetration test
            </Link>
          </p>
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {sessions.map((s) => (
          <SessionCard key={s.id} session={s} />
        ))}
      </div>
    </div>
  );
}

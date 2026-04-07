"use client";

import { useCallback, useEffect, useState } from "react";
import { listSessions } from "@/lib/api";
import type { SessionRead } from "@/lib/types";

/**
 * Polls /api/v1/sessions every `intervalMs` ms (default 5 s).
 */
export function useSessions(intervalMs = 5000) {
  const [sessions, setSessions] = useState<SessionRead[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const data = await listSessions();
      setSessions(data);
      setError(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, intervalMs);
    return () => clearInterval(timer);
  }, [refresh, intervalMs]);

  return { sessions, loading, error, refresh };
}

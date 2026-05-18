"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { listSessions } from "@/lib/api";
import type { SessionRead } from "@/lib/types";

/**
 * Polls /api/v1/sessions every `intervalMs` ms (default 5 s).
 *
 * The polling timer depends only on `intervalMs`, so frequent re-renders of
 * the parent component don't tear down and re-arm the interval (which used to
 * cause a burst of duplicate requests on tab focus).
 */
export function useSessions(intervalMs = 5000) {
  const [sessions, setSessions] = useState<SessionRead[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Keep the latest "refresh" closure in a ref so the interval callback always
  // sees up-to-date state setters without forcing the effect to re-subscribe.
  const refreshRef = useRef<() => Promise<void>>(async () => {});

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

  refreshRef.current = refresh;

  useEffect(() => {
    refreshRef.current();
    const timer = setInterval(() => {
      refreshRef.current();
    }, intervalMs);
    return () => clearInterval(timer);
  }, [intervalMs]);

  return { sessions, loading, error, refresh };
}

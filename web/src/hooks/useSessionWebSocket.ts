"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { SessionWebSocket } from "@/lib/ws";
import { getSessionToken } from "@/lib/api";
import type {
  LogEntry,
  SessionStatus,
  WsConfirmationRequestPayload,
  WsServerMessage,
} from "@/lib/types";

let _idCounter = 0;
const nextId = () => String(++_idCounter);

export interface UseSessionWebSocketReturn {
  logs: LogEntry[];
  status: SessionStatus;
  pendingConfirmation: WsConfirmationRequestPayload | null;
  isConnected: boolean;
  approve: (requestId: string) => void;
  deny: (requestId: string) => void;
}

/**
 * Core hook: manages a WebSocket connection to a session and exposes:
 * - logs[]                  — chronological list of events
 * - status                  — live session status
 * - pendingConfirmation      — non-null when operator approval is required
 * - approve() / deny()       — send confirmation_response
 * - isConnected              — WebSocket connection state
 *
 * The connection is keyed solely on `sessionId`; we hold the message-handler
 * closure in a ref so that re-renders don't repeatedly tear it down.
 */
export function useSessionWebSocket(
  sessionId: string | null,
  initialStatus: SessionStatus = "pending"
): UseSessionWebSocketReturn {
  const wsRef = useRef<SessionWebSocket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [status, setStatus] = useState<SessionStatus>(initialStatus);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [pendingConfirmation, setPendingConfirmation] =
    useState<WsConfirmationRequestPayload | null>(null);

  const handleMessageRef = useRef<(msg: WsServerMessage) => void>(() => {});
  handleMessageRef.current = (msg: WsServerMessage) => {
    switch (msg.type) {
      case "session_status":
        setStatus(msg.payload.status);
        setLogs((prev) => [
          ...prev,
          { id: nextId(), timestamp: msg.timestamp, type: msg.type, payload: msg.payload },
        ]);
        break;

      case "log":
      case "tool_start":
      case "tool_complete":
      case "finding_discovered":
      case "error":
        setLogs((prev) => [
          ...prev,
          { id: nextId(), timestamp: msg.timestamp, type: msg.type, payload: msg.payload },
        ]);
        break;

      case "confirmation_request":
        setPendingConfirmation(msg.payload);
        setLogs((prev) => [
          ...prev,
          { id: nextId(), timestamp: msg.timestamp, type: msg.type, payload: msg.payload },
        ]);
        break;

      case "pong":
        break;
    }
  };

  useEffect(() => {
    if (!sessionId) return;

    const token = getSessionToken(sessionId);
    const ws = new SessionWebSocket(
      sessionId,
      (m) => handleMessageRef.current(m),
      setIsConnected,
      token
    );
    wsRef.current = ws;

    return () => {
      ws.close();
      wsRef.current = null;
    };
  }, [sessionId]);

  const approve = useCallback((requestId: string) => {
    wsRef.current?.send({
      type: "confirmation_response",
      payload: { request_id: requestId, approved: true },
    });
    setPendingConfirmation((cur) => (cur?.request_id === requestId ? null : cur));
  }, []);

  const deny = useCallback((requestId: string) => {
    wsRef.current?.send({
      type: "confirmation_response",
      payload: { request_id: requestId, approved: false },
    });
    setPendingConfirmation((cur) => (cur?.request_id === requestId ? null : cur));
  }, []);

  return { logs, status, pendingConfirmation, isConnected, approve, deny };
}

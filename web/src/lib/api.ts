import type {
  AuditLogRead,
  FindingRead,
  SessionCreate,
  SessionRead,
  ToolInfo,
} from "./types";

const BASE_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

interface RequestOptions extends Omit<RequestInit, "headers"> {
  headers?: Record<string, string>;
  /** Override the default Accept: application/json header. */
  accept?: string;
  /** When true, return raw text instead of JSON. */
  responseType?: "json" | "text";
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { accept, responseType, headers: extraHeaders, ...init } = options;
  const headers: Record<string, string> = {
    Accept: accept ?? "application/json",
    ...(init.body ? { "Content-Type": "application/json" } : {}),
    ...extraHeaders,
  };

  const res = await fetch(`${BASE_URL}${path}`, { ...init, headers });

  if (!res.ok) {
    // Try JSON first (FastAPI sends {detail: ...}), fall back to text.
    let detail = res.statusText;
    const raw = await res.text().catch(() => "");
    if (raw) {
      try {
        const parsed = JSON.parse(raw) as { detail?: unknown; message?: unknown };
        const msg = parsed.detail ?? parsed.message;
        if (msg) detail = typeof msg === "string" ? msg : JSON.stringify(msg);
        else detail = raw;
      } catch {
        detail = raw;
      }
    }
    throw new Error(`API ${res.status}: ${detail}`);
  }

  if (res.status === 204) return undefined as unknown as T;
  if (responseType === "text") return (await res.text()) as unknown as T;
  return (await res.json()) as T;
}

// ── Sessions ────────────────────────────────────────────────────────

export const listSessions = () =>
  request<SessionRead[]>("/api/v1/sessions");

export const getSession = (id: string) =>
  request<SessionRead>(`/api/v1/sessions/${id}`);

export interface CreateSessionResponse {
  session: SessionRead;
  ws_token: string;
}

export const createSession = (data: SessionCreate) =>
  request<CreateSessionResponse>("/api/v1/sessions", {
    method: "POST",
    body: JSON.stringify(data),
  });

export const deleteSession = (id: string) =>
  request<void>(`/api/v1/sessions/${id}`, { method: "DELETE" });

export interface RunSessionResponse {
  status: string;
  session_id: string;
  ws_token: string;
}

export const runSession = (
  id: string,
  opts: { llm_provider: string; llm_model: string; max_steps: number }
) =>
  request<RunSessionResponse>(`/api/v1/sessions/${id}/run`, {
    method: "POST",
    body: JSON.stringify(opts),
  });

export const stopSession = (id: string) =>
  request<{ status: string; session_id: string }>(
    `/api/v1/sessions/${id}/stop`,
    { method: "POST", body: JSON.stringify({}) }
  );

// ── Findings ────────────────────────────────────────────────────────

export const listFindings = (sessionId: string) =>
  request<FindingRead[]>(`/api/v1/sessions/${sessionId}/findings`);

// ── Audit log ───────────────────────────────────────────────────────

export const getAuditLog = (sessionId: string) =>
  request<AuditLogRead[]>(`/api/v1/sessions/${sessionId}/audit-log`);

// ── Report ──────────────────────────────────────────────────────────

export const getReport = (
  sessionId: string,
  format: "markdown" | "json" = "markdown"
): Promise<string> =>
  request<string>(`/api/v1/sessions/${sessionId}/report?format=${format}`, {
    accept: format === "json" ? "application/json" : "text/markdown",
    responseType: "text",
  });

// ── Tools ────────────────────────────────────────────────────────────

export const listTools = () =>
  request<ToolInfo[]>("/api/v1/tools");

// ── Health ───────────────────────────────────────────────────────────

export const getHealth = () =>
  request<{ status: string; version: string }>("/api/v1/health");

// ── WebSocket token store (per-tab) ─────────────────────────────────
//
// The token returned by createSession / runSession is needed to open a
// WebSocket for that session. We keep it in sessionStorage so a page
// reload during a scan doesn't break the connection, but a new tab in
// a different browser still has to re-create or re-run the session.

const TOKEN_PREFIX = "autopen.ws-token.";

export function rememberSessionToken(sessionId: string, token: string): void {
  if (typeof window === "undefined") return;
  try {
    window.sessionStorage.setItem(TOKEN_PREFIX + sessionId, token);
  } catch {
    // sessionStorage may be unavailable (private mode); ignore.
  }
}

export function getSessionToken(sessionId: string): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.sessionStorage.getItem(TOKEN_PREFIX + sessionId);
  } catch {
    return null;
  }
}

export function forgetSessionToken(sessionId: string): void {
  if (typeof window === "undefined") return;
  try {
    window.sessionStorage.removeItem(TOKEN_PREFIX + sessionId);
  } catch {
    // ignore
  }
}

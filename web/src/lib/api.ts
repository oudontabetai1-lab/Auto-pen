import type {
  AuditLogRead,
  FindingRead,
  SessionCreate,
  SessionRead,
  ToolInfo,
} from "./types";

const BASE_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

async function request<T>(
  path: string,
  options?: RequestInit
): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => res.statusText);
    throw new Error(`API ${res.status}: ${detail}`);
  }
  // 204 No Content
  if (res.status === 204) return undefined as unknown as T;
  return res.json() as Promise<T>;
}

// ── Sessions ────────────────────────────────────────────────────────

export const listSessions = () =>
  request<SessionRead[]>("/api/v1/sessions");

export const getSession = (id: string) =>
  request<SessionRead>(`/api/v1/sessions/${id}`);

export const createSession = (data: SessionCreate) =>
  request<SessionRead>("/api/v1/sessions", {
    method: "POST",
    body: JSON.stringify(data),
  });

export const deleteSession = (id: string) =>
  request<void>(`/api/v1/sessions/${id}`, { method: "DELETE" });

export const runSession = (
  id: string,
  opts: { llm_provider: string; llm_model: string; max_steps: number }
) =>
  request<{ status: string; session_id: string }>(
    `/api/v1/sessions/${id}/run`,
    { method: "POST", body: JSON.stringify(opts) }
  );

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

export const getReport = async (
  sessionId: string,
  format: "markdown" | "json" = "markdown"
): Promise<string> => {
  const res = await fetch(
    `${BASE_URL}/api/v1/sessions/${sessionId}/report?format=${format}`
  );
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.text();
};

// ── Tools ────────────────────────────────────────────────────────────

export const listTools = () =>
  request<ToolInfo[]>("/api/v1/tools");

// ── Health ───────────────────────────────────────────────────────────

export const getHealth = () =>
  request<{ status: string; version: string }>("/api/v1/health");

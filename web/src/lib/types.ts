// ---------------------------------------------------------------------------
// API Response types (mirror of Python Pydantic schemas)
// ---------------------------------------------------------------------------

export type SessionStatus = "pending" | "running" | "paused" | "completed" | "failed";
export type ScanProfile = "web" | "network" | "cloud" | "ctf";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface SessionRead {
  id: string;
  target: string;
  profile: string;
  status: SessionStatus;
  llm_provider: string;
  llm_model: string;
  step_count: number;
  created_at: string;
  updated_at: string;
}

export interface SessionCreate {
  target: string;
  profile: ScanProfile;
  authorization_token: string;
  scope?: {
    allowed_hosts: string[];
    allowed_ports?: number[];
    exclude_hosts?: string[];
  };
  llm_provider?: string;
  llm_model?: string;
}

export interface FindingRead {
  id: string;
  session_id: string;
  severity: Severity;
  title: string;
  description: string;
  tool_name: string;
  evidence: string;
  remediation: string;
  cvss_score: number | null;
  cvss_vector: string | null;
  target: string;
  timestamp: string;
}

export interface AuditLogRead {
  id: string;
  session_id: string;
  timestamp: string;
  action: string;
  tool_name: string | null;
  params: Record<string, unknown>;
  result_summary: string;
  risk_level: RiskLevel;
  approved_by_human: boolean;
}

export interface ToolInfo {
  name: string;
  description: string;
  risk_level: RiskLevel;
  available: boolean;
}

// ---------------------------------------------------------------------------
// WebSocket message types: Server → Client
// ---------------------------------------------------------------------------

export interface WsLogPayload {
  level: "info" | "reasoning" | "warning" | "error";
  message: string;
  step?: number;
}

export interface WsToolStartPayload {
  tool_name: string;
  params: Record<string, unknown>;
  risk_level: RiskLevel;
}

export interface WsToolCompletePayload {
  tool_name: string;
  success: boolean;
  output_preview: string;
  duration_seconds: number;
}

export interface WsConfirmationRequestPayload {
  request_id: string;
  tool_name: string;
  risk_level: RiskLevel;
  params: Record<string, unknown>;
  reasoning: string;
  timeout_seconds: number;
}

export interface WsSessionStatusPayload {
  status: SessionStatus;
  step_count: number;
  summary?: string;
}

export interface WsFindingDiscoveredPayload {
  id: string;
  severity: Severity;
  title: string;
  tool_name: string;
}

export interface WsErrorPayload {
  code: string;
  message: string;
}

export type WsServerMessage =
  | { type: "log"; session_id: string; timestamp: string; payload: WsLogPayload }
  | { type: "tool_start"; session_id: string; timestamp: string; payload: WsToolStartPayload }
  | { type: "tool_complete"; session_id: string; timestamp: string; payload: WsToolCompletePayload }
  | { type: "confirmation_request"; session_id: string; timestamp: string; payload: WsConfirmationRequestPayload }
  | { type: "finding_discovered"; session_id: string; timestamp: string; payload: WsFindingDiscoveredPayload }
  | { type: "session_status"; session_id: string; timestamp: string; payload: WsSessionStatusPayload }
  | { type: "error"; session_id: string; timestamp: string; payload: WsErrorPayload }
  | { type: "pong"; timestamp: string };

// ---------------------------------------------------------------------------
// WebSocket message types: Client → Server
// ---------------------------------------------------------------------------

export type WsClientMessage =
  | { type: "confirmation_response"; payload: { request_id: string; approved: boolean } }
  | { type: "ping" };

// ---------------------------------------------------------------------------
// Frontend-only state types
// ---------------------------------------------------------------------------

export interface LogEntry {
  id: string;  // local UUID for React key
  timestamp: string;
  type: WsServerMessage["type"];
  payload: WsLogPayload | WsToolStartPayload | WsToolCompletePayload | WsFindingDiscoveredPayload | WsSessionStatusPayload | WsErrorPayload;
}

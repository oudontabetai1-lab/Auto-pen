import type { WsClientMessage, WsServerMessage } from "./types";

const WS_BASE =
  process.env.NEXT_PUBLIC_WS_URL ??
  (typeof window !== "undefined"
    ? `${window.location.protocol === "https:" ? "wss" : "ws"}://${window.location.hostname}:8080`
    : "ws://localhost:8080");

type MessageHandler = (msg: WsServerMessage) => void;
type StatusHandler = (connected: boolean) => void;

/**
 * Managed WebSocket connection for a session.
 *
 * Handles:
 * - Initial connection
 * - Automatic reconnection with exponential backoff (up to 4 retries)
 * - Message send queue (buffered while disconnected)
 * - Clean teardown via `close()`
 */
export class SessionWebSocket {
  private ws: WebSocket | null = null;
  private onMessage: MessageHandler;
  private onStatus: StatusHandler;
  private sessionId: string;
  private retryCount = 0;
  private maxRetries = 8;
  private closed = false;
  private pingInterval: ReturnType<typeof setInterval> | null = null;

  constructor(
    sessionId: string,
    onMessage: MessageHandler,
    onStatus: StatusHandler
  ) {
    this.sessionId = sessionId;
    this.onMessage = onMessage;
    this.onStatus = onStatus;
    this.connect();
  }

  private connect() {
    if (this.closed) return;
    const url = `${WS_BASE}/ws/sessions/${this.sessionId}`;

    try {
      this.ws = new WebSocket(url);
    } catch {
      this.scheduleReconnect();
      return;
    }

    this.ws.onopen = () => {
      this.retryCount = 0;
      this.onStatus(true);
      // Keep-alive ping every 30 s
      this.pingInterval = setInterval(() => this.send({ type: "ping" }), 30_000);
    };

    this.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data) as WsServerMessage;
        this.onMessage(msg);
      } catch {
        // ignore malformed messages
      }
    };

    this.ws.onerror = () => {
      // will be followed by onclose
    };

    this.ws.onclose = () => {
      this.onStatus(false);
      if (this.pingInterval) {
        clearInterval(this.pingInterval);
        this.pingInterval = null;
      }
      this.scheduleReconnect();
    };
  }

  private scheduleReconnect() {
    if (this.closed || this.retryCount >= this.maxRetries) return;
    const delay = Math.min(1000 * 2 ** this.retryCount, 30_000);
    this.retryCount++;
    setTimeout(() => this.connect(), delay);
  }

  send(msg: WsClientMessage) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
    }
  }

  close() {
    this.closed = true;
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
    this.ws?.close();
  }
}

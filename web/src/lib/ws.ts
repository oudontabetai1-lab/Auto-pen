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
 * - Initial connection (with `?token=…` auth)
 * - Automatic reconnection with exponential backoff
 * - Outbound message queue (buffered while disconnected, flushed on reconnect)
 * - Clean teardown via `close()`
 */
export class SessionWebSocket {
  private ws: WebSocket | null = null;
  private readonly onMessage: MessageHandler;
  private readonly onStatus: StatusHandler;
  private readonly sessionId: string;
  private token: string | null;
  private retryCount = 0;
  private readonly maxRetries = 8;
  private closed = false;
  private pingInterval: ReturnType<typeof setInterval> | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly outboundQueue: WsClientMessage[] = [];

  constructor(
    sessionId: string,
    onMessage: MessageHandler,
    onStatus: StatusHandler,
    token: string | null = null
  ) {
    this.sessionId = sessionId;
    this.onMessage = onMessage;
    this.onStatus = onStatus;
    this.token = token;
    this.connect();
  }

  /** Update the auth token (e.g. after /run returns a fresh one). */
  setToken(token: string | null) {
    this.token = token;
  }

  private connect() {
    if (this.closed) return;
    const qs = this.token ? `?token=${encodeURIComponent(this.token)}` : "";
    const url = `${WS_BASE}/ws/sessions/${this.sessionId}${qs}`;

    try {
      this.ws = new WebSocket(url);
    } catch {
      this.scheduleReconnect();
      return;
    }

    this.ws.onopen = () => {
      this.retryCount = 0;
      this.onStatus(true);
      this.flushQueue();
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

    this.ws.onclose = (ev) => {
      this.onStatus(false);
      if (this.pingInterval) {
        clearInterval(this.pingInterval);
        this.pingInterval = null;
      }
      // Auth failures should not loop forever.
      if (ev.code === 4401 || ev.code === 4004) {
        this.closed = true;
        return;
      }
      this.scheduleReconnect();
    };
  }

  private flushQueue() {
    while (
      this.outboundQueue.length > 0 &&
      this.ws?.readyState === WebSocket.OPEN
    ) {
      const msg = this.outboundQueue.shift()!;
      this.ws.send(JSON.stringify(msg));
    }
  }

  private scheduleReconnect() {
    if (this.closed || this.retryCount >= this.maxRetries) return;
    const delay = Math.min(1000 * 2 ** this.retryCount, 30_000);
    this.retryCount++;
    this.reconnectTimer = setTimeout(() => this.connect(), delay);
  }

  /**
   * Send a message. If the socket is closed/connecting, the message is
   * queued and flushed on the next `onopen`. Ping messages are dropped
   * when disconnected — they're keep-alives only.
   */
  send(msg: WsClientMessage) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
      return;
    }
    if (msg.type === "ping") return;
    this.outboundQueue.push(msg);
  }

  close() {
    this.closed = true;
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.ws?.close();
  }
}

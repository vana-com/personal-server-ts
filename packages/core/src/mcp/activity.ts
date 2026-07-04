/**
 * In-memory MCP activity recorder/ring buffer.
 *
 * Records start/end of every MCP tool call so the /mcp UI page can poll for
 * live and recent activity. No raw data payloads are stored — only metadata
 * about the call (tool name, scopes, counts, error code, timing).
 *
 * The ring buffer is bounded by `maxEvents`; oldest entries are evicted when
 * full. Running calls occupy a slot; the slot is updated in-place when the
 * call finishes.
 */

export type McpActivityStatus =
  "running" | "succeeded" | "failed" | "timed_out" | "aborted";

export type McpActivityPhase =
  "tool_running" | "response_preparing" | "response_ready";

export interface McpActivityEvent {
  id: string;
  tool: string;
  status: McpActivityStatus;
  /** Current server-side phase. This is PS-side only, not a client receipt ack. */
  phase: McpActivityPhase;
  startedAt: string;
  finishedAt?: string;
  durationMs?: number;
  handlerDurationMs?: number;
  payloadBytes?: number;
  textBytes?: number;
  structuredContentBytes?: number;
  /** Scopes involved in the call, where applicable. */
  scopes?: string[];
  /** Clipped query preview for search calls only. */
  queryPreview?: string;
  resultCount?: number;
  skippedCount?: number;
  errorCode?: string;
  errorMessage?: string;
}

export interface McpActivitySnapshot {
  events: McpActivityEvent[];
  running: number;
  total: number;
}

const DEFAULT_MAX_EVENTS = 50;
const QUERY_PREVIEW_MAX_CHARS = 120;

function generateId(): string {
  return `act-${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`;
}

export class McpActivityRecorder {
  private readonly _events: McpActivityEvent[] = [];
  private readonly _maxEvents: number;

  constructor(maxEvents = DEFAULT_MAX_EVENTS) {
    this._maxEvents = maxEvents;
  }

  /** Start recording a tool call. Returns the activity id. */
  start(params: {
    tool: string;
    scopes?: string[];
    queryPreview?: string;
  }): string {
    const id = generateId();
    const event: McpActivityEvent = {
      id,
      tool: params.tool,
      status: "running",
      phase: "tool_running",
      startedAt: new Date().toISOString(),
      ...(params.scopes && params.scopes.length > 0
        ? { scopes: params.scopes }
        : {}),
      ...(params.queryPreview
        ? {
            queryPreview: params.queryPreview.slice(0, QUERY_PREVIEW_MAX_CHARS),
          }
        : {}),
    };
    if (this._events.length >= this._maxEvents) {
      // Evict the oldest finished event. If all are running, evict the oldest.
      const oldestFinishedIndex = this._events.findIndex(
        (e) => e.status !== "running",
      );
      if (oldestFinishedIndex >= 0) {
        this._events.splice(oldestFinishedIndex, 1);
      } else {
        this._events.shift();
      }
    }
    this._events.push(event);
    console.info(`[mcp-activity] start id=${id} tool=${params.tool}`);
    return id;
  }

  /** Update metadata for an in-flight call. No-op if the id is not found. */
  update(
    id: string,
    patch: Partial<
      Pick<
        McpActivityEvent,
        | "phase"
        | "handlerDurationMs"
        | "payloadBytes"
        | "textBytes"
        | "structuredContentBytes"
        | "resultCount"
        | "skippedCount"
        | "errorCode"
        | "errorMessage"
      >
    >,
  ): void {
    const event = this._events.find((e) => e.id === id);
    if (!event) return;
    Object.assign(event, patch);
  }

  /** Finish a running call by id. No-op if the id is not found. */
  finish(
    id: string,
    result: {
      status: Exclude<McpActivityStatus, "running">;
      handlerDurationMs?: number;
      payloadBytes?: number;
      textBytes?: number;
      structuredContentBytes?: number;
      resultCount?: number;
      skippedCount?: number;
      errorCode?: string;
      errorMessage?: string;
    },
  ): void {
    const event = this._events.find((e) => e.id === id);
    if (!event) return;
    const finishedAt = new Date().toISOString();
    const durationMs = Date.parse(finishedAt) - Date.parse(event.startedAt);
    event.status = result.status;
    event.phase = "response_ready";
    event.finishedAt = finishedAt;
    event.durationMs = durationMs;
    if (result.handlerDurationMs !== undefined) {
      event.handlerDurationMs = result.handlerDurationMs;
    }
    if (result.payloadBytes !== undefined) {
      event.payloadBytes = result.payloadBytes;
    }
    if (result.textBytes !== undefined) {
      event.textBytes = result.textBytes;
    }
    if (result.structuredContentBytes !== undefined) {
      event.structuredContentBytes = result.structuredContentBytes;
    }
    if (result.resultCount !== undefined) {
      event.resultCount = result.resultCount;
    }
    if (result.skippedCount !== undefined) {
      event.skippedCount = result.skippedCount;
    }
    if (result.errorCode) {
      event.errorCode = result.errorCode;
    }
    if (result.errorMessage) {
      event.errorMessage = result.errorMessage;
    }

    if (result.status === "succeeded") {
      console.info(
        `[mcp-activity] finish id=${id} tool=${event.tool} status=${result.status} durationMs=${durationMs}`,
      );
    } else {
      console.warn(
        `[mcp-activity] finish id=${id} tool=${event.tool} status=${result.status} durationMs=${durationMs}${result.errorCode ? ` errorCode=${result.errorCode}` : ""}`,
      );
    }
  }

  /** Read the current snapshot, newest first. */
  snapshot(): McpActivitySnapshot {
    const events = [...this._events].reverse();
    const running = events.filter((e) => e.status === "running").length;
    return { events, running, total: events.length };
  }
}

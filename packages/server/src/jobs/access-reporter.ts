/**
 * Buffered access-record reporter (enclave profile only).
 *
 * Every MCP read the sandbox PS serves or refuses becomes one access record.
 * The sandbox cannot reach the Gateway itself, so records go to the enclave
 * agent, which signs them with the user's enclave key and relays them:
 *
 *   sandbox PS  --Bearer PS_ACCESS_TOKEN-->  agent  --node bearer-->  Gateway
 *
 * Reporting is best effort by contract: a read is never delayed, retried, or
 * failed because its record could not be delivered.
 */

import type {
  PersonalServerReadFulfillment,
  PersonalServerReadFulfillmentReporter,
} from "@opendatalabs/personal-server-ts-core/api";

const ACCESS_RECORDS_PATH = "/agent/v1/access-records";
const ACTION_READ = "read";
const POST = "POST";
const JSON_CONTENT_TYPE = "application/json";

/** One request carries at most this many records; the agent enforces it too. */
const MAX_BATCH_RECORDS = 50;
/** A partial batch waits at most this long before it is sent. */
const FLUSH_INTERVAL_MS = 5_000;
/** Backstop for an unreachable agent: drop oldest rather than grow forever. */
const MAX_QUEUED_RECORDS = 500;
const REQUEST_TIMEOUT_MS = 10_000;

export interface AccessReporterLogger {
  warn(payload: Record<string, unknown>, message: string): void;
}

export interface AccessReporterOptions {
  agentEndpoint: string;
  accessToken: string;
  chainId: number;
  logger?: AccessReporterLogger;
  fetch?: typeof fetch;
}

export interface AccessReporter extends PersonalServerReadFulfillmentReporter {
  /** Sends everything buffered. Resolves even when delivery failed. */
  flush(): Promise<void>;
  /** Stops the timer and flushes; call on shutdown. */
  stop(): Promise<void>;
}

/** Wire shape of one record. The agent adds userPsId, epoch, nodeId, signature. */
interface AccessRecordPayload {
  action: typeof ACTION_READ;
  chainId: number;
  denyReason?: string;
  grantId: string;
  granteeAddress: string;
  logId: string;
  occurredAt: string;
  outcome: PersonalServerReadFulfillment["outcome"];
  scope: string;
  source: PersonalServerReadFulfillment["source"];
  tool?: string;
}

export function createAccessReporter(
  options: AccessReporterOptions,
): AccessReporter {
  const requestFetch = options.fetch ?? fetch;
  const endpoint = `${options.agentEndpoint.replace(/\/$/, "")}${ACCESS_RECORDS_PATH}`;
  const logger = options.logger ?? consoleAccessReporterLogger;
  const queue: AccessRecordPayload[] = [];
  let timer: ReturnType<typeof setTimeout> | undefined;
  let sending: Promise<void> = Promise.resolve();

  function enqueue(event: PersonalServerReadFulfillment): void {
    queue.push(toPayload(options.chainId, event));

    if (queue.length > MAX_QUEUED_RECORDS) {
      const dropped = queue.splice(0, queue.length - MAX_QUEUED_RECORDS);
      logger.warn(
        { dropped: dropped.length },
        "Access record queue is full; oldest records dropped",
      );
    }

    if (queue.length >= MAX_BATCH_RECORDS) {
      void flush();
      return;
    }

    startTimer();
  }

  function startTimer(): void {
    if (timer) return;
    timer = setTimeout(() => {
      timer = undefined;
      void flush();
    }, FLUSH_INTERVAL_MS);
    timer.unref?.();
  }

  function clearFlushTimer(): void {
    if (!timer) return;
    clearTimeout(timer);
    timer = undefined;
  }

  // Serialized so two flushes never interleave batches on the wire.
  function flush(): Promise<void> {
    clearFlushTimer();
    sending = sending.then(async () => {
      while (queue.length > 0) {
        const batch = queue.splice(0, MAX_BATCH_RECORDS);
        await send(batch);
      }
    });

    return sending;
  }

  async function send(records: AccessRecordPayload[]): Promise<void> {
    try {
      const response = await requestFetch(endpoint, {
        method: POST,
        headers: {
          Authorization: `Bearer ${options.accessToken}`,
          "Content-Type": JSON_CONTENT_TYPE,
        },
        body: JSON.stringify({ records }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (response.ok) return;

      // Dropped, not retried: a record describes a read that already happened,
      // and a retry queue would outlive the sandbox that owns the token.
      logger.warn(
        { count: records.length, status: response.status },
        "Access records were refused",
      );
    } catch (err) {
      logger.warn(
        {
          count: records.length,
          error: err instanceof Error ? err.message : String(err),
        },
        "Access records could not be delivered",
      );
    }
  }

  return {
    async report(event): Promise<void> {
      enqueue(event);
    },
    async reportDenied(event): Promise<void> {
      enqueue(event);
    },
    flush,
    async stop(): Promise<void> {
      clearFlushTimer();
      await flush();
    },
  };
}

function toPayload(
  chainId: number,
  event: PersonalServerReadFulfillment,
): AccessRecordPayload {
  return {
    action: ACTION_READ,
    chainId,
    ...(event.denyReason === undefined ? {} : { denyReason: event.denyReason }),
    grantId: event.grantId,
    granteeAddress: event.builder,
    logId: event.logId,
    occurredAt: event.servedAt,
    outcome: event.outcome,
    scope: event.scope,
    source: event.source,
    ...(event.tool === undefined ? {} : { tool: event.tool }),
  };
}

const consoleAccessReporterLogger: AccessReporterLogger = {
  warn(payload, message) {
    console.warn(message, payload);
  },
};

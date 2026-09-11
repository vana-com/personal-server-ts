/**
 * Buffered access-record reporter (enclave profile only).
 *
 * Every MCP read the sandbox PS serves or refuses becomes one access record.
 * The sandbox cannot reach the Gateway itself, so records go to the enclave
 * agent, which signs them with the user's enclave key and relays them:
 *
 *   sandbox PS  --Bearer PS_ACCESS_TOKEN-->  agent  --node bearer-->  Gateway
 *
 * Reporting is best effort by contract: a read is never delayed or failed
 * because its record could not be delivered. Delivery itself is not best
 * effort — a failed batch is retried with backoff, and a batch that is finally
 * given up on is logged as dropped so the gap in the owner's audit trail is
 * visible rather than silent (security #9).
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
/** Delivery attempts per batch before it is given up on and logged. */
const MAX_SEND_ATTEMPTS = 3;
/** Backoff between attempts: 500 ms, then 1 s. */
const RETRY_BASE_DELAY_MS = 500;

/** Log line a dropped batch always emits; the audit gap is a metric, not noise. */
export const ACCESS_RECORDS_DROPPED = "Access records dropped";

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
  // Shutdown must not wait out the backoff; a stopping reporter sends once.
  let stopping = false;
  // Every record this reporter never delivered, across both drop paths.
  let dropped = 0;

  function enqueue(event: PersonalServerReadFulfillment): void {
    queue.push(toPayload(options.chainId, event));

    if (queue.length > MAX_QUEUED_RECORDS) {
      const overflow = queue.splice(0, queue.length - MAX_QUEUED_RECORDS);
      drop(overflow, { reason: "queue_full" });
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

  /**
   * Deliver one batch, retrying a transient failure with backoff.
   *
   *   attempt 1 --fail--> 500 ms --> attempt 2 --fail--> 1 s --> attempt 3
   *
   * A 4xx is the agent refusing these records, not a blip, so it is not
   * retried. Whatever is finally undelivered goes through `drop`, which is the
   * one place an audit gap becomes visible.
   */
  async function send(records: AccessRecordPayload[]): Promise<void> {
    for (let attempt = 1; attempt <= MAX_SEND_ATTEMPTS; attempt += 1) {
      const outcome = await attemptSend(records);
      if (outcome === null) return;

      const lastChance = attempt === MAX_SEND_ATTEMPTS || stopping;
      if (outcome.permanent || lastChance) {
        drop(records, { ...outcome, attempts: attempt });
        return;
      }

      await delay(RETRY_BASE_DELAY_MS * 2 ** (attempt - 1));
    }
  }

  /** null when the batch landed; otherwise why it did not. */
  async function attemptSend(
    records: AccessRecordPayload[],
  ): Promise<{ reason: string; permanent: boolean } | null> {
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
      if (response.ok) return null;

      return {
        reason: `refused_${response.status}`,
        permanent: response.status >= 400 && response.status < 500,
      };
    } catch (err) {
      return {
        reason: err instanceof Error ? err.message : String(err),
        permanent: false,
      };
    }
  }

  /**
   * Records that will never reach the Gateway. Reads were already served, so
   * this is the audit trail's gap: it is counted and logged under one stable
   * message, never swallowed.
   */
  function drop(
    records: AccessRecordPayload[],
    detail: { reason: string; attempts?: number },
  ): void {
    dropped += records.length;
    logger.warn(
      { count: records.length, droppedTotal: dropped, ...detail },
      ACCESS_RECORDS_DROPPED,
    );
  }

  function delay(ms: number): Promise<void> {
    return new Promise((resolve) => {
      const handle = setTimeout(resolve, ms);
      handle.unref?.();
    });
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
      stopping = true;
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

import {
  parseRetryAfterBody,
  parseRetryAfterHeader,
} from "../../stream-sync/storage-retry.js";

/** HTTP statuses by which storage says "slow down". */
const THROTTLE_STATUSES: ReadonlySet<number> = new Set([429, 503]);

/** The most of a throttle answer's body that is read to find a `retryAfter`. */
const BODY_READ_LIMIT_BYTES = 4096;

/** Up to `limit` bytes of a body as text; the rest is cancelled unread. */
async function readHead(response: Response, limit: number): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (total < limit) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  const joined = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    joined.set(chunk, at);
    at += chunk.byteLength;
  }
  return new TextDecoder().decode(joined.subarray(0, limit));
}

/**
 * How long a response asked the client to wait, in ms: the `Retry-After`
 * header (seconds or an HTTP date), else the JSON body's `retryAfter` when the
 * header is unreadable (a browser sees only the headers a CORS response
 * exposes). The body is read only when the header gives nothing, only its
 * first 4 KiB, and it is always cancelled before this returns.
 */
export async function retryAfterMsOf(
  response: Response,
): Promise<number | undefined> {
  const header = parseRetryAfterHeader(
    response.headers.get("retry-after"),
    Date.now(),
  );
  if (header !== undefined) {
    await response.body?.cancel().catch(() => undefined);
    return header;
  }
  try {
    return parseRetryAfterBody(await readHead(response, BODY_READ_LIMIT_BYTES));
  } catch {
    return undefined;
  }
}

/**
 * Finish with the body of a failed response and report what it asked to wait:
 * a throttle answer is read (the body may carry `retryAfter`), any other
 * status is cancelled unread.
 */
export async function settleFailure(
  response: Response,
): Promise<number | undefined> {
  if (!THROTTLE_STATUSES.has(response.status)) {
    await response.body?.cancel();
    return undefined;
  }
  return retryAfterMsOf(response);
}

/**
 * The error of a 429 or 503 answer: its status, and what it asked to wait.
 * The send governor reads both (`throttleOf`).
 */
export async function throttleError(response: Response): Promise<Error> {
  const retryAfterMs = await retryAfterMsOf(response);
  return Object.assign(
    new Error(`storage request failed (${response.status})`),
    {
      status: response.status,
      ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
    },
  );
}

/**
 * A `fetch` that throws on 429 and 503 instead of returning the response.
 *
 * Why: the SDK's vana-storage provider retries a 429 PUT by itself (4 tries,
 * each wait capped at 30 s), outside the send governor, and its errors carry
 * no header. A throw here ends that inner loop, so there is one retry layer,
 * and puts the status and the Retry-After on the error, which the provider
 * keeps as the `cause` of the error it throws.
 */
export function throttleAwareFetch(
  base: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>,
): (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> {
  return async (input, init) => {
    const response = await base(input, init);
    if (THROTTLE_STATUSES.has(response.status)) {
      throw await throttleError(response);
    }
    return response;
  };
}

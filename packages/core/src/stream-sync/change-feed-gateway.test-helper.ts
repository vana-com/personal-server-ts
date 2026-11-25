// A fake data gateway's change feed, as the opaque-cursor contract describes
// it. Only this fake reads inside a cursor: it mints
// `base64url("v1:" + epoch + ":" + seq)`, and it answers the way the gateway
// does. A client under test must keep what it is given and compare it for
// equality. The fake is reached through `fetch`, so the real registry client
// and the real change push run against it.
//
// Contract rules the fake implements (`GET /v1/data/changes`):
//  - no `after`: answer at once, `changed: true`;
//  - an `after` or `since` from another epoch: answer at once, `changed: true`,
//    and `delta.reset: true` when `since` was sent;
//  - the same epoch: hold until the sequence moves or `wait` seconds pass;
//    an `after` ahead of the counter is answered at once; a `since` above the
//    counter is a reset;
//  - a cursor that is not a cursor (a bare decimal included): 400
//    `Invalid after: expected a change-feed cursor`, or `Invalid since`.

import {
  decodeBase64UrlUtf8,
  encodeBase64UrlUtf8,
} from "../encoding/base64url.js";

export const EPOCH_A = "ffffffff-ffff-4fff-8fff-ffffffffffff";
export const EPOCH_B = "00000000-0000-4000-8000-000000000001";

/** The cursor the gateway mints for `epoch` at sequence `seq`. */
export function mintCursor(epoch: string, seq: number): string {
  return encodeBase64UrlUtf8(`v1:${epoch}:${seq}`);
}

/** What a cursor says; only the fake gateway and tests that audit requests read it. */
export function readCursor(
  wire: string,
): { epoch: string; seq: number } | undefined {
  const match = /^v1:([0-9a-f-]{36}):(0|[1-9]\d*)$/.exec(
    decodeBase64UrlUtf8(wire),
  );
  if (!match) return undefined;
  const read = { epoch: match[1]!, seq: Number(match[2]) };
  return mintCursor(read.epoch, read.seq) === wire ? read : undefined;
}

/** A registry row as the gateway lists it on the wire. */
export interface WireRow {
  readonly scope: string;
  readonly expectedVersion: string;
  readonly dataHash: string;
  readonly metadataHash: string;
  readonly deletedAt: null;
}

export interface FakeChangeRequest {
  readonly after: string | undefined;
  readonly since: string | undefined;
  readonly wait: string | undefined;
  readonly signal: AbortSignal | undefined;
}

export function createFakeChangeGateway(
  initial: { epoch?: string; seq?: number } = {},
) {
  let epoch = initial.epoch ?? EPOCH_A;
  let seq = initial.seq ?? 0;
  const writes: Array<{ seq: number; row: WireRow }> = [];
  const requests: FakeChangeRequest[] = [];
  const parked = new Set<() => void>();
  const scripted = new Map<number, () => Response>();
  const rejected = new Set<string>();

  const json = (status: number, body: unknown) =>
    new Response(JSON.stringify(body), { status });

  /** A cursor the gateway reads as not a cursor, once: the 400 a format change gives. */
  function rejection(afterWire: string | undefined): Response | undefined {
    if (afterWire === undefined || !rejected.delete(afterWire))
      return undefined;
    return json(400, { error: "Invalid after: expected a change-feed cursor" });
  }

  function respond(
    after: { epoch: string; seq: number } | undefined,
    since: { epoch: string; seq: number } | undefined,
    sinceWire: string | undefined,
  ): Response {
    const cursor = mintCursor(epoch, seq);
    const otherEpoch =
      (after !== undefined && after.epoch !== epoch) ||
      (since !== undefined && since.epoch !== epoch);
    const changed = after === undefined || after.seq !== seq || otherEpoch;
    if (!changed) return json(200, { cursor, changed: false });
    if (since === undefined || sinceWire === undefined)
      return json(200, { cursor, changed: true });
    if (otherEpoch || since.seq > seq)
      return json(200, {
        cursor,
        changed: true,
        delta: { since: sinceWire, reset: true },
      });
    return json(200, {
      cursor,
      changed: true,
      delta: {
        since: sinceWire,
        reset: false,
        rows: writes
          .filter((write) => write.seq > since.seq && write.seq <= seq)
          .map((write) => write.row),
        gone: [],
        serversChanged: false,
      },
    });
  }

  const fetch = ((url: string, init?: RequestInit) => {
    // A client that answers a changed answer with the same request again would
    // loop with no wait; fail the test instead of exhausting memory.
    if (requests.length >= 500)
      throw new Error("the client is sending requests in a tight loop");
    const params = new URL(url).searchParams;
    const afterWire = params.get("after") ?? undefined;
    const sinceWire = params.get("since") ?? undefined;
    const signal = init?.signal ?? undefined;
    const index = requests.length;
    requests.push({
      after: afterWire,
      since: sinceWire,
      wait: params.get("wait") ?? undefined,
      signal,
    });
    const scriptedAnswer = scripted.get(index);
    if (scriptedAnswer) return Promise.resolve(scriptedAnswer());
    const refused = rejection(afterWire);
    if (refused) return Promise.resolve(refused);
    const after = afterWire === undefined ? undefined : readCursor(afterWire);
    if (afterWire !== undefined && after === undefined)
      return Promise.resolve(
        json(400, { error: "Invalid after: expected a change-feed cursor" }),
      );
    const since = sinceWire === undefined ? undefined : readCursor(sinceWire);
    if (sinceWire !== undefined && since === undefined)
      return Promise.resolve(
        json(400, { error: "Invalid since: expected a change-feed cursor" }),
      );
    const holds =
      after !== undefined &&
      after.epoch === epoch &&
      after.seq === seq &&
      (since === undefined || since.epoch === epoch);
    if (!holds) return Promise.resolve(respond(after, since, sinceWire));
    return new Promise<Response>((resolve, reject) => {
      const done = () => {
        clearTimeout(timer);
        parked.delete(wake);
        signal?.removeEventListener("abort", onAbort);
      };
      const wake = () => {
        done();
        resolve(rejection(afterWire) ?? respond(after, since, sinceWire));
      };
      const onAbort = () => {
        done();
        reject(signal!.reason);
      };
      const timer = setTimeout(wake, Number(params.get("wait") ?? "0") * 1000);
      parked.add(wake);
      signal?.addEventListener("abort", onAbort, { once: true });
    });
  }) as unknown as typeof globalThis.fetch;

  const wakeAll = () => {
    for (const wake of [...parked]) wake();
  };

  return {
    fetch,
    requests,
    /** The cursor the gateway would answer with now. */
    cursor: () => mintCursor(epoch, seq),
    /** A write lands (with a row for a delta to carry): held requests answer. */
    commit(row?: WireRow) {
      seq += 1;
      if (row) writes.push({ seq, row });
      wakeAll();
      return mintCursor(epoch, seq);
    },
    /** The database is replaced (a dev reset, a restore): a new epoch, a counter that restarts. */
    replaceDatabase(next: { epoch: string; seq: number }) {
      epoch = next.epoch;
      seq = next.seq;
      writes.length = 0;
      wakeAll();
      return mintCursor(epoch, seq);
    },
    /** Request number `index` (from 0) gets this response, whatever it asked. */
    answerRequestWith(index: number, response: () => Response) {
      scripted.set(index, response);
    },
    /**
     * The next request that carries `cursor` as `after` (a held one answers
     * at its next wake) gets the 400 for a cursor the gateway cannot read.
     */
    rejectCursorOnce(cursor: string) {
      rejected.add(cursor);
    },
    /** Requests held at the gateway now. */
    held: () => parked.size,
  };
}

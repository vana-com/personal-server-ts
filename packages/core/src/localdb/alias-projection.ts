import {
  sizedBodies,
  WHOLE_STREAM_BATCH_BYTES,
  type StreamLimits,
} from "./alias-sized.js";
import {
  aliasViewCheck,
  assertViewCurrent,
  pinAliasStreams,
  type AliasViewCheck,
} from "./alias-view.js";
import {
  AliasTooLarge,
  openWindowed,
  wholeReadCharge,
  type AliasMemory,
  type WindowedRead,
} from "./alias-window.js";
import { readerOf, type SqlDriver } from "./driver.js";
import { PartialViewMoved } from "./partial-read.js";
import type { StreamSyncFiles } from "../stream-sync/ports.js";
import {
  isAliasRecordQuery,
  type AliasRecordQuery,
  type RecordQuery,
} from "./query.js";
import { invalidAliasBinding, type Candidate } from "./read-selection.js";
import type {
  AliasDiagnostic,
  AliasWindow,
  IncompleteAliasDiagnostic,
  LocalAliasRecord,
  LocalAliasTarget,
} from "./resolve.js";
import { holdMemory } from "./transfer-memory.js";

/** What a projection reads and the memory it is charged to. */
export interface AliasEnv {
  /**
   * The database a pin writes through. Checks of the view run on its read
   * connection, so they do not wait behind its writer.
   */
  readonly db: SqlDriver;
  readonly memory: AliasMemory;
  /**
   * The stream epochs pinned before the candidate's heads were read
   * (`pinAliasStreams`). Absent: pinned here, after them.
   */
  readonly epochs?: ReadonlyMap<string, number>;
  /**
   * Ends the read: a wait for memory stops, and its place in the governor's
   * line is given up. A read that holds memory gives it back when it ends.
   */
  readonly signal?: AbortSignal;
  /**
   * Where a windowed read writes its body before serving it (`projectAlias`).
   * The directory holds nothing else; `sweepAliasSpool` empties it at startup.
   * Absent, or with a query that is not an `AliasRecordQuery`: a body is built
   * in memory, and one above `ARRAY_BUDGET` is refused. A listing's check
   * (`checkAlias`) takes the same `env`, so it decides as the read does.
   */
  readonly spool?: StreamSyncFiles;
}

/** Why a projection has no body, or is not served as asked. */
type Refusal =
  | { readonly kind: "no_data" }
  | { readonly kind: "invalid_binding" }
  | {
      readonly kind: "incomplete";
      readonly diagnostics: readonly IncompleteAliasDiagnostic[];
    }
  /** The rows changed while the projection was checked: ask again. */
  | { readonly kind: "moved" }
  /** Above `ARRAY_BUDGET`, and not windowed into a spool: refused, as main does. */
  | { readonly kind: "too_large"; readonly bytes: number };

/** What `checkAlias` says: a body can be built, or why not. */
export type AliasCheck = { readonly kind: "ok" } | Refusal;

export type AliasProjection =
  | {
      readonly kind: "ok";
      /**
       * The payload's JSON, a piece at a time. The projection is complete
       * before the first piece is asked for, and no piece takes memory from
       * the governor: what a body keeps while its reader pauses is the text of
       * a read below `ARRAY_BUDGET` (as main holds it), or a file.
       */
      readonly body: () => AsyncIterable<string | Uint8Array>;
      /**
       * Remove what the body keeps outside memory, whether or not it was read.
       * Safe to call twice; the body calls it when it ends or fails.
       */
      readonly discard: () => Promise<void>;
    }
  | Refusal;

/**
 * The most stored bytes an alias read builds in memory: a read above it, which
 * is not windowed into a spool, is refused (`too_large`). Main's limit.
 */
export const ARRAY_BUDGET = 64 * 1024 * 1024;

/** Characters of a windowed body's elements joined before they are written. */
const OUTPUT_PIECE_CHARS = 64 * 1024;
const encoder = new TextEncoder();

/** The input a projection works on, decided and pinned. */
interface View {
  readonly connectionId: string;
  readonly fetched: readonly string[];
  readonly current: AliasViewCheck;
}

/** A body built: its text before the elements of a spooled array, the file of those elements, the text after. */
interface Built {
  readonly head: string;
  readonly file?: { readonly files: StreamSyncFiles; readonly path: string };
  readonly tail: string;
}

type Outcome = Refusal | { readonly kind: "ok"; readonly built: Built };

/**
 * Project the installed records of an alias scope for a read, or say why it
 * has no body. Reads the local database only; `query` may be wrapped by the
 * caller to substitute retained heads.
 *
 * The projection is done once, before a byte is promised, and the body is then
 * a result, not a computation. With `env.spool`, a windowed binding is
 * projected a window of parents at a time and each window's elements are
 * written to a file; the index and the window are held from the governor while
 * that runs, which is the server's pace and not the client's, and are given
 * back before the body is returned. The body then streams the file, and a
 * reader that pauses holds a file and no memory. Any other read is projected
 * whole, holding the memory of its rows and of its projection from the
 * governor until its text is built; the text is what the body keeps, as main
 * keeps it, and a read above `ARRAY_BUDGET` is refused. A result whose body is
 * never read has a file to remove: `discard`.
 */
export async function projectAlias(
  binding: LocalAliasTarget,
  candidate: Candidate,
  query: RecordQuery,
  now: string,
  env: AliasEnv,
): Promise<AliasProjection> {
  const outcome = await build(binding, candidate, query, now, env, true);
  return outcome.kind === "ok" ? bodyOf(outcome.built) : outcome;
}

/**
 * Whether a body can be built from the installed records, and nothing kept:
 * for a listing, which only reads. It decides as `projectAlias` does, on the
 * same `env`: a host with a spool checks a windowed binding a window at a
 * time, and a host without one builds it whole, so it refuses what a read
 * would refuse.
 */
export async function checkAlias(
  binding: LocalAliasTarget,
  candidate: Candidate,
  query: RecordQuery,
  now: string,
  env: AliasEnv,
): Promise<AliasCheck> {
  const outcome = await build(binding, candidate, query, now, env, false);
  return outcome.kind === "ok" ? { kind: "ok" } : outcome;
}

/**
 * The one rule for how a body is built, shared by a read and a listing's
 * check: a windowed binding is paged where the host has a spool and the query
 * can size its rows; every other read is built whole. `keep`: write the
 * elements to the spool (a read), or only check them (a listing).
 */
function build(
  binding: LocalAliasTarget,
  candidate: Candidate,
  query: RecordQuery,
  now: string,
  env: AliasEnv,
  keep: boolean,
): Promise<Outcome> {
  return inView(binding, candidate, now, env, (view) =>
    binding.window && env.spool && isAliasRecordQuery(query)
      ? paged(
          binding,
          binding.window,
          view,
          query,
          now,
          env,
          keep ? env.spool : undefined,
        )
      : whole(binding, view, query, now, env),
  );
}

/** Remove every file of a spool: the leftovers of a server that stopped mid-read. */
export async function sweepAliasSpool(spool: StreamSyncFiles): Promise<void> {
  for (const path of await spool.list("")) await spool.remove(path);
}

/** The checks every projection starts with, and a read that finds its rows moved. */
async function inView(
  binding: LocalAliasTarget,
  candidate: Candidate,
  now: string,
  env: AliasEnv,
  work: (view: View) => Promise<Outcome>,
): Promise<Outcome> {
  if (invalidAliasBinding(binding)) return { kind: "invalid_binding" };
  // Check all input heads, before reading even one record or creating a body.
  if (
    candidate.streams.some((s) => s.profile_key !== candidate.target.connector)
  ) {
    return { kind: "no_data" };
  }
  const fetched = candidate.streams.map((s) => s.stream);
  if (binding.windowed || binding.window) {
    const probe = binding.project([], now, fetched);
    if (!probe.ok && probe.error.kind === "invalid_binding")
      return { kind: "invalid_binding" };
    if (!probe.ok && probe.error.kind.includes("profile")) {
      return { kind: "no_data" };
    }
  }
  const connectionId = candidate.connection.connection_id;
  const epochs =
    env.epochs ?? (await pinAliasStreams(env.db, connectionId, fetched));
  const current = aliasViewCheck(
    readerOf(env.db),
    candidate.connection,
    candidate.streams,
    epochs,
  );
  try {
    return await work({ connectionId, fetched, current });
  } catch (error) {
    if (error instanceof PartialViewMoved) return { kind: "moved" };
    throw error;
  }
}

/** The result of a body that is built: its text, then its file, then its tail. */
function bodyOf(built: Built): AliasProjection {
  const discard = async () => {
    if (!built.file) return;
    try {
      await built.file.files.remove(built.file.path);
    } catch {
      // The file is left for the startup sweep; a failed removal must not
      // fail a response that was served.
    }
  };
  async function* chunks(): AsyncGenerator<string | Uint8Array> {
    try {
      for (let at = 0; at < built.head.length;) {
        const end = pieceEnd(built.head, at);
        yield built.head.slice(at, end);
        at = end;
      }
      if (built.file) yield* built.file.files.readChunks(built.file.path);
      if (built.tail !== "") yield built.tail;
    } finally {
      await discard();
    }
  }
  return { kind: "ok", body: chunks, discard };
}

/**
 * Every row projected in one call. Over a query that sizes its rows, the
 * memory of the rows and of their projection is held from the governor while
 * they are read and projected and the text is built; the text is then the
 * only copy, and is not held from the governor. Over a plain `RecordQuery`,
 * which cannot size them, the rows are streamed and counted, as main does.
 */
async function whole(
  binding: LocalAliasTarget,
  view: View,
  query: RecordQuery,
  now: string,
  env: AliasEnv,
): Promise<Outcome> {
  const { fetched, current } = view;
  const project = async (records: LocalAliasRecord[]): Promise<Outcome> => {
    // Checked after the rows are read, so every one of them is a pinned row.
    await assertViewCurrent(current);
    const projected = binding.project(records, now, fetched);
    if (!projected.ok && projected.error.kind === "invalid_binding")
      return { kind: "invalid_binding" };
    if (!projected.ok) return { kind: "no_data" };
    // A payload that leaves rows out is not the data: refuse it, as the
    // flag-off path does (`canonical_view_incomplete`), never serve it short.
    const incomplete = incompleteDiagnostics(projected.diagnostics);
    return incomplete.length > 0
      ? { kind: "incomplete", diagnostics: incomplete }
      : {
          kind: "ok",
          built: { head: JSON.stringify(projected.payload), tail: "" },
        };
  };
  return isAliasRecordQuery(query)
    ? wholeSized(view, query, env, project)
    : wholeStreamed(view, query, project, env.signal);
}

type Project = (records: LocalAliasRecord[]) => Promise<Outcome>;

/** Sized first, held from the governor, then read: refused above `ARRAY_BUDGET`. */
async function wholeSized(
  view: View,
  query: AliasRecordQuery,
  env: AliasEnv,
  project: Project,
): Promise<Outcome> {
  const { connectionId, fetched, current } = view;
  const sizes = new Map<string, StreamLimits>();
  let bytes = 0;
  for (const stream of fetched) {
    const stats = await query.streamStats(connectionId, stream);
    sizes.set(stream, stats);
    bytes += stats.bytes;
  }
  if (bytes > ARRAY_BUDGET) return { kind: "too_large", bytes };
  const release = await holdMemory(
    env.memory,
    wholeReadCharge(env.memory, bytes),
    0,
    env.signal,
  );
  try {
    const records: LocalAliasRecord[] = [];
    for (const stream of fetched) {
      for await (const batch of sizedBodies(
        query,
        connectionId,
        stream,
        sizes.get(stream)!,
        WHOLE_STREAM_BATCH_BYTES,
        current,
        env.signal,
      )) {
        for (const { record } of batch) {
          records.push({
            stream,
            data: JSON.parse(record.body) as Record<string, unknown>,
          });
        }
      }
    }
    return await project(records);
  } finally {
    release();
  }
}

/** Streamed and counted as it is read, with no governor: main's read of a plain `RecordQuery`. */
async function wholeStreamed(
  view: View,
  query: RecordQuery,
  project: Project,
  signal: AbortSignal | undefined,
): Promise<Outcome> {
  const records: LocalAliasRecord[] = [];
  let bytes = 0;
  for (const stream of view.fetched) {
    for await (const record of query.streamRecords(view.connectionId, stream)) {
      signal?.throwIfAborted();
      bytes += encoder.encode(record.body).byteLength;
      if (bytes > ARRAY_BUDGET) return { kind: "too_large", bytes };
      records.push({
        stream,
        data: JSON.parse(record.body) as Record<string, unknown>,
      });
    }
  }
  return project(records);
}

/**
 * Where the piece of `text` that starts at `at` ends: `OUTPUT_PIECE_CHARS`
 * later, but never between the two halves of a surrogate pair. Each piece is
 * encoded to UTF-8 on its own, and half a pair encodes as U+FFFD. (`text` is
 * `JSON.stringify` output, so every surrogate in it is part of a pair.)
 */
function pieceEnd(text: string, at: number): number {
  const end = Math.min(at + OUTPUT_PIECE_CHARS, text.length);
  if (end === text.length) return end;
  const last = text.charCodeAt(end - 1);
  return last >= 0xd800 && last <= 0xdbff ? end - 1 : end;
}

/** A diagnostic of one kind on one stream, summed over windows. */
interface Tally {
  readonly kind: string;
  readonly stream: string;
  count: number;
  readonly reasons: string[];
}

/**
 * A windowed read, a window of parents at a time, once. The payload's other
 * keys and the diagnostics are summed over the windows; with `spool`, each
 * window's elements are appended to a file as they are projected, so nothing
 * of a window outlives it. A file is removed unless the result keeps it.
 */
async function paged(
  binding: LocalAliasTarget,
  window: AliasWindow,
  view: View,
  query: AliasRecordQuery,
  now: string,
  env: AliasEnv,
  spool: StreamSyncFiles | undefined,
): Promise<Outcome> {
  const { connectionId, fetched, current } = view;
  let session: WindowedRead | null;
  try {
    session = await openWindowed({
      query,
      connectionId,
      binding,
      window,
      fetched,
      now,
      memory: env.memory,
      current,
      signal: env.signal,
    });
  } catch (error) {
    // A group that does not fit the window ceiling is read as main read it:
    // whole, in memory, charged as any in-memory read is, and refused above
    // `ARRAY_BUDGET`. It holds what main held for the same read, so a read main
    // served is served and one main refused is refused.
    if (error instanceof AliasTooLarge) {
      return whole(binding, view, query, now, env);
    }
    throw error;
  }
  // A child names no parent, or a row has no key to join on: not windowable.
  if (session === null) return whole(binding, view, query, now, env);
  const file = spool && {
    files: spool,
    path: `alias-${globalThis.crypto.randomUUID()}`,
  };
  const sums = new Map(window.sumKeys.map((key) => [key, 0]));
  const tallies = new Map<string, Tally>();
  let template: Record<string, unknown> | undefined;
  let keyOrder: string[] = [];
  let piece = "";
  let first = true;
  const write = async () => {
    await file!.files.appendMany([
      { path: file!.path, bytes: encoder.encode(piece) },
    ]);
    piece = "";
  };
  let result: Outcome | undefined;
  try {
    for await (const outcome of session.windows()) {
      env.signal?.throwIfAborted();
      if (!outcome.ok) {
        result =
          outcome.error.kind === "invalid_binding"
            ? { kind: "invalid_binding" }
            : { kind: "no_data" };
        break;
      }
      // The first window's payload shapes the whole: its other keys equal
      // every window's. Its array is not kept.
      if (template === undefined) {
        keyOrder = Object.keys(outcome.payload);
        template = { ...outcome.payload };
        delete template[window.arrayKey];
      }
      for (const key of window.sumKeys) {
        sums.set(key, sums.get(key)! + (outcome.payload[key] as number));
      }
      for (const d of outcome.diagnostics) tally(tallies, d);
      if (!file) continue;
      for (const item of outcome.payload[window.arrayKey] as unknown[]) {
        piece += (first ? "" : ",") + (JSON.stringify(item) ?? "null");
        first = false;
        if (piece.length >= OUTPUT_PIECE_CHARS) await write();
      }
    }
    const incomplete = incompleteDiagnostics(
      [...tallies.values()].map((t): AliasDiagnostic => ({
        kind: t.kind,
        stream: t.stream,
        count: t.count,
        reasons: t.reasons,
      })),
    );
    if (result === undefined && incomplete.length > 0) {
      result = { kind: "incomplete", diagnostics: incomplete };
    }
    // `template` is undefined only if every window was empty: the parents were
    // the whole input. Unreachable for a plan with a window, but never serve an
    // empty body for it: it is projected whole.
    if (result === undefined && template !== undefined) {
      if (file && piece !== "") await write();
      for (const key of window.sumKeys) template[key] = sums.get(key);
      const [head, tail] = envelopeAround(template, window.arrayKey, keyOrder);
      result = { kind: "ok", built: { head, file, tail } };
    }
  } finally {
    session.release();
    // Anything but a kept file is removed, a failure of the read included.
    if (file && result?.kind !== "ok") {
      await file.files.remove(file.path).catch(() => undefined);
    }
  }
  return result ?? whole(binding, view, query, now, env);
}

/**
 * The JSON of the payload before its array's elements and after them, built
 * from its fields: each field is serialized on its own, and the array's key
 * is where the elements go. No text of any field is searched, so no value can
 * be taken for a marker.
 */
function envelopeAround(
  fields: Record<string, unknown>,
  arrayKey: string,
  order: readonly string[],
): [prefix: string, suffix: string] {
  const entry = (key: string): string[] => {
    const value = JSON.stringify(fields[key]);
    return value === undefined ? [] : [`${JSON.stringify(key)}:${value}`];
  };
  const at = order.indexOf(arrayKey);
  if (at < 0) {
    throw new Error("alias window: the payload has no array to place");
  }
  const before = order.slice(0, at).flatMap(entry);
  const after = order.slice(at + 1).flatMap(entry);
  return [
    `{${before.map((e) => `${e},`).join("")}${JSON.stringify(arrayKey)}:[`,
    `]${after.map((e) => `,${e}`).join("")}}`,
  ];
}

function tally(into: Map<string, Tally>, d: AliasDiagnostic): void {
  if (d.kind !== "records_dropped" && d.kind !== "records_partial") return;
  const key = `${d.kind}\u0000${d.stream ?? ""}`;
  const entry = into.get(key) ?? {
    kind: d.kind,
    stream: d.stream ?? "",
    count: 0,
    reasons: [],
  };
  entry.count += d.count ?? 0;
  for (const reason of d.reasons ?? []) {
    if (!entry.reasons.includes(reason)) entry.reasons.push(reason);
  }
  into.set(key, entry);
}

/** The rows a payload leaves out or serves short, as a read names them. */
export function incompleteDiagnostics(
  diagnostics: readonly AliasDiagnostic[] | undefined,
): IncompleteAliasDiagnostic[] {
  return (diagnostics ?? []).flatMap((d) => {
    const kind =
      d.kind === "records_dropped"
        ? "dropped"
        : d.kind === "records_partial"
          ? "partial"
          : null;
    return kind === null
      ? []
      : [
          {
            stream: d.stream ?? "",
            kind,
            detail: `${d.count ?? 0} rows: ${(d.reasons ?? []).join("; ")}`,
          },
        ];
  });
}

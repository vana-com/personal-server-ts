import {
  aliasViewCheck,
  assertViewCurrent,
  pinAliasStreams,
  type AliasViewCheck,
} from "./alias-view.js";
import {
  HEAP_PER_STORED_BYTE,
  openWindowed,
  type AliasMemory,
} from "./alias-window.js";
import type { SqlDriver } from "./driver.js";
import { PartialViewMoved } from "./partial-read.js";
import type { AliasRecordQuery } from "./query.js";
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
  /** The database the rows are read from: pins and checks run on it. */
  readonly db: SqlDriver;
  readonly memory: AliasMemory;
  /**
   * The stream epochs pinned before the candidate's heads were read
   * (`pinAliasStreams`). Absent: pinned here, after them.
   */
  readonly epochs?: ReadonlyMap<string, number>;
}

export type AliasProjection =
  | {
      readonly kind: "ok";
      /**
       * The payload's JSON, a piece at a time. Nothing is read or held until
       * the first piece is asked for. From then until the last piece is taken
       * (or the body is cancelled) the memory it needs is held from the
       * governor, and then it is given back.
       */
      readonly body: () => AsyncIterable<string>;
    }
  | { readonly kind: "no_data" }
  | { readonly kind: "invalid_binding" }
  | {
      readonly kind: "incomplete";
      readonly diagnostics: readonly IncompleteAliasDiagnostic[];
    }
  /** The rows changed while the projection was checked: ask again. */
  | { readonly kind: "moved" };

/** Characters of a windowed body's elements joined before they are yielded. */
const OUTPUT_PIECE_CHARS = 64 * 1024;

/**
 * Project the installed records of an alias scope, or say why it has no body.
 * Reads the local database only; `query` may be wrapped by the caller to
 * substitute retained heads.
 *
 * A windowed binding is projected a window of parents at a time, twice: once
 * here, to learn its diagnostics and totals before any byte is promised, and
 * once in `body`, which writes each window as it is projected. Any other
 * binding is projected whole, also twice: the check here keeps nothing, and
 * `body` projects again and holds its payload's memory until it is delivered.
 * Both take the memory they hold from `env.memory` and wait for it; none
 * refuses a size. Neither pass is held between calls, so a result whose body
 * is never read holds nothing.
 */
export async function projectAlias(
  binding: LocalAliasTarget,
  candidate: Candidate,
  query: AliasRecordQuery,
  now: string,
  env: AliasEnv,
): Promise<AliasProjection> {
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
    env.db,
    candidate.connection,
    candidate.streams,
    epochs,
  );
  try {
    return binding.window
      ? await paged(
          binding,
          binding.window,
          connectionId,
          fetched,
          query,
          now,
          env,
          current,
        )
      : await whole(binding, connectionId, fetched, query, now, env, current);
  } catch (error) {
    if (error instanceof PartialViewMoved) return { kind: "moved" };
    throw error;
  }
}

/**
 * Every row projected in one call. The check holds the memory of the rows and
 * of their projection while it runs, and keeps none of it. The body takes that
 * memory again and keeps it until its last piece is taken, or it is cancelled:
 * the payload it serializes is built and held under that reservation, and no
 * other copy outlives the check.
 */
async function whole(
  binding: LocalAliasTarget,
  connectionId: string,
  fetched: readonly string[],
  query: AliasRecordQuery,
  now: string,
  env: AliasEnv,
  current: AliasViewCheck,
): Promise<AliasProjection> {
  /** The memory of every row and of its projection, from the governor. */
  const hold = async () => {
    let bytes = 0;
    for (const stream of fetched) {
      bytes += (await query.streamStats(connectionId, stream)).bytes;
    }
    return holdMemory(env.memory, bytes * HEAP_PER_STORED_BYTE, 0);
  };
  /** Project every row. Call it with the memory held. */
  const project = async () => {
    const records: LocalAliasRecord[] = [];
    for (const stream of fetched) {
      for await (const record of query.streamRecords(connectionId, stream)) {
        records.push({
          stream,
          data: JSON.parse(record.body) as Record<string, unknown>,
        });
      }
    }
    // Checked after the rows are read, so every one of them is a pinned row.
    await assertViewCurrent(current);
    return binding.project(records, now, fetched);
  };
  async function* body(): AsyncGenerator<string> {
    const release = await hold();
    try {
      const projected = await project();
      // The view is the one the check saw, so this is the payload it passed.
      if (
        !projected.ok ||
        incompleteDiagnostics(projected.diagnostics).length > 0
      ) {
        throw new Error("alias projection changed since it was checked");
      }
      const text = JSON.stringify(projected.payload);
      // A piece at a time, with the memory held until the last is taken: a
      // consumer that pauses, or stops, leaves the payload in memory under it.
      for (let at = 0; at < text.length; at += OUTPUT_PIECE_CHARS) {
        yield text.slice(at, at + OUTPUT_PIECE_CHARS);
      }
    } finally {
      release();
    }
  }
  const release = await hold();
  try {
    const projected = await project();
    if (!projected.ok && projected.error.kind === "invalid_binding")
      return { kind: "invalid_binding" };
    if (!projected.ok) return { kind: "no_data" };
    // A payload that leaves rows out is not the data: refuse it, as the
    // flag-off path does (`canonical_view_incomplete`), never serve it short.
    const incomplete = incompleteDiagnostics(projected.diagnostics);
    return incomplete.length > 0
      ? { kind: "incomplete", diagnostics: incomplete }
      : { kind: "ok", body };
  } finally {
    release();
  }
}

/** A diagnostic of one kind on one stream, summed over windows. */
interface Tally {
  readonly kind: string;
  readonly stream: string;
  count: number;
  readonly reasons: string[];
}

async function paged(
  binding: LocalAliasTarget,
  window: AliasWindow,
  connectionId: string,
  fetched: readonly string[],
  query: AliasRecordQuery,
  now: string,
  env: AliasEnv,
  current: AliasViewCheck,
): Promise<AliasProjection> {
  const open = () =>
    openWindowed({
      query,
      connectionId,
      binding,
      window,
      fetched,
      now,
      memory: env.memory,
      current,
    });
  const session = await open();
  // A child names no parent, or a row has no key to join on: not windowable.
  if (session === null) {
    return whole(binding, connectionId, fetched, query, now, env, current);
  }
  const sums = new Map(window.sumKeys.map((key) => [key, 0]));
  const tallies = new Map<string, Tally>();
  let template: Record<string, unknown> | undefined;
  try {
    for await (const outcome of session.windows()) {
      if (!outcome.ok) {
        return outcome.error.kind === "invalid_binding"
          ? { kind: "invalid_binding" }
          : { kind: "no_data" };
      }
      // The first window's payload shapes the whole: its other keys equal
      // every window's. Its array is not kept.
      if (template === undefined) {
        template = { ...outcome.payload };
        template[window.arrayKey] = PLACEHOLDER;
      }
      for (const key of window.sumKeys) {
        sums.set(key, sums.get(key)! + (outcome.payload[key] as number));
      }
      for (const d of outcome.diagnostics) tally(tallies, d);
    }
  } finally {
    session.release();
  }
  const incomplete = incompleteDiagnostics(
    [...tallies.values()].map((t): AliasDiagnostic => ({
      kind: t.kind,
      stream: t.stream,
      count: t.count,
      reasons: t.reasons,
    })),
  );
  if (incomplete.length > 0)
    return { kind: "incomplete", diagnostics: incomplete };
  if (template === undefined) {
    // Every window was empty: the parents were the whole input. Unreachable
    // for a plan with a window, but never serve an empty body for it.
    return whole(binding, connectionId, fetched, query, now, env, current);
  }
  for (const key of window.sumKeys) template[key] = sums.get(key);
  const text = JSON.stringify(template);
  const marker = JSON.stringify(PLACEHOLDER);
  const at = text.indexOf(marker);
  if (at < 0 || text.indexOf(marker, at + 1) >= 0) {
    throw new Error("alias window: the payload's array could not be placed");
  }
  const prefix = `${text.slice(0, at)}[`;
  const suffix = `]${text.slice(at + marker.length)}`;
  return {
    kind: "ok",
    body: () => pagedBody(open, window.arrayKey, prefix, suffix),
  };
}

const PLACEHOLDER = "\u0000alias-window-array\u0000";

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

/**
 * The payload's JSON: `prefix`, the elements of every window joined by commas,
 * `suffix`. An error after the first piece ends the body in that error, so a
 * reader sees a failed read and never a short, valid document.
 */
async function* pagedBody(
  open: () => Promise<Awaited<ReturnType<typeof openWindowed>>>,
  arrayKey: string,
  prefix: string,
  suffix: string,
): AsyncGenerator<string> {
  const session = await open();
  // The rows no longer window as they did when the read was checked.
  if (session === null) throw new PartialViewMoved();
  try {
    yield prefix;
    let first = true;
    let piece = "";
    for await (const outcome of session.windows()) {
      if (!outcome.ok) {
        throw new Error(
          `alias window projection failed: ${outcome.error.kind}`,
        );
      }
      for (const item of outcome.payload[arrayKey] as unknown[]) {
        piece += (first ? "" : ",") + (JSON.stringify(item) ?? "null");
        first = false;
        if (piece.length >= OUTPUT_PIECE_CHARS) {
          yield piece;
          piece = "";
        }
      }
    }
    if (piece !== "") yield piece;
    yield suffix;
  } finally {
    session.release();
  }
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

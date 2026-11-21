import type { Reservation } from "../stream-sync/send-gate.js";
import type { StreamSyncBlobs } from "../stream-sync/ports.js";
import {
  sizedBodies,
  WHOLE_STREAM_BATCH_BYTES,
  type StreamLimits,
} from "./alias-sized.js";
import { assertViewCurrent, type AliasViewCheck } from "./alias-view.js";
import { PartialViewMoved } from "./partial-read.js";
import type { AliasRecordQuery, SizedRecord } from "./query.js";
import type {
  AliasDiagnostic,
  AliasWindow,
  LocalAliasRecord,
  LocalAliasTarget,
} from "./resolve.js";
import { holdMemory } from "./transfer-memory.js";

/**
 * A windowed alias read: the projection of a binding that builds one output
 * element per parent row, computed a window of parents at a time.
 *
 * What it holds, and why that is the governor's to give. The read keeps an
 * index of the whole input (every parent row, and for each parent the key
 * hashes of its children) and one window's rows, parsed. Both are charged to
 * the store's byte budget (`StorageAccessPolicy.maxBytesInFlight`) in one
 * reservation, taken while the read holds nothing: under pressure the read
 * waits for its turn, and no size makes it fail. The window is a chunk of that
 * reservation, never a limit: a parent whose own rows are larger than a chunk
 * is a window of its own, and takes the larger reservation it needs.
 *
 * Nothing is held before it is reserved. The children are indexed a batch of
 * bodies at a time (their join key is read from the body: shared SQL has no
 * JSON functions), each batch no larger than the reservation's chunk, so the
 * bodies in memory are the ones the reservation was taken for. A larger
 * reservation is asked for with the index dropped, then the index is built
 * again under it: a read that waits holds neither a reservation nor an index.
 */
export type AliasMemory = Pick<StreamSyncBlobs, "governor">;

/**
 * Heap bytes held for each byte of stored JSON while its window is projected:
 * the text read, its parsed objects, the projected copy and the serialized
 * element. An estimate, so the budget is charged for what a window really
 * takes rather than for the size of its text. The windowed read's large-account
 * test reports the heap it measured against what was held.
 */
export const HEAP_PER_STORED_BYTE = 4;

/**
 * Heap bytes one child row costs the index: its sized record (a 64-character
 * key hash and a 64-character body hash, which the body statement checks) and
 * the slot that holds it.
 */
const INDEX_BYTES_PER_CHILD = 256;

/**
 * The share of the budget one windowed read takes for its working set. The
 * rest stays free for uploads, which draw on the same budget, so a long read
 * does not stop a publish. It sizes the chunk only: a read that needs more
 * than its share (a parent with more rows than a chunk) takes what it needs.
 */
const READ_SHARE = 0.5;

export type WindowOutcome =
  | {
      readonly ok: true;
      readonly payload: Record<string, unknown>;
      readonly diagnostics: readonly AliasDiagnostic[];
    }
  | { readonly ok: false; readonly error: { readonly kind: string } };

export interface WindowedInput {
  readonly query: AliasRecordQuery;
  readonly connectionId: string;
  readonly binding: LocalAliasTarget;
  readonly window: AliasWindow;
  /** The streams the read serves, installed and complete. */
  readonly fetched: readonly string[];
  readonly now: string;
  readonly memory: AliasMemory;
  /**
   * Whether the rows read are still those the read was decided on. Every read
   * of bodies carries its `guard`, so a body is read from the state it was
   * sized in or not at all.
   */
  readonly current: AliasViewCheck;
  /** Ends a wait for memory: the read leaves the governor's line. */
  readonly signal?: AbortSignal;
}

export interface WindowedRead {
  /** The projection of each window, in the output order of the parents. */
  windows(): AsyncGenerator<WindowOutcome, void>;
  /** Give the memory back. Safe to call twice. */
  release(): void;
}

interface Parent {
  readonly data: Record<string, unknown>;
  readonly key: unknown;
  readonly chars: number;
}

interface ChildGroup {
  readonly sized: SizedRecord[];
  chars: number;
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** A key a window can join on: a string or a number. */
const joinable = (value: unknown): boolean =>
  typeof value === "string" || typeof value === "number";

/**
 * Open a windowed read: size and take its memory, index the input and plan its
 * windows. `null` when the input cannot be windowed, because a row has no
 * usable key or a child names no parent (`LegacyProjectionWindow`: a caller
 * must refuse such input rather than window it); the caller then projects the
 * input whole.
 */
export async function openWindowed(
  input: WindowedInput,
): Promise<WindowedRead | null> {
  const { query, connectionId, window, fetched } = input;
  if (!fetched.includes(window.parentStream)) return null;
  const hasChildren = fetched.includes(window.childStream);
  const others = fetched.filter(
    (s) => s !== window.parentStream && s !== window.childStream,
  );
  // What each stream was sized at: the reservation is taken for these, and
  // every body statement below stays inside them.
  const limits = new Map<string, StreamLimits>();
  for (const stream of [window.parentStream, ...others]) {
    limits.set(stream, await query.streamStats(connectionId, stream));
  }
  const childStats = hasChildren
    ? await query.streamStats(connectionId, window.childStream)
    : { rows: 0, bytes: 0, maxBytes: 0 };
  limits.set(window.childStream, childStats);
  let otherBytes = 0;
  for (const stream of others) otherBytes += limits.get(stream)!.bytes;
  const parentStats = limits.get(window.parentStream)!;

  // What the index and the whole of the other streams cost, and then the
  // chunk: what is left of the read's share, as source bytes of one window.
  const fixed =
    (parentStats.bytes + otherBytes) * HEAP_PER_STORED_BYTE +
    childStats.rows * INDEX_BYTES_PER_CHILD;
  const share = Math.floor(input.memory.governor.limitBytes * READ_SHARE);
  const chunk = Math.max(0, Math.floor((share - fixed) / HEAP_PER_STORED_BYTE));
  // While the children are indexed, a batch of their bodies is in memory: no
  // more than a chunk, or one body if that is larger.
  const scan = Math.max(chunk, childStats.maxBytes);
  let held = fixed + scan * HEAP_PER_STORED_BYTE;
  let reservation: Reservation | undefined = await holdMemory(
    input.memory,
    held,
    0,
    input.signal,
  );
  const release = () => {
    reservation?.();
    reservation = undefined;
  };
  try {
    for (;;) {
      const attempt = await indexAndPlan(
        input,
        others,
        hasChildren,
        limits,
        scan,
        chunk,
        fixed,
        held,
      );
      if (attempt.kind === "unwindowable") {
        // Rows a moved view hid can only make the input look unwindowable.
        await assertViewCurrent(input.current);
        release();
        return null;
      }
      if (attempt.kind === "fits") {
        // The reservation is what the largest window needs, no more.
        reservation?.shrink(attempt.need);
        await assertViewCurrent(input.current);
        const { parents, children, otherRecords, plan } = attempt;
        return {
          windows: () =>
            runWindows(
              input,
              parents,
              children,
              otherRecords,
              plan,
              hasChildren,
            ),
          release,
        };
      }
      // The largest window needs more than is held. The index was dropped
      // with the attempt: hold nothing while the larger reservation waits,
      // then build the index again under it. On a view that has not moved the
      // same rows give the same plan, so the second attempt fits.
      await assertViewCurrent(input.current);
      release();
      held = attempt.need;
      reservation = await holdMemory(input.memory, held, 0, input.signal);
    }
  } catch (error) {
    release();
    throw error;
  }
}

interface Indexed {
  readonly parents: Parent[];
  readonly children: Map<unknown, ChildGroup>;
  readonly otherRecords: LocalAliasRecord[];
  readonly plan: PlannedWindow[];
}

/**
 * Index the input and plan its windows under `held` bytes. When the largest
 * window needs more than that, the answer is the size alone: the index is the
 * frame's, and gone when it returns.
 */
async function indexAndPlan(
  input: WindowedInput,
  others: readonly string[],
  hasChildren: boolean,
  limits: ReadonlyMap<string, StreamLimits>,
  scan: number,
  chunk: number,
  fixed: number,
  held: number,
): Promise<
  | { readonly kind: "unwindowable" }
  | { readonly kind: "larger"; readonly need: number }
  | ({ readonly kind: "fits"; readonly need: number } & Indexed)
> {
  const indexed = await indexInput(input, others, hasChildren, limits, scan);
  if (indexed === null) return { kind: "unwindowable" };
  const { parents, children } = indexed;
  parents.sort((a, b) => input.window.parentOrder(a.data, b.data));
  const plan = planWindows(parents, children, chunk);
  const need =
    fixed +
    HEAP_PER_STORED_BYTE * plan.reduce((m, w) => Math.max(m, w.chars), 0);
  return need <= held
    ? { kind: "fits", need, ...indexed, plan }
    : { kind: "larger", need };
}

async function indexInput(
  input: WindowedInput,
  others: readonly string[],
  hasChildren: boolean,
  limits: ReadonlyMap<string, StreamLimits>,
  scan: number,
): Promise<{
  parents: Parent[];
  children: Map<unknown, ChildGroup>;
  otherRecords: LocalAliasRecord[];
} | null> {
  const { query, connectionId, window } = input;
  const parents: Parent[] = [];
  const children = new Map<unknown, ChildGroup>();
  // Parents and other streams are held whole, under the memory reserved for
  // their stored size: each is read by sized batches inside that size.
  const bodies = (stream: string) =>
    sizedBodies(
      query,
      connectionId,
      stream,
      limits.get(stream)!,
      WHOLE_STREAM_BATCH_BYTES,
      input.current,
    );
  for await (const batch of bodies(window.parentStream)) {
    for (const { record } of batch) {
      const data: unknown = JSON.parse(record.body);
      if (!isObject(data)) return null;
      const key = data[window.parentKey];
      if (!joinable(key) || children.has(key)) return null;
      children.set(key, { sized: [], chars: 0 });
      parents.push({ data, key, chars: record.body.length });
    }
  }
  if (hasChildren && !(await indexChildren(input, children, limits, scan))) {
    return null;
  }
  const otherRecords: LocalAliasRecord[] = [];
  for (const stream of others) {
    for await (const batch of bodies(stream)) {
      for (const { record } of batch) {
        otherRecords.push({
          stream,
          data: JSON.parse(record.body) as Record<string, unknown>,
        });
      }
    }
  }
  return { parents, children, otherRecords };
}

/**
 * Add each child's sized record to its parent's group. The bodies are read,
 * to find the key they name, `scan` stored bytes at a time (a body larger than
 * that, alone) and are not kept. False when a child names no parent or is not
 * an object.
 */
async function indexChildren(
  input: WindowedInput,
  children: ReadonlyMap<unknown, ChildGroup>,
  limits: ReadonlyMap<string, StreamLimits>,
  scan: number,
): Promise<boolean> {
  const { query, connectionId, window } = input;
  // The children's bodies are not held whole: only a batch of them, so no
  // limit on their total, but their count (what the index was charged for)
  // and each one's size (what `scan` was taken for) stay inside what was sized.
  const childLimits: StreamLimits = {
    ...limits.get(window.childStream)!,
    bytes: Number.POSITIVE_INFINITY,
  };
  for await (const batch of sizedBodies(
    query,
    connectionId,
    window.childStream,
    childLimits,
    scan,
    input.current,
  )) {
    for (const { record, sized } of batch) {
      const data: unknown = JSON.parse(record.body);
      if (!isObject(data)) return false;
      const group = children.get(data[window.childKey]);
      if (!group) return false;
      group.sized.push(sized);
      group.chars += sized.bytes;
    }
  }
  return true;
}

interface PlannedWindow {
  readonly from: number;
  readonly to: number;
  /** Stored characters of its parents and their children. */
  readonly chars: number;
}

/** Cut the parents, in order, into windows of about `chunk` stored characters. */
function planWindows(
  parents: readonly Parent[],
  children: ReadonlyMap<unknown, ChildGroup>,
  chunk: number,
): PlannedWindow[] {
  const plan: PlannedWindow[] = [];
  let from = 0;
  let chars = 0;
  parents.forEach((parent, i) => {
    const own = parent.chars + children.get(parent.key)!.chars;
    if (i > from && chars + own > chunk) {
      plan.push({ from, to: i, chars });
      from = i;
      chars = 0;
    }
    chars += own;
  });
  if (parents.length > from) plan.push({ from, to: parents.length, chars });
  return plan;
}

async function* runWindows(
  input: WindowedInput,
  parents: readonly Parent[],
  children: ReadonlyMap<unknown, ChildGroup>,
  otherRecords: readonly LocalAliasRecord[],
  plan: readonly PlannedWindow[],
  hasChildren: boolean,
): AsyncGenerator<WindowOutcome, void> {
  const { query, connectionId, window, binding, now, fetched } = input;
  for (const { from, to } of plan) {
    const inWindow = parents.slice(from, to);
    const sized = inWindow.flatMap((p) => children.get(p.key)!.sized);
    const rows =
      hasChildren && sized.length > 0
        ? await query.recordsByHash(
            connectionId,
            window.childStream,
            sized,
            input.current.guard,
          )
        : [];
    // A row gone, changed or grown since the index was read: the view moved.
    if (rows.length !== sized.length) throw new PartialViewMoved();
    // Checked after the rows are read, so every one of them is a pinned row.
    await assertViewCurrent(input.current);
    const records: LocalAliasRecord[] = [
      ...inWindow.map((p) => ({ stream: window.parentStream, data: p.data })),
      ...rows.map((row) => ({
        stream: window.childStream,
        data: JSON.parse(row.body) as Record<string, unknown>,
      })),
      ...otherRecords,
    ];
    const projected = binding.project(records, now, fetched);
    yield projected.ok
      ? {
          ok: true,
          payload: projected.payload as Record<string, unknown>,
          diagnostics: projected.diagnostics ?? [],
        }
      : projected;
  }
}

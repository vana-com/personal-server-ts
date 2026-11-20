import type { Reservation } from "../stream-sync/send-gate.js";
import type { StreamSyncBlobs } from "../stream-sync/ports.js";
import { assertViewCurrent, type AliasViewCheck } from "./alias-view.js";
import type { RecordQuery } from "./query.js";
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
 * Heap bytes one child row costs the index: its 64-character key hash and the
 * slot that holds it.
 */
const INDEX_BYTES_PER_CHILD = 128;

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
  readonly query: RecordQuery;
  readonly connectionId: string;
  readonly binding: LocalAliasTarget;
  readonly window: AliasWindow;
  /** The streams the read serves, installed and complete. */
  readonly fetched: readonly string[];
  readonly now: string;
  readonly memory: AliasMemory;
  /** Whether the rows read are still those the read was decided on. */
  readonly current: AliasViewCheck;
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
  readonly hashes: string[];
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
  const stat = (stream: string) => query.streamStats(connectionId, stream);
  const parentStats = await stat(window.parentStream);
  const childStats = hasChildren
    ? await stat(window.childStream)
    : { rows: 0, bytes: 0 };
  let otherBytes = 0;
  for (const stream of others) otherBytes += (await stat(stream)).bytes;

  // What the index and the whole of the other streams cost, and then the
  // chunk: what is left of the read's share, as source bytes of one window.
  const fixed =
    (parentStats.bytes + otherBytes) * HEAP_PER_STORED_BYTE +
    childStats.rows * INDEX_BYTES_PER_CHILD;
  const share = Math.floor(input.memory.governor.limitBytes * READ_SHARE);
  const chunk = Math.max(0, Math.floor((share - fixed) / HEAP_PER_STORED_BYTE));
  let reservation: Reservation | undefined = await holdMemory(
    input.memory,
    fixed + chunk * HEAP_PER_STORED_BYTE,
    0,
  );
  const release = () => {
    reservation?.();
    reservation = undefined;
  };
  try {
    const indexed = await indexInput(input, others, hasChildren);
    if (indexed === null) {
      release();
      return null;
    }
    const { parents, children, otherRecords } = indexed;
    parents.sort((a, b) => window.parentOrder(a.data, b.data));
    const plan = planWindows(parents, children, chunk);
    // The reservation is what the largest window needs, no more: give back
    // the rest, or take a larger one, holding nothing while it waits.
    const need =
      fixed +
      HEAP_PER_STORED_BYTE * plan.reduce((m, w) => Math.max(m, w.chars), 0);
    const held = fixed + chunk * HEAP_PER_STORED_BYTE;
    if (need <= held) reservation?.shrink(need);
    else {
      release();
      reservation = await holdMemory(input.memory, need, 0);
    }
    await assertViewCurrent(input.current);
    return {
      windows: () =>
        runWindows(input, parents, children, otherRecords, plan, hasChildren),
      release,
    };
  } catch (error) {
    release();
    throw error;
  }
}

async function indexInput(
  input: WindowedInput,
  others: readonly string[],
  hasChildren: boolean,
): Promise<{
  parents: Parent[];
  children: Map<unknown, ChildGroup>;
  otherRecords: LocalAliasRecord[];
} | null> {
  const { query, connectionId, window } = input;
  const parents: Parent[] = [];
  const children = new Map<unknown, ChildGroup>();
  for await (const row of query.streamRecords(
    connectionId,
    window.parentStream,
  )) {
    const data: unknown = JSON.parse(row.body);
    if (!isObject(data)) return null;
    const key = data[window.parentKey];
    if (!joinable(key) || children.has(key)) return null;
    children.set(key, { hashes: [], chars: 0 });
    parents.push({ data, key, chars: row.body.length });
  }
  if (hasChildren) {
    for await (const row of query.streamRecords(
      connectionId,
      window.childStream,
    )) {
      const data: unknown = JSON.parse(row.body);
      if (!isObject(data)) return null;
      const group = children.get(data[window.childKey]);
      if (!group) return null;
      group.hashes.push(row.pkHash);
      group.chars += row.body.length;
    }
  }
  const otherRecords: LocalAliasRecord[] = [];
  for (const stream of others) {
    for await (const row of query.streamRecords(connectionId, stream)) {
      otherRecords.push({
        stream,
        data: JSON.parse(row.body) as Record<string, unknown>,
      });
    }
  }
  return { parents, children, otherRecords };
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
    const hashes = inWindow.flatMap((p) => children.get(p.key)!.hashes);
    const rows =
      hasChildren && hashes.length > 0
        ? await query.recordsByHash(connectionId, window.childStream, hashes)
        : [];
    // A row gone since the index was read: the view moved.
    if (rows.length !== hashes.length) throw await moved(input);
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

async function moved(input: WindowedInput): Promise<Error> {
  await assertViewCurrent(input.current);
  // The view reads as current but a row is missing: the index and the rows
  // disagree, which no pinned read can see. Fail the read; do not serve it.
  return new Error("alias window: an indexed row is missing");
}

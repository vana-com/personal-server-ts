/**
 * Legacy projection of stream views (§2.10).
 *
 * A binding with a `window` (one parent row per output element, built from
 * the parent and its children) streams at any size: parent and child rows
 * are spooled to 256 shards by the hash of the join key. Each shard is then
 * projected on its own, one parent at a time in the binding's `parentOrder`,
 * and its items are spooled with the parent row that orders them. A k-way
 * merge over the shards, one cursor per shard, writes the items in
 * `parentOrder`: the array projector's order. Working memory is about the
 * largest shard while projecting, and one read chunk per shard while
 * merging. The binding's other streams are held whole.
 *
 * Top-level keys come in the array projector's order. Nested keys of a row
 * that passes through come sorted: view lines are canonical JSON.
 *
 * Other bindings use the array projector over the whole input, refused with
 * `too_large` above the byte budget.
 */

import {
  canonicalJson,
  sha256Hex,
  utf8,
  type JsonObject,
  type Line,
  type Sha256,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  projectPdppRecordsToLegacyPayload,
  type LegacyScopeBinding,
  type PdppRecord,
} from "../legacy-projection/index.js";
import type { StreamSyncReadFiles } from "./ports.js";

export interface ProjectionInput {
  readonly scope: string;
  readonly binding: LegacyScopeBinding;
  readonly profileKey: string | undefined;
  /** Records of each bound stream; may be called once per stream. */
  readonly lines: (stream: string) => AsyncIterable<Line>;
  /** Clear bytes of each stream's view (part sizes), for the budget. */
  readonly streamBytes: (stream: string) => number;
  readonly sha256: Sha256;
  readonly spool: StreamSyncReadFiles;
  readonly spoolId: string;
  readonly budgetBytes: number;
  readonly now: string;
}

export type ProjectionPlan =
  | { readonly kind: "ok"; readonly payload: AsyncIterable<string> }
  | { readonly kind: "too_large"; readonly bytes: number };

export class ProjectionFailedError extends Error {}

const SHARDS = 256;
const SPOOL_FLUSH_BYTES = 4 * 1024 * 1024;

function options(input: ProjectionInput) {
  return {
    fetchedStreams: [...input.binding.pdppStreams],
    orderByPrimaryKey: true,
    now: input.now,
    ...(input.profileKey ? { profileKey: input.profileKey } : {}),
  };
}

function project(input: ProjectionInput, records: PdppRecord[]) {
  const result = projectPdppRecordsToLegacyPayload(
    input.scope,
    records,
    options(input),
  );
  if (!result.ok) {
    throw new ProjectionFailedError(`projection failed: ${result.error.kind}`);
  }
  return result.payload as Record<string, unknown>;
}

export async function planProjection(
  input: ProjectionInput,
): Promise<ProjectionPlan> {
  if (input.binding.window) {
    const spooled = await spoolShards(input);
    if (spooled) return { kind: "ok", payload: windowed(input, spooled) };
    // A child row names no parent: the window contract does not hold, so
    // the input goes to the array projector under its budget.
  }
  const bytes = input.binding.pdppStreams.reduce(
    (sum, stream) => sum + input.streamBytes(stream),
    0,
  );
  if (bytes > input.budgetBytes) return { kind: "too_large", bytes };
  const records: PdppRecord[] = [];
  for (const stream of input.binding.pdppStreams) {
    for await (const line of input.lines(stream)) {
      records.push({ stream, data: line.v as Record<string, unknown> });
    }
  }
  const payload = project(input, records);
  return { kind: "ok", payload: single(JSON.stringify(payload)) };
}

async function* single(text: string): AsyncGenerator<string> {
  yield text;
}

interface Spooled {
  /** Per shard, the spool files of parents and children, in write order. */
  readonly parents: string[][];
  readonly children: string[][];
  readonly others: PdppRecord[];
}

async function shardOfKey(sha256: Sha256, value: unknown): Promise<number> {
  const hash = await sha256Hex(sha256, utf8(canonicalJson([value])));
  return parseInt(hash.slice(0, 2), 16);
}

/** Spool parents and children by join-key shard; `null` if a child names no parent. */
async function spoolShards(input: ProjectionInput): Promise<Spooled | null> {
  const window = input.binding.window!;
  const parentKey = input.binding.primaryKey[window.parentStream]![0]!;
  const parents: string[][] = Array.from({ length: SHARDS }, () => []);
  const children: string[][] = Array.from({ length: SHARDS }, () => []);
  const buffers = {
    p: Array.from({ length: SHARDS }, () => [] as string[]),
    c: Array.from({ length: SHARDS }, () => [] as string[]),
  };
  let buffered = 0;
  let flushes = 0;
  const flush = async () => {
    for (const kind of ["p", "c"] as const) {
      for (let shard = 0; shard < SHARDS; shard++) {
        const rows = buffers[kind][shard]!;
        if (rows.length === 0) continue;
        const path = `spool/${input.spoolId}/${kind}${shard}-${flushes}`;
        await input.spool.write(path, utf8(rows.join("\n")));
        (kind === "p" ? parents : children)[shard]!.push(path);
        buffers[kind][shard] = [];
      }
    }
    flushes++;
    buffered = 0;
  };
  const others: PdppRecord[] = [];
  try {
    for (const stream of input.binding.pdppStreams) {
      const kind =
        stream === window.parentStream
          ? "p"
          : stream === window.childStream
            ? "c"
            : null;
      for await (const line of input.lines(stream)) {
        const record = line.v as JsonObject;
        if (kind === null) {
          others.push({ stream, data: record as Record<string, unknown> });
          continue;
        }
        const join = kind === "p" ? record[parentKey] : record[window.childKey];
        if (join === undefined || join === null) {
          if (kind === "c") {
            await input.spool.remove(`spool/${input.spoolId}`);
            return null;
          }
        }
        const shard = await shardOfKey(input.sha256, join ?? null);
        const text = JSON.stringify(record);
        buffers[kind][shard]!.push(text);
        buffered += text.length;
        if (buffered >= SPOOL_FLUSH_BYTES) await flush();
      }
    }
    await flush();
  } catch (error) {
    await input.spool.remove(`spool/${input.spoolId}`);
    throw error;
  }
  return { parents, children, others };
}

async function readRows(
  spool: StreamSyncReadFiles,
  paths: readonly string[],
): Promise<Record<string, unknown>[]> {
  const out: Record<string, unknown>[] = [];
  const decoder = new TextDecoder();
  for (const path of paths) {
    const bytes = await spool.read(path);
    if (!bytes) throw new Error("spool file is missing");
    for (const text of decoder.decode(bytes).split("\n")) {
      out.push(JSON.parse(text) as Record<string, unknown>);
    }
  }
  return out;
}

/**
 * Phase 1: project each shard one parent at a time, in `parentOrder`, and
 * spool `(parent, item)` pairs per shard. A window of one parent with exactly
 * its children is a window the binding contract allows, so each item is
 * tagged with the parent row that orders it.
 */
async function projectShards(
  input: ProjectionInput,
  spooled: Spooled,
): Promise<ProjectedShards> {
  const window = input.binding.window!;
  const parentKey = input.binding.primaryKey[window.parentStream]![0]!;
  const sums: Record<string, number> = Object.fromEntries(
    window.sumKeys.map((key) => [key, 0]),
  );
  const outputs: string[][] = [];
  let template: Record<string, unknown> | null = null;
  for (let shard = 0; shard < SHARDS; shard++) {
    if (spooled.parents[shard]!.length === 0) continue;
    const parents = await readRows(input.spool, spooled.parents[shard]!);
    const children = new Map<string, Record<string, unknown>[]>();
    for (const child of await readRows(input.spool, spooled.children[shard]!)) {
      const join = canonicalJson([child[window.childKey] as JsonObject]);
      const list = children.get(join);
      if (list) list.push(child);
      else children.set(join, [child]);
    }
    parents.sort(window.parentOrder);
    const paths: string[] = [];
    let buffer: string[] = [];
    let buffered = 0;
    const flush = async () => {
      if (buffer.length === 0) return;
      const path = `spool/${input.spoolId}/o${shard}-${paths.length}`;
      await input.spool.write(path, utf8(buffer.join("\n") + "\n"));
      paths.push(path);
      buffer = [];
      buffered = 0;
    };
    for (const parent of parents) {
      const join = canonicalJson([(parent[parentKey] ?? null) as JsonObject]);
      const payload = project(input, [
        { stream: window.parentStream, data: parent },
        ...(children.get(join) ?? []).map((data) => ({
          stream: window.childStream,
          data,
        })),
        ...spooled.others,
      ]);
      template ??= payload;
      for (const key of window.sumKeys) sums[key]! += payload[key] as number;
      const parentText = JSON.stringify(parent);
      for (const item of payload[window.arrayKey] as unknown[]) {
        const itemText = JSON.stringify(item);
        buffer.push(parentText, itemText);
        buffered += parentText.length + itemText.length;
      }
      if (buffered >= SPOOL_FLUSH_BYTES) await flush();
    }
    await flush();
    outputs.push(paths);
  }
  return { outputs, template, sums };
}

interface ProjectedShards {
  /** Per shard with parents, its output files: parent line, item line, … */
  readonly outputs: string[][];
  /** The payload of the first window: every key but the array and sums. */
  readonly template: Record<string, unknown> | null;
  readonly sums: Record<string, number>;
}

/** Lines of `paths`, in order, read a bounded chunk at a time. */
async function* spoolLines(
  spool: StreamSyncReadFiles,
  paths: readonly string[],
): AsyncGenerator<string> {
  for (const path of paths) {
    const decoder = new TextDecoder();
    let rest = "";
    for await (const chunk of spool.readChunks(path)) {
      rest += decoder.decode(chunk, { stream: true });
      let end = rest.indexOf("\n");
      while (end !== -1) {
        yield rest.slice(0, end);
        rest = rest.slice(end + 1);
        end = rest.indexOf("\n");
      }
    }
    rest += decoder.decode();
    if (rest !== "") throw new Error("spool file ends mid-line");
  }
}

interface Cursor {
  readonly shard: number;
  readonly lines: AsyncGenerator<string>;
  parent: Record<string, unknown>;
  item: string;
}

async function advance(cursor: Omit<Cursor, "parent" | "item">) {
  const parent = await cursor.lines.next();
  if (parent.done) return null;
  const item = await cursor.lines.next();
  if (item.done) throw new Error("spool file ends after a parent line");
  return {
    ...cursor,
    parent: JSON.parse(parent.value) as Record<string, unknown>,
    item: item.value,
  };
}

/**
 * Phase 2: a k-way merge of the shards' sorted outputs by `parentOrder`, one
 * cursor per shard. Shard number breaks ties, which only equal parents
 * (the same primary key, so the same shard) could produce.
 */
async function* mergeShards(
  input: ProjectionInput,
  outputs: readonly string[][],
): AsyncGenerator<string> {
  const order = input.binding.window!.parentOrder;
  const before = (a: Cursor, b: Cursor) =>
    order(a.parent, b.parent) < 0 ||
    (order(a.parent, b.parent) === 0 && a.shard < b.shard);
  const heap: Cursor[] = [];
  const push = (cursor: Cursor) => {
    heap.push(cursor);
    let i = heap.length - 1;
    while (i > 0) {
      const up = (i - 1) >> 1;
      if (!before(heap[i]!, heap[up]!)) break;
      [heap[i], heap[up]] = [heap[up]!, heap[i]!];
      i = up;
    }
  };
  const pop = (): Cursor => {
    const top = heap[0]!;
    const last = heap.pop()!;
    if (heap.length > 0) {
      heap[0] = last;
      let i = 0;
      for (;;) {
        const l = 2 * i + 1;
        const r = l + 1;
        let min = i;
        if (l < heap.length && before(heap[l]!, heap[min]!)) min = l;
        if (r < heap.length && before(heap[r]!, heap[min]!)) min = r;
        if (min === i) break;
        [heap[i], heap[min]] = [heap[min]!, heap[i]!];
        i = min;
      }
    }
    return top;
  };
  for (let shard = 0; shard < outputs.length; shard++) {
    const first = await advance({
      shard,
      lines: spoolLines(input.spool, outputs[shard]!),
    });
    if (first) push(first);
  }
  while (heap.length > 0) {
    const top = pop();
    yield top.item;
    const next = await advance(top);
    if (next) push(next);
  }
}

async function* windowed(
  input: ProjectionInput,
  spooled: Spooled,
): AsyncGenerator<string> {
  const window = input.binding.window!;
  try {
    const { outputs, template, sums } = await projectShards(input, spooled);
    if (!template) {
      // No parent rows: the whole projection of the other streams.
      yield JSON.stringify(project(input, [...spooled.others]));
      return;
    }
    // The array projector's key order: the template's, with the merged
    // array and the summed keys in their places.
    let text = "{";
    let comma = "";
    for (const [key, value] of Object.entries(template)) {
      if (key === window.arrayKey) {
        yield `${text}${comma}${JSON.stringify(key)}:[`;
        let first = true;
        for await (const item of mergeShards(input, outputs)) {
          yield (first ? "" : ",") + item;
          first = false;
        }
        text = "]";
        comma = ",";
        continue;
      }
      const out = window.sumKeys.includes(key) ? sums[key] : value;
      if (out === undefined) continue;
      text += `${comma}${JSON.stringify(key)}:${JSON.stringify(out)}`;
      comma = ",";
    }
    yield `${text}}`;
  } finally {
    await input.spool.remove(`spool/${input.spoolId}`);
  }
}

/**
 * Legacy projection of stream views (§2.10).
 *
 * A binding with a `window` (one parent row per output element, built from
 * the parent and its children) streams at any size: parent and child rows
 * are spooled to 256 shards by the hash of the join key, and each shard is
 * projected on its own while the envelope is written. Working memory is
 * about the largest shard. The binding's other streams are held whole.
 *
 * Output order: shard by shard, and within a shard in the binding's
 * `parentOrder`. The array projector orders the whole array by
 * `parentOrder`; the two orders differ when there is more than one shard.
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

async function* windowed(
  input: ProjectionInput,
  spooled: Spooled,
): AsyncGenerator<string> {
  const window = input.binding.window!;
  const fixed = new Set([window.arrayKey, ...window.sumKeys]);
  const sums: Record<string, number> = Object.fromEntries(
    window.sumKeys.map((key) => [key, 0]),
  );
  let opened = false;
  let first = true;
  try {
    for (let shard = 0; shard < SHARDS; shard++) {
      if (spooled.parents[shard]!.length === 0) continue;
      const records: PdppRecord[] = [
        ...(await readRows(input.spool, spooled.parents[shard]!)).map(
          (data) => ({ stream: window.parentStream, data }),
        ),
        ...(await readRows(input.spool, spooled.children[shard]!)).map(
          (data) => ({ stream: window.childStream, data }),
        ),
        ...spooled.others,
      ];
      const payload = project(input, records);
      if (!opened) {
        yield openPayload(payload, fixed, window.arrayKey);
        opened = true;
      }
      for (const item of payload[window.arrayKey] as unknown[]) {
        yield (first ? "" : ",") + JSON.stringify(item);
        first = false;
      }
      for (const key of window.sumKeys) sums[key]! += payload[key] as number;
    }
    if (!opened) {
      // No parent rows: the whole projection of the other streams.
      yield JSON.stringify(project(input, [...spooled.others]));
      return;
    }
    let tail = "]";
    for (const key of window.sumKeys) {
      tail += `,${JSON.stringify(key)}:${JSON.stringify(sums[key])}`;
    }
    yield `${tail}}`;
  } finally {
    await input.spool.remove(`spool/${input.spoolId}`);
  }
}

/** `{` + every key but the array and sums + `"<arrayKey>":[`. */
function openPayload(
  payload: Record<string, unknown>,
  fixed: ReadonlySet<string>,
  arrayKey: string,
): string {
  let text = "{";
  for (const [key, value] of Object.entries(payload)) {
    if (fixed.has(key) || value === undefined) continue;
    text += `${JSON.stringify(key)}:${JSON.stringify(value)},`;
  }
  return `${text}${JSON.stringify(arrayKey)}:[`;
}

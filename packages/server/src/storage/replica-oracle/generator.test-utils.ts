/**
 * Seeded command generator and shrinker for the every-prefix differential
 * (oracle design §2). Commands are plain JSON: operations keep their exact
 * bytes and ids across duplicate, reordered and repartitioned delivery, and
 * a failure report can be pasted back into `runCommands` as-is.
 */
import type {
  DeclarationBinding,
  ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  blobPayload,
  METHOD,
  OWNER,
  SOURCE,
  type BlobPayload,
} from "./ports.test-utils.js";

export const BINDINGS = {
  m: {
    digest: `sha256:${"a".repeat(64)}`,
    version: "1.0.0",
    stream: "messages",
    semantics: "mutable_state",
    primaryKey: ["id"],
    schemaDigest: `sha256:${"b".repeat(64)}`,
  },
  a: {
    digest: `sha256:${"c".repeat(64)}`,
    version: "1.0.0",
    stream: "events",
    semantics: "append_only",
    primaryKey: ["id"],
    schemaDigest: `sha256:${"b".repeat(64)}`,
  },
  /** Same stream as `m`, another declaration: never declared at start. */
  m2: {
    digest: `sha256:${"d".repeat(64)}`,
    version: "2.0.0",
    stream: "messages",
    semantics: "mutable_state",
    primaryKey: ["id"],
    schemaDigest: `sha256:${"e".repeat(64)}`,
  },
} as const satisfies Record<string, DeclarationBinding>;
export type BindingName = keyof typeof BINDINGS;
export const CONNECTIONS = ["c1", "c2", "c3"] as const;
export const PROVISIONED_AT_START = ["c1", "c2"] as const;
export const KEYS = ["k0", "k1", "k2", "k3"] as const;
export const BLOBS = ["b0", "b1", "b2"] as const;
export const UNIVERSE = {
  connections: CONNECTIONS,
  streams: [{ stream: "messages" }, { stream: "events" }],
  keys: KEYS,
};

export function blobOf(name: string): BlobPayload {
  return blobPayload(new TextEncoder().encode(`oracle blob ${name}`));
}

export type Command =
  | { k: "import"; id: string; ops: ReplicaOperation[]; blobs: string[] }
  | { k: "dup"; id: string }
  | { k: "bytes"; id: string }
  | { k: "declare"; binding: BindingName }
  | { k: "retry" }
  | {
      k: "local";
      id: string;
      connection: string;
      binding: BindingName;
      key: string;
      text: string;
    }
  | { k: "reopen" }
  | { k: "quarantine"; connection: string }
  | { k: "provision"; connection: string }
  | { k: "stage"; id: string; ops: ReplicaOperation[]; blobs: string[] }
  | { k: "promote"; id: string }
  | { k: "drop"; id: string };

export interface GeneratorOptions {
  length: number;
  /** Starting declarations; the rest may arrive through `declare`. */
  declared?: BindingName[];
  /** Exclude command shapes listed in KNOWN_DEFECTS while their fix is pending. */
  avoid?: ReadonlySet<string>;
}

/** Mulberry32: tiny, seedable, and stable across runtimes. */
export function rng(seed: number) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return {
    next,
    int: (lo: number, hi: number) => lo + Math.floor(next() * (hi - lo + 1)),
    pick: <T>(items: readonly T[]): T =>
      items[Math.floor(next() * items.length)],
    chance: (p: number) => next() < p,
  };
}

/** Weighted pick from [weight, value] pairs. */
function weighted<T>(r: ReturnType<typeof rng>, entries: [number, T][]): T {
  const total = entries.reduce((sum, [w]) => sum + w, 0);
  let x = r.next() * total;
  for (const [w, value] of entries) if ((x -= w) < 0) return value;
  return entries[entries.length - 1][1];
}

export function generateCommands(
  seed: number,
  options: GeneratorOptions,
): Command[] {
  const r = rng(seed);
  const avoid = options.avoid ?? new Set<string>();
  const declared = new Set<BindingName>(options.declared ?? ["m", "a"]);
  const commands: Command[] = [];
  const generation: Record<string, number> = { c1: 1, c2: 1, c3: 1 };
  const deleted = new Set<string>();
  const provisioned = new Set<string>(PROVISIONED_AT_START);
  const quarantined = new Set<string>();
  const sent: {
    id: string;
    ops: ReplicaOperation[];
    blobs: string[];
    missing: string[];
  }[] = [];
  const held: {
    id: string;
    ops: ReplicaOperation[];
    blobs: string[];
    missing: string[];
  }[] = [];
  const staged: string[] = [];
  const pendingBlobs = new Set<string>();
  const pool: ReplicaOperation[] = [];
  let clock = 1;
  let seq = 0;
  let batches = 0;
  const writers = ["w-b", "w-c", "w-d"];
  const counter = () => {
    const value = Math.max(1, clock + r.int(-2, 2));
    clock = Math.max(clock, value);
    return value;
  };
  const revision = (writer = r.pick(writers)) => ({
    counter: counter(),
    writerId: writer,
    operationId: `${writer}-${seq++}`,
  });
  const base = (connection: string, gen = generation[connection]) => ({
    owner: OWNER,
    sourceId: SOURCE,
    connectionId: connection,
    methodId: METHOD,
    generation: gen,
  });
  const liveConnection = () =>
    r.pick(
      CONNECTIONS.filter((c) => !deleted.has(c)).length
        ? CONNECTIONS.filter((c) => !deleted.has(c))
        : CONNECTIONS,
    );
  const upsert = (
    connection: string,
    binding: BindingName,
    key: string,
    text: string,
    gen = generation[connection],
  ): ReplicaOperation => ({
    ...base(connection, gen),
    kind: "upsert",
    declaration: BINDINGS[binding],
    recordKey: key,
    emittedAt: `2026-10-20T00:00:${String(r.int(0, 59)).padStart(2, "0")}Z`,
    data: { id: key, text },
    blobs: [],
    revision: revision(),
  });
  function logicalOps(): { ops: ReplicaOperation[]; blobs: string[] } {
    const connection = liveConnection();
    const key = r.pick(KEYS);
    const text = `t${r.int(0, 3)}`;
    const shape = weighted<string>(r, [
      [30, "upsert"],
      [12, "append"],
      [8, "delete"],
      [8, "blob"],
      [5, "register"],
      [4, "reset"],
      [1, "reset-gap"],
      [1, "reset-invalid"],
      [1, "connection-delete"],
      [6, "equivocate"],
      [2, "invalid-data"],
      [3, "other-declaration"],
      [2, "old-generation"],
    ]);
    switch (shape) {
      case "upsert":
        return { ops: [upsert(connection, "m", key, text)], blobs: [] };
      case "append":
        return { ops: [upsert(connection, "a", key, text)], blobs: [] };
      case "delete":
        if (avoid.has("quarantine-with-deletes") && quarantined.has(connection))
          return { ops: [upsert(connection, "m", key, text)], blobs: [] };
        return {
          ops: [
            {
              ...base(connection),
              kind: "delete",
              declaration: BINDINGS.m,
              recordKey: key,
              emittedAt: "2026-10-20T00:00:00Z",
              deletedAt: `2026-10-21T00:00:${String(r.int(0, 59)).padStart(2, "0")}Z`,
              revision: revision(),
            },
          ],
          blobs: [],
        };
      case "blob": {
        const name = r.pick(BLOBS);
        const { descriptor } = blobOf(name);
        const claim: ReplicaOperation = {
          ...base(connection),
          kind: "blob-claim",
          blob: descriptor,
          revision: revision(),
        };
        const record = upsert(connection, "m", key, text) as Extract<
          ReplicaOperation,
          { kind: "upsert" }
        >;
        record.data = { id: key, blob_ref: { blob_id: descriptor.blobId } };
        record.blobs = [descriptor];
        return { ops: [claim, record], blobs: [name] };
      }
      case "register":
        return {
          ops: [
            {
              ...base(connection, 1),
              kind: "connection-register",
              generation: 1,
              revision: revision(),
            },
          ],
          blobs: [],
        };
      case "reset":
      case "reset-gap":
      case "reset-invalid": {
        const previous = generation[connection];
        const next =
          shape === "reset"
            ? previous + 1
            : shape === "reset-gap"
              ? previous + 2
              : previous;
        if (shape !== "reset-invalid") generation[connection] = next;
        return {
          ops: [
            {
              ...base(connection, next),
              kind: "connection-reset",
              previousGeneration:
                shape === "reset-gap" ? previous + 1 : previous,
              revision: revision(),
            },
          ],
          blobs: [],
        };
      }
      case "connection-delete":
        deleted.add(connection);
        return {
          ops: [
            {
              ...base(connection),
              kind: "connection-delete",
              revision: revision(),
            },
          ],
          blobs: [],
        };
      case "equivocate": {
        const prior = pool.filter(
          (op) => op.kind === "upsert" || op.kind === "delete",
        );
        if (!prior.length)
          return { ops: [upsert(connection, "m", key, text)], blobs: [] };
        const original = r.pick(prior) as Extract<
          ReplicaOperation,
          { kind: "upsert" }
        >;
        const variant = weighted<string>(r, [
          [3, "content"],
          [2, "key"],
          [2, "connection"],
        ]);
        const copy = structuredClone(original) as Extract<
          ReplicaOperation,
          { kind: "upsert" }
        >;
        if (copy.kind !== "upsert")
          return { ops: [upsert(connection, "m", key, text)], blobs: [] };
        if (variant === "content")
          copy.data = { ...copy.data, text: `${text}-changed` };
        else if (variant === "key") {
          const other = KEYS.find((k) => k !== copy.recordKey)!;
          copy.recordKey = other;
          copy.data = { id: other, text: `${text}-moved` };
        } else {
          const others = CONNECTIONS.filter(
            (c) =>
              c !== copy.connectionId &&
              (!avoid.has("equivocation-unprovisioned") ||
                (provisioned.has(c) && provisioned.has(copy.connectionId))),
          );
          if (!others.length)
            copy.data = { ...copy.data, text: `${text}-changed` };
          else copy.connectionId = r.pick(others);
        }
        return { ops: [copy], blobs: [] };
      }
      case "invalid-data": {
        const op = upsert(connection, "m", key, text) as Extract<
          ReplicaOperation,
          { kind: "upsert" }
        >;
        op.data = { id: `${key}-mismatch`, text };
        return { ops: [op], blobs: [] };
      }
      case "other-declaration":
        return { ops: [upsert(connection, "m2", key, text)], blobs: [] };
      default:
        return {
          ops: [
            upsert(
              connection,
              "m",
              key,
              text,
              Math.max(1, generation[connection] - 1),
            ),
          ],
          blobs: [],
        };
    }
  }
  const deliver = (batch: (typeof sent)[number]) => {
    sent.push(batch);
    commands.push({
      k: "import",
      id: batch.id,
      ops: batch.ops,
      blobs: batch.blobs,
    });
  };
  while (commands.length < options.length) {
    const action = weighted<string>(r, [
      [40, "new"],
      [held.length ? 10 : 0, "release"],
      [sent.length ? 5 : 0, "dup"],
      [sent.length ? 4 : 0, "regroup"],
      [sent.some((b) => b.missing.length) ? 6 : 0, "bytes"],
      [declared.size < 3 ? 3 : 0, "declare"],
      [3, "retry"],
      [8, "local"],
      [4, "reopen"],
      [quarantined.size < 2 ? 1.5 : 0, "quarantine"],
      [provisioned.has("c3") ? 0 : 2, "provision"],
      [4, "stage"],
      [staged.length ? 3 : 0, "promote"],
      [staged.length ? 1 : 0, "drop"],
    ]);
    if (action === "new") {
      const ops: ReplicaOperation[] = [];
      const blobs: string[] = [];
      for (let i = r.int(1, 3); i > 0; i--) {
        const part = logicalOps();
        if (
          avoid.has("pending-bytes-for-confirmed") &&
          part.blobs.some((name) => pendingBlobs.has(name))
        )
          continue;
        ops.push(...part.ops);
        blobs.push(...part.blobs);
      }
      if (!ops.length) continue;
      pool.push(...ops);
      const withBytes = blobs.filter(() => r.chance(0.6));
      const batch = {
        id: `batch-${batches++}`,
        ops,
        blobs: [...new Set(withBytes)],
        missing: [...new Set(blobs.filter((b) => !withBytes.includes(b)))],
      };
      if (r.chance(0.25)) held.push(batch);
      else deliver(batch);
    } else if (action === "release") {
      deliver(held.splice(r.int(0, held.length - 1), 1)[0]);
    } else if (action === "dup") {
      commands.push({ k: "dup", id: r.pick(sent).id });
    } else if (action === "regroup") {
      const ops = sent.flatMap((b) => b.ops).filter(() => r.chance(0.3));
      if (ops.length)
        deliver({
          id: `batch-${batches++}`,
          ops: ops.slice(0, 6),
          blobs: [],
          missing: [],
        });
    } else if (action === "bytes") {
      const batch = r.pick(sent.filter((b) => b.missing.length));
      batch.missing = [];
      commands.push({ k: "bytes", id: batch.id });
    } else if (action === "declare") {
      const binding = r.pick(
        (["m", "a", "m2"] as const).filter((b) => !declared.has(b)),
      );
      declared.add(binding);
      commands.push({ k: "declare", binding });
    } else if (action === "retry") {
      commands.push({ k: "retry" });
    } else if (action === "local") {
      const connection = r.pick([...provisioned]);
      if (avoid.has("local-after-quarantine") && quarantined.has(connection))
        continue;
      commands.push({
        k: "local",
        id: `local-${seq++}`,
        connection,
        binding: r.chance(0.8) ? "m" : "a",
        key: r.pick(KEYS),
        text: `l${r.int(0, 3)}`,
      });
    } else if (action === "reopen") {
      commands.push({ k: "reopen" });
    } else if (action === "quarantine") {
      const connection = r.pick([...provisioned]);
      if (
        avoid.has("quarantine-with-deletes") &&
        pool.some(
          (op) => op.kind === "delete" && op.connectionId === connection,
        )
      )
        continue;
      quarantined.add(connection);
      commands.push({ k: "quarantine", connection });
    } else if (action === "provision") {
      provisioned.add("c3");
      commands.push({ k: "provision", connection: "c3" });
    } else if (action === "stage") {
      const ops: ReplicaOperation[] = [];
      const blobs: string[] = [];
      for (let i = r.int(1, 2); i > 0; i--) {
        const part = logicalOps();
        // Stage only operations every port accepts into pending custody.
        if (
          part.ops.some(
            (op) => op.kind === "upsert" && op.data.id !== op.recordKey,
          )
        )
          continue;
        if (
          avoid.has("pending-bytes-for-confirmed") &&
          part.blobs.some((name) =>
            pool.some(
              (op) =>
                (op.kind === "blob-claim" &&
                  op.blob.blobId === blobOf(name).descriptor.blobId) ||
                (op.kind === "upsert" &&
                  op.blobs.some(
                    (b) => b.blobId === blobOf(name).descriptor.blobId,
                  )),
            ),
          )
        )
          continue;
        ops.push(...part.ops);
        blobs.push(...part.blobs);
      }
      if (!ops.length) continue;
      pool.push(...ops);
      for (const name of blobs) pendingBlobs.add(name);
      const id = `pending-${batches++}`;
      staged.push(id);
      commands.push({ k: "stage", id, ops, blobs: [...new Set(blobs)] });
    } else if (action === "promote" || action === "drop") {
      const id = staged.splice(r.int(0, staged.length - 1), 1)[0];
      commands.push({ k: action, id });
    }
  }
  // Late delivery of every held batch: the reorder ends in convergence.
  for (const batch of held) deliver(batch);
  return commands;
}

/**
 * Greedy shrinker: delete command ranges (halving), then single operations
 * inside batches, then blobs. `fails` must be deterministic.
 */
export async function shrinkCommands(
  commands: Command[],
  fails: (candidate: Command[]) => Promise<boolean>,
  budget = 400,
): Promise<Command[]> {
  let current = commands;
  let runs = 0;
  const attempt = async (candidate: Command[]) => {
    if (runs++ >= budget) return false;
    if (await fails(candidate)) {
      current = candidate;
      return true;
    }
    return false;
  };
  let progress = true;
  while (progress && runs < budget) {
    progress = false;
    for (let size = Math.max(1, current.length >> 1); size >= 1; size >>= 1) {
      for (let start = 0; start + size <= current.length;) {
        const candidate = [
          ...current.slice(0, start),
          ...current.slice(start + size),
        ];
        if (await attempt(candidate)) progress = true;
        else start += size;
      }
    }
    for (let i = 0; i < current.length; i++) {
      const command = current[i];
      if (
        (command.k !== "import" && command.k !== "stage") ||
        command.ops.length < 2
      )
        continue;
      for (let j = 0; j < command.ops.length && command.ops.length > 1;) {
        const smaller = {
          ...command,
          ops: command.ops.filter((_, x) => x !== j),
        };
        const candidate = current.map((c, x) => (x === i ? smaller : c));
        if (await attempt(candidate)) {
          progress = true;
          Object.assign(command, smaller);
        } else j++;
      }
    }
    for (let i = 0; i < current.length; i++) {
      const command = current[i];
      if (
        (command.k !== "import" && command.k !== "stage") ||
        !command.blobs.length
      )
        continue;
      const candidate = current.map((c, x) =>
        x === i ? { ...command, blobs: [] } : c,
      );
      if (await attempt(candidate)) progress = true;
    }
  }
  return current;
}

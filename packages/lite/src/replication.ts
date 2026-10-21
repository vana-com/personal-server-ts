import {
  canonicalJson,
  decodeReplicaEnvelope,
  type EnvelopeExpectation,
  type ReplicaEnvelope,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  publishReplicaFragment,
  downloadReplicaFragment,
  ReplicaFragmentSizeError,
} from "@opendatalabs/personal-server-ts-core/replication/delivery";
import {
  isReplicaScope,
  replicaScope,
  fromBase64,
  toBase64,
  type ReplicaFragment,
  type Predecessor,
  type PreparedFragment,
} from "@opendatalabs/personal-server-ts-core/replication/transport";
import {
  encodeReplicaPayload,
  hashReplicaBytes,
  fragmentReplicaStream,
  assembleReplicaStream,
  inspectReplicaPayload,
  readReplicaPayloadBlob,
  replicaPayloadByteLength,
} from "@opendatalabs/personal-server-ts-core/replication/stream";
import type { ReplicaTransportPort } from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import type {
  LiteCanonicalPersistence,
  LiteCanonicalTransaction,
} from "./canonical-persistence.js";
import type { createLiteCanonicalStore } from "./canonical-store.js";

type Store = ReturnType<typeof createLiteCanonicalStore>;
interface State {
  owner: string;
  writer: string;
  sourceWriter?: string;
  sequence: number;
  previous: Predecessor | null;
  cursor: number;
  acknowledged: number;
  scan: string | null;
}
interface Batch {
  batch: string;
  owner: string;
  writer: string;
  sequence: number;
  previous: Predecessor | null;
  collectedAt: string;
  envelope: ReplicaEnvelope;
  digest: string;
  totalBytes: number;
  prepared: boolean;
  attempts: number;
  next: number;
  error?: string;
}
interface Work {
  attempts: number;
  next: number;
  state: "ready" | "published" | "imported" | "quarantined";
  error?: string;
}
interface Out extends Work {
  scope: string;
  batch: string;
  dataHash: `0x${string}`;
  metadataHash: `0x${string}`;
}
interface In extends Work {
  scope: string;
  header?: Omit<ReplicaFragment, "content">;
}
const root = "transport/";
class ReplicaGroupConflict extends Error {}
const pad = (n: number) => String(n).padStart(16, "0");
const enc = new TextEncoder();
const get = async <T>(
  tx: LiteCanonicalTransaction,
  key: string,
): Promise<T | undefined> => {
  const value = await tx.get(root + key);
  return value === undefined ? undefined : (JSON.parse(value) as T);
};
const put = (tx: LiteCanonicalTransaction, key: string, value: unknown) =>
  tx.put(root + key, canonicalJson(value));

/** Default-off trusted-host worker. Durable work is resumed by a later cycle after a kill.
 * No network runs inside a native transaction. All record merges use the canonical store.
 */
export function createLiteReplicaWorker(deps: {
  enabled?: boolean;
  persistence: LiteCanonicalPersistence;
  store: Store;
  expected: () => EnvelopeExpectation;
  credential: unknown;
  transport: ReplicaTransportPort;
  now?: () => number;
  newId?: () => string;
  /** The host MUST abort the response stream at this bound, before returning get(). */
  maxIncomingBytes?: number;
}) {
  const { persistence, store, transport } = deps;
  if (deps.enabled === true && !persistence.discardStagedBlob)
    throw new Error("replica staging cleanup capability required");
  const now = deps.now ?? Date.now;
  const id = () => (deps.newId?.() ?? crypto.randomUUID()).replaceAll("-", "");
  const incomingCap = deps.maxIncomingBytes ?? 8 * 1024 * 1024;
  if (
    !Number.isSafeInteger(incomingCap) ||
    incomingCap < 1 ||
    incomingCap > 8 * 1024 * 1024
  )
    throw new RangeError("invalid Lite replica download bound");
  const rawTransaction = persistence.transaction.bind(persistence);
  let leaseToken: string | undefined;
  const transaction: LiteCanonicalPersistence["transaction"] = (run) =>
    rawTransaction(async (tx) => {
      if (leaseToken !== undefined) {
        const lease = await get<{ token: string; until: number }>(tx, "lease");
        if (lease?.token !== leaseToken)
          throw new Error("replica transport lease lost");
        await put(tx, "lease", { token: leaseToken, until: now() + 30000 });
      }
      return run(tx);
    });
  const state = async (tx: LiteCanonicalTransaction) => {
    const value = await get<State>(tx, "state");
    if (!value || value.owner !== deps.expected().owner)
      throw new Error("immutable replica transport owner binding");
    return value;
  };
  async function* page<T>(prefix: string) {
    // Each phase visits one bounded native page per cycle. Persisted rotating
    // keyset cursors prevent completed or failing early rows from hiding later
    // work; a crash can defer a row one scan, but never acknowledges it.
    const result = await transaction(async (tx) => {
      await state(tx);
      const after = await get<string>(tx, `work/${prefix}`);
      const page = await tx.scan(root + prefix, after);
      if (
        page.after !== undefined &&
        (page.after === after || !page.entries.length)
      )
        throw new Error("invalid transport scan cursor");
      if (page.after === undefined) await tx.delete(root + `work/${prefix}`);
      else await put(tx, `work/${prefix}`, page.after);
      return page;
    });
    for (const entry of result.entries)
      yield {
        key: entry.key.slice(root.length),
        value: JSON.parse(entry.value) as T,
      };
  }
  async function read<T>(key: string) {
    return transaction(async (tx) => {
      await state(tx);
      return get<T>(tx, key);
    });
  }
  async function write(key: string, value: unknown) {
    await transaction(async (tx) => {
      await state(tx);
      await put(tx, key, value);
    });
  }
  async function deletePrefix(tx: LiteCanonicalTransaction, prefix: string) {
    let after: string | undefined;
    do {
      const page = await tx.scan(root + prefix, after);
      for (const entry of page.entries) await tx.delete(entry.key);
      after = page.after;
    } while (after !== undefined);
  }
  const groupIdentity = (header: Omit<ReplicaFragment, "content">) => {
    const {
      index: _index,
      offset: _offset,
      chunkDigest: _chunkDigest,
      ...identity
    } = header;
    return canonicalJson(identity);
  };
  async function retry(
    key: string,
    _row: Work,
    error: unknown,
    permanent = false,
  ) {
    await transaction(async (tx) => {
      await state(tx);
      const current = await get<Work>(tx, key);
      // Lost commit acknowledgments cannot resurrect completed work whose
      // redundant transport bytes were removed by that successful commit.
      if (
        !current ||
        ["published", "imported", "quarantined"].includes(current.state)
      )
        return;
      await put(tx, key, {
        ...current,
        attempts: current.attempts + 1,
        next:
          now() + Math.min(3600000, 1000 * 2 ** Math.min(current.attempts, 12)),
        state: permanent ? "quarantined" : "ready",
        error: String(error),
      });
    });
  }
  async function initialize() {
    await transaction(async (tx) => {
      const owner = deps.expected().owner;
      const existing = await get<State>(tx, "state");
      if (existing && existing.owner !== owner)
        throw new Error("immutable replica transport owner binding");
      const clock = JSON.parse((await tx.get("clock")) ?? "null") as {
        writerId: string;
      } | null;
      const s: State = existing ?? {
        owner,
        writer: id(),
        sequence: 0,
        previous: null,
        cursor: 0,
        acknowledged: 0,
        scan: null,
      };
      // The native installation watermark rotates canonical writer identity on
      // restore. Transport identity must rotate in the same case, even with old
      // retained batches still awaiting publication.
      if (clock && s.sourceWriter !== clock.writerId) {
        if (s.sourceWriter) {
          s.writer = id();
          s.sequence = 0;
          s.previous = null;
        }
        s.sourceWriter = clock.writerId;
      }
      await put(tx, "state", s);
    });
  }
  async function retain() {
    let s = (await read<State>("state"))!;
    if (s.acknowledged !== s.cursor) {
      await store.acknowledgeOutbox(s.acknowledged, s.cursor);
      await transaction(async (tx) => {
        const current = await state(tx);
        if (current.cursor !== s.cursor)
          throw new Error("replica retention cursor conflict");
        current.acknowledged = s.cursor;
        await put(tx, "state", current);
      });
      s = (await read<State>("state"))!;
    }
    const page = await store.readOutboxPage(s.cursor);
    if (!page.entries.length) return;
    const batch = id();
    const envelope: ReplicaEnvelope = {
      format: "vana-pdpp-replica",
      version: 1,
      owner: s.owner,
      batchId: batch,
      operations: [],
    };
    let cursor = s.cursor;
    for (const entry of page.entries) {
      const proposed = {
        ...envelope,
        operations: [...envelope.operations, entry.operation],
      };
      const blobs = [
        ...new Map(
          proposed.operations
            .flatMap((op) =>
              op.kind === "blob-claim"
                ? [op.blob]
                : op.kind === "upsert"
                  ? op.blobs
                  : [],
            )
            .map((blob) => [blob.blobId, blob]),
        ).values(),
      ];
      if (
        enc.encode(canonicalJson(proposed)).length > 192 * 1024 ||
        replicaPayloadByteLength(proposed) > 32768 * 100000 ||
        blobs.length > 4 ||
        blobs.reduce((total, blob) => total + blob.sizeBytes, 0) >
          256 * 1024 * 1024
      ) {
        if (!envelope.operations.length)
          throw new Error(
            "single operation exceeds replica envelope admission limit",
          );
        break;
      }
      envelope.operations.push(entry.operation);
      cursor = entry.sequence;
    }
    decodeReplicaEnvelope(canonicalJson(envelope), deps.expected());
    const bytes = () =>
      encodeReplicaPayload(envelope, (blob) => store.readBlob(blob));
    const hash = await hashReplicaBytes(bytes);
    const manifest: Batch = {
      batch,
      owner: s.owner,
      writer: s.writer,
      sequence: s.sequence + 1,
      previous: s.previous,
      collectedAt: new Date(now()).toISOString(),
      envelope,
      ...hash,
      prepared: false,
      attempts: 0,
      next: 0,
    };
    await transaction(async (tx) => {
      const current = await state(tx);
      if (
        current.cursor !== s.cursor ||
        current.writer !== s.writer ||
        current.sequence !== s.sequence
      )
        throw new Error("replica retention cursor conflict");
      await put(tx, `batches/${batch}`, manifest);
      current.cursor = cursor;
      current.sequence = manifest.sequence;
      current.previous = { batch, digest: hash.digest };
      await put(tx, "state", current);
    });
  }
  async function prepare() {
    for await (const entry of page<Batch>("batches/")) {
      const batch = entry.value;
      if (batch.prepared || batch.next > now() || batch.attempts < 0) continue;
      try {
        decodeReplicaEnvelope(canonicalJson(batch.envelope), deps.expected());
        const bytes = () =>
          encodeReplicaPayload(batch.envelope, (blob) => store.readBlob(blob));
        const actual = await hashReplicaBytes(bytes);
        if (
          actual.digest !== batch.digest ||
          actual.totalBytes !== batch.totalBytes
        )
          throw new Error("immutable retained replica payload changed");
        // Each fragment's ciphertext fits one native value; preparation writes
        // one part at a time. No part is sent until the final prepared marker.
        let count = 0;
        for await (const part of fragmentReplicaStream({
          ...batch,
          bytes,
          encrypt: transport.encrypt,
          targetChunkBytes: 32 * 1024,
          maxBlobBytes: 128 * 1024,
        })) {
          const key = `out/${batch.batch}/${pad(count++)}`;
          await transaction(async (tx) => {
            await state(tx);
            const current = await get<Batch>(tx, entry.key);
            if (current?.prepared)
              throw new Error("concurrent replica preparation");
            await put(tx, key + "/cipher", toBase64(part.encrypted));
            await put(tx, `send/${part.scope}`, {
              scope: part.scope,
              batch: batch.batch,
              dataHash: part.dataHash,
              metadataHash: part.metadataHash,
              attempts: 0,
              next: 0,
              state: "ready",
              partKey: key,
            });
          });
        }
        if (!count) throw new Error("empty replica preparation");
        await write(entry.key, { ...batch, prepared: true });
      } catch (error) {
        await write(entry.key, {
          ...batch,
          attempts: batch.attempts + 1,
          next: now() + 1000,
          error: String(error),
        });
      }
      break;
    }
  }
  async function publish() {
    for await (const entry of page<Out & { partKey: string }>("send/")) {
      const row = entry.value;
      if (row.state !== "ready" || row.next > now()) continue;
      if (!(await read<Batch>(`batches/${row.batch}`))?.prepared) continue;
      try {
        const encrypted = fromBase64(
          (await read<string>(row.partKey + "/cipher"))!,
        );
        const part: PreparedFragment = {
          scope: row.scope,
          dataHash: row.dataHash,
          metadataHash: row.metadataHash,
          plaintext: await transport.decrypt(row.scope, encrypted),
          encrypted,
        };
        const status = await publishReplicaFragment(
          transport,
          deps.expected().owner,
          part,
        );
        if (status === "confirmed")
          await transaction(async (tx) => {
            await state(tx);
            await put(tx, entry.key, {
              ...row,
              state: "published",
              error: null,
            });
            await tx.delete(root + row.partKey + "/cipher");
          });
        else
          await retry(
            entry.key,
            row,
            "registration not confirmed",
            status === "conflict",
          );
      } catch (error) {
        await retry(entry.key, row, error);
      }
    }
  }
  async function discover() {
    const s = (await read<State>("state"))!;
    const found = await transport.list(s.scan);
    if (found.scopes.length > 1000)
      throw new Error("replica feed page exceeds host bound");
    await transaction(async (tx) => {
      const current = await state(tx);
      if (current.scan !== s.scan)
        throw new Error("replica scan cursor conflict");
      for (const scope of found.scopes.filter((scope) => {
        if (!isReplicaScope(scope) || scope.length > 180) return false;
        const match =
          /^[^.]+\.([a-f0-9]{32})_([a-f0-9]{32})\.(0|[1-9][0-9]{0,4})$/.exec(
            scope,
          );
        return (
          match !== null &&
          replicaScope(match[1]!, match[2]!, Number(match[3])) === scope
        );
      })) {
        if (!(await get(tx, `receive/${scope}`)))
          await put(tx, `receive/${scope}`, {
            scope,
            attempts: 0,
            next: 0,
            state: "ready",
          });
      }
      current.scan = found.cursor;
      await put(tx, "state", current);
    });
  }
  async function download() {
    for await (const entry of page<In>("receive/")) {
      const row = entry.value;
      if (row.state !== "ready" || row.header || row.next > now()) continue;
      try {
        const result = await downloadReplicaFragment(
          transport,
          deps.expected().owner,
          row.scope,
          incomingCap,
        );
        if (result.status !== "confirmed") {
          await retry(
            entry.key,
            row,
            "registration not confirmed",
            result.status === "conflict",
          );
          continue;
        }
        const { content, ...header } = result.fragment;
        const group = `${header.writer}_${header.batch}`;
        await transaction(async (tx) => {
          await state(tx);
          const prefix = `content/${group}/${pad(header.index)}/`;
          // The incoming Node fragment may exceed one value. Split its base64
          // text into bounded native rows without assembling a scope or batch.
          for (
            let offset = 0, index = 0;
            offset < content.length;
            offset += 64 * 1024, index++
          )
            await put(
              tx,
              prefix + pad(index),
              content.slice(offset, offset + 64 * 1024),
            );
          const prior = await get<Omit<ReplicaFragment, "content">>(
            tx,
            `groups/${group}`,
          );
          if (prior && groupIdentity(prior) !== groupIdentity(header))
            throw new ReplicaGroupConflict("replica group equivocation");
          if (!prior) await put(tx, `groups/${group}`, header);
          await put(tx, `parts/${group}/${pad(header.index)}`, {
            scope: row.scope,
            header,
          });
          await put(tx, entry.key, { ...row, header, error: null });
        });
      } catch (error) {
        await retry(
          entry.key,
          row,
          error,
          error instanceof ReplicaGroupConflict ||
            error instanceof ReplicaFragmentSizeError,
        );
      }
    }
  }
  async function* fragments(group: string, count: number) {
    for (let i = 0; i < count; i++) {
      const part = await read<{
        scope: string;
        header: Omit<ReplicaFragment, "content">;
      }>(`parts/${group}/${pad(i)}`);
      if (!part) throw new Error("incomplete replica batch");
      let content = "";
      let after: string | undefined;
      do {
        const result = await transaction(async (tx) => {
          await state(tx);
          return tx.scan(root + `content/${group}/${pad(i)}/`, after);
        });
        for (const entry of result.entries)
          content += JSON.parse(entry.value) as string;
        after = result.after;
      } while (after !== undefined);
      yield { ...part.header, content };
    }
  }
  async function importReady() {
    for await (const entry of page<Omit<ReplicaFragment, "content">>(
      "groups/",
    )) {
      const first = entry.value;
      const group = `${first.writer}_${first.batch}`;
      const status = await read<{
        state: string;
        next?: number;
        attempts?: number;
      }>(`group-status/${group}`);
      if (status?.state === "quarantined" || (status?.next ?? 0) > now())
        continue;
      if (await read(`imported/${group}`)) {
        await write(`group-status/${group}`, { state: "imported" });
        continue;
      }
      if (first.previous) {
        const prior = await read<{ digest: string; sequence: number }>(
          `imported/${first.writer}_${first.previous.batch}`,
        );
        if (
          !prior ||
          prior.digest !== first.previous.digest ||
          prior.sequence !== first.sequence - 1
        )
          continue;
      }
      const reserved = await read<string>(
        `sequence/${first.writer}/${pad(first.sequence)}`,
      );
      if (reserved && reserved !== first.batch) {
        await write(`group-status/${group}`, {
          state: "quarantined",
          error: "replica batch equivocation",
        });
        continue;
      }
      // Missing fragments are normal discovery progress, not an import attempt.
      const complete = await transaction(async (tx) => {
        let after: string | undefined;
        let count = 0;
        do {
          const page = await tx.scan(root + `parts/${group}/`, after);
          count += page.entries.length;
          after = page.after;
        } while (after !== undefined);
        return count === first.count;
      });
      if (!complete) continue;
      const staged: {
        stagingId: string;
        descriptor: Parameters<Store["stageBlob"]>[0];
      }[] = [];
      try {
        const bytes = () =>
          assembleReplicaStream(() => fragments(group, first.count));
        const decoded = await inspectReplicaPayload(bytes, deps.expected());
        if (decoded.envelope.batchId !== first.batch)
          throw new Error("invalid replica payload binding");
        const claims = decoded.envelope.operations.flatMap((op) =>
          op.kind === "blob-claim"
            ? [op.blob]
            : op.kind === "upsert"
              ? op.blobs
              : [],
        );
        if (
          decoded.blobs.length > 4 ||
          decoded.blobs.reduce((total, blob) => total + blob.sizeBytes, 0) >
            256 * 1024 * 1024
        )
          throw new ReplicaGroupConflict(
            "replica batch exceeds native staging bound",
          );
        for (const blob of decoded.blobs) {
          const descriptor = claims.find(
            (c) =>
              c.blobId === blob.blobId &&
              c.sha256 === blob.sha256 &&
              c.sizeBytes === blob.sizeBytes,
          );
          if (!descriptor) throw new Error("unbound replica binary");
          const existing = await transaction((tx) =>
            tx.blob(descriptor.blobId),
          );
          if (existing) {
            if (canonicalJson(existing) !== canonicalJson(descriptor))
              throw new ReplicaGroupConflict("replica blob metadata conflict");
            continue;
          }
          const stagingId = await store.stageBlob(
            descriptor,
            readReplicaPayloadBlob(bytes, blob.blobId),
          );
          staged.push({ stagingId, descriptor });
        }
        await store.import({
          id: group,
          envelope: decoded.envelope,
          credential: deps.credential,
          blobs: staged,
          withinTransaction: async (tx) => {
            await state(tx);
            if (
              (await get<{ token: string }>(tx, "lease"))?.token !== leaseToken
            )
              throw new Error("replica transport lease lost");
            const sequenceKey = `sequence/${first.writer}/${pad(first.sequence)}`;
            const existing = await get<string>(tx, sequenceKey);
            const imported = await get<{ digest: string; sequence: number }>(
              tx,
              `imported/${group}`,
            );
            if (
              (existing && existing !== first.batch) ||
              (imported &&
                (imported.digest !== first.digest ||
                  imported.sequence !== first.sequence))
            )
              throw new Error("replica batch equivocation");
            if (first.previous) {
              const previous = await get<{ digest: string; sequence: number }>(
                tx,
                `imported/${first.writer}_${first.previous.batch}`,
              );
              if (
                !previous ||
                previous.digest !== first.previous.digest ||
                previous.sequence !== first.sequence - 1
              )
                throw new Error("missing replica predecessor");
            }
            await put(tx, sequenceKey, first.batch);
            await put(tx, `imported/${group}`, {
              digest: first.digest,
              sequence: first.sequence,
            });
            // Original operations and attached blob bytes now live in the
            // canonical store. Remove redundant transport bodies in THIS commit.
            await deletePrefix(tx, `content/${group}/`);
            await deletePrefix(tx, `parts/${group}/`);
            await tx.delete(root + `groups/${group}`);
            await put(tx, `group-status/${group}`, { state: "imported" });
          },
        });
        await write(`group-status/${group}`, { state: "imported" });
      } catch (error) {
        if (await read(`imported/${group}`))
          await write(`group-status/${group}`, { state: "imported" });
        else
          await write(`group-status/${group}`, {
            state:
              error instanceof ReplicaGroupConflict ? "quarantined" : "pending",
            error: String(error),
            attempts: (status?.attempts ?? 0) + 1,
            next:
              now() +
              Math.min(
                3600000,
                1000 * 2 ** Math.min(status?.attempts ?? 0, 12),
              ),
          });
      } finally {
        for (const blob of staged)
          await persistence.discardStagedBlob!(blob.stagingId);
      }
    }
  }
  async function retryRetainedConnections() {
    const after = await read<string>("work/retry-connections");
    const page = await store.retry({ credential: deps.credential, after });
    await transaction(async (tx) => {
      await state(tx);
      if (page.after === undefined)
        await tx.delete(root + "work/retry-connections");
      else await put(tx, "work/retry-connections", page.after);
    });
  }
  let running = false;
  return {
    async status() {
      if (deps.enabled !== true) return { enabled: false as const };
      const result = {
        enabled: true as const,
        pending: 0,
        quarantined: 0,
        published: 0,
        imported: 0,
      };
      for (const prefix of [
        "batches/",
        "send/",
        "receive/",
        "groups/",
        "group-status/",
      ]) {
        let after: string | undefined;
        do {
          const page = await transaction((tx) => tx.scan(root + prefix, after));
          for (const entry of page.entries) {
            const row = JSON.parse(entry.value) as {
              state: string;
              header?: unknown;
              prepared?: boolean;
            };
            if (prefix === "batches/") {
              if (!row.prepared) result.pending++;
              continue;
            }
            if (prefix === "groups/") {
              if (
                !(await read(
                  `imported/${entry.key.slice((root + prefix).length)}`,
                ))
              )
                result.pending++;
              continue;
            }
            if (row.state === "quarantined") result.quarantined++;
            else if (row.state === "published") result.published++;
            else if (prefix === "group-status/" && row.state === "imported")
              result.imported++;
            else if (row.state === "ready" && !row.header) result.pending++;
          }
          after = page.after;
        } while (after !== undefined);
      }
      const s = await read<State>("state");
      if (s && (await store.readOutboxPage(s.cursor)).entries.length)
        result.pending++;
      return result;
    },
    async cycle() {
      if (deps.enabled !== true || running) return;
      running = true;
      try {
        const token = id();
        const acquired = await rawTransaction(async (tx) => {
          const lease = await get<{ token: string; until: number }>(
            tx,
            "lease",
          );
          if (lease && lease.until > now()) return false;
          await put(tx, "lease", { token, until: now() + 30000 });
          return true;
        });
        if (!acquired) return;
        leaseToken = token;
        await initialize();
        const failures: unknown[] = [];
        for (const phase of [
          retain,
          prepare,
          publish,
          discover,
          download,
          importReady,
          retryRetainedConnections,
        ]) {
          try {
            await phase();
          } catch (error) {
            failures.push(error);
          }
        }
        if (failures.length)
          throw new AggregateError(failures, "Lite replica cycle incomplete");
      } finally {
        const token = leaseToken;
        leaseToken = undefined;
        try {
          if (token !== undefined)
            await rawTransaction(async (tx) => {
              if ((await get<{ token: string }>(tx, "lease"))?.token === token)
                await tx.delete(root + "lease");
            });
        } finally {
          running = false;
        }
      }
    },
  };
}

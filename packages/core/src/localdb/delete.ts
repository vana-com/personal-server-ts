// A connection delete. One write per namespace ends the connection: its
// control row's tombstone (the fence). Readers follow the connection log, and
// the log's lifetimes end with the control row (`log-apply.ts`): a segment of
// an earlier generation holds nothing of a later one, and every log commit
// requires the control row active at its generation. So the fence is the
// whole of a delete on the registry. Nothing reads a per-stream row, and the
// gateway refuses a write to one once the log row exists; the delete writes
// none.
//
// The fences go in one batch request (delete-batch.ts), within the gateway's
// bounds. A fence the request did not store (it lost a race, or got no
// answer) is posted alone and confirmed by a read (`landFence`), as a resumed
// delete does.
import { keccakOf } from "../stream-sync/crypto-port.js";
import {
  classifyControl,
  controlHashes,
  controlScope,
  deriveKeyCheck,
  parseScope,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { RegistryRefusedError } from "../stream-sync/ports.js";
import { commitFences } from "./delete-batch.js";
import type { LocalSyncDeps } from "./deps.js";
import type { ErasureReport } from "./log-erase.js";
import { purgeConnection } from "./purge.js";
import {
  ConnectionLifetimeChanged,
  formatLifetime,
  holdsLifetime,
  parseLifetime,
} from "./delete-lifetime.js";
export {
  ConnectionLifetimeChanged,
  InvalidConnectionLifetime,
} from "./delete-lifetime.js";

export class ConnectionStoppedError extends Error {
  constructor(readonly connector: string) {
    super(
      `connection of ${connector} is stopped: deleted, not reconnected; an explicit connect is required`,
    );
    this.name = "ConnectionStoppedError";
  }
}
export class ConnectionDeleteSuperseded extends Error {
  constructor(readonly connector: string) {
    super(`delete of ${connector} was superseded before it landed`);
    this.name = "ConnectionDeleteSuperseded";
  }
}

/** Persisted byte-for-byte in delete_intents before any registry write. */
export interface DeleteIntent {
  readonly id?: string;
  /** The version each namespace's control row held when the delete was planned. */
  readonly pins: readonly { readonly ns: string; readonly version: number }[];
  /**
   * The delete named a lifetime: its purge reaches the connections of these
   * pins and no other, here or on resume. Absent: the connector's delete as it
   * always was, which ends every local connection of it.
   */
  readonly pinned?: true;
  /**
   * The control tombstones this delete confirmed, one per namespace. `version`
   * is the tombstone's registry version, always its pin + 1.
   */
  readonly fences?: readonly {
    readonly ns: string;
    readonly version: number;
  }[];
}
export interface PendingDelete {
  readonly connector: string;
  readonly why: string;
}
/**
 * What a delete request tells its caller. `fenced` is true when the control
 * tombstone is confirmed in the registry (or there is no control row to
 * tombstone): every other surface now sees the connection as deleted and
 * refuses its data. It is false while the registry has not confirmed it: other
 * surfaces still see the connection, and the landing goes on in the
 * background until it finishes.
 */
export interface ConnectionDeleteRequest {
  readonly deleteId: string;
  readonly fenced: boolean;
}
export interface ConnectionDeleter {
  /**
   * `lifetime` is what `readConnectionLifetime` answered when the person chose
   * to delete: the delete then ends that connection and no other. A connection
   * made since refuses it (`ConnectionLifetimeChanged`), and one this delete
   * already ended is done. Absent: the delete ends whatever is connected now.
   */
  requestConnectionDelete(
    connector: string,
    options?: { readonly lifetime?: string },
  ): Promise<ConnectionDeleteRequest>;
  /** The lifetime the connector's live control rows hold now (see `delete-lifetime.ts`). */
  readConnectionLifetime(connector: string): Promise<string>;
  resumeDeletes(): Promise<readonly PendingDelete[]>;
}
/**
 * The erasure of deleted connections' log objects, as the deleter drives it
 * (`log-erase.ts`). Never throws; `pending` says a later call still has work.
 */
export type EraseLogs = (
  connector: string,
  signal: AbortSignal,
  /** Namespaces of the connector whose delete has not settled here: not erased. */
  options?: { readonly skipNamespaces: ReadonlySet<string> },
) => Promise<ErasureReport>;
/** One running landing: when its fences ended, and when all of it did. */
interface Landing {
  readonly fenced: Promise<boolean>;
  readonly done: Promise<void>;
}

/** `work`'s answer, or `false` once `ms` has passed (never: wait for `work`). */
function withinBudget(work: Promise<boolean>, ms?: number): Promise<boolean> {
  if (ms === undefined) return work;
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), ms);
    void work
      .then(resolve, () => resolve(false))
      .finally(() => clearTimeout(timer));
  });
}

export function createConnectionDeleter(
  originalDeps: LocalSyncDeps,
  options: {
    readonly eraseLegacy?: (connector: string) => Promise<void>;
    /**
     * Physically erases the log objects of a deleted connection from storage.
     * It runs only once the delete is settled: no delete of the connector is
     * in flight (its intent is cleared), and per namespace: a namespace with
     * a local connection that is not purged is another lifetime and is never
     * erased, while the connector's other deleted namespaces are. It runs
     * after the delete, never inside it: a connection added again must not
     * wait for storage, and a failure leaves the delete done. An erasure that
     * is not finished is resumed by `resumeErasures` (the sync's retry loop),
     * and once at the first call after a start, for deletes settled before it.
     */
    readonly eraseLogs?: EraseLogs;
    /**
     * How long a request waits for the fence before it answers
     * `fenced: false`. The landing keeps going in the background and the
     * resume loop re-checks it. Each registry request uses the same deadline.
     * Production passes the loop's first resume
     * wait, so a delete that has not fenced by then is the one the loop would
     * pick up next. Absent: the request waits for the fence however long it
     * takes (tests only).
     */
    readonly fenceWaitMs?: number;
  } = {},
) {
  // Each registry request gets the same budget as the first resume wait.
  // A lost POST reply remains ambiguous; landFence confirms it with a fresh read.
  // Race the signal too, so a non-cooperating adapter cannot hold a flight.
  const stop = new AbortController();
  const bounded = async <T>(
    work: (signal: AbortSignal) => Promise<T>,
  ): Promise<T> => {
    const timeout = new AbortController();
    const timer =
      options.fenceWaitMs === undefined
        ? undefined
        : setTimeout(
            () => timeout.abort(new Error("registry deadline exceeded")),
            options.fenceWaitMs,
          );
    const signal = AbortSignal.any([stop.signal, timeout.signal]);
    try {
      signal.throwIfAborted();
      return await new Promise<T>((resolve, reject) => {
        const abort = () => reject(signal.reason);
        signal.addEventListener("abort", abort, { once: true });
        work(signal)
          .then(resolve, reject)
          .finally(() => signal.removeEventListener("abort", abort));
      });
    } finally {
      clearTimeout(timer);
    }
  };
  const registry = originalDeps.registry;
  const deps: LocalSyncDeps = {
    ...originalDeps,
    registry: {
      ...registry,
      ...(registry.batchPolicy && {
        batchPolicy: () => registry.batchPolicy!(),
      }),
      read: (scope) => bounded((signal) => registry.read(scope, signal)),
      post: (request) => bounded((signal) => registry.post(request, signal)),
      listControlRows: () =>
        bounded((signal) => registry.listControlRows(signal)),
      ...(registry.postBatch && {
        postBatch: (request) =>
          bounded((signal) => registry.postBatch!(request, signal)),
      }),
      ...(registry.readBatchPolicy && {
        readBatchPolicy: () =>
          bounded((signal) => registry.readBatchPolicy!(signal)),
      }),
    },
  };
  const keccak = keccakOf(deps.streamCrypto);
  const flights = new Map<string, Landing>();
  const requests = new Set<Promise<ConnectionDeleteRequest>>();
  /** Erasures running, by connector: one at a time per connector. */
  const erasures = new Map<string, Promise<void>>();
  /** Connectors whose erasure ended `pending`, until a later pass finishes it. */
  const erasing = new Set<string>();
  /** The start sweep (deletes settled before this process) is still owed. */
  let sweepOwed = options.eraseLogs !== undefined;
  /**
   * The control rows the plan listed, by delete id, then by scope. Only a
   * delete this process just planned has one; the landing takes it. Each
   * fence lands only over the head the listing showed at its pin.
   */
  const listings = new Map<string, Map<string, ControlRead>>();
  const hashesOf = async () =>
    controlHashes(
      keccak,
      await deriveKeyCheck((m) => deps.keys.namespaceHmac(m)),
    );
  type Hashes = Awaited<ReturnType<typeof hashesOf>>;
  const readIntent = async (
    connector: string,
  ): Promise<DeleteIntent | null> => {
    const [row] = await deps.db.query<{ delete_id: string; intent: string }>(
      "SELECT delete_id,intent FROM delete_intents WHERE connector=?",
      [connector],
    );
    if (!row) return null;
    const intent: DeleteIntent = JSON.parse(row.intent);
    if (
      !Array.isArray(intent.pins) ||
      intent.pins.some((p) => !Number.isSafeInteger(p.version) || p.version < 1)
    )
      throw new Error("invalid stored delete intent");
    for (const fence of intent.fences ?? []) {
      const pin = intent.pins.find((p) => p.ns === fence.ns);
      if (!pin || fence.version !== pin.version + 1)
        throw new Error("invalid stored delete intent");
    }
    for (const pin of intent.pins) controlScope(connector, pin.ns);
    return {
      pins: intent.pins,
      fences: intent.fences,
      ...(intent.pinned && { pinned: true as const }),
      id: row.delete_id,
    };
  };
  const save = (connector: string, intent: DeleteIntent) =>
    deps.db.batch([
      {
        sql: "INSERT OR REPLACE INTO delete_intents(connector,delete_id,intent) VALUES (?,?,?)",
        params: [connector, intent.id!, JSON.stringify(intent)],
      },
    ]);
  const clear = (connector: string, id: string) =>
    deps.db.batch([
      {
        sql: "DELETE FROM delete_intents WHERE connector=? AND delete_id=?",
        params: [connector, id],
      },
    ]);
  /**
   * The pins, from one listing of the control rows. A listing is as fresh as a
   * read of the row, and taken after this call; the row may still move before
   * the delete writes, which a read could not prevent either. Each fence is a
   * compare-and-set on the version and the head the listing showed, so a pin
   * that went stale loses its write, and the per-row pass reads again.
   */
  async function plan(connector: string): Promise<{
    intent: DeleteIntent;
    listing: Map<string, ControlRead>;
    ended: Map<string, number>;
  }> {
    const [hashes, entries] = await Promise.all([
      hashesOf(),
      deps.registry.listControlRows(),
      // The gateway's batch bounds, beside the listing: the landing needs
      // them, and asks once per process. A failure here is the landing's to
      // report.
      deps.registry.readBatchPolicy?.().catch(() => undefined),
    ]);
    const pins: { ns: string; version: number }[] = [];
    const listing = new Map<string, ControlRead>();
    // The control rows already tombstoned, by namespace: the end of a lifetime.
    const ended = new Map<string, number>();
    for (const entry of entries) {
      const parsed = parseScope(entry.scope);
      if (parsed?.kind !== "control" || parsed.connector !== connector)
        continue;
      const current = classifyControl(entry.read, hashes);
      listing.set(entry.scope, { ...entry.read });
      if (current.kind === "deleted") ended.set(parsed.ns, current.version);
      // A control row of another key ends the same way: its tombstone is the
      // same for every key.
      if (current.kind === "active" || current.kind === "foreign")
        pins.push({
          ns: parsed.ns,
          version:
            current.kind === "active" ? current.generation : current.version,
        });
    }
    return { intent: { id: deps.newOp(), pins }, listing, ended };
  }
  async function readConnectionLifetime(connector: string): Promise<string> {
    stop.signal.throwIfAborted();
    controlScope(connector, "");
    const { intent } = await plan(connector);
    return formatLifetime(
      connector,
      new Map(intent.pins.map((p) => [p.ns, p.version])),
    );
  }
  function samePlan(a: DeleteIntent, b: DeleteIntent) {
    return (
      a.pins.length === b.pins.length &&
      a.pins.every((p) =>
        b.pins.some((q) => q.ns === p.ns && q.version === p.version),
      )
    );
  }
  /**
   * Run `work` holding the queue of every local connection of `connector`, so
   * no commit of theirs is in flight, and none starts, until it ends. A first
   * save commits a connection's control row and first segment in one request
   * under that queue; a plan that listed the registry while one was in flight
   * would find no control row to fence, and the commit would land after the
   * delete answered. Waiting here puts the commit before the listing, which
   * then pins its control row. A commit that waits behind the hold begins
   * after the delete saved its intent (which defers it) or purged the
   * connection (which changes its basis, so it plans again). Only a delete
   * with a local connection no pin covers needs it.
   */
  async function holdingConnections<T>(
    connector: string,
    work: (held: ReadonlySet<string>) => Promise<T>,
  ): Promise<T> {
    const ids = (
      await deps.db.query<{ connection_id: string }>(
        "SELECT connection_id FROM connections WHERE connector=? ORDER BY connection_id",
        [connector],
      )
    ).map((row) => row.connection_id);
    const hold = (i: number): Promise<T> =>
      i === ids.length
        ? work(new Set(ids))
        : deps.queue.run(ids[i]!, "purge", () => hold(i + 1));
    return hold(0);
  }
  async function hasUnpinnedConnection(
    connector: string,
    intent: DeleteIntent,
  ) {
    const rows = await deps.db.query<{ ns: string }>(
      "SELECT ns FROM connections WHERE connector=?",
      [connector],
    );
    return rows.some((row) => !intent.pins.some((p) => p.ns === row.ns));
  }
  async function purgeLocal(
    connector: string,
    intent: DeleteIntent,
    held: ReadonlySet<string> = new Set(),
  ) {
    const connections = await deps.db.query<{
      connection_id: string;
      ns: string;
      generation: number;
      control_version: number;
    }>(
      "SELECT connection_id,ns,generation,control_version FROM connections WHERE connector=?",
      [connector],
    );
    for (const connection of connections) {
      const pin = intent.pins.find((p) => p.ns === connection.ns);
      // A delete that named a lifetime ends what its pins name, nothing else.
      if (!pin && intent.pinned) continue;
      if (pin && connection.generation > pin.version) continue;
      const inQueue = held.has(connection.connection_id)
        ? (work: () => Promise<void>) => work()
        : (work: () => Promise<void>) =>
            deps.queue.run(connection.connection_id, "purge", work);
      await inQueue(async () => {
        const [current] = await deps.db.query<{ generation: number }>(
          "SELECT generation FROM connections WHERE connection_id=?",
          [connection.connection_id],
        );
        if (pin && current && current.generation > pin.version) return;
        const nested: LocalSyncDeps = {
          ...deps,
          queue: {
            run: (id, kind, work) =>
              id === connection.connection_id
                ? work()
                : deps.queue.run(id, kind, work),
          },
        };
        await purgeConnection(nested, connection.connection_id, {
          controlVersion: pin ? pin.version + 1 : connection.control_version,
        });
        await deps.db.batch([
          {
            sql: "UPDATE run_streams SET decision='discarded',reason='control_deleted',replace=0 WHERE run_id IN (SELECT run_id FROM runs WHERE connection_id=?)",
            params: [connection.connection_id],
          },
          {
            sql: "UPDATE runs SET state='ended' WHERE connection_id=?",
            params: [connection.connection_id],
          },
        ]);
      });
    }
  }
  const sign = (
    scope: string,
    dataHash: `0x${string}`,
    metadataHash: `0x${string}`,
    version: number,
  ) =>
    deps.signer.signAddData({
      ownerAddress: deps.ownerAddress,
      scope,
      dataHash,
      metadataHash,
      expectedVersion: BigInt(version),
    });
  async function signPost(
    scope: string,
    dataHash: `0x${string}`,
    metadataHash: `0x${string}`,
    version: number,
  ) {
    const signature = await sign(scope, dataHash, metadataHash, version);
    return deps.registry.post({
      ownerAddress: deps.ownerAddress,
      scope,
      dataHash,
      metadataHash,
      expectedVersion: String(version),
      signature,
    });
  }
  /**
   * Land the control tombstone of one namespace alone: the per-row pass, for
   * a fence the batch request did not store, and for a resumed delete.
   *
   * The post is a CAS at `pin + 1`, sent blind and then confirmed by a read:
   * a lost reply, a reply that never arrives, a conflict and a registry that
   * lags all end in the same read. Any control version at or above the
   * tombstone's proves it landed, whoever wrote it (it may already have been
   * followed by a reconnect), so a fence never lands twice (a retry resends the
   * same `pin + 1`, and the registry refuses it). A row of another key that
   * moved past the pin without a tombstone is another lifetime: the delete is
   * superseded.
   */
  async function landFence(
    connector: string,
    pin: { readonly ns: string; readonly version: number },
    hashes: Hashes,
  ) {
    const scope = controlScope(connector, pin.ns);
    const landed = async () => {
      const after = classifyControl(await deps.registry.read(scope), hashes);
      if (after.kind === "foreign" && after.version > pin.version)
        throw new ConnectionDeleteSuperseded(connector);
      return after.kind === "deleted"
        ? after.version >= pin.version + 1
        : after.kind === "active" && after.generation > pin.version;
    };
    try {
      await signPost(
        scope,
        hashes.tombstoneData,
        hashes.tombstoneMetadata,
        pin.version + 1,
      );
    } catch (error) {
      if (!(error instanceof RegistryRefusedError && error.status === 409)) {
        // Uncertain: the tombstone may have committed and only its reply
        // been lost. A read decides, so a registry that now refuses every
        // post but still answers reads does not hold the delete pending.
        // When the read cannot prove the fence either, the failure stands.
        if (
          await landed().catch((e: unknown) => {
            if (e instanceof ConnectionDeleteSuperseded) throw e;
            return false;
          })
        )
          return;
        throw error;
      }
    }
    if (!(await landed()))
      throw new Error("control fence pending without confirmed tombstone");
  }

  /** Wait for every promise; throw the first failure, a supersession only if nothing else failed. */
  async function settleAll(work: readonly Promise<unknown>[]) {
    const results = await Promise.allSettled(work);
    const failures = results.flatMap((r) =>
      r.status === "rejected" ? [r.reason] : [],
    );
    const real = failures.find(
      (e) => !(e instanceof ConnectionDeleteSuperseded),
    );
    if (real !== undefined) throw real;
    if (failures.length > 0) throw failures[0];
  }

  async function land(
    connector: string,
    fencesEnded: (fenced: boolean) => void,
  ) {
    const stored = await readIntent(connector);
    if (!stored) {
      fencesEnded(true);
      return;
    }
    let intent: DeleteIntent = stored;
    const hashes = await hashesOf();
    const listed = listings.get(stored.id!);
    listings.delete(stored.id!);
    let saved: Promise<unknown> = Promise.resolve();
    const persist = (change: (current: DeleteIntent) => DeleteIntent) => {
      const next = change(intent);
      intent = next;
      saved = saved.then(() => save(connector, next));
      return saved;
    };
    const fenced = (ns: string) =>
      intent.fences?.some((f) => f.ns === ns) ?? false;
    const recordFence = (pin: {
      readonly ns: string;
      readonly version: number;
    }) =>
      persist((current) => ({
        ...current,
        fences: [
          ...(current.fences ?? []),
          { ns: pin.ns, version: pin.version + 1 },
        ],
      }));
    try {
      const unfenced = intent.pins.filter((p) => !fenced(p.ns));
      if (unfenced.length > 0) {
        // Every fence in one request (all or nothing): a compare-and-set on
        // each pin and, when the plan listed it, on the control head there.
        const rows = await Promise.all(
          unfenced.map(async (pin) => {
            const scope = controlScope(connector, pin.ns);
            const head = listed?.get(scope);
            return {
              scope,
              ...(head?.found &&
                head.version === pin.version && {
                  expectedHeadDataHash: head.dataHash as `0x${string}`,
                }),
              dataHash: hashes.tombstoneData,
              metadataHash: hashes.tombstoneMetadata,
              expectedVersion: String(pin.version + 1),
              signature: await sign(
                scope,
                hashes.tombstoneData,
                hashes.tombstoneMetadata,
                pin.version + 1,
              ),
            };
          }),
        );
        const turns = await commitFences({
          registry: deps.registry,
          ownerAddress: deps.ownerAddress,
          rows,
        });
        for (const [i, pin] of unfenced.entries())
          if (turns[i] === "committed") await recordFence(pin);
      }
      // The per-row pass: each fence the request did not store.
      await settleAll(
        intent.pins
          .filter((p) => !fenced(p.ns))
          .map(async (pin) => {
            await landFence(connector, pin, hashes);
            await recordFence(pin);
          }),
      );
      fencesEnded(true);
      await saved;
      await purgeLocal(connector, intent);
      await options.eraseLegacy?.(connector);
      await clear(connector, intent.id!);
    } catch (error) {
      await saved.catch(() => undefined);
      if (error instanceof ConnectionDeleteSuperseded) {
        await purgeLocal(connector, intent);
        await clear(connector, intent.id!);
      }
      throw error;
    }
  }
  /**
   * The namespaces of `connector` whose delete has not settled here: a local
   * connection in them is not purged (a connection added again, or one the
   * purge has not reached, is another lifetime). `null` while a delete of the
   * connector is in flight: nothing of it is settled. One namespace's live
   * connection never holds back another's erasure: a delete that names a
   * lifetime leaves a local connection no pin names, by design.
   */
  async function unsettledNamespaces(
    connector: string,
  ): Promise<ReadonlySet<string> | null> {
    const [intent] = await deps.db.query(
      "SELECT 1 FROM delete_intents WHERE connector=?",
      [connector],
    );
    if (intent) return null;
    const live = await deps.db.query<{ ns: string }>(
      "SELECT DISTINCT ns FROM connections WHERE connector=? AND control_state<>'deleted'",
      [connector],
    );
    return new Set(live.map((row) => row.ns));
  }
  /**
   * One erasure pass for `connector`; answers whether it is unfinished. The
   * caller has consumed the connector's queue entry: what is queued after
   * that is news from while the pass runs, and this does not touch it.
   */
  async function eraseSettled(connector: string): Promise<boolean> {
    try {
      if (stop.signal.aborted) return false;
      const skipNamespaces = await unsettledNamespaces(connector);
      if (skipNamespaces === null) return false;
      return (
        await options.eraseLogs!(connector, stop.signal, { skipNamespaces })
      ).pending;
    } catch (error) {
      // The eraser reports a failure as pending; this is its own bug or a
      // database that went away. Try again later, never fail the delete.
      deps.logger.warn(
        {
          connector,
          error: error instanceof Error ? error.message : String(error),
        },
        "stream sync: connection log erasure failed",
      );
      return true;
    }
  }
  /**
   * One erasure at a time per connector. A caller while one runs queues the
   * connector again, since what it knows (a delete settled) may be newer than
   * what the running pass read. A pass takes its queue entry when it starts,
   * so an entry present when it ends arrived during it: it runs again. An
   * entry the pass itself leaves (`pending`) waits for the retry loop.
   */
  function eraseLogsOf(connector: string): Promise<void> {
    if (!options.eraseLogs) return Promise.resolve();
    const held = erasures.get(connector);
    if (held) {
      erasing.add(connector);
      return held;
    }
    const run = (async () => {
      let again: boolean;
      do {
        erasing.delete(connector);
        const unfinished = await eraseSettled(connector);
        again = erasing.has(connector) && !stop.signal.aborted;
        if (unfinished) erasing.add(connector);
      } while (again);
    })().finally(() => {
      if (erasures.get(connector) === run) erasures.delete(connector);
    });
    erasures.set(connector, run);
    return run;
  }
  function schedule(connector: string): Landing {
    const held = flights.get(connector);
    if (held) return held;
    let fencesEnded!: (fenced: boolean) => void;
    const fenced = new Promise<boolean>((resolve) => (fencesEnded = resolve));
    const done: Promise<void> = deps.queue
      .run(`delete:${connector}`, "purge", () => land(connector, fencesEnded))
      .finally(() => {
        fencesEnded(false); // a landing that failed before its fence says "not fenced"
        if (flights.get(connector) === landing) flights.delete(connector);
      });
    const landing: Landing = { fenced, done };
    flights.set(connector, landing);
    // A delete that settled is erased from storage, outside its own queue.
    void done.then(
      () => eraseLogsOf(connector),
      () => undefined,
    );
    return landing;
  }
  async function resumeDelete(
    connector: string,
  ): Promise<PendingDelete | null> {
    if (stop.signal.aborted || !(await readIntent(connector))) return null;
    if (stop.signal.aborted) return null;
    try {
      await schedule(connector).done;
      return null;
    } catch (error) {
      return { connector, why: error instanceof Error ? error.name : "Error" };
    }
  }
  async function requestConnectionDelete(
    connector: string,
    request: { readonly lifetime?: string } = {},
  ) {
    stop.signal.throwIfAborted();
    controlScope(connector, "");
    // A token this server did not write is refused before anything is planned.
    const named =
      request.lifetime === undefined
        ? null
        : parseLifetime(connector, request.lifetime);
    const intent = await deps.queue.run(
      `delete:${connector}`,
      "purge",
      async () => {
        const decide = async (
          planned: Awaited<ReturnType<typeof plan>>,
          held: ReadonlySet<string>,
        ) => {
          // The connection the person deleted, not whatever is connected now:
          // checked on the plan this delete would act on, before it saves or
          // purges anything.
          if (
            named &&
            !holdsLifetime(
              named,
              new Map(planned.intent.pins.map((p) => [p.ns, p.version])),
              planned.ended,
            )
          )
            throw new ConnectionLifetimeChanged(connector);
          const open = await readIntent(connector);
          const empty = planned.intent.pins.length === 0;
          // The lifetime it names has ended: nothing of it is left to delete,
          // and what is local now is not that connection's. Only the delete
          // already recorded for this very lifetime is resumed. A token that
          // names no row is not an ended lifetime: it was read for a
          // connection with no control row (never published), and a delete
          // of that one is a local purge, as with no token.
          if (named && named.size > 0 && empty)
            return open &&
              open.pins.every((pin) => named.get(pin.ns) === pin.version)
              ? open
              : null;
          if (open && (empty || samePlan(open, planned.intent))) return open;
          if (empty) {
            await purgeLocal(connector, planned.intent, held);
            await options.eraseLegacy?.(connector);
            return null;
          }
          const next = named
            ? { ...planned.intent, pinned: true as const }
            : planned.intent;
          await save(connector, next);
          listings.set(next.id!, planned.listing);
          await purgeLocal(connector, next, held);
          return next;
        };
        const planned = await plan(connector);
        // A local connection with no control row in the listing may be
        // creating it: its first save commits control row and first segment
        // in one request, under the connection's queue. That listing cannot
        // tell whether the commit is in flight. Wait for the queue, then
        // list again: the commit has landed (the listing pins its control
        // row) or none is in flight and none starts before the intent is
        // saved or the connection purged. A connection every pin covers
        // needs no wait: its fence is a compare-and-set on the row the
        // listing showed.
        if (await hasUnpinnedConnection(connector, planned.intent))
          return holdingConnections(connector, async (held) =>
            decide(await plan(connector), held),
          );
        return decide(planned, new Set());
      },
    );
    if (!intent) {
      // Nothing to fence: the connection was deleted already, or never saved.
      // Its delete is settled, and what an earlier delete left is erased.
      void eraseLogsOf(connector);
      return { deleteId: deps.newOp(), fenced: true };
    }
    const landing = schedule(connector);
    landing.done.catch((error) =>
      deps.logger.warn(
        {
          connector,
          reason: error instanceof Error ? error.name : "Error",
          // The cause an operator needs: a delete that stays pending blocks
          // every reconnect, and the name alone ("Error") does not say why.
          message: error instanceof Error ? error.message : String(error),
          ...(error instanceof Error && { stack: error.stack }),
        },
        "connection delete pending",
      ),
    );
    // The request waits for the fences only; the local purge runs after the
    // answer. A registry that is slower than the budget answers "not fenced
    // yet"; the landing is not cancelled and the resume loop re-checks it.
    return {
      deleteId: intent.id!,
      fenced: await withinBudget(landing.fenced, options.fenceWaitMs),
    };
  }
  return {
    requestConnectionDelete(
      connector: string,
      lifetime?: { readonly lifetime?: string },
    ) {
      const request = requestConnectionDelete(connector, lifetime);
      requests.add(request);
      void request.then(
        () => requests.delete(request),
        () => requests.delete(request),
      );
      return request;
    },
    readConnectionLifetime,
    async resumeDeletes() {
      const rows = await deps.db.query<{ connector: string }>(
        "SELECT connector FROM delete_intents ORDER BY connector",
      );
      return (
        await Promise.all(rows.map(({ connector }) => resumeDelete(connector)))
      ).filter((p): p is PendingDelete => p !== null);
    },
    resumeDelete,
    /** A connection of the connector was purged here: its erasure may be owed. */
    noteSettled(connector: string) {
      if (options.eraseLogs) erasing.add(connector);
    },
    /**
     * A connection was purged and its connector is unknown: the sweep of
     * every deleted connection is owed again.
     */
    noteSweepOwed() {
      if (options.eraseLogs) sweepOwed = true;
    },
    /** Whether erasure work is owed: the start sweep, or an unfinished erasure. */
    erasureOwed: () => sweepOwed || erasing.size > 0,
    /**
     * Run the owed erasures: first, once, every connector with a connection
     * deleted here (a delete settled before this process started, or adopted
     * from another device); then every connector whose erasure is unfinished.
     * Answers true while one is still unfinished, so the caller retries.
     */
    async resumeErasures(): Promise<boolean> {
      if (!options.eraseLogs || stop.signal.aborted) return false;
      if (sweepOwed) {
        const rows = await deps.db.query<{ connector: string }>(
          "SELECT DISTINCT connector FROM connections WHERE control_state='deleted' ORDER BY connector",
        );
        for (const { connector } of rows) erasing.add(connector);
        // Only once the rows are queued: a query that failed leaves it owed.
        sweepOwed = false;
      }
      // A run in progress is waited for, not queued again: what it leaves
      // unfinished is in `erasing` when it ends, and so is what arrived
      // while it ran. Without this wait the loop would find the queue empty
      // (a running pass has taken its entry) and stop with that work owed.
      await Promise.all(
        [...new Set([...erasing, ...erasures.keys()])].map(
          (connector) => erasures.get(connector) ?? eraseLogsOf(connector),
        ),
      );
      return erasing.size > 0;
    },
    async close() {
      stop.abort(new Error("sync closed"));
      await Promise.allSettled([...requests]);
      await Promise.allSettled(
        [...flights.values()].map((flight) => flight.done),
      );
      // After the flights: a landing that ends starts its erasure, which the
      // abort above stops.
      await Promise.resolve();
      await Promise.allSettled([...erasures.values()]);
    },
  };
}

import { keccak_256 } from "@noble/hashes/sha3";
import {
  classifyControl,
  classifyStreamRow,
  controlHashes,
  controlScope,
  deriveKeyCheck,
  digestHead,
  encodeHead,
  HEAD_FORMAT,
  headBlobName,
  parseScope,
  sameControl,
  streamScope,
  verifyHead,
  type ControlState,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { manifestStreamLister } from "../stream-sync/artifacts.js";
import {
  deleteMetadataHash,
  deleteEndedEarlierLifetime,
  endedGenerationDeleteMetadataHash,
} from "../stream-sync/delete-metadata.js";
import { RegistryRefusedError } from "../stream-sync/ports.js";
import type { LocalSyncDeps } from "./deps.js";
import { purgeConnection } from "./purge.js";

export class ConnectionStoppedError extends Error {
  constructor(readonly connector: string) {
    super(
      `connection of ${connector} is stopped: deleted, not reconnected; an explicit connect is required`,
    );
    this.name = "ConnectionStoppedError";
  }
}
export class ConnectorNotVerifiedError extends Error {
  constructor(readonly connector: string) {
    super(
      `no verified manifest names the streams of ${connector}; its delete cannot fence rowless streams`,
    );
    this.name = "ConnectorNotVerifiedError";
  }
}
export class ConnectionDeleteSuperseded extends Error {
  constructor(readonly connector: string) {
    super(`delete of ${connector} was superseded before it landed`);
    this.name = "ConnectionDeleteSuperseded";
  }
}

/** One stored stream pin. Missing control/pin fields belong to older intents. */
interface StreamPin {
  readonly ns: string;
  readonly stream: string;
  readonly control?: ControlState;
  readonly pin?: number;
}
/** Persisted byte-for-byte in delete_intents before any registry write. */
export interface DeleteIntent {
  readonly id?: string;
  readonly pins: readonly { readonly ns: string; readonly version: number }[];
  readonly streams?: readonly StreamPin[];
  /**
   * The control tombstones this delete confirmed, one per namespace. `version`
   * is the tombstone's registry version, always its pin + 1. A namespace named
   * here is fenced: stream cleanup under it removes only data of the lifetime
   * the pin names or an earlier one. A namespace not named here (an older
   * intent, a control row of another key, no control row) is cleaned and
   * finished the way it was before fences existed.
   */
  readonly fences?: readonly {
    readonly ns: string;
    readonly version: number;
  }[];
  /** Cleanup only: every stream of the intent is tombstoned. Says nothing of the control row. */
  readonly streamsLanded?: true;
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
 * surfaces still see the connection, and data they publish before the fence
 * lands is deleted with the rest. Either way stream cleanup goes on in the
 * background until it finishes.
 */
export interface ConnectionDeleteRequest {
  readonly deleteId: string;
  readonly fenced: boolean;
}
export interface ConnectionDeleter {
  requestConnectionDelete(connector: string): Promise<ConnectionDeleteRequest>;
  resumeDeletes(): Promise<readonly PendingDelete[]>;
}
/** One running landing: when its fence phase ended, and when all of it did. */
interface Landing {
  readonly fenced: Promise<boolean>;
  readonly done: Promise<void>;
}
const keccak = async (bytes: Uint8Array) => keccak_256(bytes);
const ATTEMPTS = 8;

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
  deps: LocalSyncDeps,
  options: {
    readonly declaredStreams: (connector: string) => readonly string[];
    readonly retainedManifests?: () => readonly string[];
    readonly eraseLegacy?: (connector: string) => Promise<void>;
    /**
     * How long a request waits for the fence before it answers
     * `fenced: false`. The landing keeps going in the background and the
     * resume loop re-checks it. Production passes the loop's first resume
     * wait, so a delete that has not fenced by then is the one the loop would
     * pick up next. Absent: the request waits for the fence however long it
     * takes (tests only).
     */
    readonly fenceWaitMs?: number;
  },
): ConnectionDeleter {
  const flights = new Map<string, Landing>();
  const keyInfo = async () => {
    const keyCheck = await deriveKeyCheck((m) => deps.keys.namespaceHmac(m));
    return { keyCheck, hashes: await controlHashes(keccak, keyCheck) };
  };
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
      intent.pins.some(
        (p) => !Number.isSafeInteger(p.version) || p.version < 1,
      ) ||
      (intent.streams !== undefined && !Array.isArray(intent.streams))
    )
      throw new Error("invalid stored delete intent");
    for (const fence of intent.fences ?? []) {
      const pin = intent.pins.find((p) => p.ns === fence.ns);
      if (!pin || fence.version !== pin.version + 1)
        throw new Error("invalid stored delete intent");
    }
    for (const pin of intent.pins) controlScope(connector, pin.ns);
    for (const pin of intent.streams ?? [])
      streamScope(connector, pin.ns, pin.stream);
    return { ...intent, id: row.delete_id };
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
  async function plan(
    connector: string,
  ): Promise<{ intent: DeleteIntent; empty: boolean }> {
    const { hashes } = await keyInfo();
    const controls = new Map<string, ControlState>();
    const pins: { ns: string; version: number }[] = [];
    for (const entry of await deps.registry.listControlRows()) {
      const parsed = parseScope(entry.scope);
      if (parsed?.kind !== "control" || parsed.connector !== connector)
        continue;
      const current = classifyControl(
        await deps.registry.read(entry.scope),
        hashes,
      );
      controls.set(parsed.ns, current);
      if (current.kind === "active" || current.kind === "foreign")
        pins.push({
          ns: parsed.ns,
          version:
            current.kind === "active" ? current.generation : current.version,
        });
    }
    const streams: StreamPin[] = [];
    for (const entry of await deps.registry.listStreamRows(connector)) {
      const parsed = parseScope(entry.scope);
      if (parsed?.kind === "stream" && parsed.connector === connector)
        streams.push({
          ns: parsed.ns,
          stream: parsed.stream,
          control: controls.get(parsed.ns) ?? { kind: "absent" },
        });
    }
    const empty = pins.length === 0 && streams.length === 0;
    if (!empty) {
      const declared = new Set([
        ...options.declaredStreams(connector),
        ...manifestStreamLister(options.retainedManifests?.() ?? [])(connector),
      ]);
      if (declared.size === 0 && streams.length === 0)
        throw new ConnectorNotVerifiedError(connector);
      for (const name of declared)
        if (!streams.some((s) => s.ns === "" && s.stream === name))
          streams.push({
            ns: "",
            stream: name,
            control: controls.get("") ?? { kind: "absent" },
          });
    }
    return { intent: { id: deps.newOp(), pins, streams }, empty };
  }
  function samePlan(a: DeleteIntent, b: DeleteIntent) {
    return (
      a.pins.length === b.pins.length &&
      a.pins.every((p) =>
        b.pins.some((q) => q.ns === p.ns && q.version === p.version),
      ) &&
      a.streams?.length === b.streams?.length &&
      (a.streams ?? []).every((p) =>
        b.streams?.some(
          (q) =>
            p.ns === q.ns &&
            p.stream === q.stream &&
            (p.control && q.control ? sameControl(p.control, q.control) : true),
        ),
      )
    );
  }
  async function purgeLocal(connector: string, intent: DeleteIntent) {
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
      if (pin && connection.generation > pin.version) continue;
      await deps.queue.run(connection.connection_id, "purge", async () => {
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
  async function signPost(
    scope: string,
    dataHash: `0x${string}`,
    metadataHash: `0x${string}`,
    version: number,
  ) {
    const signature = await deps.signer.signAddData({
      ownerAddress: deps.ownerAddress,
      scope,
      dataHash,
      metadataHash,
      expectedVersion: BigInt(version),
    });
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
   * Land the control tombstone of one namespace: the delete's single
   * linearization point. Other surfaces read the control row to decide the
   * connection exists, and the gateway checks it in the transaction of every
   * publish, so once it is tombstoned no publish of the ended lifetime lands.
   *
   * The post is a CAS at `pin + 1`, sent blind and then confirmed by a read:
   * a lost reply, a reply that never arrives, a conflict and a registry that
   * lags all end in the same read. Any control version at or above the
   * tombstone's proves it landed, whoever wrote it (it may already have been
   * followed by a reconnect), so a fence never lands twice (a retry resends the
   * same `pin + 1`, and the registry refuses it) and is never judged
   * "superseded".
   */
  async function landFence(
    connector: string,
    pin: { readonly ns: string; readonly version: number },
    hashes: Awaited<ReturnType<typeof keyInfo>>["hashes"],
  ) {
    const scope = controlScope(connector, pin.ns);
    const landed = async () => {
      const after = classifyControl(await deps.registry.read(scope), hashes);
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
        if (await landed().catch(() => false)) return;
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
    fencePhaseEnded: (fenced: boolean) => void,
  ) {
    const stored = await readIntent(connector);
    if (!stored) {
      fencePhaseEnded(true);
      return;
    }
    let intent: DeleteIntent = stored;
    const { keyCheck, hashes } = await keyInfo();
    // Streams are cleaned in parallel and each saves its own pin, so saves
    // run in the order the intent changed.
    let saved: Promise<unknown> = Promise.resolve();
    const persist = (change: (current: DeleteIntent) => DeleteIntent) => {
      const next = change(intent);
      intent = next;
      saved = saved.then(() => save(connector, next));
      return saved;
    };
    const fencedAt = (ns: string) => {
      const fence = intent.fences?.find((f) => f.ns === ns);
      return fence && intent.pins.find((p) => p.ns === ns)?.version;
    };
    /**
     * One stream's tombstone. Under a fence the stream is cleaned against the
     * lifetime the fence ended (`ended`), not against the control row, which
     * has since been tombstoned and may have been reconnected: the row is
     * tombstoned only when it holds data of that lifetime or an earlier one,
     * and a row of a later lifetime is left as it is. Without a fence the
     * control row must still be the one the plan saw.
     */
    async function cleanStream(
      connector: string,
      target: StreamPin,
      hashes: Awaited<ReturnType<typeof keyInfo>>["hashes"],
      keyCheck: string,
    ) {
      const scope = streamScope(connector, target.ns, target.stream);
      let finished = false;
      let signedPin = target.pin;
      // A rejected CAS spends one of ATTEMPTS, and so does a landed CAS that
      // the next read no longer shows. A landed CAS the next read confirms
      // is free: confirming it must not consume the attempt that won.
      let spent = 0;
      let landed = false;
      for (;;) {
        const row = await deps.registry.read(scope);
        const ended = fencedAt(target.ns);
        // Fenced: the lifetime this delete ended, as the control row said
        // before the fence. Otherwise the control row now.
        const now: ControlState =
          ended !== undefined
            ? { kind: "active", generation: ended }
            : classifyControl(
                await deps.registry.read(controlScope(connector, target.ns)),
                hashes,
              );
        if (ended === undefined) {
          const pin = intent.pins.find((p) => p.ns === target.ns);
          const holds = target.control
            ? sameControl(now, target.control)
            : pin
              ? (now.kind === "active"
                  ? now.generation
                  : now.kind === "foreign"
                    ? now.version
                    : -1) === pin.version
              : now.kind === "absent";
          if (!holds) throw new ConnectionDeleteSuperseded(connector);
        }
        // A completed delete already fences this lifetime. Keep its row,
        // including its version and hashes, even on a device with no local state.
        if (
          now.kind === "deleted" &&
          row.found &&
          deleteEndedEarlierLifetime(scope, row, now.version)
        ) {
          finished = true;
          break;
        }
        if (now.kind === "foreign")
          throw new Error(
            "stream delete pending without ended generation proof",
          );
        // A deleted control at v fences every active generation <= v.
        // Use v as a conservative boundary when the old marker has lost
        // its proof: reconnect must create active(v+1). This does not
        // infer a lost active generation or weaken the reader's rule.
        // With no control, the first lifetime is generation 1, matching
        // the empty delete head, so the legacy v1 marker remains usable.
        const endedGeneration =
          now.kind === "active"
            ? now.generation
            : now.kind === "deleted"
              ? now.version
              : undefined;
        // With a known lifetime, only its v2 metadata proves the boundary.
        // A tombstoned row or a head fence cannot substitute for that proof.
        const marked = (version: number, hash: string) =>
          (now.kind === "absent" &&
            hash.toLowerCase() === deleteMetadataHash(scope, version)) ||
          (endedGeneration !== undefined &&
            hash.toLowerCase() ===
              endedGenerationDeleteMetadataHash(
                scope,
                version,
                endedGeneration,
              ));
        let lastDelete =
          row.found &&
          ((now.kind === "absent" &&
            classifyStreamRow(row, hashes) === "tombstoned") ||
            marked(row.version, row.metadataHash))
            ? row.version
            : 0;
        if (
          now.kind === "absent" &&
          row.found &&
          lastDelete === 0 &&
          signedPin !== undefined
        ) {
          try {
            const cipher = await deps.blobs.get(
              `${scope}/${headBlobName(row.dataHash)}`,
            );
            if (cipher) {
              const verified = await verifyHead(
                keccak,
                await deps.keys.decrypt(scope, cipher),
                {
                  dataHash: row.dataHash,
                  connector,
                  ns: target.ns,
                  stream: target.stream,
                  keyCheck,
                },
              );
              if (verified.kind === "ok")
                lastDelete = verified.head.lastDeleteVersion ?? 0;
            }
          } catch {
            // Deleting requires the control pin and CAS, never a readable old head.
          }
        }
        if (
          signedPin === undefined ? lastDelete > 0 : lastDelete >= signedPin
        ) {
          finished = true;
          break;
        }
        if (landed) spent++;
        if (spent >= ATTEMPTS) break;
        const version = row.found ? row.version + 1 : 1;
        const head = encodeHead({
          format: HEAD_FORMAT,
          connector,
          ns: target.ns,
          stream: target.stream,
          generation: 1,
          keyCheck,
          lastDeleteVersion: version,
          complete: false,
          observedAt: deps.now(),
          parts: [],
          primaryKey: ["id"],
          profile: { key: null, version: "0.0.0" },
          recordCount: 0,
        });
        const digest = await digestHead(keccak, head);
        // Under a fence, the row must hold nothing newer than the ended
        // lifetime before it is tombstoned. The check runs beside the head
        // upload (a head blob is content-addressed and harmless if unused).
        const oldDataOnly =
          ended !== undefined &&
          row.found &&
          classifyStreamRow(row, hashes) !== "tombstoned"
            ? holdsEndedLifetimeOnly(
                connector,
                target,
                row,
                ended,
                hashes,
                keyCheck,
              )
            : Promise.resolve(true);
        const [olderOnly] = await Promise.all([
          oldDataOnly,
          deps.keys
            .encrypt(scope, head)
            .then((cipher) =>
              deps.blobs.put(`${scope}/${digest.blobName}`, cipher),
            ),
        ]);
        if (!olderOnly) {
          // A later lifetime owns this row. It is not this delete's to remove.
          finished = true;
          break;
        }
        await persist((current) => ({
          ...current,
          streams: current.streams!.map((p) =>
            p.ns === target.ns && p.stream === target.stream
              ? { ...p, pin: version }
              : p,
          ),
        }));
        let conflict = false;
        try {
          conflict =
            (
              await signPost(
                scope,
                digest.dataHash,
                endedGeneration === undefined
                  ? deleteMetadataHash(scope, version)
                  : endedGenerationDeleteMetadataHash(
                      scope,
                      version,
                      endedGeneration,
                    ),
                version,
              )
            ).kind === "conflict";
        } catch (error) {
          if (!(error instanceof RegistryRefusedError && error.status === 409))
            throw error;
          conflict = true;
        }
        if (conflict) {
          await new Promise<void>((resolve) =>
            setTimeout(resolve, Math.min(10 * 2 ** spent, 1000)),
          );
          spent++;
        }
        landed = !conflict;
        // The next authoritative read proves whether this pin landed.
        signedPin = version;
      }
      if (!finished)
        throw new Error("stream delete pending after version conflicts");
    }

    /**
     * Whether a live stream row holds data of the ended lifetime (`ended`) or
     * an earlier one only. `row` was read before this runs.
     *
     * While the control row still reads exactly the fence (deleted at
     * `ended + 1`), no later lifetime exists, and none can have published
     * before this read: a publish needs an active control row of its own
     * generation. Otherwise the control row has moved (a reconnect), and the
     * head's own generation says which lifetime wrote the row. A head that
     * cannot be read then leaves the question open, and the delete stays
     * pending rather than guess.
     */
    async function holdsEndedLifetimeOnly(
      connector: string,
      target: StreamPin,
      row: Extract<
        Awaited<ReturnType<LocalSyncDeps["registry"]["read"]>>,
        { found: true }
      >,
      ended: number,
      hashes: Awaited<ReturnType<typeof keyInfo>>["hashes"],
      keyCheck: string,
    ): Promise<boolean> {
      const control = classifyControl(
        await deps.registry.read(controlScope(connector, target.ns)),
        hashes,
      );
      if (control.kind === "deleted" && control.version === ended + 1)
        return true;
      const scope = streamScope(connector, target.ns, target.stream);
      const cipher = await deps.blobs.get(
        `${scope}/${headBlobName(row.dataHash)}`,
      );
      if (cipher) {
        const verified = await verifyHead(
          keccak,
          await deps.keys.decrypt(scope, cipher),
          {
            dataHash: row.dataHash,
            connector,
            ns: target.ns,
            stream: target.stream,
            keyCheck,
          },
        );
        if (verified.kind === "ok") return verified.head.generation <= ended;
      }
      throw new Error(
        "stream delete pending: the lifetime of the stream's head is unproven",
      );
    }

    try {
      // Phase 1, the fence. A control row of another key is not tombstoned
      // here: its streams cannot be proven and stay pending as before.
      const foreign = new Set(
        (intent.streams ?? [])
          .filter((s) => s.control?.kind === "foreign")
          .map((s) => s.ns),
      );
      await settleAll(
        intent.pins
          .filter((p) => fencedAt(p.ns) === undefined && !foreign.has(p.ns))
          .map(async (pin) => {
            await landFence(connector, pin, hashes);
            await persist((current) => ({
              ...current,
              fences: [
                ...(current.fences ?? []),
                { ns: pin.ns, version: pin.version + 1 },
              ],
            }));
          }),
      );
      const unfenced = () =>
        intent.pins.filter((p) => fencedAt(p.ns) === undefined);
      fencePhaseEnded(unfenced().length === 0);
      // Phase 2, cleanup. Each stream is its own scope with its own CAS, so
      // streams do not wait for one another.
      if (!intent.streamsLanded) {
        await settleAll(
          (intent.streams ?? []).map((target) =>
            cleanStream(connector, target, hashes, keyCheck),
          ),
        );
        await persist((current) => ({ ...current, streamsLanded: true }));
      }
      // Control rows that no fence covered (another key's): the old order.
      for (const pin of unfenced()) {
        const scope = controlScope(connector, pin.ns);
        try {
          await signPost(
            scope,
            hashes.tombstoneData,
            hashes.tombstoneMetadata,
            pin.version + 1,
          );
        } catch (error) {
          if (!(error instanceof RegistryRefusedError && error.status === 409))
            throw error;
        }
        const after = classifyControl(await deps.registry.read(scope), hashes);
        if (after.kind !== "deleted") {
          if (
            after.kind === "absent" ||
            (after.kind === "active" && after.generation <= pin.version)
          )
            throw new Error(
              "control delete pending without confirmed tombstone",
            );
          throw new ConnectionDeleteSuperseded(connector);
        }
      }
      await saved;
      await purgeLocal(connector, intent);
      await options.eraseLegacy?.(connector);
      await clear(connector, intent.id!);
    } catch (error) {
      await saved.catch(() => undefined);
      if (error instanceof ConnectionDeleteSuperseded)
        await clear(connector, intent.id!);
      throw error;
    }
  }
  function schedule(connector: string): Landing {
    const held = flights.get(connector);
    if (held) return held;
    let fencePhaseEnded!: (fenced: boolean) => void;
    const fenced = new Promise<boolean>(
      (resolve) => (fencePhaseEnded = resolve),
    );
    const done: Promise<void> = deps.queue
      .run(`delete:${connector}`, "purge", () =>
        land(connector, fencePhaseEnded),
      )
      .finally(() => {
        fencePhaseEnded(false); // a landing that failed before its fence says "not fenced"
        if (flights.get(connector) === landing) flights.delete(connector);
      });
    const landing: Landing = { fenced, done };
    flights.set(connector, landing);
    return landing;
  }
  return {
    async requestConnectionDelete(connector) {
      controlScope(connector, "");
      const intent = await deps.queue.run(
        `delete:${connector}`,
        "purge",
        async () => {
          const open = await readIntent(connector);
          let planned: Awaited<ReturnType<typeof plan>>;
          try {
            planned = await plan(connector);
          } catch (error) {
            if (open && error instanceof ConnectorNotVerifiedError) return open;
            throw error;
          }
          if (open && (planned.empty || samePlan(open, planned.intent)))
            return open;
          if (planned.empty) {
            await purgeLocal(connector, planned.intent);
            await options.eraseLegacy?.(connector);
            return null;
          }
          await save(connector, planned.intent);
          await purgeLocal(connector, planned.intent);
          return planned.intent;
        },
      );
      if (!intent) return { deleteId: deps.newOp(), fenced: true };
      const landing = schedule(connector);
      landing.done.catch((error) =>
        deps.logger.warn(
          { connector, reason: error instanceof Error ? error.name : "Error" },
          "connection delete pending",
        ),
      );
      // The request waits for the fence only: one registry write and its
      // confirming read. Cleanup keeps running after the answer. A registry
      // that is slower than the budget answers "not fenced yet"; the landing
      // is not cancelled and the resume loop re-checks it.
      return {
        deleteId: intent.id!,
        fenced: await withinBudget(landing.fenced, options.fenceWaitMs),
      };
    },
    async resumeDeletes() {
      const rows = await deps.db.query<{ connector: string }>(
        "SELECT connector FROM delete_intents ORDER BY connector",
      );
      const pending: PendingDelete[] = [];
      for (const { connector } of rows) {
        try {
          await schedule(connector).done;
        } catch (error) {
          pending.push({
            connector,
            why: error instanceof Error ? error.name : "Error",
          });
        }
      }
      return pending;
    },
  };
}

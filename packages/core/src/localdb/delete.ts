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
  readonly streamsLanded?: true;
}
export interface PendingDelete {
  readonly connector: string;
  readonly why: string;
}
export interface ConnectionDeleter {
  requestConnectionDelete(
    connector: string,
  ): Promise<{ readonly deleteId: string }>;
  resumeDeletes(): Promise<readonly PendingDelete[]>;
}
const keccak = async (bytes: Uint8Array) => keccak_256(bytes);
const ATTEMPTS = 8;

export function createConnectionDeleter(
  deps: LocalSyncDeps,
  options: {
    readonly declaredStreams: (connector: string) => readonly string[];
    readonly retainedManifests?: () => readonly string[];
    readonly eraseLegacy?: (connector: string) => Promise<void>;
  },
): ConnectionDeleter {
  const flights = new Map<string, Promise<void>>();
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
  async function land(connector: string) {
    let intent = await readIntent(connector);
    if (!intent) return;
    const { keyCheck, hashes } = await keyInfo();
    try {
      if (!intent.streamsLanded) {
        for (const target of intent.streams ?? []) {
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
            const now = classifyControl(
              await deps.registry.read(controlScope(connector, target.ns)),
              hashes,
            );
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
            const ended =
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
              (ended !== undefined &&
                hash.toLowerCase() ===
                  endedGenerationDeleteMetadataHash(scope, version, ended));
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
            const observedAt = deps.now();
            const head = encodeHead({
              format: HEAD_FORMAT,
              connector,
              ns: target.ns,
              stream: target.stream,
              generation: 1,
              keyCheck,
              lastDeleteVersion: version,
              complete: false,
              observedAt,
              replacedAt: observedAt,
              parts: [],
              primaryKey: ["id"],
              profile: { key: null, version: "0.0.0" },
              recordCount: 0,
            });
            const digest = await digestHead(keccak, head);
            await deps.blobs.put(
              `${scope}/${digest.blobName}`,
              await deps.keys.encrypt(scope, head),
            );
            intent = {
              ...intent,
              streams: intent.streams!.map((p) =>
                p.ns === target.ns && p.stream === target.stream
                  ? { ...p, pin: version }
                  : p,
              ),
            };
            await save(connector, intent);
            let conflict = false;
            try {
              conflict =
                (
                  await signPost(
                    scope,
                    digest.dataHash,
                    ended === undefined
                      ? deleteMetadataHash(scope, version)
                      : endedGenerationDeleteMetadataHash(
                          scope,
                          version,
                          ended,
                        ),
                    version,
                  )
                ).kind === "conflict";
            } catch (error) {
              if (!(
                error instanceof RegistryRefusedError && error.status === 409
              ))
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
        intent = { ...intent, streamsLanded: true };
        await save(connector, intent);
      }
      for (const pin of intent.pins) {
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
      await purgeLocal(connector, intent);
      await options.eraseLegacy?.(connector);
      await clear(connector, intent.id!);
    } catch (error) {
      if (error instanceof ConnectionDeleteSuperseded)
        await clear(connector, intent.id!);
      throw error;
    }
  }
  function schedule(connector: string): Promise<void> {
    const held = flights.get(connector);
    if (held) return held;
    const task = deps.queue
      .run(`delete:${connector}`, "purge", () => land(connector))
      .finally(() => {
        if (flights.get(connector) === task) flights.delete(connector);
      });
    flights.set(connector, task);
    return task;
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
      if (!intent) return { deleteId: deps.newOp() };
      void schedule(connector).catch((error) =>
        deps.logger.warn(
          { connector, reason: error instanceof Error ? error.name : "Error" },
          "connection delete pending",
        ),
      );
      return { deleteId: intent.id! };
    },
    async resumeDeletes() {
      const rows = await deps.db.query<{ connector: string }>(
        "SELECT connector FROM delete_intents ORDER BY connector",
      );
      const pending: PendingDelete[] = [];
      for (const { connector } of rows) {
        try {
          await schedule(connector);
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

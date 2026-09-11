import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import { mkdir, open, readFile, rename, rm } from "node:fs/promises";
import { dirname } from "node:path";
import {
  isMcpTokenExpired,
  matchesMcpRefreshHash,
  type McpConnectionRecord,
  type McpConnectionStore,
  type McpOAuthAuthorizationRecord,
  type McpOAuthAuthorizationStore,
} from "@opendatalabs/personal-server-ts-core/mcp";
import type { Address } from "viem";
import type { ClaimResponse } from "@opendatalabs/vana-sdk/protocol/jobs";
import { userPsId } from "@opendatalabs/vana-sdk/protocol/identity";

export type McpWakeupIdentity = ClaimResponse["identity"];

const AAD = Buffer.from("vana.mcp.tee-state.v1");

export interface McpOwnerBinding {
  owner: Address;
  chainId: number;
}

export interface McpRollbackIdentity {
  identity: McpWakeupIdentity;
  generation: number;
}
export interface McpRollbackReceipt {
  migrationId: string;
  digest: string;
  owners: number;
  connections: number;
}
interface RollbackPreparation {
  importedDigest: string;
  ownersDigest: string;
  identities: Record<string, { digest: string; generation: number }>;
  receipt: McpRollbackReceipt;
}

interface State {
  writer?: {
    fenced: boolean;
    migrationId?: string;
    target?: string;
    importedId?: string;
    importedDigest?: string;
    rollback?: RollbackPreparation;
    rollbackActivated?: {
      migrationId: string;
      importedDigest: string;
      receiptDigest: string;
    };
  };
  connections: Record<string, McpConnectionRecord>;
  authorizations: Record<string, McpOAuthAuthorizationRecord>;
  owners: Record<string, McpOwnerBinding>;
  identities: Record<string, McpWakeupIdentity>;
}

export interface McpDurableState {
  /** These methods are exposed only through an attested encrypted migration peer. */
  fenceAndExport(migrationId: string, target: string): Promise<Uint8Array>;
  importSnapshot(
    snapshot: Uint8Array,
    migrationId: string,
  ): Promise<{ connections: number; digest: string }>;
  migrationStatus(): Promise<{
    fenced: boolean;
    importedId?: string;
    rollbackActivated?: boolean;
  }>;
  activateRollback(receipt: McpRollbackReceipt): Promise<void>;
  prepareRollback(
    migrationId: string,
    resolve: (binding: McpOwnerBinding) => Promise<McpRollbackIdentity>,
  ): Promise<McpRollbackReceipt>;
  getRollbackPreparation(): Promise<{
    receipt: McpRollbackReceipt;
    owners: {
      binding: McpOwnerBinding;
      identity: McpWakeupIdentity;
      generation: number;
    }[];
  }>;
  approvedOwnerBindings(): Promise<McpOwnerBinding[]>;
  connections: McpConnectionStore;
  authorizations: McpOAuthAuthorizationStore;
  bindOwner(connectionId: string, binding: McpOwnerBinding): Promise<void>;
  getOwner(connectionId: string): Promise<McpOwnerBinding | null>;
  rememberIdentity(identity: McpWakeupIdentity): Promise<void>;
  getIdentity(userPsId: string): Promise<McpWakeupIdentity | null>;
  /** Serializes multi-step OAuth mutations in the single ingress process. */
  exclusive<T>(operation: () => Promise<T>): Promise<T>;
}

/**
 * Single-CVM, single-writer store. Only ciphertext is written to its durable
 * volume; the caller obtains its 32-byte key from the TEE key agent. This is
 * deliberately not a multi-process or fleet database.
 */
export async function openMcpDurableState(options: {
  path: string;
  key: Uint8Array;
}): Promise<McpDurableState> {
  if (options.key.length !== 32)
    throw new Error("MCP state key must be 32 bytes");
  const key = Buffer.from(options.key);
  let state: State = {
    connections: {},
    authorizations: {},
    owners: {},
    identities: {},
  };
  try {
    const envelope = JSON.parse(await readFile(options.path, "utf8")) as {
      v: number;
      iv: string;
      tag: string;
      ciphertext: string;
    };
    if (envelope.v !== 1) throw new Error("Unsupported MCP state version");
    const decipher = createDecipheriv(
      "aes-256-gcm",
      key,
      Buffer.from(envelope.iv, "base64"),
    );
    decipher.setAAD(AAD);
    decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, "base64")),
      decipher.final(),
    ]);
    try {
      state = JSON.parse(plaintext.toString("utf8")) as State;
      state.identities ??= {};
      if (!state.connections || !state.authorizations || !state.owners) {
        throw new Error("Invalid MCP state");
      }
    } finally {
      plaintext.fill(0);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }

  let writes: Promise<unknown> = Promise.resolve();
  let operations: Promise<unknown> = Promise.resolve();
  const assertActive = (): void => {
    if (state.writer?.fenced)
      throw new Error("MCP writer fenced for migration");
  };
  const mutate = <T>(change: (draft: State) => T): Promise<T> => {
    const result = writes.then(async () => {
      assertActive();
      const draft = structuredClone(state);
      const value = change(draft);
      await persist(options.path, key, draft);
      state = draft;
      return structuredClone(value);
    });
    writes = result.catch(() => undefined);
    return result;
  };
  const read = async <T>(select: (current: State) => T): Promise<T> => {
    await writes;
    assertActive();
    return structuredClone(select(state));
  };

  return {
    // Read-only membership reconciliation remains possible after writer fencing;
    // it never exposes connection keys or permits an OAuth mutation.
    approvedOwnerBindings: async () => {
      await writes;
      return structuredClone(rollbackOwners(state).bindings);
    },
    prepareRollback(migrationId, resolve) {
      const operation = operations.then(() => {
        const prepared = writes.then(async () => {
          assertActive();
          if (
            !migrationId ||
            state.writer?.importedId !== migrationId ||
            !state.writer.importedDigest
          )
            throw new Error("Rollback requires the exact imported migration");
          // A failed refresh must not leave an earlier receipt usable at boot.
          const pending = structuredClone(state);
          delete pending.writer!.rollback;
          delete pending.writer!.rollbackActivated;
          await persist(options.path, key, pending);
          state = pending;
          const required = rollbackOwners(state);
          const draft = structuredClone(state);
          const identities: RollbackPreparation["identities"] = {};
          // Resolve one owner at a time on the small source TEE, without writing
          // a partial cache or exposing owner bindings to the operator.
          for (const binding of required.bindings) {
            const resolved = await resolve(binding);
            const id = userPsId(binding.chainId, binding.owner);
            if (
              resolved.identity.userPsId !== id ||
              !Number.isSafeInteger(resolved.identity.epoch) ||
              resolved.identity.epoch < 1 ||
              !Number.isSafeInteger(resolved.generation) ||
              resolved.generation < 0
            )
              throw new Error("Rollback identity does not match its owner");
            draft.identities[id] = structuredClone(resolved.identity);
            identities[id] = {
              digest: rollbackDigest(resolved.identity),
              generation: resolved.generation,
            };
          }
          const receipt = {
            migrationId,
            digest: rollbackDigest({
              migrationId,
              importedDigest: state.writer!.importedDigest,
              ownersDigest: required.digest,
              identities,
            }),
            owners: required.bindings.length,
            connections: required.connections,
          };
          draft.writer!.rollback = {
            importedDigest: state.writer!.importedDigest!,
            ownersDigest: required.digest,
            identities,
            receipt,
          };
          await persist(options.path, key, draft);
          state = draft;
          return structuredClone(receipt);
        });
        writes = prepared.catch(() => undefined);
        return prepared;
      });
      operations = operation.catch(() => undefined);
      return operation;
    },
    getRollbackPreparation: () =>
      read((current) => {
        const prepared = current.writer?.rollback;
        const required = rollbackOwners(current);
        if (
          !prepared ||
          prepared.receipt.migrationId !== current.writer?.importedId ||
          prepared.importedDigest !== current.writer.importedDigest ||
          prepared.ownersDigest !== required.digest ||
          Object.keys(prepared.identities).length !== required.bindings.length
        )
          throw new Error(
            "Rollback identities are not prepared for this imported state",
          );
        const owners = required.bindings.map((binding) => {
          const id = userPsId(binding.chainId, binding.owner);
          const identity = current.identities[id];
          if (
            !identity ||
            prepared.identities[id]?.digest !== rollbackDigest(identity)
          )
            throw new Error("Rollback identity changed after preparation");
          return {
            binding,
            identity,
            generation: prepared.identities[id]!.generation,
          };
        });
        return { receipt: prepared.receipt, owners };
      }),
    activateRollback: (receipt) =>
      mutate((draft) => {
        const prepared = draft.writer?.rollback;
        if (
          !prepared ||
          receipt.migrationId !== draft.writer?.importedId ||
          receipt.digest !== prepared.receipt.digest ||
          prepared.importedDigest !== draft.writer.importedDigest ||
          prepared.ownersDigest !== rollbackOwners(draft).digest ||
          Object.entries(prepared.identities).some(
            ([id, value]) =>
              value.digest !== rollbackDigest(draft.identities[id]),
          )
        )
          throw new Error("Rollback preparation changed before activation");
        draft.writer.rollbackActivated = {
          migrationId: receipt.migrationId,
          importedDigest: prepared.importedDigest,
          receiptDigest: receipt.digest,
        };
      }),
    migrationStatus: async () => {
      await writes;
      return {
        fenced: state.writer?.fenced ?? false,
        ...(state.writer?.rollbackActivated
          ? {
              rollbackActivated:
                state.writer.rollbackActivated.migrationId ===
                  state.writer.importedId &&
                state.writer.rollbackActivated.importedDigest ===
                  state.writer.importedDigest &&
                state.writer.rollbackActivated.receiptDigest ===
                  state.writer.rollback?.receipt.digest,
            }
          : {}),
        ...(state.writer?.importedId
          ? { importedId: state.writer.importedId }
          : {}),
      };
    },
    fenceAndExport(migrationId, target): Promise<Uint8Array> {
      if (!migrationId || !target)
        return Promise.reject(new Error("Migration identity required"));
      const result = operations.then(async () => {
        const exported = writes.then(async () => {
          if (
            state.writer?.fenced &&
            (state.writer.migrationId !== migrationId ||
              state.writer.target !== target)
          )
            throw new Error("MCP writer already fenced for another migration");
          const draft = structuredClone(state);
          draft.writer = { ...draft.writer, fenced: true, migrationId, target };
          await persist(options.path, key, draft);
          state = draft;
          return Buffer.from(
            JSON.stringify({ v: 1, migrationId, state: draft }),
          );
        });
        writes = exported.catch(() => undefined);
        return exported;
      });
      operations = result.catch(() => undefined);
      return result;
    },
    importSnapshot(
      snapshot,
      migrationId,
    ): Promise<{ connections: number; digest: string }> {
      const result = operations.then(async () => {
        const imported = writes.then(async () => {
          const digest = createHash("sha256").update(snapshot).digest("hex");
          if (
            state.writer?.importedId === migrationId &&
            state.writer.importedDigest === digest &&
            !state.writer.fenced
          )
            return {
              connections: Object.keys(state.connections).length,
              digest,
            };
          if (
            !state.writer?.fenced &&
            (Object.keys(state.connections).length ||
              Object.keys(state.authorizations).length)
          )
            throw new Error("Cannot replace active MCP writer");
          const incoming = JSON.parse(
            Buffer.from(snapshot).toString("utf8"),
          ) as { v: number; migrationId: string; state: State };
          if (
            incoming.v !== 1 ||
            incoming.migrationId !== migrationId ||
            !incoming.state?.writer?.fenced ||
            incoming.state.writer.migrationId !== migrationId ||
            !incoming.state.connections ||
            !incoming.state.authorizations ||
            !incoming.state.owners ||
            !incoming.state.identities
          )
            throw new Error("Invalid fenced MCP snapshot");
          const draft = incoming.state;
          draft.writer = {
            fenced: false,
            importedId: migrationId,
            importedDigest: digest,
          };
          await persist(options.path, key, draft);
          state = draft;
          return { connections: Object.keys(draft.connections).length, digest };
        });
        writes = imported.catch(() => undefined);
        return imported;
      });
      operations = result.catch(() => undefined);
      return result;
    },
    connections: {
      create: (record) =>
        mutate((draft) => {
          if (draft.connections[record.id])
            throw new Error("MCP connection already exists");
          draft.connections[record.id] = structuredClone(record);
        }),
      list: () => read((current) => Object.values(current.connections)),
      getById: (id) => read((current) => current.connections[id] ?? null),
      getByTokenHash: (hash) =>
        read(
          (current) =>
            Object.values(current.connections).find(
              (record) =>
                record.tokenHash === hash &&
                record.status === "approved" &&
                !isMcpTokenExpired(record),
            ) ?? null,
        ),
      getByRefreshTokenHash: (hash) =>
        read(
          (current) =>
            Object.values(current.connections).find((record) =>
              matchesMcpRefreshHash(record, hash),
            ) ?? null,
        ),
      update: (id, patch) =>
        mutate((draft) => {
          const record = draft.connections[id];
          if (!record) return null;
          return (draft.connections[id] = { ...record, ...patch });
        }),
    },
    authorizations: {
      create: (record) =>
        mutate((draft) => {
          if (draft.authorizations[record.id])
            throw new Error("MCP authorization already exists");
          draft.authorizations[record.id] = structuredClone(record);
        }),
      getById: (id) => read((current) => current.authorizations[id] ?? null),
      getByCodeHash: (hash) =>
        read(
          (current) =>
            Object.values(current.authorizations).find(
              (record) => record.authorizationCodeHash === hash,
            ) ?? null,
        ),
      update: (id, patch) =>
        mutate((draft) => {
          const record = draft.authorizations[id];
          if (!record) return null;
          return (draft.authorizations[id] = { ...record, ...patch });
        }),
      delete: (id) =>
        mutate((draft) => {
          delete draft.authorizations[id];
        }),
    },
    bindOwner: (connectionId, binding) =>
      mutate((draft) => {
        if (!draft.connections[connectionId])
          throw new Error("Unknown MCP connection");
        const prior = draft.owners[connectionId];
        if (
          prior &&
          (prior.owner.toLowerCase() !== binding.owner.toLowerCase() ||
            prior.chainId !== binding.chainId)
        ) {
          throw new Error("MCP connection owner cannot change");
        }
        draft.owners[connectionId] = structuredClone(binding);
      }),
    getOwner: (id) => read((current) => current.owners[id] ?? null),
    rememberIdentity: (identity) =>
      mutate((draft) => {
        const previous = draft.identities[identity.userPsId];
        if (!previous || identity.epoch >= previous.epoch) {
          draft.identities[identity.userPsId] = structuredClone(identity);
        }
      }),
    getIdentity: (id) => read((current) => current.identities[id] ?? null),
    exclusive<T>(operation: () => Promise<T>): Promise<T> {
      const result = operations.then(operation);
      operations = result.catch(() => undefined);
      return result;
    },
  };
}

function rollbackDigest(value: unknown): string {
  const canonical = JSON.stringify(value, (_key, item: unknown) => {
    if (item && typeof item === "object" && !Array.isArray(item))
      return Object.fromEntries(
        Object.entries(item).sort(([a], [b]) => a.localeCompare(b)),
      );
    return item;
  });
  return createHash("sha256").update(canonical).digest("hex");
}

function rollbackOwners(state: State): {
  bindings: McpOwnerBinding[];
  digest: string;
  connections: number;
} {
  const connections = Object.values(state.connections)
    .filter((connection) => connection.status === "approved")
    .sort((a, b) => a.id.localeCompare(b.id));
  const bindings = new Map<string, McpOwnerBinding>();
  const entries = connections.map((connection) => {
    const binding = state.owners[connection.id];
    if (!binding) throw new Error("Approved rollback connection has no owner");
    const id = userPsId(binding.chainId, binding.owner);
    bindings.set(id, binding);
    return {
      connectionId: connection.id,
      owner: binding.owner.toLowerCase(),
      chainId: binding.chainId,
    };
  });
  return {
    bindings: [...bindings.values()],
    digest: rollbackDigest(entries),
    connections: connections.length,
  };
}

async function persist(path: string, key: Buffer, state: State): Promise<void> {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(AAD);
  const plaintext = Buffer.from(JSON.stringify(state));
  let ciphertext: Buffer;
  try {
    ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  } finally {
    plaintext.fill(0);
  }
  const serialized = JSON.stringify({
    v: 1,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  });
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${randomBytes(8).toString("hex")}.tmp`;
  try {
    const file = await open(temporary, "wx", 0o600);
    try {
      await file.writeFile(serialized, "utf8");
      await file.sync();
    } finally {
      await file.close();
    }
    await rename(temporary, path);
    const directory = await open(dirname(path), "r");
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  } finally {
    await rm(temporary, { force: true });
  }
}

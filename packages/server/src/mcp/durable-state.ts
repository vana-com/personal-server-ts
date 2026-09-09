import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import { mkdir, open, readFile, rename, rm } from "node:fs/promises";
import { dirname } from "node:path";
import type {
  McpConnectionRecord,
  McpConnectionStore,
  McpOAuthAuthorizationRecord,
  McpOAuthAuthorizationStore,
} from "@opendatalabs/personal-server-ts-core/mcp";
import type { Address } from "viem";
import type { ClaimResponse } from "@opendatalabs/vana-sdk/protocol/jobs";

export type McpWakeupIdentity = ClaimResponse["identity"];

const AAD = Buffer.from("vana.mcp.tee-state.v1");

export interface McpOwnerBinding {
  owner: Address;
  chainId: number;
}

interface State {
  writer?: {
    fenced: boolean;
    migrationId?: string;
    target?: string;
    importedId?: string;
    importedDigest?: string;
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
  migrationStatus(): Promise<{ fenced: boolean; importedId?: string }>;
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
    migrationStatus: async () => {
      await writes;
      return {
        fenced: state.writer?.fenced ?? false,
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
                record.tokenHash === hash && record.status === "approved",
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

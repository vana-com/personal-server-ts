import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  deriveMasterKey,
  deriveScopeKey,
} from "@opendatalabs/vana-sdk/browser";
import type {
  ServerAccount,
  SignTypedDataParams,
} from "@opendatalabs/personal-server-ts-core/keys";
import type {
  AccessLogEntry,
  AccessLogWriter,
} from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { AccessLogReader } from "@opendatalabs/personal-server-ts-core/logging/access-reader";
import type { PsLiteTokenStore } from "./runtime.js";

export type PsLiteStateKey = "config-v1" | "server-identity-v1" | "relay-v1";

export interface PsLiteStateStore {
  get<T>(key: PsLiteStateKey): Promise<T | null>;
  set<T>(key: PsLiteStateKey, value: T): Promise<void>;
  delete(key: PsLiteStateKey): Promise<void>;
}

export interface IndexedDbPsLiteStateStoreOptions {
  dbName?: string;
  storeName?: string;
}

export interface IndexedDbPsLiteTokenStoreOptions {
  dbName?: string;
  storeName?: string;
}

export interface IndexedDbPsLiteAccessLogStoreOptions {
  dbName?: string;
  storeName?: string;
}

export interface PsLiteEncryptedPrivateKey {
  algorithm: "AES-GCM";
  iv: string;
  ciphertext: string;
}

export interface PsLiteEncryptedServerIdentity {
  version: 1;
  address: `0x${string}`;
  publicKey: `0x${string}`;
  encryptedPrivateKey: PsLiteEncryptedPrivateKey;
  createdAt: string;
  updatedAt: string;
}

export interface PsLiteUnlockedServerIdentity {
  persisted: PsLiteEncryptedServerIdentity;
  account: ServerAccount;
}

export interface PsLiteRelayState {
  sessionId?: string;
  controlUrl?: string;
  publicSuffix?: string;
  publicUrl?: string;
  updatedAt: string;
}

const DEFAULT_STATE_DB_NAME = "personal-server-lite";
const DEFAULT_STATE_STORE = "state";
const DEFAULT_TOKEN_STORE = "tokens";
const DEFAULT_ACCESS_LOG_STORE = "accessLogs";
const STATE_DB_VERSION = 2;
const CONFIG_KEY = "config-v1";
const SERVER_IDENTITY_KEY = "server-identity-v1";
const ACCESS_LOG_TIMESTAMP_INDEX = "timestamp";

interface PsLiteTokenRecord {
  token: string;
  expiresAt: string | null;
}

type PsLiteAccessLogRecord = AccessLogEntry;

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

async function importAesKey(masterKey: Uint8Array): Promise<CryptoKey> {
  const identityKey = deriveScopeKey(masterKey, "ps-lite.server-identity");
  return crypto.subtle.importKey("raw", identityKey, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

async function encryptPrivateKey(
  privateKey: `0x${string}`,
  ownerSignature: `0x${string}`,
): Promise<PsLiteEncryptedPrivateKey> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await importAesKey(deriveMasterKey(ownerSignature));
  const plaintext = new TextEncoder().encode(privateKey);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext),
  );
  return {
    algorithm: "AES-GCM",
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(ciphertext),
  };
}

async function decryptPrivateKey(
  encrypted: PsLiteEncryptedPrivateKey,
  ownerSignature: `0x${string}`,
): Promise<`0x${string}`> {
  const key = await importAesKey(deriveMasterKey(ownerSignature));
  const iv = base64ToBytes(encrypted.iv);
  const ciphertext = base64ToBytes(encrypted.ciphertext);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: toArrayBuffer(iv) },
    key,
    toArrayBuffer(ciphertext),
  );
  return new TextDecoder().decode(plaintext) as `0x${string}`;
}

function accountFromPrivateKey(privateKey: `0x${string}`): ServerAccount {
  const account = privateKeyToAccount(privateKey);
  return {
    address: account.address,
    publicKey: account.publicKey,
    async signTypedData(params: SignTypedDataParams): Promise<`0x${string}`> {
      return account.signTypedData({
        domain: params.domain as Parameters<
          typeof account.signTypedData
        >[0]["domain"],
        types: params.types as Parameters<
          typeof account.signTypedData
        >[0]["types"],
        primaryType: params.primaryType,
        message: params.message,
      });
    },
    async signMessage(message: string): Promise<`0x${string}`> {
      return account.signMessage({ message });
    },
  };
}

function createPsLiteStateSchema(
  db: IDBDatabase,
  transaction: IDBTransaction | null,
  stores: {
    stateStoreName: string;
    tokenStoreName: string;
    accessLogStoreName: string;
  },
): void {
  if (!db.objectStoreNames.contains(stores.stateStoreName)) {
    db.createObjectStore(stores.stateStoreName);
  }
  if (!db.objectStoreNames.contains(stores.tokenStoreName)) {
    db.createObjectStore(stores.tokenStoreName, { keyPath: "token" });
  }
  if (!db.objectStoreNames.contains(stores.accessLogStoreName)) {
    const accessLogs = db.createObjectStore(stores.accessLogStoreName, {
      keyPath: "logId",
    });
    accessLogs.createIndex(ACCESS_LOG_TIMESTAMP_INDEX, "timestamp");
  } else {
    const accessLogs = transaction?.objectStore(stores.accessLogStoreName);
    if (
      accessLogs &&
      !accessLogs.indexNames.contains(ACCESS_LOG_TIMESTAMP_INDEX)
    ) {
      accessLogs.createIndex(ACCESS_LOG_TIMESTAMP_INDEX, "timestamp");
    }
  }
}

function openStateDb(options: {
  dbName: string;
  stateStoreName?: string;
  tokenStoreName?: string;
  accessLogStoreName?: string;
}): Promise<IDBDatabase> {
  if (typeof indexedDB === "undefined") {
    throw new Error("IndexedDB is not available in this runtime");
  }

  return new Promise((resolve, reject) => {
    const request = indexedDB.open(options.dbName, STATE_DB_VERSION);
    request.onupgradeneeded = () => {
      createPsLiteStateSchema(request.result, request.transaction, {
        stateStoreName: options.stateStoreName ?? DEFAULT_STATE_STORE,
        tokenStoreName: options.tokenStoreName ?? DEFAULT_TOKEN_STORE,
        accessLogStoreName:
          options.accessLogStoreName ?? DEFAULT_ACCESS_LOG_STORE,
      });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function runStateTransaction<T>(
  options: Required<IndexedDbPsLiteStateStoreOptions>,
  mode: IDBTransactionMode,
  callback: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  return openStateDb({
    dbName: options.dbName,
    stateStoreName: options.storeName,
  }).then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const transaction = db.transaction(options.storeName, mode);
        const store = transaction.objectStore(options.storeName);
        const request = callback(store);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
        transaction.oncomplete = () => db.close();
        transaction.onerror = () => {
          db.close();
          reject(transaction.error);
        };
      }),
  );
}

function runStoreTransaction<T>(
  options: {
    dbName: string;
    storeName: string;
    schemaStore: "token" | "accessLog";
  },
  mode: IDBTransactionMode,
  callback: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  return openStateDb({
    dbName: options.dbName,
    tokenStoreName:
      options.schemaStore === "token" ? options.storeName : undefined,
    accessLogStoreName:
      options.schemaStore === "accessLog" ? options.storeName : undefined,
  }).then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const transaction = db.transaction(options.storeName, mode);
        const store = transaction.objectStore(options.storeName);
        const request = callback(store);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
        transaction.oncomplete = () => db.close();
        transaction.onerror = () => {
          db.close();
          reject(transaction.error);
        };
      }),
  );
}

function normalizeTokenExpiresAt(
  value: string | Date | null | undefined,
): string | null {
  if (value == null) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new Error("Invalid token expiry");
  }
  return date.toISOString();
}

function tokenIsExpired(expiresAt: string | null | undefined): boolean {
  return expiresAt ? new Date(expiresAt).getTime() <= Date.now() : false;
}

async function purgeExpiredTokens(options: {
  dbName: string;
  storeName: string;
  schemaStore: "token";
}): Promise<void> {
  const tokens = await runStoreTransaction<PsLiteTokenRecord[]>(
    options,
    "readonly",
    (store) => store.getAll(),
  );
  const expired = tokens.filter((entry) => tokenIsExpired(entry.expiresAt));
  if (expired.length === 0) return;

  await Promise.all(
    expired.map((entry) =>
      runStoreTransaction<undefined>(options, "readwrite", (store) =>
        store.delete(entry.token),
      ),
    ),
  );
}

export function createMemoryPsLiteStateStore(
  seed?: Partial<Record<PsLiteStateKey, unknown>>,
): PsLiteStateStore {
  const values = new Map<PsLiteStateKey, unknown>(
    Object.entries(seed ?? {}) as Array<[PsLiteStateKey, unknown]>,
  );
  return {
    async get<T>(key: PsLiteStateKey) {
      return values.has(key) ? clone(values.get(key) as T) : null;
    },
    async set<T>(key: PsLiteStateKey, value: T) {
      values.set(key, clone(value));
    },
    async delete(key: PsLiteStateKey) {
      values.delete(key);
    },
  };
}

export function createIndexedDbPsLiteStateStore(
  options: IndexedDbPsLiteStateStoreOptions = {},
): PsLiteStateStore {
  const resolved = {
    dbName: options.dbName ?? DEFAULT_STATE_DB_NAME,
    storeName: options.storeName ?? DEFAULT_STATE_STORE,
  };
  return {
    async get<T>(key: PsLiteStateKey) {
      const value = await runStateTransaction<T | undefined>(
        resolved,
        "readonly",
        (store) => store.get(key),
      );
      return value ?? null;
    },
    async set<T>(key: PsLiteStateKey, value: T) {
      await runStateTransaction<IDBValidKey>(resolved, "readwrite", (store) =>
        store.put(value, key),
      );
    },
    async delete(key: PsLiteStateKey) {
      await runStateTransaction<undefined>(resolved, "readwrite", (store) =>
        store.delete(key),
      );
    },
  };
}

export function createIndexedDbPsLiteTokenStore(
  options: IndexedDbPsLiteTokenStoreOptions = {},
): PsLiteTokenStore {
  const resolved = {
    dbName: options.dbName ?? DEFAULT_STATE_DB_NAME,
    storeName: options.storeName ?? DEFAULT_TOKEN_STORE,
    schemaStore: "token" as const,
  };

  return {
    capabilities: { tokens: "indexeddb" },
    async getTokens() {
      await purgeExpiredTokens(resolved);
      const tokens = await runStoreTransaction<PsLiteTokenRecord[]>(
        resolved,
        "readonly",
        (store) => store.getAll(),
      );
      return tokens.map((entry) => entry.token);
    },
    async isValid(token) {
      const entry = await runStoreTransaction<PsLiteTokenRecord | undefined>(
        resolved,
        "readonly",
        (store) => store.get(token),
      );
      if (!entry) return false;
      if (tokenIsExpired(entry.expiresAt)) {
        await runStoreTransaction<undefined>(resolved, "readwrite", (store) =>
          store.delete(token),
        );
        return false;
      }
      return true;
    },
    async addToken(token, options) {
      await runStoreTransaction<IDBValidKey>(resolved, "readwrite", (store) =>
        store.put({
          token,
          expiresAt: normalizeTokenExpiresAt(options?.expiresAt),
        } satisfies PsLiteTokenRecord),
      );
    },
    async removeToken(token) {
      await runStoreTransaction<undefined>(resolved, "readwrite", (store) =>
        store.delete(token),
      );
    },
  } as PsLiteTokenStore & { capabilities: { tokens: "indexeddb" } };
}

export function createIndexedDbPsLiteAccessLogStore(
  options: IndexedDbPsLiteAccessLogStoreOptions = {},
): AccessLogReader & AccessLogWriter {
  const resolved = {
    dbName: options.dbName ?? DEFAULT_STATE_DB_NAME,
    storeName: options.storeName ?? DEFAULT_ACCESS_LOG_STORE,
    schemaStore: "accessLog" as const,
  };

  return {
    capabilities: { accessLogs: "indexeddb" },
    async write(entry) {
      await runStoreTransaction<IDBValidKey>(resolved, "readwrite", (store) =>
        store.put({ ...entry } satisfies PsLiteAccessLogRecord),
      );
    },
    async read(options) {
      const limit = options?.limit ?? 50;
      const offset = options?.offset ?? 0;
      const logs = await runStoreTransaction<PsLiteAccessLogRecord[]>(
        resolved,
        "readonly",
        (store) => store.getAll(),
      );
      logs.sort(
        (a, b) =>
          new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
      );
      return {
        logs: logs.slice(offset, offset + limit),
        total: logs.length,
        limit,
        offset,
      };
    },
  } as AccessLogReader &
    AccessLogWriter & { capabilities: { accessLogs: "indexeddb" } };
}

export async function loadOrCreatePsLiteConfig(
  store: PsLiteStateStore,
  defaults?: Partial<ServerConfig>,
): Promise<ServerConfig> {
  const existing = await store.get<unknown>(CONFIG_KEY);
  const config = ServerConfigSchema.parse(existing ?? defaults ?? {});
  if (!existing) {
    await store.set(CONFIG_KEY, config);
  }
  return config;
}

export async function savePsLiteConfig(
  store: PsLiteStateStore,
  value: unknown,
): Promise<ServerConfig> {
  const config = ServerConfigSchema.parse(value);
  await store.set(CONFIG_KEY, config);
  return config;
}

export async function loadOrCreatePsLiteServerIdentity(params: {
  store: PsLiteStateStore;
  ownerSignature: `0x${string}`;
  now?: () => Date;
}): Promise<PsLiteUnlockedServerIdentity> {
  const now = (params.now ?? (() => new Date()))().toISOString();
  const existing =
    await params.store.get<PsLiteEncryptedServerIdentity>(SERVER_IDENTITY_KEY);

  if (existing) {
    const privateKey = await decryptPrivateKey(
      existing.encryptedPrivateKey,
      params.ownerSignature,
    );
    const account = accountFromPrivateKey(privateKey);
    if (account.address.toLowerCase() !== existing.address.toLowerCase()) {
      throw new Error("Encrypted PS Lite server identity is corrupt");
    }
    return { persisted: existing, account };
  }

  const privateKey = generatePrivateKey();
  const account = accountFromPrivateKey(privateKey);
  const persisted: PsLiteEncryptedServerIdentity = {
    version: 1,
    address: account.address,
    publicKey: account.publicKey,
    encryptedPrivateKey: await encryptPrivateKey(
      privateKey,
      params.ownerSignature,
    ),
    createdAt: now,
    updatedAt: now,
  };
  await params.store.set(SERVER_IDENTITY_KEY, persisted);
  return { persisted, account };
}

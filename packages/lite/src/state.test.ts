import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createIndexedDbPsLiteAccessLogStore,
  createIndexedDbPsLiteTokenStore,
  loadPsLiteRelayState,
  loadOrCreatePsLiteConfig,
  loadOrCreatePsLiteServerIdentity,
  savePsLiteRelayState,
  savePsLiteConfig,
} from "./state.js";
import { createMemoryPsLiteStateStore } from "./test-support/memory.js";

const OWNER_SIGNATURE =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b" as const;

type FakeStoreRecord = {
  keyPath?: string;
  records: Map<IDBValidKey, unknown>;
  indexes: Set<string>;
};

type FakeDbRecord = {
  version: number;
  stores: Map<string, FakeStoreRecord>;
};

class FakeDomStringList {
  constructor(private readonly values: () => Iterable<string>) {}

  contains(value: string): boolean {
    return Array.from(this.values()).includes(value);
  }
}

class FakeIdbRequest<T = unknown> {
  result!: T;
  error: Error | null = null;
  onsuccess: (() => void) | null = null;
  onerror: (() => void) | null = null;
}

class FakeIdbOpenRequest extends FakeIdbRequest<FakeIdbDatabase> {
  transaction: FakeIdbTransaction | null = null;
  onupgradeneeded: (() => void) | null = null;
}

class FakeIdbTransaction {
  oncomplete: (() => void) | null = null;
  onerror: (() => void) | null = null;

  constructor(
    private readonly db: FakeDbRecord,
    private readonly storeNames: string[],
  ) {}

  objectStore(name: string): FakeIdbObjectStore {
    if (!this.storeNames.includes(name)) {
      throw new Error(`Object store ${name} is not in this transaction`);
    }
    const store = this.db.stores.get(name);
    if (!store) throw new Error(`Missing object store ${name}`);
    return new FakeIdbObjectStore(store, this);
  }

  complete(): void {
    this.oncomplete?.();
  }
}

class FakeIdbObjectStore {
  readonly indexNames: FakeDomStringList;

  constructor(
    private readonly store: FakeStoreRecord,
    private readonly transaction?: FakeIdbTransaction,
  ) {
    this.indexNames = new FakeDomStringList(() => this.store.indexes.values());
  }

  createIndex(name: string): void {
    this.store.indexes.add(name);
  }

  get(key: IDBValidKey): FakeIdbRequest<unknown> {
    return this.request(() => this.store.records.get(key));
  }

  getAll(): FakeIdbRequest<unknown[]> {
    return this.request(() => Array.from(this.store.records.values()));
  }

  put(value: unknown, key?: IDBValidKey): FakeIdbRequest<IDBValidKey> {
    return this.request(() => {
      const recordKey =
        key ?? (value as Record<string, IDBValidKey>)[this.store.keyPath ?? ""];
      this.store.records.set(recordKey, JSON.parse(JSON.stringify(value)));
      return recordKey;
    });
  }

  delete(key: IDBValidKey): FakeIdbRequest<undefined> {
    return this.request(() => {
      this.store.records.delete(key);
      return undefined;
    });
  }

  private request<T>(run: () => T): FakeIdbRequest<T> {
    const request = new FakeIdbRequest<T>();
    queueMicrotask(() => {
      request.result = run();
      request.onsuccess?.();
      queueMicrotask(() => this.transaction?.complete());
    });
    return request;
  }
}

class FakeIdbDatabase {
  readonly objectStoreNames: FakeDomStringList;

  constructor(private readonly record: FakeDbRecord) {
    this.objectStoreNames = new FakeDomStringList(() =>
      this.record.stores.keys(),
    );
  }

  createObjectStore(
    name: string,
    options?: { keyPath?: string },
  ): FakeIdbObjectStore {
    const store = {
      keyPath: options?.keyPath,
      records: new Map<IDBValidKey, unknown>(),
      indexes: new Set<string>(),
    };
    this.record.stores.set(name, store);
    return new FakeIdbObjectStore(store);
  }

  transaction(name: string, _mode: IDBTransactionMode): FakeIdbTransaction {
    return new FakeIdbTransaction(this.record, [name]);
  }

  close(): void {}
}

function installFakeIndexedDb(): void {
  const dbs = new Map<string, FakeDbRecord>();

  vi.stubGlobal("indexedDB", {
    open(name: string, version?: number): FakeIdbOpenRequest {
      const request = new FakeIdbOpenRequest();
      queueMicrotask(() => {
        let record = dbs.get(name);
        const needsUpgrade = !record || (version ?? 1) > record.version;
        if (!record) {
          record = { version: version ?? 1, stores: new Map() };
          dbs.set(name, record);
        }
        const database = new FakeIdbDatabase(record);
        request.result = database;
        if (needsUpgrade) {
          record.version = version ?? record.version;
          request.transaction = new FakeIdbTransaction(record, []);
          request.transaction.objectStore = (storeName: string) => {
            const store = record.stores.get(storeName);
            if (!store) throw new Error(`Missing object store ${storeName}`);
            return new FakeIdbObjectStore(store);
          };
          request.onupgradeneeded?.();
        }
        request.onsuccess?.();
      });
      return request;
    },
  });
}

describe("PS Lite browser state", () => {
  beforeEach(() => {
    installFakeIndexedDb();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("loads default config and persists edits", async () => {
    const store = createMemoryPsLiteStateStore();

    const config = await loadOrCreatePsLiteConfig(store);
    expect(config.server.port).toBe(8080);

    const saved = await savePsLiteConfig(store, {
      ...config,
      server: { ...config.server, origin: "https://lite.example" },
    });

    expect(saved.server.origin).toBe("https://lite.example");
    await expect(loadOrCreatePsLiteConfig(store)).resolves.toMatchObject({
      server: { origin: "https://lite.example" },
    });
  });

  it("creates an encrypted browser server identity and unlocks it after reload", async () => {
    const store = createMemoryPsLiteStateStore();
    const first = await loadOrCreatePsLiteServerIdentity({
      store,
      ownerSignature: OWNER_SIGNATURE,
      now: () => new Date("2026-05-08T00:00:00.000Z"),
    });

    expect(first.persisted.encryptedPrivateKey.ciphertext).toMatch(
      /^[A-Za-z0-9+/]+=*$/,
    );
    const persisted = await store.get("server-identity-v1");
    expect(persisted).toMatchObject({
      address: first.account.address,
      publicKey: first.account.publicKey,
      createdAt: "2026-05-08T00:00:00.000Z",
    });

    const second = await loadOrCreatePsLiteServerIdentity({
      store,
      ownerSignature: OWNER_SIGNATURE,
    });

    expect(second.account.address).toBe(first.account.address);
    await expect(second.account.signMessage("hello")).resolves.toMatch(/^0x/);
  });

  it("rejects unlock with the wrong owner-derived key", async () => {
    const store = createMemoryPsLiteStateStore();
    await loadOrCreatePsLiteServerIdentity({
      store,
      ownerSignature: OWNER_SIGNATURE,
    });

    await expect(
      loadOrCreatePsLiteServerIdentity({
        store,
        ownerSignature: `0x${"11".repeat(65)}`,
      }),
    ).rejects.toThrow();
  });

  it("persists PS Lite relay state", async () => {
    const store = createMemoryPsLiteStateStore();

    await expect(loadPsLiteRelayState(store)).resolves.toBeNull();

    await expect(
      savePsLiteRelayState(store, {
        sessionId: "session-1",
        controlUrl: "wss://relay.example",
        publicSuffix: "relay.example",
        publicUrl: "https://session-1.relay.example",
        updatedAt: "2026-05-08T00:00:00.000Z",
      }),
    ).resolves.toMatchObject({
      sessionId: "session-1",
      publicUrl: "https://session-1.relay.example",
    });

    await expect(loadPsLiteRelayState(store)).resolves.toMatchObject({
      sessionId: "session-1",
      controlUrl: "wss://relay.example",
      publicSuffix: "relay.example",
    });
  });

  it("persists PS Lite tokens in IndexedDB and purges expired entries", async () => {
    const first = createIndexedDbPsLiteTokenStore({ dbName: "tokens-test" });
    await first.addToken("vana_ps_valid", {
      expiresAt: "2999-01-01T00:00:00.000Z",
    });
    await first.addToken("vana_ps_expired", {
      expiresAt: "2000-01-01T00:00:00.000Z",
    });

    const second = createIndexedDbPsLiteTokenStore({ dbName: "tokens-test" });

    await expect(second.isValid("vana_ps_valid")).resolves.toBe(true);
    await expect(second.isValid("vana_ps_expired")).resolves.toBe(false);
    await expect(second.getTokens()).resolves.toEqual(["vana_ps_valid"]);

    await second.removeToken("vana_ps_valid");
    await expect(first.getTokens()).resolves.toEqual([]);
  });

  it("persists PS Lite access logs in a separate IndexedDB store", async () => {
    const dbName = "access-logs-test";
    const tokenStore = createIndexedDbPsLiteTokenStore({ dbName });
    const logs = createIndexedDbPsLiteAccessLogStore({ dbName });

    await tokenStore.addToken("vana_ps_session");
    await logs.write({
      logId: "log-older",
      grantId: "grant-1",
      builder: "0xbuilder",
      action: "read",
      scope: "photos",
      timestamp: "2026-05-08T00:00:00.000Z",
      ipAddress: "127.0.0.1",
      userAgent: "vitest",
    });
    await logs.write({
      logId: "log-newer",
      grantId: "grant-2",
      builder: "0xbuilder",
      action: "read",
      scope: "messages",
      timestamp: "2026-05-08T01:00:00.000Z",
      ipAddress: "127.0.0.1",
      userAgent: "vitest",
    });

    await expect(logs.read({ limit: 1, offset: 0 })).resolves.toMatchObject({
      logs: [{ logId: "log-newer" }],
      total: 2,
      limit: 1,
      offset: 0,
    });
    await expect(logs.read({ limit: 1, offset: 1 })).resolves.toMatchObject({
      logs: [{ logId: "log-older" }],
    });
    await expect(tokenStore.getTokens()).resolves.toEqual(["vana_ps_session"]);
  });
});

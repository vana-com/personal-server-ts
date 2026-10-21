import { describe, it, expect } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";

import type { PdppGrantBinding } from "@opendatalabs/personal-server-ts-core/grants";
import { createSqlitePdppGrantBindingStore } from "./pdpp-grant-binding-sqlite-store.js";
import { createTestBoundRecordStore } from "../__fixtures__/bound-record-store.js";

const PERMISSION = {
  chainId: 14800,
  contractAddress: "0xD54523048AdD05b4d734aFaE7C68324Ebb7373eF" as const,
  permissionId: "42",
};

function makeBinding(
  overrides: Partial<PdppGrantBinding> = {},
): PdppGrantBinding {
  return Object.freeze({
    pdppGrantId: "pdpp-grant-1",
    permission: PERMISSION,
    ownerAddress: "0x00000000000000000000000000000000000000AA",
    granteeAddress: "0x00000000000000000000000000000000000000C1",
    pdppClientId: "client-app-1",
    granteeId: "0x00000000000000000000000000000000000000C1",
    grantVersion: "1",
    boundAt: "2026-09-17T10:00:00.000Z",
    ...overrides,
  });
}

function expectFailure(fn: () => unknown, reason?: RegExp): void {
  let thrown: unknown;
  try {
    fn();
  } catch (error) {
    thrown = error;
  }
  expect(thrown, "expected the call to throw").toBeDefined();
  const err = thrown as { errorCode?: string; details?: { reason?: string } };
  expect(err.errorCode).toBe("INVALID_SIGNATURE");
  if (reason) {
    expect(err.details?.reason ?? "").toMatch(reason);
  }
}

describe("createSqlitePdppGrantBindingStore", () => {
  it("retains and returns a binding by either key", () => {
    const db = new Database(":memory:");
    const store = createSqlitePdppGrantBindingStore(db);
    const binding = makeBinding();
    store.putBinding(binding);

    expect(store.getByPdppGrantId("pdpp-grant-1")).toEqual(binding);
    expect(store.getBindingsForPermission(PERMISSION)).toEqual([binding]);
  });

  it("returns null / empty for an unknown binding rather than throwing", () => {
    const db = new Database(":memory:");
    const store = createSqlitePdppGrantBindingStore(db);
    expect(store.getByPdppGrantId("nope")).toBeNull();
    expect(store.getBindingsForPermission(PERMISSION)).toEqual([]);
  });

  it("is idempotent for an identical re-put", () => {
    const db = new Database(":memory:");
    const store = createSqlitePdppGrantBindingStore(db);
    store.putBinding(makeBinding());
    expect(() => store.putBinding(makeBinding())).not.toThrow();
    // No duplicate row created.
    const count = db
      .prepare("SELECT COUNT(*) as c FROM pdpp_grant_bindings")
      .get() as { c: number };
    expect(count.c).toBe(1);
  });

  it("is idempotent across case-differing addresses", () => {
    const db = new Database(":memory:");
    const store = createSqlitePdppGrantBindingStore(db);
    store.putBinding(makeBinding());
    expect(() =>
      store.putBinding(
        makeBinding({
          ownerAddress:
            "0x00000000000000000000000000000000000000aa" as `0x${string}`,
          granteeAddress:
            "0x00000000000000000000000000000000000000c1" as `0x${string}`,
          granteeId:
            "0x00000000000000000000000000000000000000c1" as `0x${string}`,
        }),
      ),
    ).not.toThrow();

    // Original values retained, not overwritten by the differently-cased put.
    expect(store.getByPdppGrantId("pdpp-grant-1")?.ownerAddress).toBe(
      "0x00000000000000000000000000000000000000AA",
    );
    const count = db
      .prepare("SELECT COUNT(*) as c FROM pdpp_grant_bindings")
      .get() as { c: number };
    expect(count.c).toBe(1);
  });

  it("looks up a permission with a differently-cased contract address", () => {
    const db = new Database(":memory:");
    const store = createSqlitePdppGrantBindingStore(db);
    store.putBinding(makeBinding());

    expect(
      store.getBindingsForPermission({
        ...PERMISSION,
        contractAddress:
          PERMISSION.contractAddress.toLowerCase() as `0x${string}`,
      }),
    ).toEqual([makeBinding()]);
  });

  it("rejects a conflicting rewrite for the same PDPP grant id, with no partial row left behind", () => {
    const db = new Database(":memory:");
    const store = createSqlitePdppGrantBindingStore(db);
    store.putBinding(makeBinding());

    expectFailure(
      () =>
        store.putBinding(
          makeBinding({
            permission: { ...PERMISSION, permissionId: "43" },
          }),
        ),
      /different binding already exists for this PDPP grant/i,
    );

    // Original stands; no second row was inserted anywhere.
    expect(
      store.getByPdppGrantId("pdpp-grant-1")?.permission.permissionId,
    ).toBe("42");
    const count = db
      .prepare("SELECT COUNT(*) as c FROM pdpp_grant_bindings")
      .get() as { c: number };
    expect(count.c).toBe(1);
  });

  it("rejects a re-put of the same PDPP grant id claiming a different grantVersion", () => {
    const db = new Database(":memory:");
    const store = createSqlitePdppGrantBindingStore(db);
    store.putBinding(makeBinding({ grantVersion: "1" }));

    expectFailure(
      () => store.putBinding(makeBinding({ grantVersion: "2" })),
      /different binding already exists for this PDPP grant/i,
    );

    expect(store.getByPdppGrantId("pdpp-grant-1")?.grantVersion).toBe("1");
    const count = db
      .prepare("SELECT COUNT(*) as c FROM pdpp_grant_bindings")
      .get() as { c: number };
    expect(count.c).toBe(1);
  });

  it("rejects a malformed grantVersion at write time", () => {
    const db = new Database(":memory:");
    const store = createSqlitePdppGrantBindingStore(db);

    expectFailure(
      () => store.putBinding(makeBinding({ grantVersion: "01" })),
      /grantVersion/i,
    );
    expectFailure(
      () => store.putBinding(makeBinding({ grantVersion: "0" })),
      /grantVersion/i,
    );
    expectFailure(
      () => store.putBinding(makeBinding({ grantVersion: "-1" })),
      /grantVersion/i,
    );

    const count = db
      .prepare("SELECT COUNT(*) as c FROM pdpp_grant_bindings")
      .get() as { c: number };
    expect(count.c).toBe(0);
  });

  it("rejects a null grantVersion on a new write — null is only readable back from a preserved legacy row", () => {
    const db = new Database(":memory:");
    const store = createSqlitePdppGrantBindingStore(db);

    expectFailure(
      () => store.putBinding(makeBinding({ grantVersion: null })),
      /grantVersion must be a positive decimal uint256 string/i,
    );

    const count = db
      .prepare("SELECT COUNT(*) as c FROM pdpp_grant_bindings")
      .get() as { c: number };
    expect(count.c).toBe(0);
  });

  it("rejects a runtime-numeric grantVersion on a new write, despite the string type", () => {
    const db = new Database(":memory:");
    const store = createSqlitePdppGrantBindingStore(db);

    expectFailure(
      () =>
        store.putBinding(makeBinding({ grantVersion: 1 as unknown as string })),
      /grantVersion must be a positive decimal uint256 string/i,
    );

    const count = db
      .prepare("SELECT COUNT(*) as c FROM pdpp_grant_bindings")
      .get() as { c: number };
    expect(count.c).toBe(0);
  });

  it("two distinct grants at two different versions coexist on one permission", () => {
    const db = new Database(":memory:");
    const store = createSqlitePdppGrantBindingStore(db);
    const first = makeBinding({ grantVersion: "1" });
    const second = makeBinding({
      pdppGrantId: "pdpp-grant-2",
      grantVersion: "2",
    });
    store.putBinding(first);
    store.putBinding(second);

    expect(store.getBindingsForPermission(PERMISSION)).toEqual([first, second]);
    const count = db
      .prepare("SELECT COUNT(*) as c FROM pdpp_grant_bindings")
      .get() as { c: number };
    expect(count.c).toBe(2);
  });

  it("does not mirror any revocation status field", () => {
    const db = new Database(":memory:");
    const store = createSqlitePdppGrantBindingStore(db);
    store.putBinding(makeBinding());
    expect(
      Object.keys(store.getByPdppGrantId("pdpp-grant-1") ?? {}),
    ).not.toContain("revokedAt");
  });

  it("isolates bindings across chain id and contract address", () => {
    const db = new Database(":memory:");
    const store = createSqlitePdppGrantBindingStore(db);
    store.putBinding(makeBinding());

    // Same permissionId, different chain — must be a distinct binding slot.
    const otherChain = makeBinding({
      pdppGrantId: "pdpp-grant-chain-2",
      permission: { ...PERMISSION, chainId: 1480 },
    });
    expect(() => store.putBinding(otherChain)).not.toThrow();
    expect(
      store.getBindingsForPermission({ ...PERMISSION, chainId: 1480 }),
    ).toEqual([otherChain]);

    // Same permissionId, same chain, different contract — also distinct.
    const otherContract = makeBinding({
      pdppGrantId: "pdpp-grant-contract-2",
      permission: {
        ...PERMISSION,
        contractAddress:
          "0x0000000000000000000000000000000000000999" as `0x${string}`,
      },
    });
    expect(() => store.putBinding(otherContract)).not.toThrow();
    expect(store.getByPdppGrantId("pdpp-grant-1")).toEqual(makeBinding());
  });

  it("survives a real disk reopen", () => {
    const dir = mkdtempSync(join(tmpdir(), "pdpp-grant-binding-test-"));
    const dbPath = join(dir, "bindings.db");
    try {
      const db1 = new Database(dbPath);
      const store1 = createSqlitePdppGrantBindingStore(db1);
      store1.putBinding(makeBinding());
      db1.close();

      const db2 = new Database(dbPath);
      const store2 = createSqlitePdppGrantBindingStore(db2);
      expect(store2.getByPdppGrantId("pdpp-grant-1")).toEqual(makeBinding());
      expect(store2.getBindingsForPermission(PERMISSION)).toEqual([
        makeBinding(),
      ]);
      db2.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("coexists with the pdpp records store on the same database handle", () => {
    const db = new Database(":memory:");
    const bindingStore = createSqlitePdppGrantBindingStore(db);
    const recordStore = createTestBoundRecordStore(db);

    bindingStore.putBinding(makeBinding());
    recordStore.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "messages",
          key: "msg_1",
          data: { id: "msg_1", content: "hi" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );

    expect(bindingStore.getByPdppGrantId("pdpp-grant-1")).toEqual(
      makeBinding(),
    );
    expect(recordStore.getRecord("inst_1", "messages", "msg_1")?.data).toEqual({
      id: "msg_1",
      content: "hi",
    });
    recordStore.close();
  });

  it("migration preserves a pre-existing legacy row, retrievable but with a null grantVersion", () => {
    // Simulate a database created by the pre-migration build: only the
    // original columns exist, and permission_key carried a UNIQUE index.
    const db = new Database(":memory:");
    db.exec(`
      CREATE TABLE pdpp_grant_bindings_schema_version (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        version INTEGER NOT NULL
      );
      INSERT INTO pdpp_grant_bindings_schema_version (id, version) VALUES (1, 1);
      CREATE TABLE pdpp_grant_bindings (
        pdpp_grant_id TEXT PRIMARY KEY,
        permission_key TEXT NOT NULL UNIQUE,
        chain_id INTEGER NOT NULL,
        contract_address TEXT NOT NULL,
        permission_id TEXT NOT NULL,
        owner_address TEXT NOT NULL,
        grantee_address TEXT NOT NULL,
        pdpp_client_id TEXT NOT NULL,
        grantee_id TEXT NOT NULL,
        bound_at TEXT NOT NULL
      );
      INSERT INTO pdpp_grant_bindings
        (pdpp_grant_id, permission_key, chain_id, contract_address, permission_id,
         owner_address, grantee_address, pdpp_client_id, grantee_id, bound_at)
      VALUES
        ('pdpp-grant-legacy', '14800:0xd54523048add05b4d734afae7c68324ebb7373ef:42', 14800,
         '0xD54523048AdD05b4d734aFaE7C68324Ebb7373eF', '42',
         '0x00000000000000000000000000000000000000AA',
         '0x00000000000000000000000000000000000000C1',
         'client-app-1', '0x00000000000000000000000000000000000000C1',
         '2026-01-01T00:00:00.000Z');
    `);

    const store = createSqlitePdppGrantBindingStore(db);

    const legacy = store.getByPdppGrantId("pdpp-grant-legacy");
    expect(legacy).not.toBeNull();
    expect(legacy?.grantVersion).toBeNull();
    expect(store.getBindingsForPermission(PERMISSION)).toEqual([legacy]);

    // The legacy row cannot authorize anything by itself — that is exercised
    // by `grantVersionStillAuthorizes`/`verifyPdppGrantBinding` in
    // pdpp-binding.test.ts, which denies a null retained version. This test
    // only proves the migration keeps the row inspectable, not that it can
    // acquire an invented version: a fresh put for the same identity but a
    // real version must still be rejected as a conflicting rewrite.
    expectFailure(
      () =>
        store.putBinding(
          makeBinding({ pdppGrantId: "pdpp-grant-legacy", grantVersion: "1" }),
        ),
      /different binding already exists for this PDPP grant/i,
    );
  });

  it("refuses to open a database with a newer schema version than this build supports", () => {
    const db = new Database(":memory:");
    createSqlitePdppGrantBindingStore(db);
    db.prepare(
      "UPDATE pdpp_grant_bindings_schema_version SET version = 9999 WHERE id = 1",
    ).run();
    expect(() => createSqlitePdppGrantBindingStore(db)).toThrow(
      /newer than this build supports/,
    );
  });
});

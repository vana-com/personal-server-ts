import Database from "better-sqlite3";
import { expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  canonicalJson,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  binding,
  upsert,
} from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import {
  replicaChainCommitment,
  type ReplicaTransportPort,
} from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import {
  fragmentReplicaPayload,
  replicaDigest,
  toBase64,
} from "@opendatalabs/personal-server-ts-core/replication/transport";
import { createReplicaRecordStore } from "../storage/pdpp-replica-canonical-port.js";
import { createReplicaReceiver } from "../storage/pdpp-replication-receiver.js";
import { createReplicaTransportWorker } from "../storage/pdpp-replication-transport.js";
import { createTestReplicaRoster } from "@opendatalabs/personal-server-ts-core/replication/writer-identity.test-utils";
import {
  enableReplicaTestIdentity,
  remoteReplicaTestWriter,
  replicaTestAuthority,
} from "../storage/pdpp-replica-writer-identity.test-utils.js";
import {
  approveNarrowConsent,
  openConsentIssuer,
  openReplicaResourceServer,
} from "./pdpp-replica-quarantine-fixture.js";

it.each(["key", "connection"] as const)(
  "pending owner reads preserve imported-slot %s quarantine through the real issuer HTTP boundary",
  async (scope) => {
    const root = mkdtempSync(join(tmpdir(), "8b-pending-quarantine-"));
    const db = new Database(join(root, "replica.sqlite"));
    const store = createReplicaRecordStore(db);
    // Batch statements name the owner wallet, so it is an address.
    const owner = "0x00000000000000000000000000000000000000bb";
    const sourceId = "https://replica-journey.invalid/declaration";
    const credential = "local-receiver";
    const roster = createTestReplicaRoster();
    const authority = replicaTestAuthority(roster);
    const remote = remoteReplicaTestWriter(roster, owner);
    const writerId = remote.writers.operation;
    const identity = {
      owner,
      sourceId,
      connectionId: "conn",
      methodId: "collector",
      generation: 1,
    };
    const envelope = (batchId: string, operations: ReplicaOperation[]) => ({
      format: "vana-pdpp-replica" as const,
      version: 1 as const,
      owner,
      batchId,
      operations,
    });
    const registration: ReplicaOperation = {
      ...identity,
      kind: "connection-register",
      revision: { counter: 1, writerId, operationId: "register" },
    };
    for (const instance of ["conn", "conn-other"])
      store.registerConnection({
        instance,
        sourceId,
        method: "collector",
        label: "trusted local mapping",
      });
    enableReplicaTestIdentity(db, { owner, roster, authority });
    store.replication.beginBaseline({
      owner,
      declarations: [{ sourceId, binding }],
    });
    const receiver = createReplicaReceiver({
      db,
      store,
      owner,
      enabled: true,
      authenticate: (value) => (value === credential ? owner : undefined),
      declarations: () => [{ sourceId, binding, validateData: () => true }],
    });
    receiver.import({
      credential,
      envelope: envelope("registration", [
        registration,
        {
          ...registration,
          connectionId: "conn-other",
          revision: { ...registration.revision, operationId: "register-other" },
        },
      ]),
    });
    const bytes = Buffer.from("persistently quarantined binary sentinel");
    const blobId = replicaDigest(bytes);
    const blob = {
      blobId,
      sha256: blobId,
      sizeBytes: bytes.length,
      mimeType: "application/octet-stream",
    };
    const target = {
      ...upsert("quarantined-target", 5, undefined, writerId),
      ...identity,
      recordKey: "quarantined-id",
      data: {
        id: "quarantined-id",
        text: "QUARANTINED-PAYLOAD-MUST-STAY-HIDDEN",
        collected_at: "2026-10-20T00:00:00Z",
        private_note: "owner only",
        blob_ref: {
          blob_id: blobId,
          sha256: blobId.slice(7),
          size_bytes: bytes.length,
          mime_type: blob.mimeType,
        },
      },
      blobs: [blob],
    };
    const claim: ReplicaOperation = {
      ...identity,
      kind: "blob-claim",
      blob,
      revision: { counter: 4, writerId, operationId: "target-blob" },
    };
    const batch = "1".repeat(32);
    const operations = [
      ...(scope === "connection" ? [registration] : []),
      claim,
      target,
    ];
    const parts = await fragmentReplicaPayload({
      owner,
      writer: remote.writers.transport,
      batch,
      sequence: 1,
      previous: null,
      collectedAt: "2026-10-20T00:00:00Z",
      bytes: Buffer.from(
        canonicalJson({
          envelope: envelope(batch, operations),
          blobs: [{ blobId, bytes: toBase64(bytes) }],
        }),
      ),
      sign: remote.sign,
      encrypt: async (_scope, value) => value,
    });
    let conflicted = false;
    const port: ReplicaTransportPort = {
      encrypt: async (_scope, value) => value,
      decrypt: async (_scope, value) => value,
      put: async () => {},
      register: async () => {},
      get: async (id) => parts.find((part) => part.scope === id)!.encrypted,
      list: async () => ({
        scopes: parts.map((part) => part.scope),
        cursor: null,
      }),
      evidence: async (id) => {
        const part = parts.find((part) => part.scope === id)!;
        return {
          head: {
            owner,
            scope: id,
            version: "1",
            dataHash: part.dataHash,
            metadataHash: part.metadataHash,
            deleted: false,
          },
          chain: {
            owner,
            scope: id,
            version: "1",
            currentVersion: conflicted ? "9" : "1",
            status: "Active",
            commitment: replicaChainCommitment(
              part.dataHash,
              part.metadataHash,
            ),
            chainId: 14800,
            registry: `0x${"2".repeat(40)}`,
            blockNumber: 123n,
            blockHash: `0x${"3".repeat(64)}`,
            blockTimestamp: 1000n,
          },
          pending: false,
        };
      },
    };
    const transport = createReplicaTransportWorker({
      db,
      enabled: true,
      expected: () => ({ owner, declarations: [{ sourceId, binding }] }),
      exporter: store.replication,
      receiver,
      credential,
      transport: port,
      authority,
    });
    const issuer = await openConsentIssuer(root, owner, 3600);
    let resource:
      Awaited<ReturnType<typeof openReplicaResourceServer>> | undefined;
    try {
      await transport.cycle();
      const consent = await approveNarrowConsent(issuer);
      resource = await openReplicaResourceServer(store, {
        owner,
        tokens: issuer.tokens,
        reads: (reader) => receiver.readStore({ reader }),
      });
      const read = (token: string, path: string, init: RequestInit = {}) =>
        fetch(resource!.origin + "/pdpp/v1" + path, {
          ...init,
          headers: { authorization: `Bearer ${token}`, ...init.headers },
        });
      const targetPath = "/streams/messages/records/quarantined-id";
      const blobPath = `/blobs/${encodeURIComponent(blobId)}`;
      for (const token of [issuer.credential, consent.token]) {
        const response = await read(token, targetPath);
        expect(response.status).toBe(200);
        expect((await response.json()).data.text).toBe(target.data.text);
        const binary = await read(token, blobPath);
        expect(binary.status).toBe(200);
        expect(Buffer.from(await binary.arrayBuffer())).toEqual(bytes);
      }
      conflicted = true;
      await transport.cycle();
      expect(
        db
          .prepare("SELECT state FROM pdpp_transport_inbox WHERE scope=?")
          .get(parts[0].scope),
      ).toEqual({ state: "quarantined" });
      expect(
        store.getRecord("conn", "messages", target.recordKey),
      ).toBeUndefined();
      // An unrelated pending batch must not revive retained, quarantined winners.
      // It lives on another connection: a terminal batch withdraws every
      // connection it touched (contract v3.1 A), so nothing on "conn" stays.
      const pending = {
        ...upsert("pending-control", 10),
        ...identity,
        connectionId: "conn-other",
        recordKey: "pending-control",
        data: {
          id: "pending-control",
          text: "unaffected pending owner control",
          collected_at: "2026-10-20T00:00:00Z",
          private_note: "owner only",
        },
      };
      receiver.stage({
        credential,
        id: "unrelated-pending",
        envelope: envelope("unrelated-pending", [pending]),
      });
      const pendingPath = "/streams/messages/records/pending-control";
      const pendingOwner = await read(issuer.credential, pendingPath);
      expect(pendingOwner.status).toBe(200);
      expect(await pendingOwner.json()).toMatchObject({
        confirmation: "not yet confirmed",
        data: { text: pending.data.text },
      });
      expect((await read(consent.token, pendingPath)).status).toBe(404);
      for (const token of [issuer.credential, consent.token]) {
        for (const path of [
          targetPath,
          "/streams/messages/records",
          "/streams/messages/records?changes_since=",
          "/streams",
        ]) {
          const response = await read(token, path);
          const body = await response.text();
          expect
            .soft(response.status, path)
            .toBe(path === targetPath ? 404 : 200);
          for (const sentinel of [target.data.text, target.recordKey, blobId])
            expect.soft(body, path).not.toContain(sentinel);
          if (token === consent.token)
            expect.soft(body, path).not.toContain(pending.data.text);
        }
        for (const init of [
          {},
          { method: "HEAD" },
          { headers: { range: "bytes=0-7" } },
        ]) {
          const response = await read(token, blobPath, init);
          expect
            .soft(response.status, "quarantined blob GET/HEAD/range")
            .toBe(404);
          expect
            .soft(
              Buffer.from(await response.arrayBuffer()).includes(
                bytes.subarray(0, 8),
              ),
            )
            .toBe(false);
        }
      }
    } finally {
      await resource?.close();
      await issuer.close();
      store.close();
      rmSync(root, { recursive: true, force: true });
    }
  },
);

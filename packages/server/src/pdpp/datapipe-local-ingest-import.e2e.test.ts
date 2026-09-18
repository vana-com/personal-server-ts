/**
 * End-to-end: a `$pdpp`-annotated envelope POSTed to the LOCAL ingest route
 * reaches a scoped PDPP read.
 *
 * This is the local-producer twin of `datapipe-sync-import.e2e.test.ts`. That
 * test proves the gateway-sync arrival route: an encrypted blob pulled by the
 * download worker, decrypted, imported, served. This one proves the other
 * door — `POST /v1/data/:scope`, owner-authenticated, the path a local
 * producer (the Unity web app writing into a Personal Server on this machine)
 * actually uses when there is no gateway between them.
 *
 * Why this test exists at all: before the change it accompanies, the two
 * doors did NOT agree. `pdppImporter` was reachable only from
 * `sync/workers/download.ts`; the ingest route in `core/src/api/index.ts`
 * stored and indexed the envelope and returned 201 without ever offering it
 * to the importer. A local producer's write therefore half-landed — durable
 * in the legacy store, invisible to every PDPP read — and the 201 said
 * nothing was wrong. The assertions below are written to fail loudly if that
 * regresses: a 201 alone is never accepted as proof, only a record read back
 * off the PDPP record store.
 *
 * Nothing the claim depends on is mocked:
 *
 *   - the route is the real `dataRoutes`, with the real owner auth gate
 *     (a real Web3Signed header over the real request);
 *   - the declaration is the REAL delivered GitHub `SourceDeclaration`, read
 *     from disk, parsed by the real `parseDeclaration` and retained through
 *     the real `buildDeclarationRegistry` including its connector trust gate;
 *   - the importer is the real `createPdppImporter`, wired exactly as
 *     `createPdppSyncImporter` wires it at boot;
 *   - the record store is the real better-sqlite3 backend on a real file;
 *   - the read is the real `listRecords` surface the resource server serves,
 *     restricted to the instance handles a grant would carry.
 *
 * GitHub rather than Instagram deliberately: `github.profile` is the scope
 * the Unity web producer writes from a public-target collection, and the
 * declaration is a real upstream-ported document, so the digest check below
 * is an interoperability result between two repositories rather than PS
 * agreeing with itself.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import Database from "better-sqlite3";
import { pino } from "pino";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { HierarchyManagerOptions } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { PdppRecordStore } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import {
  createPdppImporter,
  type PdppImporter,
} from "@opendatalabs/personal-server-ts-core/sync";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import { createSqliteRecordStore } from "../storage/pdpp-records-sqlite-store.js";
import { dataRoutes } from "../routes/data.js";
import {
  buildDeclarationRegistry,
  singleInstanceInventory,
} from "./deployment.js";

const SERVER_ORIGIN = "http://localhost:8080";
const SCOPE = "github.profile";
const STREAM = "user";
const CONNECTOR = "github";
const SOURCE_ID = "https://registry.pdpp.dev/connectors/github";

const ownerWallet = createTestWallet(9);
const SUBJECT = ownerWallet.address.toLowerCase();
const INSTANCE = `${CONNECTOR}:${SUBJECT}`;

/**
 * The REAL delivered SourceDeclaration, read from disk — never inlined, for
 * the same reason the sync e2e gives: a document written here would prove
 * only that PS agrees with this test.
 */
const DECLARATION_PATH = join(
  import.meta.dirname,
  "../../../core/src/pdpp/__fixtures__/github.source-declaration.json",
);
const DECLARATION_DOCUMENT = readFileSync(DECLARATION_PATH, "utf-8");

const DOCUMENT_DIGEST = createHash("sha256")
  .update(DECLARATION_DOCUMENT, "utf8")
  .digest("hex");

/**
 * The digest the Unity producer stamps for this exact document. Pinned as a
 * literal so a change to the declaration is a deliberate, visible act rather
 * than a silent re-baseline, and so a drift fails here rather than as a
 * confusing `digest_mismatch` at import time.
 *
 * Independently reproduced against the producer's own bytes: the Unity
 * repository builds this document in
 * `packages/app-runtime/src/sources/pdpp-source-declarations.ts`
 * (`githubCanonicalDeclarationJson`) and that string is byte-identical to the
 * fixture read above.
 */
const PUBLISHED_DIGEST =
  "00c64092177a2830f670bd2cab83eab788e0c23575ad26b5b5762064b97ab3bb";

const logger = pino({ level: "silent" });

/** The `$pdpp` metadata block exactly as the Unity producer writes it. */
function pdppMetadata(recordId: string) {
  return {
    version: 1,
    sourceId: SOURCE_ID,
    declaration: {
      source: CONNECTOR,
      version: "0.5.1",
      upstreamCommit: "6d2be0a2a1c052afcffc8ec035190e1dffc3c128",
      digest: `sha256:${DOCUMENT_DIGEST}`,
    },
    stream: {
      name: STREAM,
      scope: SCOPE,
      semantics: "mutable_state",
      primaryKey: ["id"],
      cursorField: "updated_at",
      consentTimeField: "created_at",
    },
    record: { key: { id: recordId }, op: "upsert" },
    run: { id: "dp_local_ingest", source: CONNECTOR },
  };
}

function githubUser(overrides: Record<string, unknown> = {}) {
  return {
    id: "583231",
    login: "octocat",
    name: "The Octocat",
    created_at: "2011-01-25T18:44:36Z",
    updated_at: "2026-09-18T10:00:00Z",
    ...overrides,
  };
}

/**
 * Wire the importer the way `createPdppSyncImporter` does at boot, through
 * the REAL declaration registry so the trust gate and the parser both run.
 */
function buildImporter(store: PdppRecordStore): PdppImporter {
  const registry = buildDeclarationRegistry({
    declarations: [{ sourceId: SOURCE_ID, document: DECLARATION_DOCUMENT }],
    // Derived from the scopes this PS holds, as the real bootstrap does.
    supportedConnectors: [CONNECTOR],
    logger,
  });
  expect(registry.retained).toHaveLength(1);

  const snapshot = registry.retained[0];
  const document = registry.retainedDocuments.get(SOURCE_ID);
  expect(document).toBe(DECLARATION_DOCUMENT);

  return createPdppImporter({
    store,
    declarations: [
      {
        sourceId: snapshot.source_id,
        version: snapshot.version,
        documentDigest: createHash("sha256")
          .update(document as string, "utf8")
          .digest("hex"),
        streams: snapshot.streams.map((s) => ({
          name: s.name,
          primaryKey: s.primary_key,
          semantics: "mutable_state" as const,
        })),
      },
    ],
    instanceFor: (sourceId) =>
      singleInstanceInventory(SUBJECT, sourceId).eligibleFor("")[0],
    logger,
  });
}

describe("the declaration under test is the producer's own document", () => {
  it("is byte-identical to the document the Unity producer digests", () => {
    expect(DOCUMENT_DIGEST).toBe(PUBLISHED_DIGEST);
  });
});

describe("local POST /v1/data/:scope -> PDPP import -> scoped read", () => {
  let dataDir: string;
  let recordsDir: string;
  let db: Database.Database;
  let store: PdppRecordStore;
  let importer: PdppImporter;
  let app: ReturnType<typeof dataRoutes>;
  let cleanup: () => void;

  beforeEach(async () => {
    dataDir = await mkdtemp(join(tmpdir(), "pdpp-local-ingest-data-"));
    recordsDir = await mkdtemp(join(tmpdir(), "pdpp-local-ingest-records-"));
    db = new Database(join(recordsDir, "records.db"));
    store = createSqliteRecordStore(db);
    importer = buildImporter(store);

    const indexDb = initializeDatabase(":memory:");
    const indexManager = createIndexManager(indexDb);
    const hierarchyOptions: HierarchyManagerOptions = { dataDir };
    const accessLogWriter: AccessLogWriter = {
      write: vi.fn().mockResolvedValue(undefined),
    };

    app = dataRoutes({
      indexManager,
      hierarchyOptions,
      logger,
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway: {} as unknown as GatewayClient,
      accessLogWriter,
      pdppImporter: importer,
    });
    cleanup = () => indexManager.close();
  });

  afterEach(async () => {
    cleanup();
    store.close();
    await rm(dataDir, { recursive: true, force: true });
    await rm(recordsDir, { recursive: true, force: true });
  });

  /** POST a body to the ingest route as the owner, signing the real bytes. */
  async function ownerWrite(body: unknown, scope = SCOPE) {
    const rawBody = JSON.stringify(body);
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: `/${scope}`,
      body: new TextEncoder().encode(rawBody),
    });
    return app.request(`/${scope}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: auth },
      body: rawBody,
    });
  }

  /**
   * Wait until the wall clock crosses a second boundary.
   *
   * The legacy ingest path stamps `collectedAt` at second granularity
   * (`collectedAt()` in core's data API strips the milliseconds) and the
   * index is unique on the derived path, so two writes inside the same second
   * collide there — before the PDPP importer is ever reached. That is a
   * property of the legacy path this change does not touch, so the multi-write
   * cases below space their writes the way two real collections are spaced,
   * rather than asserting around a collision that has nothing to do with the
   * behaviour under test.
   */
  async function nextSecond(): Promise<void> {
    const start = Math.floor(Date.now() / 1000);
    while (Math.floor(Date.now() / 1000) === start) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }

  function readRecords() {
    return store.listRecords(STREAM, {
      instanceIds: [INSTANCE],
      limit: 50,
      order: "asc",
    });
  }

  it("imports a $pdpp envelope and serves it under a scoped read", async () => {
    const res = await ownerWrite({
      ...githubUser(),
      $pdpp: pdppMetadata("583231"),
    });
    expect(res.status).toBe(201);

    // The claim is about the PDPP record store, not the 201: before this
    // path offered the envelope to the importer, the status was identical
    // and this read returned nothing.
    const page = readRecords();
    expect(page.data).toHaveLength(1);
    const record = page.data[0];
    expect(record.deleted).toBe(false);
    if (record.deleted) return;
    expect(record.instance).toBe(INSTANCE);
    expect(record.stream).toBe(STREAM);
    expect(record.data.id).toBe("583231");
    expect(record.data.login).toBe("octocat");
  });

  it("upserts on the declared primary key rather than duplicating", async () => {
    await ownerWrite({ ...githubUser(), $pdpp: pdppMetadata("583231") });
    await nextSecond();
    const second = await ownerWrite({
      ...githubUser({ name: "Renamed Octocat" }),
      $pdpp: pdppMetadata("583231"),
    });
    expect(second.status).toBe(201);

    const page = readRecords();
    expect(page.data).toHaveLength(1);
    const record = page.data[0];
    if (record.deleted) throw new Error("expected a stored record");
    expect(record.data.name).toBe("Renamed Octocat");
  });

  it("keeps two distinct primary keys as two records", async () => {
    await ownerWrite({ ...githubUser(), $pdpp: pdppMetadata("583231") });
    await nextSecond();
    await ownerWrite({
      ...githubUser({ id: "999001", login: "hubot" }),
      $pdpp: pdppMetadata("999001"),
    });

    const page = readRecords();
    expect(page.data).toHaveLength(2);
  });

  it("stores a legacy envelope without $pdpp and imports nothing", async () => {
    // The ordinary non-PDPP case must be untouched: still a 201, still
    // stored, and silently skipped by the importer rather than rejected.
    const res = await ownerWrite(githubUser());
    expect(res.status).toBe(201);
    expect(readRecords().data).toHaveLength(0);
  });

  it("commits the legacy write even when the declaration digest is wrong", async () => {
    // A producer that stamps a digest this deployment cannot verify is a
    // rejection, not a failed write: the record is already durable by the
    // time the importer sees it, so the route must still answer 201 and the
    // PDPP store must stay empty rather than accept an unverifiable record.
    const res = await ownerWrite({
      ...githubUser(),
      $pdpp: {
        ...pdppMetadata("583231"),
        declaration: {
          source: CONNECTOR,
          version: "0.5.1",
          upstreamCommit: null,
          digest: `sha256:${"0".repeat(64)}`,
        },
      },
    });
    expect(res.status).toBe(201);
    expect(readRecords().data).toHaveLength(0);

    // And the legacy read-back still serves the record, proving the refusal
    // was scoped to the PDPP surface.
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "GET",
      uri: `/${SCOPE}`,
    });
    const read = await app.request(`/${SCOPE}`, {
      headers: { Authorization: auth },
    });
    expect(read.status).toBe(200);
    const envelope = (await read.json()) as { data: Record<string, unknown> };
    expect(envelope.data.login).toBe("octocat");
  });

  it("does not import when the deployment mounted no PDPP importer", async () => {
    // The absent-importer wiring must be inert rather than throwing: this is
    // every non-PDPP deployment.
    const indexDb = initializeDatabase(":memory:");
    const indexManager = createIndexManager(indexDb);
    const bare = dataRoutes({
      indexManager,
      hierarchyOptions: { dataDir },
      logger,
      serverOrigin: SERVER_ORIGIN,
      serverOwner: ownerWallet.address,
      gateway: {} as unknown as GatewayClient,
      accessLogWriter: { write: vi.fn().mockResolvedValue(undefined) },
    });

    const rawBody = JSON.stringify({
      ...githubUser(),
      $pdpp: pdppMetadata("583231"),
    });
    const auth = await buildWeb3SignedHeader({
      wallet: ownerWallet,
      aud: SERVER_ORIGIN,
      method: "POST",
      uri: `/${SCOPE}`,
      body: new TextEncoder().encode(rawBody),
    });
    const res = await bare.request(`/${SCOPE}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: auth },
      body: rawBody,
    });
    expect(res.status).toBe(201);
    expect(readRecords().data).toHaveLength(0);
    indexManager.close();
  });
});

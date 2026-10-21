import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import pino from "pino";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  Builder,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { buildDataBlocksAsync } from "@opendatalabs/personal-server-ts-core/storage/blocks";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { initializeDatabase } from "./storage/index-schema.js";
import { createIndexManager } from "./storage/index-manager.js";
import { createNodeDataStorage } from "./storage/node-data-storage.js";
import {
  computeQuestion,
  createFakeInferenceProvider,
  createInMemoryQuestionStore,
  type QuestionRegistration,
} from "@opendatalabs/personal-server-ts-core/derivatives";
import { reindexLegacyDataFiles } from "./storage/node-data-storage.js";
import { withLegacyProjection } from "@opendatalabs/personal-server-ts-core/storage/legacy-projection";
import { computeDataPointId } from "@opendatalabs/personal-server-ts-core/sync";
import { dataRoutes } from "./routes/data.js";
import { storageForReader } from "../../core/src/storage/disclosure-policy.js";
import { redactJsonEnvelopeBytesForGrantee } from "@opendatalabs/personal-server-ts-core/api";

const logger = pino({ level: "silent" });
const ORIGIN = "http://localhost:8080";
const owner = createTestWallet(0);
const builder = createTestWallet(5);
const GRANT_ID = "grant-probe";
const DERIVED = "coach.weekly";

/**
 * An owner-registered derivative reads its sources as the owner, so an answer
 * computed from PDPP data must carry PDPP origin. Otherwise a legacy chain
 * grant that covers the derived scope reads PDPP data past the disclosure
 * policy. Real Node storage, real compute, real GET /v1/data route.
 */
const SECRET = "pdpp-only-score-99";
const AT = "2026-09-01T00:00:00.000Z";

function sourceEnvelope(scope: string, native: boolean): DataFileEnvelope {
  return {
    version: "1.0",
    scope,
    collectedAt: AT,
    data: native
      ? {
          id: "a1",
          score: SECRET,
          $pdpp: { version: 1, sourceId: "https://registry.pdpp.dev/oura" },
        }
      : { id: "legacy-row", score: "legacy-score-7" },
  } as DataFileEnvelope;
}

let dataDir: string;
let indexManager: IndexManager;
let storage: DataStoragePort;

function gatewayFor(granteeAddress: `0x${string}`): GatewayClient {
  const grant = {
    id: GRANT_ID,
    grantorAddress: owner.address,
    granteeId: granteeAddress,
    scopes: ["coach.*"],
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    expiresAt: null,
    expired: false,
    revokedAt: null,
    paymentStatus: "paid",
    grantVersion: "1",
  } as unknown as GatewayGrantResponse;
  const registered: Builder = {
    id: granteeAddress,
    ownerAddress: owner.address,
    granteeAddress,
    publicKey: "0x04",
    appUrl: "https://app.test",
    addedAt: "2026-01-21T10:00:00.000Z",
  };
  return {
    isRegisteredBuilder: vi.fn().mockResolvedValue(true),
    getBuilder: vi.fn().mockResolvedValue(registered),
    getGrant: vi.fn().mockResolvedValue(grant),
    listGrantsByUser: vi.fn().mockResolvedValue([]),
    getSchemaForScope: vi.fn().mockResolvedValue(null),
    getServer: vi.fn().mockResolvedValue(null),
    getDataPoint: vi.fn().mockResolvedValue(null),
    listDataPointsByOwner: vi
      .fn()
      .mockResolvedValue({ dataPoints: [], cursor: null }),
    getSchema: vi.fn().mockResolvedValue(null),
    registerServer: vi.fn().mockResolvedValue({ alreadyRegistered: false }),
    registerDataPoint: vi.fn().mockResolvedValue({ dataPointId: "0xdp" }),
    createGrant: vi.fn().mockResolvedValue({ grantId: GRANT_ID }),
    revokeGrant: vi.fn().mockResolvedValue(undefined),
  } as unknown as GatewayClient;
}

async function put(envelope: DataFileEnvelope) {
  const written = await storage.writeEnvelope(envelope);
  const built = await buildDataBlocksAsync({
    scope: envelope.scope,
    collectedAt: envelope.collectedAt,
    content: envelope,
  });
  await storage.writeBlockManifest?.(
    envelope.scope,
    envelope.collectedAt,
    built.manifest,
    built.blocks,
  );
  return storage.insertEntry({
    fileId: null,
    path: written.relativePath,
    scope: envelope.scope,
    collectedAt: envelope.collectedAt,
    sizeBytes: written.sizeBytes,
  });
}

function registration(sourceScopes: string[]): QuestionRegistration {
  return {
    questionId: "q-1",
    derivedScope: DERIVED,
    sourceScopes,
    question: "How did I sleep?",
    model: null,
    answerShape: null,
    recompute: "on-change",
    registeredBy: { kind: "owner" },
    status: "pending",
    error: null,
    errorCode: null,
    createdAt: "2026-08-27T00:00:00.000Z",
    updatedAt: "2026-08-27T00:00:00.000Z",
    lastComputedAt: null,
    derivedVersion: null,
    derivedCollectedAt: null,
  };
}

async function computeOwnerDerivative(sourceScopes: string[]) {
  const outcome = await computeQuestion("q-1", {
    storage,
    store: createInMemoryQuestionStore({
      initial: [registration(sourceScopes)],
    }),
    provider: createFakeInferenceProvider({
      respond: () => ({
        content: JSON.stringify({
          answer: "sources said: " + SECRET + " legacy-score-7",
          evidence: null,
        }),
      }),
    }),
    serverOwner: owner.address,
    now: () => new Date("2026-09-02T00:00:00.000Z"),
    retryDelaysMs: [0, 0],
  });
  expect(outcome.status, JSON.stringify(outcome)).toBe("ready");
}

beforeEach(async () => {
  dataDir = await mkdtemp(join(tmpdir(), "derivative-origin-"));
  indexManager = createIndexManager(initializeDatabase(":memory:"));
  storage = createNodeDataStorage({
    indexManager,
    hierarchyOptions: { dataDir },
  });
});

afterEach(async () => {
  indexManager.close();
  await rm(dataDir, { recursive: true, force: true });
});

function app() {
  return dataRoutes({
    indexManager,
    hierarchyOptions: { dataDir },
    logger,
    serverOrigin: ORIGIN,
    serverOwner: owner.address,
    gateway: gatewayFor(builder.address),
    accessLogWriter: { write: async () => undefined },
  });
}

async function signedGet(
  wallet: ReturnType<typeof createTestWallet>,
  path: string,
) {
  return app().request(path, {
    headers: {
      Authorization: await buildWeb3SignedHeader({
        wallet,
        aud: ORIGIN,
        method: "GET",
        uri: path,
        ...(wallet === owner ? {} : { grantId: GRANT_ID }),
      }),
    },
  });
}

describe("derivative output carries the origin of its sources", () => {
  it("a derivative over a PDPP source is refused to a chain grant and read by the owner", async () => {
    await put(sourceEnvelope("oura.sleep", true));
    await computeOwnerDerivative(["oura.sleep"]);

    const chain = await signedGet(builder, `/${DERIVED}`);
    const chainText = await chain.text();
    expect(chain.status, chainText).toBe(403);
    expect(chainText).toContain("GRANT_REQUIRED");
    expect(chainText).not.toContain(SECRET);

    const owned = await signedGet(owner, `/${DERIVED}`);
    const ownedText = await owned.text();
    expect(owned.status, ownedText).toBe(200);
    expect(ownedText).toContain(SECRET);

    expect(storage.findEntry({ scope: DERIVED })).toMatchObject({
      producer: "pdpp-derivative",
      pdppOrigin: true,
    });
  });

  it("a derivative over a mix of PDPP and legacy sources is refused", async () => {
    await put(sourceEnvelope("oura.sleep", true));
    await put(sourceEnvelope("oura.legacy", false));
    await computeOwnerDerivative(["oura.legacy", "oura.sleep"]);
    const chain = await signedGet(builder, `/${DERIVED}`);
    expect(chain.status, await chain.text()).toBe(403);
  });

  it("generated source coordinates are private to the owner of a real computed answer", async () => {
    const hidden = "bank.transactions";
    await put(sourceEnvelope(hidden, false));
    await computeOwnerDerivative([hidden]);
    const owned = await signedGet(owner, `/${DERIVED}`);
    const ownerBody = await owned.json();
    expect(owned.status).toBe(200);
    expect(ownerBody.data.sources).toEqual([
      { scope: hidden, version: 1, collectedAt: AT },
    ]);
    const chain = await signedGet(builder, `/${DERIVED}`);
    const text = await chain.text();
    console.log(
      JSON.stringify({
        probe: "generated-source-disclosure",
        status: chain.status,
        text,
      }),
    );
    expect(chain.status).toBe(200);
    expect(text).not.toContain(hidden);
    expect(text).not.toContain(AT);
    expect(text).not.toContain(computeDataPointId(owner.address, hidden));
    expect(JSON.parse(text).data).not.toHaveProperty("sources");
  });

  it.each([
    "blocks",
    "manifest",
    "old-policy-blocks",
    "old-policy-manifest",
    "bytes",
  ])(
    "generated source metadata uses the common redaction policy: %s",
    async (mode) => {
      await put(sourceEnvelope("bank.transactions", false));
      await computeOwnerDerivative(["bank.transactions"]);
      const entry = storage.findEntry({ scope: DERIVED })!;
      const envelope = await storage.readEnvelope(DERIVED, entry.collectedAt);
      let text: string;
      if (mode === "bytes") {
        text = new TextDecoder().decode(
          redactJsonEnvelopeBytesForGrantee(
            new TextEncoder().encode(JSON.stringify(envelope)),
          ),
        );
      } else {
        if (mode.startsWith("old-policy")) {
          const built = await buildDataBlocksAsync({
            scope: DERIVED,
            collectedAt: entry.collectedAt,
            content: envelope,
          });
          built.manifest.redaction = {
            dropTopLevelLineage: true,
            dropMetadataLineage: false,
          };
          await storage.writeBlockManifest!(
            DERIVED,
            entry.collectedAt,
            built.manifest,
            built.blocks,
          );
        }
        const guarded = storageForReader(storage, "grantee");
        text = JSON.stringify(
          mode.endsWith("manifest")
            ? await guarded.readBlockManifest!(DERIVED, entry.collectedAt, {
                generation: entry.generation,
              })
            : await guarded.readScopeBlocks!(DERIVED, entry.collectedAt, {
                generation: entry.generation,
                maxBytes: 100000,
                maxBlocks: 100,
              }),
        );
      }
      console.log(
        JSON.stringify({ probe: "generated-common-redaction", mode, text }),
      );
      expect(text).not.toContain("bank.transactions");
      expect(text).not.toContain(AT);
      expect(text).not.toContain("$.data.sources");
      expect(JSON.stringify(envelope.data)).toContain("bank.transactions");
    },
  );

  it("an ordinary user-authored sources field remains readable", async () => {
    const sources = [
      { scope: "user-authored.scope", version: 31, collectedAt: AT },
    ];
    await put({
      version: "1.0",
      scope: DERIVED,
      collectedAt: AT,
      data: { sources, answer: "ordinary content" },
    });
    const chain = await signedGet(builder, `/${DERIVED}`);
    expect(chain.status).toBe(200);
    expect((await chain.json()).data.sources).toEqual(sources);
  });

  it.each(["pre-marker-computed", "user-authored-lookalike"])(
    "historical release gate: %s has no trusted compute discriminator",
    async (fixture) => {
      // Pre-marker output fixture: the exact shape previously written by
      // owner compute is also a valid owner-authored record. Latest mutable
      // registrations and this payload cannot attest which write occurred.
      const sources = [
        { scope: "bank.transactions", version: 1, collectedAt: AT },
      ];
      const ids = [computeDataPointId(owner.address, "bank.transactions")];
      const data = {
        questionId: "q-1",
        question: "Weekly summary",
        answer: "ordinary answer",
        evidence: null,
        model: "fake-model",
        computedAt: "2026-09-02T00:00:00.000Z",
        sources,
        lineage: ids,
        $lineage: {
          sources: ids,
          writtenAt: "2026-09-02T00:00:00.000Z",
          origin: "legacy",
        },
      };
      await put({
        version: "1.0",
        scope: DERIVED,
        collectedAt: "2026-09-02T00:00:00Z",
        data,
      });
      const chain = await signedGet(builder, `/${DERIVED}`);
      const body = await chain.json();
      console.log(
        JSON.stringify({
          probe: "historical-compute-ambiguity",
          fixture,
          status: chain.status,
          sources: body.data?.sources,
        }),
      );
      expect(chain.status).toBe(200);
      expect(data.$lineage).not.toHaveProperty("kind");
      expect(body.data.sources).toEqual(sources);
      // This is a documented unresolved historical F1 gate, not a privacy
      // closure: arbitrary content cannot be quarantined from shape alone.
    },
  );

  it("a derivative over legacy-only sources stays readable by the chain grant", async () => {
    await put(sourceEnvelope("oura.legacy", false));
    await computeOwnerDerivative(["oura.legacy"]);

    const chain = await signedGet(builder, `/${DERIVED}`);
    const text = await chain.text();
    expect(chain.status, text).toBe(200);
    expect(text).toContain("legacy-score-7");
    expect(storage.findEntry({ scope: DERIVED })).toMatchObject({
      producer: null,
      pdppOrigin: false,
    });
  });

  it("a request cannot assert the server-only pdpp-derivative producer", async () => {
    const raw = JSON.stringify({ id: "x" });
    const res = await app().request(`/${DERIVED}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Vana-Producer": "pdpp-derivative",
        Authorization: await buildWeb3SignedHeader({
          wallet: owner,
          aud: ORIGIN,
          method: "POST",
          uri: `/${DERIVED}`,
          body: new TextEncoder().encode(raw),
        }),
      },
      body: raw,
    });
    expect(res.status).toBe(400);
  });
});

describe("joined projection and derivative history", () => {
  function conversations(): DataFileEnvelope {
    return {
      version: "1.0",
      scope: "chatgpt.conversations",
      collectedAt: AT,
      data: {
        records: [
          {
            id: "conv-1",
            title: "Trip",
            create_time: AT,
            update_time: AT,
            current_node: "m1",
            message_count_on_current_branch: 1,
          },
        ],
      },
    } as DataFileEnvelope;
  }
  function messages(producer?: "pdpp-projector"): DataFileEnvelope {
    return {
      version: "1.0",
      scope: "chatgpt.messages",
      collectedAt: AT,
      ...(producer ? { producer } : {}),
      data: {
        records: [
          {
            id: "m1",
            conversation_id: "conv-1",
            parent_id: null,
            role: "user",
            content: "joined-legacy-marker",
            content_type: "text",
            model_slug: null,
            create_time: AT,
            on_current_branch: true,
          },
        ],
      },
    } as DataFileEnvelope;
  }

  async function computeOverProjection() {
    const outcome = await computeQuestion("q-1", {
      storage: withLegacyProjection(storage),
      store: createInMemoryQuestionStore({
        initial: [registration(["chatgpt.conversations"])],
      }),
      provider: createFakeInferenceProvider({
        respond: (request) => ({
          content: JSON.stringify({
            answer: JSON.stringify(request).includes("joined-legacy-marker")
              ? "joined-legacy-marker"
              : "absent",
            evidence: null,
          }),
        }),
      }),
      serverOwner: owner.address,
      now: () => new Date("2026-09-02T00:00:00.000Z"),
      retryDelaysMs: [0, 0],
    });
    expect(outcome.status).toBe("ready");
  }

  it("positive control: a joined projection whose inputs are all legacy stays readable", async () => {
    await put(conversations());
    await put(messages());
    await computeOverProjection();
    const chain = await signedGet(builder, `/${DERIVED}`);
    const text = await chain.text();
    expect(chain.status, text).toBe(200);
    expect(text).toContain("joined-legacy-marker");
  });

  it("a recompute of a pre-fix derivative from legacy sources is readable again", async () => {
    await put(sourceEnvelope("oura.legacy", false));
    await put({
      version: "1.0",
      scope: DERIVED,
      collectedAt: AT,
      data: {
        questionId: "q-1",
        answer: "old-answer",
        $lineage: {
          sources: [computeDataPointId(owner.address, "oura.legacy")],
          writtenAt: AT,
        },
      },
    } as DataFileEnvelope);
    const before = await signedGet(builder, `/${DERIVED}`);
    expect(before.status, await before.text()).toBe(403);

    await computeOwnerDerivative(["oura.legacy"]);
    const after = await signedGet(builder, `/${DERIVED}`);
    const text = await after.text();
    expect(after.status, text).toBe(200);
    expect(text).toContain("legacy-score-7");
    expect(
      (await storage.readEnvelope(DERIVED, "2026-09-02T00:00:00Z")).data,
    ).toMatchObject({ $lineage: { origin: "legacy" } });
  });

  it("a derivative a request writes cannot claim a legacy origin", async () => {
    const raw = JSON.stringify({
      id: "x",
      $lineage: { sources: [], writtenAt: AT, origin: "legacy" },
    });
    const res = await app().request(`/${DERIVED}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: await buildWeb3SignedHeader({
          wallet: owner,
          aud: ORIGIN,
          method: "POST",
          uri: `/${DERIVED}`,
          body: new TextEncoder().encode(raw),
        }),
      },
      body: raw,
    });
    expect(res.status).toBe(400);
  });
});

describe("independent review probes", () => {
  it("preserves PDPP origin through an owner projection that joins a PDPP sibling", async () => {
    const marker = "synthetic-joined-marker";
    await put({
      version: "1.0",
      scope: "chatgpt.conversations",
      collectedAt: AT,
      data: {
        records: [
          {
            id: "conv-1",
            title: "Trip",
            create_time: AT,
            update_time: AT,
            current_node: "m1",
            message_count_on_current_branch: 1,
          },
        ],
      },
    } as DataFileEnvelope);
    await put({
      version: "1.0",
      scope: "chatgpt.messages",
      collectedAt: AT,
      producer: "pdpp-projector",
      data: {
        records: [
          {
            id: "m1",
            conversation_id: "conv-1",
            parent_id: null,
            role: "user",
            content: marker,
            content_type: "text",
            model_slug: null,
            create_time: AT,
            on_current_branch: true,
          },
        ],
      },
    } as DataFileEnvelope);
    expect(
      storage.findEntry({ scope: "chatgpt.conversations" })?.pdppOrigin,
    ).toBe(false);
    expect(storage.findEntry({ scope: "chatgpt.messages" })?.pdppOrigin).toBe(
      true,
    );
    const served = withLegacyProjection(storage);
    let sawInput = false;
    const outcome = await computeQuestion("q-1", {
      storage: served,
      store: createInMemoryQuestionStore({
        initial: [registration(["chatgpt.conversations"])],
      }),
      provider: createFakeInferenceProvider({
        respond: (request) => {
          sawInput = JSON.stringify(request).includes(marker);
          return {
            content: JSON.stringify({
              answer: sawInput ? marker : "absent",
              evidence: null,
            }),
          };
        },
      }),
      serverOwner: owner.address,
      now: () => new Date("2026-09-02T00:00:00.000Z"),
      retryDelaysMs: [0, 0],
    });
    expect(outcome.status).toBe("ready");
    expect(sawInput).toBe(true);
    const response = await signedGet(builder, `/${DERIVED}`);
    const leakedMarker = (await response.text()).includes(marker);
    console.log(
      JSON.stringify({
        probe: "projection-origin",
        status: response.status,
        leakedSyntheticMarker: leakedMarker,
        outputPdpp: storage.findEntry({ scope: DERIVED })?.pdppOrigin,
      }),
    );
    expect(response.status).toBe(403);
  });
});

describe("independent version and chain probes", () => {
  it("keeps a new derivative chain marked", async () => {
    await put(sourceEnvelope("oura.sleep", true));
    await computeOwnerDerivative(["oura.sleep"]);
    const outcome = await computeQuestion("q-chain", {
      storage,
      store: createInMemoryQuestionStore({
        initial: [
          {
            ...registration([DERIVED]),
            questionId: "q-chain",
            derivedScope: "summary.daily",
          },
        ],
      }),
      provider: createFakeInferenceProvider(),
      serverOwner: owner.address,
      now: () => new Date("2026-09-03T00:00:00.000Z"),
      retryDelaysMs: [0, 0],
    });
    expect(outcome.status).toBe("ready");
    expect(storage.findEntry({ scope: "summary.daily" })?.pdppOrigin).toBe(
      true,
    );
  });
  it("marks a recompute after a legacy source gets a new PDPP version", async () => {
    await put(sourceEnvelope("oura.sleep", false));
    await computeOwnerDerivative(["oura.sleep"]);
    expect(storage.findEntry({ scope: DERIVED })?.pdppOrigin).toBe(false);
    await put({
      ...sourceEnvelope("oura.sleep", true),
      collectedAt: "2026-09-03T00:00:00.000Z",
    });
    await computeOwnerDerivative(["oura.sleep"]);
    expect(storage.findEntry({ scope: DERIVED })?.pdppOrigin).toBe(true);
    expect((await signedGet(builder, `/${DERIVED}`)).status).toBe(403);
  });
  it("refuses an existing pre-patch PDPP answer used as a new derivative source", async () => {
    await put(sourceEnvelope("oura.sleep", true));
    await put({
      version: "1.0",
      scope: "archive.answer",
      collectedAt: AT,
      data: {
        questionId: "old-question",
        question: "How did I sleep?",
        answer: SECRET,
        sources: [{ scope: "oura.sleep", version: 1, collectedAt: AT }],
        $lineage: {
          sources: [computeDataPointId(owner.address, "oura.sleep")],
          writtenAt: AT,
        },
      },
    } as DataFileEnvelope);
    await computeOwnerDerivative(["archive.answer"]);
    const response = await signedGet(builder, `/${DERIVED}`);
    console.log(
      JSON.stringify({
        probe: "pre-patch-chain",
        status: response.status,
        outputPdpp: storage.findEntry({ scope: DERIVED })?.pdppOrigin,
      }),
    );
    expect(response.status).toBe(403);
  });
});

describe("independent stamp persistence probe", () => {
  it("keeps the stamp through reindex and rejects removing it at the same version", async () => {
    await put(sourceEnvelope("oura.sleep", true));
    await computeOwnerDerivative(["oura.sleep"]);
    const entry = storage.findEntry({ scope: DERIVED })!;
    const original = await storage.readEnvelope(DERIVED, entry.collectedAt);
    expect((original as unknown as { producer: string }).producer).toBe(
      "pdpp-derivative",
    );
    const stripped = { ...original } as unknown as Record<string, unknown>;
    delete stripped.producer;
    await expect(
      storage.writeEnvelope(stripped as unknown as DataFileEnvelope),
    ).rejects.toThrow(/conflict/i);
    const recoveredIndex = createIndexManager(initializeDatabase(":memory:"));
    try {
      await reindexLegacyDataFiles({
        indexManager: recoveredIndex,
        hierarchyOptions: { dataDir },
      });
      expect(recoveredIndex.findLatestByScope(DERIVED)).toMatchObject({
        producer: "pdpp-derivative",
        pdppOrigin: true,
      });
    } finally {
      recoveredIndex.close();
    }
  });
});

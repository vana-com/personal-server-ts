import { describe, expect, it } from "vitest";
import type { JsonObject } from "@opendatalabs/personal-server-ts-stream-sync";
import { projectPdppRecordsToLegacyPayload } from "../legacy-projection/index.js";
import type { StreamSyncReadService } from "./service.js";
import { liveStreamCounts, readTargets } from "./service.js";
import { testOwnerKey } from "./testing.js";
import { ask, body, Fixture, masterKey } from "./service-fixture.js";

describe("stream-sync reads", () => {
  it("serves a logical stream read as {records} from the imported view", async () => {
    const f = new Fixture(await testOwnerKey(masterKey(1)));
    const ns = await f.key.ns("acme", "account-1");
    await f.activate("acme", ns);
    const records = Array.from({ length: 40 }, (_, i) => ({
      id: `r${i}`,
      n: i,
    }));
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records,
      prefixes: ["0", "1"],
    });
    const service = await f.service();
    await f.sync(service);

    const decision = await service.resolve(ask("pdpp.acme.items"));
    // A paid read binds its access record to the served head.
    expect(decision).toMatchObject({
      served: { scope: `pdpp.acme~${ns}.items`, version: 1 },
    });
    const envelope = await body(decision);
    expect(envelope.version).toBe("1.0");
    expect(envelope.scope).toBe("pdpp.acme.items");
    expect(Object.keys(envelope.data)).toEqual(["records"]);
    expect(envelope.data.records.map((r: any) => r.id).sort()).toEqual(
      records.map((r) => r.id).sort(),
    );
  });

  it("errors the body, never ends it, when a part fails after bytes are sent", async () => {
    const f = new Fixture(await testOwnerKey(masterKey(13)));
    const ns = await f.key.ns("acme", "account-1");
    await f.activate("acme", ns);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: Array.from({ length: 80 }, (_, i) => ({
        id: `r${i}`,
        pad: "x".repeat(2048),
      })),
      prefixes: ["0", "1"],
    });
    const service = await f.service();
    await f.sync(service);
    const decision = await service.resolve(ask("pdpp.acme.items"));
    if (decision.kind !== "view") throw new Error(decision.kind);

    const read = f.files.read.bind(f.files);
    let partReads = 0;
    f.files.read = async (path) => {
      if (path.includes("/parts/") && partReads++ > 0) {
        throw new Error("part unreadable");
      }
      return read(path);
    };
    const reader = decision.body.getReader();
    const chunks: Uint8Array[] = [];
    const outcome = await (async () => {
      for (;;) {
        const next = await reader.read();
        if (next.done) return "ended";
        chunks.push(next.value);
      }
    })().catch((error: Error) => error.message);
    const text = new TextDecoder().decode(Buffer.concat(chunks));
    expect(outcome).toBe("part unreadable");
    expect(text.length).toBeGreaterThan(0);
    expect(() => JSON.parse(text)).toThrow();
  });

  it("maps a source name to no other connector without signed alias data", async () => {
    // claude.conversations reads the connector its binding names. A raw
    // `pdpp.<source>.<stream>` name reads connector <source> only: no signed
    // connector data carries a source alias yet, and a list in code may not.
    const f = new Fixture(await testOwnerKey(masterKey(12)));
    const ns = await f.key.ns("anthropic", "account-1");
    await f.activate("anthropic", ns);
    for (const stream of ["account_profile", "conversations", "messages"]) {
      await f.publish({
        connector: "anthropic",
        ns,
        stream,
        generation: 1,
        records: [],
      });
    }
    const service = await f.service();
    await f.sync(service);
    expect((await service.resolve(ask("claude.conversations"))).kind).toBe(
      "view",
    );
    expect(
      (await service.resolve(ask("pdpp.anthropic.conversations"))).kind,
    ).toBe("view");
    expect((await service.resolve(ask("pdpp.claude.conversations"))).kind).toBe(
      "pass",
    );
  });

  it("never accepts a physical name as a requested name", () => {
    expect(readTargets("pdpp.acme~0123456789abcdef.items")).toEqual([]);
    expect(readTargets("pdpp.acme~.items")).toEqual([]);
  });

  it("serves one account only: the connection with the newest heads", async () => {
    const f = new Fixture(await testOwnerKey(masterKey(2)));
    const a = await f.key.ns("acme", "account-a");
    const b = await f.key.ns("acme", "account-b");
    await f.activate("acme", a);
    await f.activate("acme", b);
    await f.publish({
      connector: "acme",
      ns: a,
      stream: "items",
      generation: 1,
      records: [{ id: "a1" }, { id: "a2" }],
    });
    await f.publish({
      connector: "acme",
      ns: b,
      stream: "items",
      generation: 1,
      records: [{ id: "b1" }],
    });
    const service = await f.service();
    await f.sync(service);

    const plain = await body(await service.resolve(ask("pdpp.acme.items")));
    expect(plain.data.records).toEqual([{ id: "b1" }]);
    const named = await body(
      await service.resolve(ask("pdpp.acme.items", { connection: a })),
    );
    expect(named.data.records.map((r: any) => r.id).sort()).toEqual([
      "a1",
      "a2",
    ]);
    expect(
      (
        await service.resolve(
          ask("pdpp.acme.items", { connection: "f".repeat(16) }),
        )
      ).kind,
    ).toBe("unavailable");
  });

  it("serves a complete view over a legacy file, and the legacy file over an incomplete view", async () => {
    const f = new Fixture(await testOwnerKey(masterKey(3)));
    const ns = await f.key.ns("acme", "account-1");
    await f.activate("acme", ns);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "x" }],
      complete: false,
    });
    const service = await f.service();
    await f.sync(service);
    expect(
      (await service.resolve(ask("pdpp.acme.items", { legacyFile: true })))
        .kind,
    ).toBe("legacy");
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "x" }],
      complete: true,
    });
    await f.sync(service);
    expect(
      (await service.resolve(ask("pdpp.acme.items", { legacyFile: true })))
        .kind,
    ).toBe("view");
  });

  it("serves nothing for a deleted connector, legacy file or not", async () => {
    const f = new Fixture(await testOwnerKey(masterKey(4)));
    const ns = await f.key.ns("acme", "account-1");
    await f.activate("acme", ns);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "x" }],
    });
    await f.deleteConnection("acme", ns);
    const service = await f.service();
    await f.sync(service);
    expect(
      await service.resolve(ask("pdpp.acme.items", { legacyFile: true })),
    ).toEqual({
      kind: "unavailable",
      reason: "deleted",
    });
  });

  it("reports another owner key as key_mismatch and serves none of it", async () => {
    const f = new Fixture(await testOwnerKey(masterKey(5)));
    const other = await testOwnerKey(masterKey(6));
    const ns = await other.ns("acme", "account-1");
    await f.activate("acme", ns, other);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "x" }],
      key: other,
    });
    const service = await f.service();
    await f.sync(service);
    expect((await service.resolve(ask("pdpp.acme.items"))).kind).toBe(
      "key_mismatch",
    );
    expect(service.status().issues).toEqual([
      expect.objectContaining({
        connector: "acme",
        stream: null,
        problem: "key_mismatch",
      }),
    ]);
  });

  it("pins input versions: a cursor of a retired version is stale", async () => {
    const f = new Fixture(await testOwnerKey(masterKey(7)));
    const ns = await f.key.ns("acme", "account-1");
    await f.activate("acme", ns);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "v1" }],
    });
    const service = await f.service();
    await f.sync(service);
    const first = await service.resolve(ask("pdpp.acme.items"));
    if (first.kind !== "view") throw new Error(first.kind);
    // A read in flight keeps its version through an import.
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "v2" }],
    });
    await f.sync(service);
    expect(
      JSON.parse(await new Response(first.body).text()).data.records,
    ).toEqual([{ id: "v1" }]);
    expect(
      (await service.resolve(ask("pdpp.acme.items", { cursor: first.cursor })))
        .kind,
    ).toBe("cursor_stale");
  });

  it("counts only live heads, and a live count equals a named-connection read of that stream", async () => {
    const f = new Fixture(await testOwnerKey(masterKey(21)));
    const rows = (n: number) =>
      Array.from({ length: n }, (_, i) => ({ id: `r${i}` }));
    const publishAll = async (connector: string, ns: string) => {
      await f.activate(connector, ns);
      await f.publish({
        connector,
        ns,
        stream: "items",
        generation: 1,
        records: rows(7),
      });
    };
    // A live connection with a live stream, a pending head and a tombstoned stream.
    const ns = await f.key.ns("acme", "account-1");
    await publishAll("acme", ns);
    await f.publish({
      connector: "acme",
      ns,
      stream: "pending",
      generation: 1,
      records: rows(3),
      withholdBlobs: true,
    });
    await f.publish({
      connector: "acme",
      ns,
      stream: "gone",
      generation: 1,
      records: rows(4),
    });
    const nsGen = await f.key.ns("beta", "account-1");
    await publishAll("beta", nsGen);
    const nsDeleted = await f.key.ns("gamma", "account-1");
    await publishAll("gamma", nsDeleted);
    const service = await f.service();
    await f.sync(service);
    // Everything above except the withheld pending stream was imported while
    // live. Now each imported one loses liveness.
    const gone = [...f.rows.values()].find((r) => r.scope.endsWith(".gone"))!;
    f.rows.set(gone.scope, { ...gone, deletedAt: gone.addedAt });
    // A newer control generation after the head was imported.
    await f.activate("beta", nsGen);
    await f.deleteConnection("gamma", nsDeleted);
    await f.sync(service);
    const byName = new Map(
      liveStreamCounts(service.status()).map((row) => [
        `${row.connector}.${row.stream}`,
        row.records,
      ]),
    );

    // Live: the count equals a named-connection read of the stream.
    expect(byName.get("acme.items")).toBe(7);
    const read = await body(
      await service.resolve(ask("pdpp.acme.items", { connection: ns })),
    );
    expect(read.data.records).toHaveLength(7);
    // Not live: no count, and an owner read does not serve the stream.
    expect(byName.get("acme.pending")).toBeNull();
    expect(byName.get("acme.gone")).toBeNull();
    expect(byName.get("beta.items")).toBeNull();
    expect(byName.get("gamma.items")).toBeNull();
    expect(
      await service.resolve(ask("pdpp.gamma.items", { connection: nsDeleted })),
    ).toEqual({ kind: "unavailable", reason: "deleted" });
    expect(
      (await service.resolve(ask("pdpp.beta.items", { connection: nsGen })))
        .kind,
    ).not.toBe("view");
  });

  it("does not block import on local outbox entries and overlays their rows", async () => {
    const f = new Fixture(await testOwnerKey(masterKey(8)));
    const ns = await f.key.ns("acme", "account-1");
    await f.activate("acme", ns);
    f.overlay.runs = [
      {
        runId: "local",
        ns,
        generation: 1,
        state: "failed",
        streams: [
          {
            name: "items",
            rows: [
              { o: 5_000_000_000_000, r: "local", v: { id: "a", local: true } },
              { o: 5_000_000_000_000, r: "local", v: { id: "only-local" } },
            ],
          },
        ],
      },
    ];
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "a" }, { id: "b" }],
    });
    const service = await f.service();
    await f.sync(service);
    const envelope = await body(await service.resolve(ask("pdpp.acme.items")));
    const byId = Object.fromEntries(
      envelope.data.records.map((r: any) => [r.id, r]),
    );
    expect(Object.keys(byId).sort()).toEqual(["a", "b", "only-local"]);
    expect(byId.a).toEqual({ id: "a", local: true });
  });

  it("retries a head whose blobs are not in storage yet", async () => {
    const f = new Fixture(await testOwnerKey(masterKey(9)));
    const ns = await f.key.ns("acme", "account-1");
    await f.activate("acme", ns);
    const built = await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "x" }],
      withholdBlobs: true,
    });
    const service = await f.service();
    await f.sync(service);
    expect(service.status().issues).toEqual([
      expect.objectContaining({ problem: "blob_missing" }),
    ]);
    for (const [k, v] of built.blobs) f.blobs.set(k, v);
    await service.importPending();
    expect(service.status().issues).toEqual([]);
    expect((await service.resolve(ask("pdpp.acme.items"))).kind).toBe("view");
  });

  it("streams chatgpt.conversations by shard with the array projector's records and order", async () => {
    const f = new Fixture(await testOwnerKey(masterKey(10)));
    const ns = await f.key.ns("chatgpt", "account-1");
    await f.activate("chatgpt", ns);
    const conversations: JsonObject[] = [];
    const messages: JsonObject[] = [];
    for (let c = 0; c < 60; c++) {
      const id = `conv-${c}`;
      conversations.push({
        id,
        title: `t${c}`,
        create_time: "2026-01-01T00:00:00.000Z",
        update_time: `2026-01-${String((c % 28) + 1).padStart(2, "0")}T00:00:00.000Z`,
        current_node: `${id}:n1`,
        message_count_on_current_branch: 2,
      });
      for (let m = 0; m < 2; m++) {
        messages.push({
          id: `${id}:n${m}`,
          conversation_id: id,
          parent_id: m ? `${id}:n0` : null,
          role: m ? "assistant" : "user",
          content: `m${m}`,
          content_type: "text",
          model_slug: null,
          create_time: "2026-01-01T00:00:00.000Z",
          on_current_branch: true,
        });
      }
    }
    await f.publish({
      connector: "chatgpt",
      ns,
      stream: "conversations",
      generation: 1,
      records: conversations,
    });
    await f.publish({
      connector: "chatgpt",
      ns,
      stream: "messages",
      generation: 1,
      records: messages,
    });
    const service = await f.service();
    await f.sync(service);
    const decision = await service.resolve(ask("chatgpt.conversations"));
    // A joined name binds a paid read to the window's parent stream head.
    expect(decision).toMatchObject({
      served: { scope: `pdpp.chatgpt~${ns}.conversations`, version: 1 },
    });
    const streamed = await body(decision);
    const whole = projectPdppRecordsToLegacyPayload(
      "chatgpt.conversations",
      [
        ...conversations.map((data) => ({ stream: "conversations", data })),
        ...messages.map((data) => ({ stream: "messages", data })),
      ],
      {
        fetchedStreams: ["conversations", "messages"],
        orderByPrimaryKey: true,
        profileKey: "chatgpt",
        now: "2026-11-02T00:00:00.000Z",
      },
    );
    if (!whole.ok) throw new Error("projection failed");
    const array = whole.payload as Record<string, any>;
    // The array projector's order too: newest update first.
    expect(streamed.data.conversations).toEqual(array.conversations);
    expect(streamed.data.total).toBe(array.total);
    expect({ ...streamed.data, conversations: [] }).toEqual({
      ...array,
      conversations: [],
    });
  });

  describe("stream tombstones", () => {
    const encodings = ["deletedAt only", "hash pair only"] as const;

    async function importedLive(seed: number) {
      const f = new Fixture(await testOwnerKey(masterKey(seed)));
      const ns = await f.key.ns("acme", "account-1");
      await f.activate("acme", ns);
      const first = await f.publish({
        connector: "acme",
        ns,
        stream: "items",
        generation: 1,
        records: [{ id: "a" }, { id: "b" }],
      });
      const service = await f.service();
      await f.sync(service);
      expect((await service.resolve(ask("pdpp.acme.items"))).kind).toBe("view");
      return { f, ns, first, service };
    }

    async function tombstone(
      f: Fixture,
      scope: string,
      encoding: (typeof encodings)[number],
    ) {
      const prev = f.rows.get(scope)!;
      const { tombstone: t } = await f.key.control();
      const next = String(Number(prev.expectedVersion) + 1);
      f.rows.set(
        scope,
        encoding === "deletedAt only"
          ? {
              ...prev,
              expectedVersion: next,
              deletedAt: "2026-11-01T01:00:00.000Z",
            }
          : {
              ...prev,
              dataHash: t.dataHash,
              metadataHash: t.metadataHash,
              expectedVersion: next,
              deletedAt: null,
            },
      );
      return t.dataHash.slice(2).toLowerCase();
    }

    const view = (s: StreamSyncReadService) =>
      s.resolve(ask("pdpp.acme.items")).then((d) => d.kind);

    for (const encoding of encodings) {
      it(`makes the old records unavailable (${encoding})`, async () => {
        const { f, first, service } = await importedLive(21);
        const tombHash = await tombstone(f, first.scope, encoding);
        const feed = [...f.rows.values()];
        f.blobGets.length = 0;

        await service.observe(feed, { fromStart: true, lastPage: true });
        expect(await view(service)).not.toBe("view");

        await service.importPending();
        expect(await view(service)).not.toBe("view");
        expect(f.blobGets.filter((k) => k.includes(tombHash))).toEqual([]);

        const restarted = await f.service();
        expect(await view(restarted)).not.toBe("view");
        await restarted.importPending();
        expect(await view(restarted)).not.toBe("view");
        expect(f.blobGets.filter((k) => k.includes(tombHash))).toEqual([]);
      });

      it(`imports a later live version without resurrecting the deleted one (${encoding})`, async () => {
        const { f, ns, first, service } = await importedLive(22);
        await tombstone(f, first.scope, encoding);
        await f.sync(service);
        await f.publish({
          connector: "acme",
          ns,
          stream: "items",
          generation: 1,
          records: [{ id: "c" }],
        });
        await f.sync(service);
        const ids = async (s: StreamSyncReadService) =>
          (await body(await s.resolve(ask("pdpp.acme.items")))).data.records
            .map((r: any) => r.id)
            .sort();
        expect(await ids(service)).toEqual(["c"]);
        expect(await ids(await f.service())).toEqual(["c"]);
      });
    }
  });
});

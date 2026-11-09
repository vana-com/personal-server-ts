import { readFileSync } from "node:fs";
import ts from "typescript";
import { expect, it } from "vitest";
import * as protocol from "@opendatalabs/personal-server-ts-stream-sync";
import * as bytes from "../../../stream-sync/src/bytes.js";
import * as errors from "../../../stream-sync/src/errors.js";
import * as jsonPorts from "../../../stream-sync/src/json.js";
import * as names from "../../../stream-sync/src/names.js";
import { Rig, CONNECTOR, T0 } from "../stream-sync-read/writer-rig.js";
import { ask, body } from "../stream-sync-read/service-fixture.js";
import { createStreamSyncKeyPorts, streamSyncHashes } from "./crypto.js";
import { publicationMetadataHash } from "../publication/publish.js";

// Frozen functions are transpiled, not rewritten. The harness supplies only I/O,
// admission and one already encoded intake part; row classification, format
// acceptance, base choice, planning, signing order and POST order are historical.
function frozenModule(name: string, require: (id: string) => unknown) {
  const text = readFileSync(
    new URL(`__fixtures__/pre-fence-${name}.ts.txt`, import.meta.url),
    "utf8",
  );
  const js = ts.transpileModule(text, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
    },
  }).outputText;
  const exports: any = {};
  new Function("require", "exports", js)(require, exports);
  return exports;
}
function family(prefix: string) {
  const head = frozenModule(
    `${prefix}head`,
    (id) =>
      ({
        "./bytes.js": bytes,
        "./errors.js": errors,
        "./json.js": jsonPorts,
        "./names.js": names,
      })[id],
  );
  const classify = frozenModule(`${prefix}classify`, () => undefined);
  const plan = frozenModule(`${prefix}plan`, () => ({ ...protocol, ...head }));
  return { head, classify, plan, prefix };
}
const families = { fde: family(""), ea: family("ea-") };
async function device(r: Rig, snapshot: keyof typeof families) {
  const { head, classify, plan, prefix } = families[snapshot];
  const keys = createStreamSyncKeyPorts(
    `0x${"1f".repeat(32)}${"2a".repeat(32)}1b`,
  );
  const control = await protocol.controlHashes(
    streamSyncHashes.keccak256,
    "0000000000000000",
  );
  const binding = await r.writer.binding();
  const scope = protocol.streamScope(CONNECTOR, "", "items");
  const text = readFileSync(
    new URL(`__fixtures__/pre-fence-${prefix}writer.ts.txt`, import.meta.url),
    "utf8",
  );
  const js = ts.transpileModule(text, {
    compilerOptions: { target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const deps = {
    ...protocol,
    ...head,
    ...classify,
    ...plan,
    publicationMetadataHash,
    decoder: new TextDecoder(),
    json: (v: unknown) => new TextEncoder().encode(JSON.stringify(v)),
    parseHeadKey: (request: any) =>
      `${request.scope}/h-${request.dataHash.slice(2).toLowerCase()}`,
  };
  const FrozenWriter = new Function(
    "deps",
    `const {${Object.keys(deps).join(",")}}=deps;\n${js}\nreturn FrozenWriter;`,
  )(deps);
  const writer = new FrozenWriter();
  const files = r.files;
  const part = await protocol.encodeWinners(streamSyncHashes.sha256, "", [
    {
      pkHash: await protocol.pkHash(streamSyncHashes.sha256, { id: "stale" }, [
        "id",
      ]),
      text: protocol.canonicalJson({ o: T0, r: "old", v: { id: "stale" } }),
    },
  ]);
  if (!part) throw new Error("missing intake part");
  await r.blobMap.set(
    `${scope}/${protocol.partBlobName(1, part.entry.hash)}`,
    await keys.encrypt(scope, part.data),
  );
  Object.assign(writer, {
    control,
    hashes: streamSyncHashes,
    selected: new Set(),
    options: {
      registry: r.gateway,
      blobs: {
        get: async (k: string) => r.blobMap.get(k) ?? null,
        put: async (k: string, b: Uint8Array) => {
          r.blobMap.set(k, b);
        },
      },
      keys,
      home: { files },
    },
    keys: async () => ({ ...binding, control }),
    admit: async () => 1,
    readState: async () => ({ seedTargets: {}, receipts: {} }),
    buildParts: async () => ({ parts: [part.entry] }),
    fault: () => {},
    writeEntry: async () => {},
    committed: async () => {},
    setStream: (host: any, name: string, value: any) => {
      host.entry.streams[name] = value;
    },
    sign: async (
      scope: string,
      dataHash: string,
      metadataHash: string,
      version: number,
    ) => ({
      scope,
      dataHash,
      metadataHash,
      expectedVersion: String(version),
      signature: "0x00",
      ownerAddress: binding.owner,
    }),
  });
  const row = await r.gateway.read(scope);
  const host = {
    target: 1,
    generation: 1,
    checkpointUsed: null,
    entry: {
      runId: "old",
      connector: CONNECTOR,
      ns: "",
      observedAt: T0,
      full: true,
      streams: { items: { state: "planned" } },
    },
    streams: {
      items: {
        index: 0,
        primaryKey: ["id"],
        profile: { key: null, version: "1.0.0" },
        shardBytes: [part.data.length],
        seedApplies: false,
        fullStream: false,
        rowAtStart: {
          tombstoned: classify.classifyStreamRow(row, control) === "tombstoned",
        },
      },
    },
  };
  return { writer, host, scope, control, classify: classify.classifyStreamRow };
}

it.each(["fde", "ea"] as const)(
  "verbatim %s plan refuses a delete head before POST (mutant: old tombstone hashes; EA_DELETE_ROW_AS_TOMBSTONE)",
  async (snapshot) => {
    const r = new Rig();
    await r.open();
    // Second-delete witness: the historical boolean fence admits tombstone ->
    // tombstone, so only the format barrier prevents stale records returning.
    const control = await protocol.controlHashes(
      streamSyncHashes.keccak256,
      "0000000000000000",
    );
    const scope = protocol.streamScope(CONNECTOR, "", "items");
    await r.collect({
      runId: "base",
      key: "id",
      version: "1.0.0",
      full: true,
      rows: [{ id: "base" }],
    });
    await r.publish();
    await r.gateway.post({
      scope,
      ownerAddress: `0x${"11".repeat(20)}`,
      dataHash: control.tombstoneData,
      metadataHash: control.tombstoneMetadata,
      expectedVersion: "2",
      signature: "0x00",
    });
    const old = await device(r, snapshot);
    await r.deleteStreamHeadsOnly();
    expect(old.classify(await r.gateway.read(old.scope), old.control)).toBe(
      "present",
    );
    const commits = r.gateway.log.length;
    let failure: any;
    try {
      await old.writer.planAndPost(old.host, "items");
    } catch (error) {
      failure = error;
    }
    await r.sync();
    const decision = await r.service.resolve(ask("pdpp.acme.items"));
    const observed =
      decision.kind === "view" || decision.kind === "local_pending"
        ? (await body(decision)).data.records
        : decision;
    expect(observed).toMatchObject({ kind: "unavailable", reason: "deleted" });
    expect(failure?.problem).toBe("unsupported_format");
    expect(r.gateway.log).toHaveLength(commits);
    expect(await r.registeredHead()).toMatchObject({
      format: 3,
      lastDeleteVersion: 3,
      recordCount: 0,
    });
  },
);

it.each(["fde", "ea"] as const)(
  "verbatim %s resend conflicts at its persisted version",
  async (snapshot) => {
    const r = new Rig();
    await r.open();
    const old = await device(r, snapshot);
    old.writer.fault = (point: string) => {
      if (point === "after_request_persisted")
        throw new Error("stop before POST");
    };
    await expect(old.writer.planAndPost(old.host, "items")).rejects.toThrow(
      "stop before POST",
    );
    old.writer.fault = () => {};
    // Another device takes the version first, then the delete advances the row.
    await r.collect({
      runId: "base",
      key: "id",
      version: "1.0.0",
      full: true,
      rows: [{ id: "base" }],
    });
    await r.publish();
    // Capture the signed request, then advance the row with the new delete head.
    await r.deleteStreamHeadsOnly();
    expect(old.classify(await r.gateway.read(old.scope), old.control)).toBe(
      "present",
    );
    const commits = r.gateway.log.length;
    expect(await old.writer.resend(old.host, "items")).toBe(false);
    expect(r.gateway.log).toHaveLength(commits);
    expect(await r.registeredHead()).toMatchObject({
      format: 3,
      lastDeleteVersion: 2,
      recordCount: 0,
    });
  },
);

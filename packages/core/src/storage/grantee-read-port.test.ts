/**
 * The grantee read port: the only storage a non-owner read gets.
 *
 * Its stream is the version the read authorized: provenance comes from the
 * row storage derived from the published bytes, and the bytes are checked
 * against that row's digest while they stream, under a hard input cap. A row
 * without a digest is decided on one bounded read of its bytes, and the
 * stream is then checked against the digest of those bytes.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import type { DataStoragePort } from "../ports/index.js";
import type { IndexEntry } from "./index/types.js";
import { envelopeGeneration } from "./hierarchy/generation.js";
import {
  AuthorizedVersion,
  granteeReadPort,
  readerSource,
  StoredEnvelopeReadError,
  type GranteeReadPort,
} from "./disclosure-policy.js";
import { readDataContract } from "../contracts/data.js";
import { resolveBlockRedactionContext } from "./blocks/redaction.js";
import { withLegacyProjection } from "./legacy-projection.js";
import {
  loadSource,
  type QuestionComputeDeps,
} from "../derivatives/compute.js";

const SCOPE = "acme.notes";
const AT = "2026-09-01T00:00:00.000Z";
const CHUNK = 1024;

function envelope(data: Record<string, unknown>): DataFileEnvelope {
  return { version: "1.0", scope: SCOPE, collectedAt: AT, data };
}

const legacy = envelope({ notes: ["a".repeat(8 * CHUNK)] });
const otherLegacy = envelope({ notes: ["b".repeat(8 * CHUNK)] });
const pdpp = envelope({
  notes: ["c"],
  $pdpp: { version: 1, sourceId: "https://registry.pdpp.dev/acme" },
});

const encode = (value: unknown) =>
  new TextEncoder().encode(JSON.stringify(value, null, 2));
const sha256 = (bytes: Uint8Array) =>
  createHash("sha256").update(bytes).digest("hex");

/** A raw port over one stored file whose bytes a test can change. */
function rawStore(initial: DataFileEnvelope) {
  const state = {
    bytes: encode(initial),
    opens: 0,
    delivered: 0,
    /** Runs as each stream opens, before it captures the bytes. */
    onOpen: undefined as undefined | ((open: number) => void),
  };
  const entry: IndexEntry = {
    id: 1,
    fileId: null,
    schemaId: null,
    path: "acme/notes/x.json",
    scope: SCOPE,
    collectedAt: AT,
    createdAt: AT,
    sizeBytes: state.bytes.byteLength,
    version: 1,
    dataPointId: null,
    pdppOrigin: false,
    generation: envelopeGeneration(initial),
    contentDigest: sha256(state.bytes),
  };
  const raw = {
    findEntry: () => entry,
    listVersions: () => [entry],
    readEnvelope: async () =>
      JSON.parse(new TextDecoder().decode(state.bytes)) as DataFileEnvelope,
    readEnvelopeStream: async () => {
      state.opens += 1;
      state.onOpen?.(state.opens);
      const bytes = state.bytes;
      let offset = 0;
      return new ReadableStream<Uint8Array>({
        pull(controller) {
          if (offset >= bytes.byteLength) return controller.close();
          const chunk = bytes.slice(offset, offset + CHUNK);
          offset += chunk.byteLength;
          state.delivered += chunk.byteLength;
          controller.enqueue(chunk);
        },
      });
    },
    writeEnvelope: async () => {
      throw new Error("not used");
    },
  } as unknown as DataStoragePort;
  return { raw, entry, state };
}

/** The stream of `entry` through `port`, pinned as a worker pins it. */
function streamOf(port: GranteeReadPort, entry: IndexEntry, maxBytes: number) {
  return port.readEnvelopeStream!(port.pinVersion(entry), { maxBytes });
}

async function drain(stream: ReadableStream<Uint8Array>): Promise<string> {
  return new Response(stream).text();
}

describe("granteeReadPort stream", () => {
  it("serves the pinned bytes unchanged", async () => {
    const { raw, entry, state } = rawStore(legacy);
    const port = granteeReadPort(raw);

    const text = await drain(await streamOf(port, entry, 1 << 20));

    expect(text).toBe(new TextDecoder().decode(state.bytes));
    expect(state.opens).toBe(1);
  });

  it("refuses a row storage recorded as PDPP before opening the bytes", async () => {
    const { raw, entry, state } = rawStore(pdpp);
    entry.pdppOrigin = true;

    await expect(
      streamOf(granteeReadPort(raw), entry, 1 << 20),
    ).rejects.toMatchObject({ errorCode: "GRANT_REQUIRED" });
    expect(state.opens).toBe(0);
  });

  it("errors at the end when the bytes are not the pinned digest", async () => {
    const { raw, entry, state } = rawStore(legacy);
    state.bytes = encode(otherLegacy);

    const stream = await streamOf(granteeReadPort(raw), entry, 1 << 20);

    await expect(drain(stream)).rejects.toMatchObject({
      name: "StoredEnvelopeReadError",
      code: "generation_mismatch",
    });
  });

  it("stops reading at the cap whatever the row says the size is", async () => {
    const { raw, entry, state } = rawStore(legacy);
    entry.sizeBytes = 10;

    const stream = await streamOf(granteeReadPort(raw), entry, 3 * CHUNK);

    const error = await drain(stream).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(StoredEnvelopeReadError);
    expect(error).toMatchObject({ code: "too_large" });
    expect(state.delivered).toBeLessThanOrEqual(5 * CHUNK);
    expect(state.bytes.byteLength).toBeGreaterThan(8 * CHUNK);
  });

  describe("a row without a digest", () => {
    it("decides on the bytes: PDPP bytes are refused before streaming", async () => {
      const { raw, entry } = rawStore(pdpp);
      delete entry.contentDigest;
      delete entry.generation;
      entry.pdppOrigin = false;

      await expect(
        streamOf(granteeReadPort(raw), entry, 1 << 20),
      ).rejects.toMatchObject({ errorCode: "GRANT_REQUIRED" });
    });

    it("refuses bytes that are not the pinned generation", async () => {
      const { raw, entry, state } = rawStore(legacy);
      delete entry.contentDigest;
      state.bytes = encode(otherLegacy);

      await expect(
        streamOf(granteeReadPort(raw), entry, 1 << 20),
      ).rejects.toMatchObject({ code: "generation_mismatch" });
    });

    it("streams only the bytes it decided on", async () => {
      const { raw, entry, state } = rawStore(legacy);
      delete entry.contentDigest;
      delete entry.generation;
      // The deciding read sees the legacy bytes; the stream sees others.
      state.onOpen = (open) => {
        if (open === 2) state.bytes = encode(otherLegacy);
      };

      const stream = await streamOf(granteeReadPort(raw), entry, 1 << 20);

      await expect(drain(stream)).rejects.toMatchObject({
        code: "generation_mismatch",
      });
    });

    it("applies the cap to the deciding read", async () => {
      const { raw, entry, state } = rawStore(legacy);
      delete entry.contentDigest;

      await expect(
        streamOf(granteeReadPort(raw), entry, 2 * CHUNK),
      ).rejects.toMatchObject({ code: "too_large" });
      expect(state.delivered).toBeLessThanOrEqual(4 * CHUNK);
    });
  });
});

describe("granteeReadPort authorized versions", () => {
  it("takes provenance from storage, not from the row a caller passes", async () => {
    const { raw, entry, state } = rawStore(pdpp);
    entry.pdppOrigin = true;
    const port = granteeReadPort(raw);

    await expect(
      port.readEnvelopeStream!(
        port.pinVersion({ ...entry, pdppOrigin: false } as IndexEntry),
        { maxBytes: 1 << 20 },
      ),
    ).rejects.toMatchObject({ errorCode: "GRANT_REQUIRED" });
    expect(state.opens).toBe(0);
  });

  it("rejects a version it did not mint", async () => {
    const { raw, entry } = rawStore(legacy);
    const port = granteeReadPort(raw);
    const forged = Object.create(AuthorizedVersion.prototype) as never;

    await expect(
      port.readEnvelopeStream!(forged, { maxBytes: 1 << 20 }),
    ).rejects.toBeInstanceOf(TypeError);
    await expect(
      port.readEnvelopeStream!({ ...entry } as never, { maxBytes: 1 << 20 }),
    ).rejects.toBeInstanceOf(TypeError);
  });

  it("refuses a version whose row storage no longer holds", async () => {
    const { raw, entry } = rawStore(legacy);
    const port = granteeReadPort(raw);
    const version = port.pinVersion(entry);
    entry.id = 2; // deleted and indexed again at the same path

    await expect(
      port.readEnvelopeStream!(version, { maxBytes: 1 << 20 }),
    ).rejects.toMatchObject({ code: "generation_mismatch" });
  });
});

describe("granteeReadPort projected blocks", () => {
  // A semantic test that does not use `pinVersion`: an MCP-style block read
  // of a projected scope, pinned by the generation it authorized.
  const scope = "chatgpt.conversations";
  const conversation = (title: string) =>
    envelope({
      records: [
        {
          id: "c",
          title,
          create_time: "2026-09-01T10:00:00Z",
          update_time: "2026-09-01T10:05:00Z",
          current_node: null,
          message_count_on_current_branch: 0,
        },
      ],
    });

  function projectedStore() {
    const authorized = { ...conversation("AUTHORIZED_A"), scope };
    const state = { bytes: encode(authorized) };
    const entry: IndexEntry = {
      id: 1,
      fileId: null,
      schemaId: null,
      path: "chatgpt/conversations/x.json",
      scope,
      collectedAt: AT,
      createdAt: AT,
      sizeBytes: state.bytes.byteLength,
      version: 1,
      dataPointId: null,
      pdppOrigin: false,
      generation: envelopeGeneration(authorized),
      contentDigest: sha256(state.bytes),
    };
    const forScope = (lookup: { scope: string }) =>
      lookup.scope === scope ? entry : undefined;
    const raw = {
      findEntry: forScope,
      listVersions: (s: string) => (s === scope ? [entry] : []),
      readEnvelope: async () =>
        JSON.parse(new TextDecoder().decode(state.bytes)) as DataFileEnvelope,
      readEnvelopeStream: async () => new Blob([state.bytes]).stream(),
      readScopeBlocks: async () => {
        throw new Error("a projected scope is not read from a sidecar");
      },
      readBlockManifest: async () => null,
    } as unknown as DataStoragePort;
    return { raw, entry, state, scope };
  }

  it("serves blocks of the version the row records", async () => {
    const { raw, entry } = projectedStore();
    const port = granteeReadPort(withLegacyProjection(raw));

    const read = await port.readScopeBlocks!(scope, AT, {
      maxBytes: 100_000,
      generation: entry.generation!,
    });

    expect(JSON.stringify(read)).toContain("AUTHORIZED_A");
  });

  it("refuses blocks once the bytes are another version's", async () => {
    const { raw, entry, state } = projectedStore();
    state.bytes = encode({ ...conversation("REPLACED_B"), scope });
    const port = granteeReadPort(withLegacyProjection(raw));

    await expect(
      port.readScopeBlocks!(scope, AT, {
        maxBytes: 100_000,
        generation: entry.generation!,
      }),
    ).rejects.toMatchObject({ code: "generation_mismatch" });
  });
});

describe("granteeReadPort surface", () => {
  it("exposes reads only, never the raw port's writes or listings", () => {
    const { raw } = rawStore(legacy);
    const port = granteeReadPort(raw) as unknown as Record<string, unknown>;

    expect(Object.keys(port).sort()).toEqual([
      "findEntry",
      "pinVersion",
      "readEnvelope",
      "readEnvelopeStream",
      "readStoredEnvelope",
    ]);
    expect("writeEnvelope" in port).toBe(false);
    expect("listVersions" in port).toBe(false);
  });

  it("is minted once per storage port", () => {
    const { raw } = rawStore(legacy);
    expect(granteeReadPort(raw)).toBe(granteeReadPort(raw));
  });
});

/**
 * Compile-time contract, checked by the test below with the TypeScript
 * compiler. Never called.
 */
export function granteeReadPortTypeContract(
  raw: DataStoragePort,
  port: GranteeReadPort,
  computeDeps: QuestionComputeDeps,
): void {
  const accept = (granted: GranteeReadPort) => granted;
  accept(port);
  accept(granteeReadPort(raw));
  // @ts-expect-error A raw storage port is not a grantee read port.
  accept(raw);
  // @ts-expect-error Neither is a look-alike object: only the owner mints one.
  accept({ findEntry: raw.findEntry, readEnvelope: raw.readEnvelope });
  // @ts-expect-error The port has no writes.
  void port.writeEnvelope;
  const rowNotVersion = { id: 1, scope: "a.b", collectedAt: "t" };
  // @ts-expect-error A version is minted by the port, never built from a row.
  void port.readEnvelopeStream?.(rowNotVersion, { maxBytes: 1 });

  // The real consumer signature: /v1/data and TEE jobs read through it.
  const owner = { reader: "owner" as const, storage: raw };
  void readDataContract({ source: owner, scopeParam: "a.b" });
  const granted = readerSource("grantee", raw);
  void readDataContract({ source: granted, scopeParam: "a.b" });
  const rawAsGrantee = { reader: "grantee" as const, storage: raw };
  // @ts-expect-error A non-owner read never takes a raw storage port.
  void readDataContract({ source: rawAsGrantee, scopeParam: "a.b" });

  // The real derivative source reader and MCP legacy redaction fallback
  // take reader-specific ports, including after the pager extraction.
  void loadSource(computeDeps, "a.b", granted);
  // @ts-expect-error A non-owner's derivative source never reads a raw port.
  void loadSource(computeDeps, "a.b", rawAsGrantee);
  void resolveBlockRedactionContext(port, "a.b", "t", []);
  // @ts-expect-error MCP block redaction reads the grantee's view only.
  void resolveBlockRedactionContext(raw, "a.b", "t", []);
}

describe("granteeReadPort type", () => {
  const file = fileURLToPath(import.meta.url);
  const source = readFileSync(file, "utf8");

  // The second compile reuses the first one's unchanged files.
  let previous: ts.Program | undefined;

  function diagnostics(text: string): readonly ts.Diagnostic[] {
    const options: ts.CompilerOptions = {
      strict: true,
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.Node16,
      moduleResolution: ts.ModuleResolutionKind.Node16,
      esModuleInterop: true,
      skipLibCheck: true,
      resolveJsonModule: true,
      noEmit: true,
      types: ["node"],
    };
    const host = ts.createCompilerHost(options);
    const getSourceFile = host.getSourceFile.bind(host);
    host.getSourceFile = (name, language, ...rest) =>
      name === file
        ? ts.createSourceFile(name, text, language)
        : getSourceFile(name, language, ...rest);
    host.readFile = ((readFile) => (name: string) =>
      name === file ? text : readFile(name))(host.readFile.bind(host));
    const program = ts.createProgram([file], options, host, previous);
    previous = program;
    return ts
      .getPreEmitDiagnostics(program)
      .filter((d) => d.file?.fileName === file);
  }

  it("rejects a raw storage port where a grantee read port is required", () => {
    // Every @ts-expect-error above is used: an unused one is itself an error.
    expect(
      diagnostics(source).map((d) =>
        ts.flattenDiagnosticMessageText(d.messageText, "\n"),
      ),
    ).toEqual([]);

    // Without the directives, the same lines fail to compile, for the
    // reasons the directives name.
    const unguarded = diagnostics(
      source.replace(/\/\/ @ts-expect-error[^\n]*\n/g, "\n"),
    );
    expect(unguarded.map((d) => d.code).sort()).toEqual([
      2322, 2345, 2345, 2345, 2345, 2345, 2551,
    ]);
  }, 120_000);
});

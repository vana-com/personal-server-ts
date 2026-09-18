/**
 * Importer tests.
 *
 * These drive the importer through its real public surface against the real
 * in-memory record store — no re-implementation of the validation logic in
 * the test, because a test that recomputes what it is checking only proves
 * the two copies agree. The declaration document here is a real spec-core §5
 * document and its digest is computed with `node:crypto` at setup time, so
 * the digest gate is exercised against a genuinely-derived value rather than
 * a hardcoded string the importer is told to expect.
 */

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createMemoryRecordStore,
  type PdppRecordStore,
} from "../storage/pdpp-records/index.js";
import {
  createPdppImporter,
  normalizeDigest,
  type ImportableEnvelope,
  type PdppImporter,
  type RetainedDeclaration,
} from "./pdpp-import.js";
import type { Logger } from "../logger/index.js";

const SOURCE_ID = "https://registry.pdpp.dev/connectors/instagram";

/** A real declaration document, as a deployment would retain it on disk. */
const DECLARATION_DOCUMENT = JSON.stringify(
  {
    source_id: SOURCE_ID,
    source_kind: "connector",
    version: "0.1.0-local",
    streams: [
      {
        name: "profile",
        fields: ["id", "username", "full_name"],
        required_fields: ["id", "username"],
        primary_key: ["id"],
      },
    ],
  },
  null,
  2,
);

const DOCUMENT_DIGEST = createHash("sha256")
  .update(DECLARATION_DOCUMENT, "utf8")
  .digest("hex");

const RETAINED: RetainedDeclaration = {
  sourceId: SOURCE_ID,
  version: "0.1.0-local",
  documentDigest: DOCUMENT_DIGEST,
  streams: [
    { name: "profile", primaryKey: ["id"], semantics: "mutable_state" },
  ],
};

const INSTANCE = "instagram:0xowner";

function silentLogger(): Logger {
  const noop = () => undefined;
  return {
    info: noop,
    warn: noop,
    error: noop,
    debug: noop,
    trace: noop,
    fatal: noop,
  } as unknown as Logger;
}

function setup(overrides: Partial<RetainedDeclaration> = {}): {
  importer: PdppImporter;
  store: PdppRecordStore;
} {
  const store = createMemoryRecordStore();
  const importer = createPdppImporter({
    store,
    declarations: [{ ...RETAINED, ...overrides }],
    instanceFor: (sourceId) => (sourceId === SOURCE_ID ? INSTANCE : undefined),
    logger: silentLogger(),
  });
  return { importer, store };
}

/** An envelope shaped exactly as the producer writes it, `$pdpp` inside `data`. */
function envelope(
  options: {
    id?: string;
    username?: string;
    fullName?: string;
    collectedAt?: string;
    scope?: string;
    digest?: string;
    streamName?: string;
    primaryKey?: string[];
    semantics?: string;
    metaVersion?: number;
    declarationVersion?: string;
    recordKey?: Record<string, unknown>;
    op?: string;
    sourceId?: string;
    pdpp?: unknown;
  } = {},
): ImportableEnvelope {
  const data: Record<string, unknown> = {
    id: options.id ?? "235680975",
    username: options.username ?? "callumflack",
    full_name: options.fullName ?? "Callum Flack",
  };
  if (options.pdpp !== undefined) {
    if (options.pdpp !== null) data.$pdpp = options.pdpp;
  } else {
    data.$pdpp = {
      version: options.metaVersion ?? 1,
      sourceId: options.sourceId ?? SOURCE_ID,
      declaration: {
        source: "instagram",
        version: options.declarationVersion ?? "0.1.0-local",
        upstreamCommit: null,
        digest: options.digest ?? `sha256:${DOCUMENT_DIGEST}`,
      },
      stream: {
        name: options.streamName ?? "profile",
        scope: options.scope ?? "instagram.profile",
        semantics: options.semantics ?? "mutable_state",
        primaryKey: options.primaryKey ?? ["id"],
      },
      record: {
        key: options.recordKey ?? { id: options.id ?? "235680975" },
        op: options.op ?? "upsert",
      },
      run: { id: "dp_run_1", source: "instagram" },
    };
  }
  return {
    scope: options.scope ?? "instagram.profile",
    collectedAt: options.collectedAt ?? "2026-09-17T10:00:00.000Z",
    data,
  };
}

describe("normalizeDigest", () => {
  it("accepts a bare hex digest and a sha256-prefixed one identically", () => {
    const hex = "a".repeat(64);
    expect(normalizeDigest(hex)).toBe(hex);
    expect(normalizeDigest(`sha256:${hex}`)).toBe(hex);
    // The producer writes lowercase, but a digest is not case-bearing.
    expect(normalizeDigest(`SHA256:${"A".repeat(64)}`)).toBe(hex);
  });

  it("refuses a non-sha256 algorithm rather than stripping the prefix", () => {
    // The failure mode lenient parsing invites: treating some other
    // algorithm's output as if it were the SHA-256 we computed.
    expect(normalizeDigest(`sha512:${"a".repeat(64)}`)).toBeNull();
    expect(normalizeDigest(`md5:${"a".repeat(32)}`)).toBeNull();
  });

  it("refuses malformed hex", () => {
    expect(normalizeDigest("not-a-digest")).toBeNull();
    expect(normalizeDigest(`sha256:${"a".repeat(63)}`)).toBeNull();
    expect(normalizeDigest(`sha256:${"z".repeat(64)}`)).toBeNull();
  });
});

describe("createPdppImporter", () => {
  it("imports a verified envelope and strips $pdpp from the stored record", () => {
    const { importer, store } = setup();

    const outcome = importer.importEnvelope(envelope());

    expect(outcome).toMatchObject({
      status: "imported",
      instance: INSTANCE,
      stream: "profile",
      recordKey: "235680975",
    });

    const stored = store.getRecord(INSTANCE, "profile", "235680975");
    expect(stored).toBeDefined();
    // The metadata must not survive into the served payload: it is not part
    // of the declared schema, so a field projection would not cover it.
    expect(stored?.data).toEqual({
      id: "235680975",
      username: "callumflack",
      full_name: "Callum Flack",
    });
    expect(stored?.data).not.toHaveProperty("$pdpp");
    expect(stored?.emittedAt).toBe("2026-09-17T10:00:00.000Z");
    expect(stored?.version).toBe(1);
  });

  it("accepts a bare-hex digest as readily as the prefixed form", () => {
    const { importer } = setup();
    const outcome = importer.importEnvelope(
      envelope({ digest: DOCUMENT_DIGEST }),
    );
    expect(outcome.status).toBe("imported");
  });

  it("leaves a non-PDPP envelope alone", () => {
    const { importer, store } = setup();
    const outcome = importer.importEnvelope({
      scope: "instagram.profile",
      collectedAt: "2026-09-17T10:00:00.000Z",
      data: { id: "235680975", username: "callumflack" },
    });
    expect(outcome).toEqual({ status: "skipped" });
    expect(store.listStreams([INSTANCE])).toEqual([]);
  });

  describe("idempotency and change semantics", () => {
    it("reports an unchanged re-import without allocating a new version", () => {
      const { importer, store } = setup();
      expect(importer.importEnvelope(envelope()).status).toBe("imported");

      // The sync worker re-downloads the same data point on any full
      // reconcile. A second ingest here would bump the version and publish a
      // changes_since entry for a record that did not change.
      const second = importer.importEnvelope(envelope());

      expect(second.status).toBe("unchanged");
      expect(store.getRecord(INSTANCE, "profile", "235680975")?.version).toBe(
        1,
      );
    });

    it("treats a key-order-only difference as unchanged", () => {
      const { importer, store } = setup();
      importer.importEnvelope(envelope());

      const reordered = envelope();
      const data = reordered.data as Record<string, unknown>;
      const meta = data.$pdpp;
      // Re-serialize the payload with its keys in a different order.
      reordered.data = {
        $pdpp: meta,
        full_name: data.full_name,
        username: data.username,
        id: data.id,
      };

      expect(importer.importEnvelope(reordered).status).toBe("unchanged");
      expect(store.getRecord(INSTANCE, "profile", "235680975")?.version).toBe(
        1,
      );
    });

    it("imports a new version when the payload actually changes", () => {
      const { importer, store } = setup();
      importer.importEnvelope(envelope());

      const outcome = importer.importEnvelope(
        envelope({
          username: "callum",
          collectedAt: "2026-09-18T10:00:00.000Z",
        }),
      );

      expect(outcome.status).toBe("imported");
      const stored = store.getRecord(INSTANCE, "profile", "235680975");
      expect(stored?.version).toBe(2);
      expect(stored?.data.username).toBe("callum");
    });

    it("surfaces only real changes through changes_since", () => {
      const { importer, store } = setup();
      const start = store.changesSince("profile", {
        instanceIds: [INSTANCE],
        limit: 50,
      });
      const anchor = start.nextChangesSince;
      expect(anchor).toBeDefined();

      importer.importEnvelope(envelope());
      // Three re-syncs of an unchanged record.
      importer.importEnvelope(envelope());
      importer.importEnvelope(envelope());
      importer.importEnvelope(envelope());

      const page = store.changesSince("profile", {
        instanceIds: [INSTANCE],
        changesSince: anchor,
        limit: 50,
      });

      // One real change, not four. This is the honest-changes_since property.
      expect(page.data).toHaveLength(1);
      expect(page.data[0].recordKey).toBe("235680975");
    });

    it("ignores a delete for a record it never held", () => {
      const { importer, store } = setup();
      const outcome = importer.importEnvelope(envelope({ op: "delete" }));
      // Writing a tombstone here would announce the removal of something
      // this store never served.
      expect(outcome.status).toBe("unchanged");
      expect(store.getRecord(INSTANCE, "profile", "235680975")).toBeUndefined();
    });

    it("applies a delete for a record it holds", () => {
      const { importer, store } = setup();
      importer.importEnvelope(envelope());

      const outcome = importer.importEnvelope(envelope({ op: "delete" }));

      expect(outcome.status).toBe("imported");
      expect(store.getRecord(INSTANCE, "profile", "235680975")).toBeUndefined();
    });
  });

  describe("fail-closed verification", () => {
    it("rejects a digest that does not match the retained document", () => {
      const { importer, store } = setup();
      const outcome = importer.importEnvelope(
        envelope({ digest: `sha256:${"b".repeat(64)}` }),
      );
      expect(outcome).toMatchObject({
        status: "rejected",
        rejection: { code: "digest_mismatch" },
      });
      expect(store.getRecord(INSTANCE, "profile", "235680975")).toBeUndefined();
    });

    it("rejects a non-sha256 digest algorithm", () => {
      const { importer } = setup();
      const outcome = importer.importEnvelope(
        envelope({ digest: `sha512:${DOCUMENT_DIGEST}` }),
      );
      expect(outcome).toMatchObject({
        status: "rejected",
        rejection: { code: "digest_mismatch" },
      });
    });

    it("rejects a digest taken over a re-serialization of the document", () => {
      // Guards the exact interop break found against the producer: digesting
      // a canonicalized (key-sorted, minified) form instead of the retained
      // bytes. It is the same document semantically, and it must still fail
      // — the check exists to prove the producer read THESE BYTES.
      const canonicalized = JSON.stringify(JSON.parse(DECLARATION_DOCUMENT));
      const canonicalDigest = createHash("sha256")
        .update(canonicalized, "utf8")
        .digest("hex");
      expect(canonicalDigest).not.toBe(DOCUMENT_DIGEST);

      const { importer } = setup();
      const outcome = importer.importEnvelope(
        envelope({ digest: `sha256:${canonicalDigest}` }),
      );
      expect(outcome).toMatchObject({
        status: "rejected",
        rejection: { code: "digest_mismatch" },
      });
    });

    it("rejects an unsupported $pdpp version", () => {
      const { importer } = setup();
      const outcome = importer.importEnvelope(envelope({ metaVersion: 2 }));
      expect(outcome).toMatchObject({
        status: "rejected",
        rejection: { code: "unsupported_metadata_version" },
      });
    });

    it("rejects a source with no retained declaration", () => {
      const { importer } = setup();
      const outcome = importer.importEnvelope(
        envelope({ sourceId: "https://registry.pdpp.dev/connectors/spotify" }),
      );
      expect(outcome).toMatchObject({
        status: "rejected",
        rejection: { code: "unknown_source" },
      });
    });

    it("rejects a declaration version that disagrees with the retained one", () => {
      const { importer } = setup();
      const outcome = importer.importEnvelope(
        envelope({ declarationVersion: "9.9.9" }),
      );
      expect(outcome).toMatchObject({
        status: "rejected",
        rejection: { code: "declaration_version_mismatch" },
      });
    });

    it("rejects metadata whose scope disagrees with the envelope's", () => {
      // Metadata for one scope riding on a blob decrypted under another
      // scope's key.
      const { importer } = setup();
      const e = envelope();
      (e.data as Record<string, unknown>).$pdpp = {
        ...((e.data as Record<string, unknown>).$pdpp as object),
        stream: {
          name: "profile",
          scope: "youtube.profile",
          semantics: "mutable_state",
          primaryKey: ["id"],
        },
      };
      const outcome = importer.importEnvelope(e);
      expect(outcome).toMatchObject({
        status: "rejected",
        rejection: { code: "scope_mismatch" },
      });
    });

    it("rejects a stream the retained declaration does not declare", () => {
      const { importer } = setup();
      const outcome = importer.importEnvelope(
        envelope({ streamName: "followers" }),
      );
      expect(outcome).toMatchObject({
        status: "rejected",
        rejection: { code: "unknown_stream" },
      });
    });

    it("rejects a primary key that disagrees with the declaration", () => {
      const { importer } = setup();
      const outcome = importer.importEnvelope(
        envelope({ primaryKey: ["username"] }),
      );
      expect(outcome).toMatchObject({
        status: "rejected",
        rejection: { code: "primary_key_mismatch" },
      });
    });

    it("rejects semantics that disagree with what this deployment derived", () => {
      const { importer } = setup();
      const outcome = importer.importEnvelope(
        envelope({ semantics: "append_only" }),
      );
      expect(outcome).toMatchObject({
        status: "rejected",
        rejection: { code: "semantics_mismatch" },
      });
    });

    it("rejects a record key that does not describe the payload", () => {
      const { importer, store } = setup();
      // The producer claims one identity; the payload carries another. Stored
      // under the claimed key, a grant naming it would authorize a row that
      // is not the row it names.
      const outcome = importer.importEnvelope(
        envelope({ recordKey: { id: "999999999" } }),
      );
      expect(outcome).toMatchObject({
        status: "rejected",
        rejection: { code: "record_key_mismatch" },
      });
      expect(store.getRecord(INSTANCE, "profile", "999999999")).toBeUndefined();
      expect(store.getRecord(INSTANCE, "profile", "235680975")).toBeUndefined();
    });

    it("rejects when no instance handle can be derived", () => {
      const store = createMemoryRecordStore();
      const importer = createPdppImporter({
        store,
        declarations: [RETAINED],
        instanceFor: () => undefined,
        logger: silentLogger(),
      });
      const outcome = importer.importEnvelope(envelope());
      expect(outcome).toMatchObject({
        status: "rejected",
        rejection: { code: "no_instance" },
      });
    });
  });

  describe("malformed metadata", () => {
    it.each([
      ["$pdpp is not an object", "nonsense"],
      ["$pdpp is empty", {}],
      ["version is not a number", { version: "1", sourceId: SOURCE_ID }],
      [
        "declaration is missing",
        { version: 1, sourceId: SOURCE_ID, stream: {}, record: {} },
      ],
      [
        "stream is missing",
        {
          version: 1,
          sourceId: SOURCE_ID,
          declaration: { version: "0.1.0-local", digest: DOCUMENT_DIGEST },
        },
      ],
      [
        "primaryKey is empty",
        {
          version: 1,
          sourceId: SOURCE_ID,
          declaration: { version: "0.1.0-local", digest: DOCUMENT_DIGEST },
          stream: {
            name: "profile",
            scope: "instagram.profile",
            primaryKey: [],
          },
          record: { key: { id: "1" } },
        },
      ],
      [
        "op is not a known directive",
        {
          version: 1,
          sourceId: SOURCE_ID,
          declaration: { version: "0.1.0-local", digest: DOCUMENT_DIGEST },
          stream: {
            name: "profile",
            scope: "instagram.profile",
            primaryKey: ["id"],
          },
          record: { key: { id: "1" }, op: "destroy" },
        },
      ],
    ])("rejects when %s", (_label, pdpp) => {
      const { importer, store } = setup();
      const outcome = importer.importEnvelope(envelope({ pdpp }));
      expect(outcome).toMatchObject({
        status: "rejected",
        rejection: { code: "malformed_metadata" },
      });
      expect(store.listStreams([INSTANCE])).toEqual([]);
    });

    it("never throws on hostile metadata shapes", () => {
      const { importer } = setup();
      for (const pdpp of [
        [],
        null,
        42,
        { version: 1, sourceId: SOURCE_ID, declaration: [], stream: [] },
        { version: 1, sourceId: SOURCE_ID, declaration: { digest: 1 } },
      ]) {
        // `null` means "no $pdpp key at all" in the helper, which is skipped;
        // everything else must be a rejection, and nothing may throw.
        expect(() => importer.importEnvelope(envelope({ pdpp }))).not.toThrow();
      }
    });
  });
});

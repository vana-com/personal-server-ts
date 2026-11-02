/**
 * Two conformance gaps this lane shipped, now closed.
 *
 * Both were found by the sync-import lane reading the code rather than
 * trusting it, and both were mine.
 *
 * 1. THE RETAINED DIGEST WAS UNVERIFIABLE FROM THE STORE. `retainDeclaration`
 *    persisted `JSON.stringify(snapshot)` — the PARSED snapshot — so
 *    re-digesting what the store holds produced a different value than the
 *    retained `digest` column. The exact bytes existed only in boot config.
 *    §9 AS item 16 requires the retained declaration to survive into consent
 *    evidence; a digest nobody can re-check is retention in name only.
 *
 * 2. STREAM SEMANTICS WERE UNFALSIFIABLE. `DeclaredStream` carried no
 *    semantics, so the RS hardcoded `mutable_state` for every stream. An
 *    `append_only` declaration was silently coerced into upsert behavior, and
 *    a producer claiming `append_only` had nothing to disagree with.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  computeDeclarationDigest,
  openPdppAuthStore,
  parseDeclaration,
  type PdppAuthStore,
} from "./index.js";

const SOURCE_ID = "https://registry.pdpp.dev/connectors/spotify";

function declarationDocument(
  streams: Record<string, unknown>[] = [
    {
      name: "top_artists",
      fields: ["id", "name"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
): string {
  // Deliberately NOT canonical JSON: trailing whitespace and key ordering are
  // exactly what a re-serialized snapshot would lose.
  return JSON.stringify(
    {
      source_id: SOURCE_ID,
      source_kind: "connector",
      version: "2026-08-11",
      streams,
    },
    null,
    2,
  );
}

let dir: string;
let store: PdppAuthStore;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "pdpp-decl-"));
  store = openPdppAuthStore(join(dir, "auth.db"));
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("the retained declaration digest is verifiable from the store", () => {
  it("persists the exact bytes, so the digest re-computes", () => {
    const document = declarationDocument();
    const parsed = parseDeclaration(document, SOURCE_ID);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;

    store.retainDeclaration(parsed.snapshot, document);

    const retrieved = store.getDeclarationDocument(SOURCE_ID, "2026-08-11");
    expect(retrieved).toBe(document);
    // The point: re-digesting what the store holds reproduces the retained
    // digest. Before this column existed it could not.
    expect(computeDeclarationDigest(retrieved!)).toBe(parsed.snapshot.digest);
  });

  it("shows why the snapshot alone was not enough", () => {
    const document = declarationDocument();
    const parsed = parseDeclaration(document, SOURCE_ID);
    if (!parsed.ok) return;

    // Re-serializing the parsed snapshot is what the store used to hold.
    const reserialized = JSON.stringify(parsed.snapshot);
    expect(computeDeclarationDigest(reserialized)).not.toBe(
      parsed.snapshot.digest,
    );
  });

  it("returns null rather than guessing when no document was retained", () => {
    const parsed = parseDeclaration(declarationDocument(), SOURCE_ID);
    if (!parsed.ok) return;

    // A row retained before this column existed.
    store.retainDeclaration(parsed.snapshot);

    // Null means "cannot verify from the store", never "verified".
    expect(store.getDeclarationDocument(SOURCE_ID, "2026-08-11")).toBeNull();
  });

  it("BACKFILLS a document onto a row retained without one", () => {
    // The upgrade case the sync-import lane caught: `ON CONFLICT DO NOTHING`
    // would leave `document` NULL forever, because the pre-existing row keeps
    // winning on every restart. An importer that fails closed on a missing
    // document would then silently stop importing until the declaration
    // version happened to change.
    const document = declarationDocument();
    const parsed = parseDeclaration(document, SOURCE_ID);
    if (!parsed.ok) return;

    store.retainDeclaration(parsed.snapshot);
    expect(store.getDeclarationDocument(SOURCE_ID, "2026-08-11")).toBeNull();

    store.retainDeclaration(parsed.snapshot, document);
    expect(store.getDeclarationDocument(SOURCE_ID, "2026-08-11")).toBe(
      document,
    );
  });

  it("never overwrites bytes an issued grant already points at", () => {
    const original = declarationDocument();
    const parsed = parseDeclaration(original, SOURCE_ID);
    if (!parsed.ok) return;
    store.retainDeclaration(parsed.snapshot, original);

    // A re-retrieval of the SAME version with different bytes must not
    // disturb what a grant was resolved against.
    const tampered = `${original} `;
    store.retainDeclaration(parsed.snapshot, tampered);

    expect(store.getDeclarationDocument(SOURCE_ID, "2026-08-11")).toBe(
      original,
    );
  });
});

describe("stream semantics come from the declaration", () => {
  it("carries append_only through parsing", () => {
    const parsed = parseDeclaration(
      declarationDocument([
        {
          name: "events",
          fields: ["id"],
          required_fields: ["id"],
          primary_key: ["id"],
          semantics: "append_only",
        },
      ]),
      SOURCE_ID,
    );
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.snapshot.streams[0].semantics).toBe("append_only");
  });

  it("leaves semantics absent when a declaration omits it", () => {
    const parsed = parseDeclaration(declarationDocument(), SOURCE_ID);
    if (!parsed.ok) return;
    // Absent, not defaulted here — the consumer applies `mutable_state`, so
    // declarations written before this field keep their exact meaning.
    expect(parsed.snapshot.streams[0].semantics).toBeUndefined();
  });

  it("REJECTS an unrecognized semantics rather than coercing it", () => {
    // Coercing an unknown value to `mutable_state` would upsert records a
    // declaration may have meant to be immutable.
    const parsed = parseDeclaration(
      declarationDocument([
        {
          name: "events",
          fields: ["id"],
          required_fields: ["id"],
          primary_key: ["id"],
          semantics: "ledger_only",
        },
      ]),
      SOURCE_ID,
    );
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.failure.code).toBe("invalid_document");
    expect(parsed.failure.message).toContain("ledger_only");
  });
});

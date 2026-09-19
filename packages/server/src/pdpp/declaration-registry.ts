/**
 * A declaration registry that can change while the server is running.
 *
 * `buildDeclarationRegistry` (deployment.ts) parses `config.pdpp
 * .declarationPaths` once at construction and pins the survivors. That is the
 * right shape for a deployment whose declarations are config, and it stays
 * exactly as it was. What it cannot do is accept a candidate: offering one
 * means editing config and restarting, so a caller cannot ask "would you
 * accept this?" and get an answer in the same server lifetime.
 *
 * This is that acceptance surface's storage. Two properties it must have that
 * the boot-time registry does not:
 *
 *   - **Mutable in place.** The AS's `resolveDeclaration` lookup must see an
 *     accepted declaration immediately, or an acceptance is indistinguishable
 *     from a refusal until the next restart.
 *   - **Durable.** An operator who submitted a declaration must not silently
 *     lose it on restart, which would make acceptance look transactional and
 *     behave like a cache.
 *
 * ## Why this is a separate table from `pdpp_declarations`
 *
 * The auth store's `pdpp_declarations` retains a snapshot per
 * `(source_id, version)` and is deliberately immutable — it is the evidence an
 * ISSUED GRANT points at, and rewriting it would change what an owner
 * consented to after the fact. This table answers a different question:
 * *which* version is currently authoritative for a source. Those must not
 * share a row, because accepting a new version has to move the current
 * pointer while leaving every retained revision a live grant depends on
 * exactly where it was.
 */

import Database from "better-sqlite3";
import { isDeepStrictEqual } from "node:util";
import { parseDeclaration } from "@opendatalabs/personal-server-ts-core/pdpp";
import type {
  DeclarationFailure,
  DeclarationSnapshot,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import type { Logger } from "pino";

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS pdpp_current_declarations (
  source_id TEXT NOT NULL,
  version TEXT NOT NULL,
  digest TEXT NOT NULL,
  snapshot_json TEXT NOT NULL,
  -- The exact submitted bytes. snapshot_json is the parsed projection, so
  -- re-digesting it does NOT reproduce digest; a producer's claimed digest
  -- can only honestly be checked against what was actually submitted.
  document TEXT NOT NULL,
  accepted_at TEXT NOT NULL,
  is_current INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (source_id, version)
);

CREATE INDEX IF NOT EXISTS pdpp_current_declarations_current_idx
  ON pdpp_current_declarations (source_id, is_current);
`;

export interface MutableDeclarationRegistry {
  /** The live lookup the AS consumes. Null when nothing is retained. */
  resolve(sourceId: string): DeclarationSnapshot | null;
  /** The exact retained bytes for a source, for digest verification. */
  documentFor(sourceId: string): string | null;
  /** Every currently-authoritative declaration. */
  list(): DeclarationSnapshot[];
  /**
   * Validate a candidate and, on success, make it authoritative for its
   * source. A refusal changes nothing — in particular it must not displace an
   * already-retained declaration, or one malformed submission would disarm a
   * working grant surface.
   */
  submit(document: string): DeclarationSubmissionResult;
  close(): void;
}

export type DeclarationSubmissionResult =
  | { ok: true; snapshot: DeclarationSnapshot }
  | { ok: false; failure: DeclarationFailure };

export interface OpenDeclarationRegistryOptions {
  /** SQLite file. Use `:memory:` for a registry that does not outlive it. */
  path: string;
  /**
   * The connector inventory this PS serves. A declaration naming a source
   * this server holds no data for is refused even when an operator submits
   * it: a grant over data that cannot exist here is at best useless, and at
   * worst a consent screen showing an owner something they are not sharing.
   */
  supportedConnectors: string[];
  logger: Logger;
  /**
   * Declarations from `config.pdpp.declarationPaths`, seeded on open so a
   * deployment that has always configured its declarations keeps working
   * unchanged. Submitted declarations win over seeds for the same source:
   * an operator's explicit later decision is the more recent one.
   */
  seed?: { sourceId: string; document: string }[];
}

export function openDeclarationRegistry(
  options: OpenDeclarationRegistryOptions,
): MutableDeclarationRegistry {
  const db = new Database(options.path);
  db.pragma("journal_mode = WAL");
  migrateSchema(db);

  const supported = new Set(options.supportedConnectors);

  function accept(document: string): DeclarationSubmissionResult {
    // The submitted document names its own source, so there is no separately
    // supplied id to cross-check it against. Reading the claim first and
    // parsing against it means `source_id_mismatch` stays reachable for a
    // document whose nested `source.id` disagrees with its normalized form,
    // rather than being unreachable here by construction.
    const claimed = claimedSourceId(document);
    if (claimed === null) {
      return {
        ok: false,
        failure: {
          code: "invalid_document",
          message: "declaration is not valid JSON, or declares no source id",
        },
      };
    }

    const parsed = parseDeclaration(document, claimed);
    if (!parsed.ok) return parsed;

    const connector = connectorNameFor(parsed.snapshot.source_id);
    if (!supported.has(connector)) {
      // `untrusted_source` rather than `invalid_document`: the document may
      // be perfectly well formed. What is refused is its authority here.
      return {
        ok: false,
        failure: {
          code: "untrusted_source",
          message: `this server does not serve the '${connector}' connector, so it does not accept a declaration for it`,
        },
      };
    }

    const existing = db
      .prepare(
        `SELECT snapshot_json FROM pdpp_current_declarations
         WHERE source_id = ? AND version = ?`,
      )
      .get(parsed.snapshot.source_id, parsed.snapshot.version) as
      { snapshot_json: string } | undefined;
    if (existing) {
      const retained = JSON.parse(
        existing.snapshot_json,
      ) as DeclarationSnapshot;
      if (!sameDeclarationContent(retained, parsed.snapshot)) {
        return {
          ok: false,
          failure: {
            code: "declaration_equivocation",
            message:
              "different content was already accepted under this (source.id, declaration_version) key",
          },
        };
      }
      return { ok: true, snapshot: retained };
    }

    db.transaction(() => {
      db.prepare(
        "UPDATE pdpp_current_declarations SET is_current = 0 WHERE source_id = ?",
      ).run(parsed.snapshot.source_id);
      db.prepare(
        `INSERT INTO pdpp_current_declarations
           (source_id, version, digest, snapshot_json, document, accepted_at, is_current)
         VALUES (?, ?, ?, ?, ?, ?, 1)`,
      ).run(
        parsed.snapshot.source_id,
        parsed.snapshot.version,
        parsed.snapshot.digest,
        JSON.stringify(parsed.snapshot),
        document,
        new Date().toISOString(),
      );
    })();

    return { ok: true, snapshot: parsed.snapshot };
  }

  // Seeds go through the same `accept` as a submission — one acceptance path,
  // so a configured declaration and a submitted one cannot diverge on what
  // counts as valid. A seed for a source that already has a submission is
  // skipped: the operator's later explicit decision wins over boot config.
  for (const seed of options.seed ?? []) {
    const existing = db
      .prepare("SELECT 1 FROM pdpp_current_declarations WHERE source_id = ?")
      .get(seed.sourceId);
    if (existing) continue;
    const result = accept(seed.document);
    if (!result.ok) {
      options.logger.warn(
        { sourceId: seed.sourceId, reason: result.failure.message },
        "PDPP declaration rejected: not retained",
      );
    }
  }

  return {
    resolve(sourceId) {
      const row = db
        .prepare(
          `SELECT snapshot_json FROM pdpp_current_declarations
           WHERE source_id = ? AND is_current = 1`,
        )
        .get(sourceId) as { snapshot_json: string } | undefined;
      return row
        ? (JSON.parse(row.snapshot_json) as DeclarationSnapshot)
        : null;
    },
    documentFor(sourceId) {
      const row = db
        .prepare(
          `SELECT document FROM pdpp_current_declarations
           WHERE source_id = ? AND is_current = 1`,
        )
        .get(sourceId) as { document: string } | undefined;
      return row?.document ?? null;
    },
    list() {
      const rows = db
        .prepare(
          `SELECT snapshot_json FROM pdpp_current_declarations
           WHERE is_current = 1 ORDER BY source_id`,
        )
        .all() as { snapshot_json: string }[];
      return rows.map(
        (r) => JSON.parse(r.snapshot_json) as DeclarationSnapshot,
      );
    },
    submit: accept,
    close() {
      db.close();
    },
  };
}

function migrateSchema(db: Database.Database): void {
  const columns = db
    .prepare("PRAGMA table_info(pdpp_current_declarations)")
    .all() as { name: string }[];
  if (columns.length === 0) {
    db.exec(SCHEMA_SQL);
    return;
  }
  if (columns.some((column) => column.name === "is_current")) {
    db.exec(SCHEMA_SQL);
    return;
  }

  db.transaction(() => {
    db.exec(
      "ALTER TABLE pdpp_current_declarations RENAME TO pdpp_current_declarations_legacy",
    );
    db.exec(SCHEMA_SQL);
    db.exec(
      `INSERT INTO pdpp_current_declarations
         (source_id, version, digest, snapshot_json, document, accepted_at, is_current)
       SELECT source_id, version, digest, snapshot_json, document, accepted_at, 1
       FROM pdpp_current_declarations_legacy`,
    );
    db.exec("DROP TABLE pdpp_current_declarations_legacy");
  })();
}

function sameDeclarationContent(
  a: DeclarationSnapshot,
  b: DeclarationSnapshot,
): boolean {
  const { digest: _aDigest, ...aContent } = a;
  const { digest: _bDigest, ...bContent } = b;
  return isDeepStrictEqual(aContent, bContent);
}

/**
 * The source id a document claims, read without validating anything else.
 *
 * Accepts both the normative nested shape (`source: { id }`) and the internal
 * flat one (`source_id`), because `parseDeclaration` normalizes between them
 * and this has to agree with whichever it will read.
 */
function claimedSourceId(document: string): string | null {
  let doc: unknown;
  try {
    doc = JSON.parse(document);
  } catch {
    return null;
  }
  if (typeof doc !== "object" || doc === null) return null;
  const record = doc as { source?: { id?: unknown }; source_id?: unknown };
  const nested = record.source?.id;
  if (typeof nested === "string" && nested.length > 0) return nested;
  if (typeof record.source_id === "string" && record.source_id.length > 0) {
    return record.source_id;
  }
  return null;
}

/**
 * The connector a source id belongs to — the last path segment of the URI
 * (`https://registry.pdpp.dev/connectors/spotify` → `spotify`). Falls back to
 * the whole id for an unparseable value, so an odd source fails the supported
 * check rather than silently matching a connector it is not.
 */
function connectorNameFor(sourceId: string): string {
  try {
    const segments = new URL(sourceId).pathname
      .split("/")
      .filter((s) => s.length > 0);
    return segments[segments.length - 1] ?? sourceId;
  } catch {
    return sourceId;
  }
}

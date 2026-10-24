import { canonicalJson } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import { createHash } from "node:crypto";
import type Database from "better-sqlite3";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import type {
  DeleteDataPort,
  DataStoragePort,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { StorageAdapter } from "@opendatalabs/personal-server-ts-core/storage/adapters";
import {
  assertLegacyPublicationAllowed,
  assertLegacyHistoryMutable,
  legacyPublicationFenced,
} from "./legacy-publication-fence.js";
import { keccak256, stringToHex } from "viem";
import { envelopeGeneration } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import {
  decryptWithPassword,
  deriveScopeKey,
} from "@opendatalabs/vana-sdk/node";
import { isTombstoneHashes } from "@opendatalabs/vana-sdk/node";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import {
  HistoryOnlyVersionError,
  parseGatewayNextVersion,
} from "@opendatalabs/personal-server-ts-core/publication";

function assertRestoreNotSuperseded(
  db: Database.Database,
  scope: string,
  dataHash: unknown,
): void {
  if (
    typeof dataHash === "string" &&
    db
      .prepare(
        `SELECT 1 FROM legacy_publication_restore_versions r
    JOIN data_files f ON f.id=r.version_id WHERE f.scope=? AND r.data_hash=? AND r.state='superseded'`,
      )
      .get(scope, dataHash)
  )
    throw new HistoryOnlyVersionError(scope);
}

// An accepted journal row, current authorization and latest persisted head must
// all agree. An old operation/epoch or a different head never inherits the permit.
const restoreHeadSql = `SELECT a.operation, a.body_sha256, f.generation, f.collected_at
  FROM legacy_publication_restore_authorization a
  JOIN legacy_publication_policy p ON p.scope=a.scope AND p.owner=a.owner AND p.server_generation=a.server_generation AND p.epoch=a.epoch AND p.state='restoring'
  JOIN owner_import_operations o ON o.scope=a.scope AND o.owner=a.owner AND o.operation=a.operation AND o.authority=a.authority AND o.body_sha256=a.body_sha256 AND o.state='accepted'
  JOIN data_files f ON f.scope=a.scope AND f.path=o.path AND f.collected_at=o.collected_at
  WHERE a.scope=? AND a.owner=? AND f.generation IS NOT NULL
    AND f.id=(SELECT id FROM data_files WHERE scope=a.scope ORDER BY julianday(collected_at) DESC, id DESC LIMIT 1)
    AND NOT EXISTS (SELECT 1 FROM legacy_publication_policy other WHERE other.scope=a.scope AND other.state!='mirroring' AND (other.owner!=a.owner OR other.server_generation!=a.server_generation))`;

function authorizedRestoreMessage(
  db: Database.Database,
  owner: string,
  scopes: readonly string[],
  message: unknown,
): boolean {
  if (scopes.length !== 1 || !message || typeof message !== "object")
    return false;
  const head = db
    .prepare(restoreHeadSql)
    .get(scopes[0], owner.toLowerCase()) as
    { operation: string; generation: string } | undefined;
  if (!head) return false;
  const publication = db
    .prepare(
      "SELECT * FROM legacy_publication_restore_publications WHERE scope=? AND operation=? AND head_generation=?",
    )
    .get(scopes[0], head.operation, head.generation) as
    | {
        version: string;
        data_hash: string;
        metadata_hash: string;
        ciphertext_sha256: string;
      }
    | undefined;
  if (!publication) return false;
  const m = message as Record<string, unknown>;
  if (m.key !== undefined)
    return (
      m.key === `${scopes[0]}/${publication.version}` &&
      m.ciphertextSha256 === publication.ciphertext_sha256
    );
  return (
    m.scope === scopes[0] &&
    String(m.expectedVersion) === publication.version &&
    m.dataHash === publication.data_hash &&
    m.metadataHash === publication.metadata_hash
  );
}

export function legacyScopeMayReference(
  scopes: readonly string[],
  scope: string,
): boolean {
  return (
    scopes.length === 0 ||
    scopes.some((raw) => {
      const ref = raw.startsWith("write:") ? raw.slice(6) : raw;
      if (ref === scope || ref === "*") return true;
      if (ref.endsWith(".*")) return scope.startsWith(ref.slice(0, -1));
      return !/^[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+$/.test(ref);
    })
  );
}

/** Local signatures are credentials too, even if registration times out.
 * Keep their identities indefinitely for authoritative inventory reconciliation.
 * This journal cannot prove that a grant expired or a publication settled.
 */
export function recordLegacyIssuanceIntent(
  db: Database.Database,
  owner: string,
  scopes: readonly string[],
  kind: "grant" | "publication",
  message: unknown,
): void {
  db.transaction(() => {
    if (
      kind === "publication" &&
      scopes.length === 1 &&
      message &&
      typeof message === "object"
    )
      assertRestoreNotSuperseded(
        db,
        scopes[0],
        (message as { dataHash?: unknown }).dataHash,
      );
    const fences = db
      .prepare(
        "SELECT scope FROM legacy_publication_policy WHERE state != 'mirroring'",
      )
      .all() as { scope: string }[];
    for (const { scope } of fences) {
      if (
        legacyScopeMayReference(scopes, scope) &&
        !(
          kind === "publication" &&
          scopes[0] === scope &&
          authorizedRestoreMessage(db, owner, scopes, message)
        )
      )
        throw new ProtocolError(
          409,
          "legacy_scope_retired",
          "Legacy credential issuance and publication are fenced",
          { scope },
        );
    }
    const serialized = JSON.stringify(message, (_key, value: unknown) =>
      typeof value === "bigint" ? value.toString() : value,
    );
    const canonicalMessage = canonicalJson(JSON.parse(serialized));
    const id = createHash("sha256")
      .update(`${kind}:${canonicalMessage}`)
      .digest("hex");
    db.prepare(
      "INSERT OR IGNORE INTO legacy_publication_issuance(id, owner, scopes_json, kind, message_json) VALUES (?, ?, ?, ?, ?)",
    ).run(
      id,
      owner.toLowerCase(),
      JSON.stringify(scopes),
      kind,
      canonicalMessage,
    );
  }).immediate();
}

export function withLegacySignerFence(
  db: Database.Database,
  signer: ServerSigner,
): ServerSigner {
  return new Proxy(signer, {
    get(target, property) {
      if (property === "signGrantRegistration")
        return async (
          message: Parameters<ServerSigner["signGrantRegistration"]>[0],
        ) => {
          recordLegacyIssuanceIntent(
            db,
            message.grantorAddress,
            message.scopes,
            "grant",
            message,
          );
          return target.signGrantRegistration(message);
        };
      if (property === "signAddData")
        return async (message: Parameters<ServerSigner["signAddData"]>[0]) => {
          if (isTombstoneHashes(message.dataHash, message.metadataHash))
            assertLegacyHistoryMutable(db, message.scope);
          recordLegacyIssuanceIntent(
            db,
            message.ownerAddress,
            [message.scope],
            "publication",
            message,
          );
          return target.signAddData(message);
        };
      const value = Reflect.get(target, property);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

/** A restore pin allows one remote version per operation. A gateway 409 whose
 * next valid version is below the pinned one proves the pinned version is not
 * registered and cannot be now (registry versions are sequential). Only that
 * refusal releases the pin, so the publisher's rebase can pin the registry's
 * version. Any other failure, including a lost response, keeps the pin.
 */
function releaseRefusedRestorePin(
  db: Database.Database,
  message: Parameters<GatewayClient["registerDataPoint"]>[0],
  error: unknown,
): void {
  if (!(error instanceof Error) || !/Gateway error: 409\b/.test(error.message))
    return;
  const next = parseGatewayNextVersion(error.message);
  if (next === null || !/^[1-9][0-9]*$/.test(String(message.expectedVersion)))
    return;
  if (BigInt(next) >= BigInt(message.expectedVersion)) return;
  db.prepare(
    "DELETE FROM legacy_publication_restore_publications WHERE scope=? AND version=? AND data_hash=? AND metadata_hash=?",
  ).run(
    message.scope,
    String(message.expectedVersion),
    message.dataHash,
    message.metadataHash,
  );
}

/** Also fences submitted external signatures, not just signatures we minted.
 * The remote side still needs the global fence: an already dispatched request
 * can only be drained/certified by its authoritative registration service.
 */
export function withLegacyGatewayFence(
  db: Database.Database,
  gateway: GatewayClient,
): GatewayClient {
  return new Proxy(gateway, {
    get(target, property) {
      if (property === "createGrant")
        return async (message: Parameters<GatewayClient["createGrant"]>[0]) => {
          recordLegacyIssuanceIntent(
            db,
            message.grantorAddress,
            message.scopes,
            "grant",
            message,
          );
          return target.createGrant(message);
        };
      if (property === "registerDataPoint")
        return async (
          message: Parameters<GatewayClient["registerDataPoint"]>[0],
        ) => {
          if (isTombstoneHashes(message.dataHash, message.metadataHash))
            assertLegacyHistoryMutable(db, message.scope);
          recordLegacyIssuanceIntent(
            db,
            message.ownerAddress,
            [message.scope],
            "publication",
            message,
          );
          try {
            return await target.registerDataPoint(message);
          } catch (error) {
            releaseRefusedRestorePin(db, message, error);
            throw error;
          }
        };
      const value = Reflect.get(target, property);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

export function withLegacyStorageFence(
  db: Database.Database,
  owner: string,
  storage: StorageAdapter,
  masterKey?: Uint8Array,
  local?: DataStoragePort,
): StorageAdapter {
  return new Proxy(storage, {
    get(target, property) {
      if (property === "upload")
        return async (key: string, bytes: Uint8Array) => {
          const scope = key.split("/", 1)[0];
          const ciphertextSha256 = createHash("sha256")
            .update(bytes)
            .digest("hex");
          const dataHash = await authorizeRestoredBytes(
            db,
            owner,
            key,
            bytes,
            masterKey,
            local,
          );
          recordLegacyIssuanceIntent(db, owner, [scope], "publication", {
            key,
            ciphertextSha256,
            ...(dataHash ? { dataHash } : {}),
          });
          return target.upload(key, bytes);
        };
      if (property === "download")
        return async (url: string) => {
          const bytes = await target.download(url);
          // A retry may encounter ciphertext reserved before an uncertain remote
          // registration. Re-verify that occupant through the same exact permit.
          const active = db
            .prepare(
              `SELECT a.scope, r.version FROM legacy_publication_restore_authorization a
          JOIN legacy_publication_restore_publications r ON r.scope=a.scope AND r.operation=a.operation`,
            )
            .all() as { scope: string; version: string }[];
          const match = active.find(
            (row) => target.urlForKey(`${row.scope}/${row.version}`) === url,
          );
          if (match)
            await authorizeRestoredBytes(
              db,
              owner,
              `${match.scope}/${match.version}`,
              bytes,
              masterKey,
              local,
            );
          return bytes;
        };
      const value = Reflect.get(target, property);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

/** Pending deletion retries must also preserve the retained scope. */
export function withLegacyDeletionFence(
  db: Database.Database,
  port: DeleteDataPort,
): DeleteDataPort {
  const check = (scope: string) => {
    assertLegacyPublicationAllowed(db, scope);
    assertLegacyHistoryMutable(db, scope);
  };
  return {
    async tombstone(scope) {
      check(scope);
      return port.tombstone(scope);
    },
    async deleteBlobVersions(scope, versions) {
      check(scope);
      return port.deleteBlobVersions(scope, versions);
    },
  };
}

function assertRestoreKey(key: string, scope: string): void {
  if (!new RegExp(`^${scope.replaceAll(".", "\\.")}/[1-9][0-9]*$`).test(key))
    throw new ProtocolError(
      409,
      "legacy_scope_retired",
      "Restoration requires an exact scope and positive version key",
    );
}

async function authorizeRestoredBytes(
  db: Database.Database,
  owner: string,
  key: string,
  bytes: Uint8Array,
  masterKey?: Uint8Array,
  local?: DataStoragePort,
): Promise<string | undefined> {
  const scope = key.split("/", 1)[0];
  const ciphertextSha256 = createHash("sha256").update(bytes).digest("hex");
  // This check remains active after reopening. It also covers a queued entry
  // captured before retirement, or encryption that completed after the barrier.
  const hasRestores = db
    .prepare(
      `SELECT 1 FROM legacy_publication_restore_versions r
    JOIN data_files f ON f.id=r.version_id WHERE f.scope=? LIMIT 1`,
    )
    .get(scope);
  let clear: Uint8Array | undefined;
  if (hasRestores) {
    if (!masterKey) rejectRestoredPublication();
    clear = await decryptWithPassword(
      bytes,
      Buffer.from(deriveScopeKey(masterKey!, scope)).toString("hex"),
    );
    assertRestoreNotSuperseded(db, scope, keccak256(clear));
  }
  if (legacyPublicationFenced(db, scope)) {
    // No alternate recovery uploader: verify the real worker ciphertext
    // here, then pin exactly one remote version and its commitments.
    assertRestoreKey(key, scope);
    const snapshot = db
      .prepare(restoreHeadSql)
      .get(scope, owner.toLowerCase()) as { collected_at: string } | undefined;
    if (!masterKey || !local || !snapshot) rejectRestoredPublication();
    const stored = await local!.readEnvelope(scope, snapshot!.collected_at);
    const password = Buffer.from(deriveScopeKey(masterKey!, scope)).toString(
      "hex",
    );
    const decrypted = (clear ??= await decryptWithPassword(bytes, password));
    if (!Buffer.from(decrypted).equals(Buffer.from(JSON.stringify(stored))))
      rejectRestoredPublication();
    const envelope = JSON.parse(new TextDecoder().decode(decrypted)) as {
      scope: string;
      collectedAt: string;
      data: unknown;
    };
    db.transaction(() => {
      const head = db
        .prepare(restoreHeadSql)
        .get(scope, owner.toLowerCase()) as
        | { operation: string; body_sha256: string; generation: string }
        | undefined;
      if (
        !head ||
        envelope.scope !== scope ||
        envelopeGeneration(envelope) !== head.generation ||
        createHash("sha256")
          .update(canonicalJson(envelope.data))
          .digest("hex") !== head.body_sha256
      )
        rejectRestoredPublication();
      const version = key.slice(scope.length + 1);
      const dataHash = keccak256(decrypted);
      const metadataHash = keccak256(
        stringToHex(
          JSON.stringify({
            scope,
            collectedAt: envelope.collectedAt,
            sizeBytes: bytes.byteLength,
          }),
        ),
      );
      const prior = db
        .prepare(
          "SELECT version, data_hash FROM legacy_publication_restore_publications WHERE scope=? AND operation=?",
        )
        .get(scope, head!.operation) as
        { version: string; data_hash: string } | undefined;
      if (prior && (prior.version !== version || prior.data_hash !== dataHash))
        rejectRestoredPublication();
      // OpenPGP retries can have fresh ciphertext. Only verified identical
      // head bytes at the same pinned key can update their size/hash.
      db.prepare(
        `INSERT INTO legacy_publication_restore_publications VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scope, operation) DO UPDATE SET metadata_hash=excluded.metadata_hash, ciphertext_sha256=excluded.ciphertext_sha256`,
      ).run(
        scope,
        head!.operation,
        head!.generation,
        version,
        dataHash,
        metadataHash,
        ciphertextSha256,
      );
      recordLegacyIssuanceIntent(db, owner, [scope], "publication", {
        key,
        ciphertextSha256,
      });
    }).immediate();
  }
  return clear ? keccak256(clear) : undefined;
}

function rejectRestoredPublication(): never {
  throw new ProtocolError(
    409,
    "legacy_scope_retired",
    "Restoration does not match the current authorized operation, head, bytes or version",
  );
}

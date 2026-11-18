import {
  canonicalJson,
  controlScope,
  deriveNs,
  isPlainObject,
  toHex,
  type JsonValue,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { sha256 } from "@noble/hashes/sha2";
import {
  applicationAuthority,
  type VerifiedApplicationAuthority,
  type ApplicationAuthority,
} from "../write/application.js";
import {
  observeWriteGrant,
  type GrantObservationPort,
} from "../policy/data-write.js";
import { ProtocolError } from "../errors/catalog.js";
import { compileRecordSchema } from "../storage/pdpp-records/schema.js";
import { announceRecordsCommitted, type LocalSyncDeps } from "./deps.js";
import { createApplicationGrantStore } from "./application-grants.js";
import { mutationIdentity } from "./mutation-identity.js";
import { mergeIncoming, withOrigin } from "./merge.js";
import { prepareBlob } from "./blobs.js";
import type { SqlStatement } from "./driver.js";

/** Full snapshot supplied by the host's declaration/onboarding authority.
 * The host has accepted sourceId as a protected resource and bound writer to it.
 * Publishing/trust policy stays outside localdb; a request's document is not authority.
 */
export interface AcceptedApplicationDeclaration {
  readonly document: string;
  readonly writer: string;
  readonly bindingRevision: string;
}
export type ResolveApplicationDeclaration = (input: {
  readonly digest: string;
  readonly sourceId: string;
  readonly writer: string;
}) => Promise<AcceptedApplicationDeclaration | null>;
export interface ApplicationEnvelope {
  readonly mutationId: string;
  readonly declaration: { readonly digest: string };
  readonly record: {
    readonly stream: string;
    readonly key: string | readonly string[];
    readonly data: Record<string, JsonValue>;
    readonly emitted_at: string;
    readonly op?: "upsert" | "delete";
  };
  readonly blobs?: readonly {
    readonly sha256: string;
    readonly mimeType: string;
    readonly bytes: readonly number[];
  }[];
}
export interface ApplicationReceipt {
  readonly mutationId: string;
  readonly recordRef: {
    readonly source: string;
    readonly instance: string;
    readonly stream: string;
    readonly key: string;
  };
  readonly publication: "pending";
}
export interface AuthorizedApplicationMutation {
  readonly kind: "authorized-application-mutation";
}
export interface ApplicationIntake {
  readonly grants: GrantObservationPort;
  prepare(
    authority: VerifiedApplicationAuthority,
    input: ApplicationEnvelope,
  ): Promise<AuthorizedApplicationMutation>;
  replay(
    authority: VerifiedApplicationAuthority,
    input: ApplicationEnvelope,
  ): Promise<ApplicationReceipt | null>;
  commit(mutation: AuthorizedApplicationMutation): Promise<ApplicationReceipt>;
}
function fail(code: string, status = 409): never {
  throw new ProtocolError(status, code, code);
}
export const applicationSource = (builder: string): string =>
  `urn:vana:builder:${builder.toLowerCase()}`;
const digestOf = (text: string) =>
  toHex(sha256(new TextEncoder().encode(text)));
const semanticHash = (input: ApplicationEnvelope): string =>
  digestOf(canonicalJson(input as unknown as JsonValue));

export function createApplicationIntake(
  deps: LocalSyncDeps,
  resolve?: ResolveApplicationDeclaration,
): ApplicationIntake {
  type Prepared = {
    authority: ApplicationAuthority;
    input: ApplicationEnvelope;
    hash: string;
    source: string;
    connector: string;
    ns: string;
    connection: string;
    generation: number;
    revision: string;
    deleteSnapshot: number;
    document: string;
    version: string;
    primaryKey: string[];
    semantics: string;
    row: Awaited<ReturnType<typeof mutationIdentity>>;
    blobs: readonly {
      hash: string;
      statements: ReturnType<typeof prepareBlob>;
    }[];
  };
  const capabilities = new WeakMap<AuthorizedApplicationMutation, Prepared>();
  const grants = createApplicationGrantStore(deps.db);
  async function receipt(
    authority: ApplicationAuthority,
    input: ApplicationEnvelope,
  ): Promise<ApplicationReceipt | null> {
    if (authority.owner.toLowerCase() !== deps.ownerAddress.toLowerCase())
      fail("APPLICATION_OWNER_MISMATCH", 403);
    const [row] = await deps.db.query<{
      request_hash: string;
      receipt: string;
    }>(
      "SELECT request_hash, receipt FROM application_receipts WHERE source_id=? AND mutation_id=?",
      [applicationSource(authority.builder), input.mutationId],
    );
    if (!row) return null;
    if (row.request_hash !== semanticHash(input))
      fail("APPLICATION_MUTATION_CONFLICT");
    return JSON.parse(row.receipt) as ApplicationReceipt;
  }
  return {
    grants,
    async replay(token, input) {
      return receipt(applicationAuthority(token), input);
    },
    async prepare(token, envelope) {
      const authority = applicationAuthority(token);
      if (authority.owner.toLowerCase() !== deps.ownerAddress.toLowerCase())
        fail("APPLICATION_OWNER_MISMATCH", 403);
      // Snapshot caller-owned objects before yielding; no reusable mutable authority.
      const input = JSON.parse(JSON.stringify(envelope)) as ApplicationEnvelope;
      if (
        !input ||
        typeof input.mutationId !== "string" ||
        !input.mutationId ||
        input.mutationId.length > 128 ||
        !input.record ||
        !isPlainObject(input.record.data) ||
        !input.declaration ||
        !/^[a-f0-9]{64}$/.test(input.declaration.digest)
      )
        fail("INVALID_APPLICATION_MUTATION", 400);
      const source = applicationSource(authority.builder);
      const accepted = await resolve?.({
        digest: input.declaration.digest,
        sourceId: source,
        writer: authority.builder,
      });
      if (
        !accepted ||
        accepted.writer.toLowerCase() !== authority.builder.toLowerCase() ||
        !accepted.bindingRevision
      )
        fail("APPLICATION_DECLARATION_UNAVAILABLE", 403);
      if (digestOf(accepted.document) !== input.declaration.digest)
        fail("APPLICATION_DECLARATION_DIGEST_MISMATCH", 400);
      const doc = JSON.parse(accepted.document);
      if (
        doc.source?.id !== source ||
        doc.source?.kind !== "provider_native" ||
        typeof doc.declaration_version !== "string" ||
        !doc.declaration_version ||
        !Array.isArray(doc.streams)
      )
        fail("INVALID_APPLICATION_DECLARATION", 400);
      const stream = doc.streams.find(
        (s: { name: string }) => s.name === input.record.stream,
      );
      if (
        !stream ||
        !/^[a-zA-Z0-9_-]+$/.test(stream.name) ||
        !["mutable_state", "append_only"].includes(stream.semantics) ||
        !Array.isArray(stream.primary_key) ||
        !stream.primary_key.length ||
        stream.primary_key.some(
          (k: unknown) =>
            typeof k !== "string" ||
            typeof input.record.data[k] !== "string" ||
            !input.record.data[k],
        )
      )
        fail("INVALID_APPLICATION_RECORD", 400);
      if (
        !Number.isFinite(Date.parse(input.record.emitted_at)) ||
        ![undefined, "upsert", "delete"].includes(input.record.op)
      )
        fail("INVALID_APPLICATION_RECORD", 400);
      if (input.record.op === "delete" && stream.semantics === "append_only")
        fail("APPLICATION_APPEND_ONLY");
      if (
        !stream.schema ||
        !compileRecordSchema(stream.schema)(input.record.data)
      )
        fail("APPLICATION_SCHEMA_VIOLATION", 400);
      const row = await mutationIdentity(
        input.record.data,
        stream.primary_key,
        input.record.key as string | string[],
      );
      const connector = `app-${digestOf(source)}`;
      const ns = await deriveNs(
        (bytes) => deps.keys.namespaceHmac(bytes),
        connector,
        source,
      );
      const connection = controlScope(connector, ns);
      const [binding] = await deps.db.query<{
        revision: string;
        connection_id: string;
      }>(
        "SELECT revision, connection_id FROM application_sources WHERE source_id=?",
        [source],
      );
      if (
        binding &&
        (binding.revision !== accepted.bindingRevision ||
          binding.connection_id !== connection)
      )
        fail("APPLICATION_SOURCE_BINDING_CHANGED");
      const [known] = await deps.db.query<{ generation: number }>(
        "SELECT generation FROM connections WHERE connection_id=?",
        [connection],
      );
      const [state] = await deps.db.query<{ last_delete_version: number }>(
        "SELECT last_delete_version FROM stream_state WHERE connection_id=? AND stream=?",
        [connection, input.record.stream],
      );
      const blobs = (input.blobs ?? []).map((blob) => {
        if (
          !Array.isArray(blob.bytes) ||
          blob.bytes.some((b) => !Number.isInteger(b) || b < 0 || b > 255)
        )
          fail("INVALID_APPLICATION_BLOB", 400);
        if (!row.body.includes(JSON.stringify(blob.sha256)))
          fail("UNREFERENCED_APPLICATION_BLOB", 400);
        return {
          hash: blob.sha256,
          statements: prepareBlob({
            ...blob,
            bytes: new Uint8Array(blob.bytes),
          }),
        };
      });
      const cap = Object.freeze({
        kind: "authorized-application-mutation" as const,
      });
      capabilities.set(cap, {
        authority,
        input,
        hash: semanticHash(input),
        source,
        connector,
        ns,
        connection,
        generation: known?.generation ?? 1,
        deleteSnapshot: state?.last_delete_version ?? 0,
        revision: accepted.bindingRevision,
        document: accepted.document,
        version: doc.declaration_version,
        primaryKey: stream.primary_key,
        semantics: stream.semantics,
        row,
        blobs,
      });
      return cap;
    },
    async commit(cap) {
      const p = capabilities.get(cap);
      if (!p) fail("UNAUTHORIZED_APPLICATION_MUTATION", 403);
      return deps.queue.run(p.connection, "end", async () => {
        const replay = await receipt(p.authority, p.input);
        if (replay) return replay;
        const op = deps.newOp();
        const { row, input } = p;
        const result: ApplicationReceipt = {
          mutationId: input.mutationId,
          recordRef: {
            source: p.source,
            instance: p.connection,
            stream: input.record.stream,
            key: row.recordKey,
          },
          publication: "pending",
        };
        const statements: SqlStatement[] = [
          {
            sql: "INSERT OR IGNORE INTO application_sources(source_id,writer,revision,connection_id) VALUES (?,?,?,?)",
            params: [
              p.source,
              p.authority.builder.toLowerCase(),
              p.revision,
              p.connection,
            ],
          },
          {
            sql: "INSERT OR IGNORE INTO application_declarations(source_id,version,digest,document) VALUES (?,?,?,?)",
            params: [p.source, p.version, input.declaration.digest, p.document],
          },
          {
            sql: "INSERT OR IGNORE INTO connections(connection_id,connector,ns,control_state) VALUES (?,?,?,'active')",
            params: [p.connection, p.connector, p.ns],
          },
          {
            sql: "INSERT OR IGNORE INTO stream_state(connection_id,stream,primary_key,semantics,incremental,profile_key,profile_version,complete) VALUES (?,?,?,?,1,?,?,1)",
            params: [
              p.connection,
              input.record.stream,
              JSON.stringify(p.primaryKey),
              p.semantics,
              p.source,
              p.version,
            ],
          },
          {
            sql: "CREATE TEMP TABLE IF NOT EXISTS application_guard(op TEXT PRIMARY KEY, ok INTEGER NOT NULL CHECK(ok=1))",
          },
          {
            sql: `INSERT INTO application_guard SELECT ?, CASE WHEN
              EXISTS(SELECT 1 FROM application_grants WHERE grant_id=? AND revision=? AND status='active' AND (expires_at IS NULL OR expires_at>=?))
              AND EXISTS(SELECT 1 FROM application_sources WHERE source_id=? AND writer=? AND revision=? AND connection_id=?)
              AND EXISTS(SELECT 1 FROM connections c WHERE c.connection_id=? AND c.generation=? AND c.control_state IN ('active','absent') AND c.deleted_at IS NULL AND NOT EXISTS(SELECT 1 FROM delete_intents d WHERE d.connector=c.connector))
              AND EXISTS(SELECT 1 FROM stream_state WHERE connection_id=? AND stream=? AND last_delete_version=? AND primary_key=? AND semantics=?)
              AND EXISTS(SELECT 1 FROM application_declarations WHERE source_id=? AND version=? AND digest=? AND document=?)
              THEN 1 ELSE 0 END`,
            params: [
              op,
              p.authority.grant.id,
              observeWriteGrant(p.authority.grant).revision,
              deps.now(),
              p.source,
              p.authority.builder.toLowerCase(),
              p.revision,
              p.connection,
              p.connection,
              p.generation,
              p.connection,
              input.record.stream,
              p.deleteSnapshot,
              JSON.stringify(p.primaryKey),
              p.semantics,
              p.source,
              p.version,
              input.declaration.digest,
              p.document,
            ],
          },
          { sql: "DELETE FROM application_guard WHERE op=?", params: [op] },
          {
            sql: `INSERT INTO incoming(op,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256,first_o,stamp_n) VALUES (?,?,?,?,?,?,?,?,?,0)`,
            params: [
              op,
              input.record.stream,
              row.hash,
              row.recordKey,
              deps.now(),
              `application:${op}`,
              row.body,
              row.bodySha256,
              deps.now(),
            ],
          },
          ...mergeIncoming(op, p.connection),
          ...p.blobs.flatMap((blob) => [
            ...blob.statements(p.generation),
            {
              sql: "INSERT OR IGNORE INTO blob_refs(blob_id,connection_id,stream,pk_hash) VALUES (?,?,?,?)",
              params: [blob.hash, p.connection, input.record.stream, row.hash],
            },
          ]),
          {
            sql: "INSERT INTO application_receipts(source_id,mutation_id,request_hash,receipt,provenance,declaration_digest) VALUES (?,?,?,?,?,?)",
            params: [
              p.source,
              input.mutationId,
              p.hash,
              JSON.stringify(result),
              JSON.stringify(p.authority.attribution),
              input.declaration.digest,
            ],
          },
        ];
        try {
          await deps.db.batch(withOrigin("local", statements));
        } catch (error) {
          if (String(error).includes("CHECK constraint failed"))
            fail("APPLICATION_AUTHORITY_CHANGED", 403);
          throw error;
        }
        announceRecordsCommitted(deps);
        return result;
      });
    },
  };
}

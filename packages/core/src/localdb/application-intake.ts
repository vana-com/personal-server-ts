import { factsGuard, type StreamFacts } from "./admit.js";
import {
  canonicalJson,
  controlScope,
  streamScope,
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
import { mutationIdentity, stageMutation } from "./mutation-identity.js";
import { mergeIncoming, withOrigin } from "./merge.js";
import { prepareApplicationBlobs } from "./application-blobs.js";
import type { SqlStatement } from "./driver.js";

/** Full snapshot supplied by the host's declaration/onboarding authority.
 * The host has accepted sourceId as a protected resource and bound writer to it.
 * Publishing/trust policy stays outside localdb; a request's document is not authority.
 */
export interface AcceptedApplicationDeclaration {
  readonly scopeBindings: Readonly<Record<string, readonly string[]>>;
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
  /** Trusted host observation of a new binding revision, through the same writer. */
  readonly bindings: {
    record(input: {
      readonly sourceId: string;
      readonly writer: string;
      readonly revision: string;
    }): Promise<void>;
  };
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
const semanticHash = (input: ApplicationEnvelope, scope: string): string =>
  digestOf(canonicalJson({ scope, envelope: input } as unknown as JsonValue));

export function createApplicationIntake(
  deps: LocalSyncDeps,
  resolve?: ResolveApplicationDeclaration,
): ApplicationIntake {
  type Prepared = {
    authority: ApplicationAuthority;
    grant: NonNullable<ApplicationAuthority["grant"]>;
    input: ApplicationEnvelope;
    hash: string;
    source: string;
    connector: string;
    ns: string;
    connection: string;
    generation: number;
    revision: string;
    deleteSnapshot: number;
    facts: StreamFacts;
    document: string;
    version: string;
    primaryKey: string[];
    semantics: string;
    row: Awaited<ReturnType<typeof mutationIdentity>>;
    blobs: ReturnType<typeof prepareApplicationBlobs>;
  };
  const capabilities = new WeakMap<AuthorizedApplicationMutation, Prepared>();
  const grants = createApplicationGrantStore(deps.db);
  async function receipt(
    authority: ApplicationAuthority,
    input: ApplicationEnvelope,
  ): Promise<ApplicationReceipt | null> {
    if (
      !input ||
      typeof input.mutationId !== "string" ||
      !input.mutationId ||
      input.mutationId.length > 128 ||
      !input.record ||
      !isPlainObject(input.record.data) ||
      !input.declaration ||
      typeof input.declaration.digest !== "string"
    )
      fail("INVALID_APPLICATION_MUTATION", 400);
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
    if (row.request_hash !== semanticHash(input, authority.scope))
      fail("APPLICATION_MUTATION_CONFLICT");
    return JSON.parse(row.receipt) as ApplicationReceipt;
  }
  return {
    grants,
    bindings: {
      async record(input) {
        if (
          input.sourceId !== applicationSource(input.writer) ||
          !input.revision
        )
          fail("INVALID_APPLICATION_BINDING", 400);
        const connector = `app-${digestOf(input.sourceId)}`;
        const ns = await deriveNs(
          (bytes) => deps.keys.namespaceHmac(bytes),
          connector,
          input.sourceId,
        );
        await deps.db.batch([
          {
            sql: "INSERT OR IGNORE INTO application_sources(source_id,writer,revision,connection_id) VALUES (?,?,?,?)",
            params: [
              input.sourceId,
              input.writer.toLowerCase(),
              input.revision,
              controlScope(connector, ns),
            ],
          },
          {
            sql: "UPDATE application_sources SET revision=? WHERE source_id=? AND writer=?",
            params: [
              input.revision,
              input.sourceId,
              input.writer.toLowerCase(),
            ],
          },
        ]);
      },
    },
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
      if (!authority.grant) fail("APPLICATION_GRANT_REQUIRED", 403);
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
        typeof stream.name !== "string" ||
        stream.name === "" ||
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
      try {
        if (
          !stream.schema ||
          !compileRecordSchema(stream.schema)(input.record.data)
        )
          fail("APPLICATION_SCHEMA_VIOLATION", 400);
      } catch (error) {
        if (error instanceof ProtocolError) throw error;
        fail("INVALID_APPLICATION_DECLARATION", 400);
      }
      if (
        !accepted.scopeBindings?.[authority.scope]?.includes(
          input.record.stream,
        )
      )
        fail("APPLICATION_SCOPE_BINDING_MISMATCH", 403);
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
      streamScope(connector, ns, input.record.stream);
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
      const [state] = await deps.db.query<
        { [K in keyof StreamFacts]: StreamFacts[K] } & {
          last_delete_version: number;
        }
      >(
        "SELECT last_delete_version, head_version, head_generation, floor_version, floor_o, primary_key AS local_primary_key FROM stream_state WHERE connection_id=? AND stream=?",
        [connection, input.record.stream],
      );
      const blobs = prepareApplicationBlobs(input);
      const cap = Object.freeze({
        kind: "authorized-application-mutation" as const,
      });
      capabilities.set(cap, {
        authority,
        grant: authority.grant,
        input,
        hash: semanticHash(input, authority.scope),
        source,
        connector,
        ns,
        connection,
        generation: known?.generation ?? 1,
        deleteSnapshot: state?.last_delete_version ?? 0,
        facts: state ?? {
          head_version: 0,
          head_generation: null,
          floor_version: null,
          floor_o: null,
          local_primary_key: JSON.stringify(stream.primary_key),
        },
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
        const streamFacts = factsGuard(
          p.connection,
          input.record.stream,
          p.facts,
        );
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
            sql: "INSERT OR IGNORE INTO connections(connection_id,connector,ns,control_state) VALUES (?,?,?,'absent')",
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
              EXISTS(SELECT 1 FROM application_grants WHERE grant_id=? AND revision=? AND authority_hash=? AND status='active' AND (expires_at IS NULL OR expires_at>=?))
              AND EXISTS(SELECT 1 FROM application_sources WHERE source_id=? AND writer=? AND revision=? AND connection_id=?)
              AND EXISTS(SELECT 1 FROM connections c WHERE c.connection_id=? AND c.generation=? AND c.control_state IN ('active','absent') AND c.deleted_at IS NULL AND NOT EXISTS(SELECT 1 FROM delete_intents d WHERE d.connector=c.connector))
              AND EXISTS(SELECT 1 FROM stream_state WHERE connection_id=? AND stream=? AND last_delete_version=? AND primary_key=? AND semantics=?)
              AND EXISTS(SELECT 1 FROM application_declarations WHERE source_id=? AND version=? AND digest=? AND document=?)
              AND ${streamFacts.sql}
              THEN 1 ELSE 0 END`,
            params: [
              op,
              p.grant.id,
              observeWriteGrant(p.grant).revision,
              observeWriteGrant(p.grant).authorityHash!,
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
              ...(streamFacts.params ?? []),
            ],
          },
          { sql: "DELETE FROM application_guard WHERE op=?", params: [op] },
          {
            sql: "CREATE TEMP TABLE IF NOT EXISTS application_append_guard(op TEXT PRIMARY KEY, ok INTEGER NOT NULL CONSTRAINT application_append_only CHECK(ok=1))",
          },
          {
            sql: `INSERT INTO application_append_guard SELECT ?, CASE WHEN ? <> 'append_only' OR NOT EXISTS(SELECT 1 FROM records WHERE connection_id=? AND stream=? AND pk_hash=? AND (body<>? OR body_sha256<>?)) THEN 1 ELSE 0 END`,
            params: [
              op,
              p.semantics,
              p.connection,
              input.record.stream,
              row.hash,
              row.body,
              row.bodySha256,
            ],
          },
          {
            sql: "DELETE FROM application_append_guard WHERE op=?",
            params: [op],
          },
          {
            sql: "CREATE TEMP TABLE IF NOT EXISTS mutation_stamps(op TEXT PRIMARY KEY, o INTEGER NOT NULL)",
          },
          {
            sql: `INSERT INTO mutation_stamps SELECT ?, MAX(?,COALESCE((SELECT MAX(COALESCE(seen_o,stamp_o))+1 FROM records WHERE connection_id=?),0),COALESCE((SELECT MAX(stamp_o)+1 FROM record_tombstones WHERE connection_id=?),0))`,
            params: [op, deps.now(), p.connection, p.connection],
          },
          ...(input.record.op === "delete"
            ? [
                {
                  sql: `INSERT INTO record_changes(connection_id,stream,pk_hash,record_key,op,stamp_o,stamp_r,origin,explicit_delete,pk_values) SELECT ?,?,?,?,'remove',o,?,'local',1,? FROM mutation_stamps WHERE op=? AND NOT EXISTS(SELECT 1 FROM records WHERE connection_id=? AND stream=? AND pk_hash=?)`,
                  params: [
                    p.connection,
                    input.record.stream,
                    row.hash,
                    row.recordKey,
                    `application:${op}`,
                    row.keyValues,
                    op,
                    p.connection,
                    input.record.stream,
                    row.hash,
                  ],
                },
                {
                  sql: `INSERT OR REPLACE INTO record_tombstones(connection_id,stream,pk_hash,stamp_o,stamp_r) SELECT ?,?,?,o,? FROM mutation_stamps WHERE op=?`,
                  params: [
                    p.connection,
                    input.record.stream,
                    row.hash,
                    `application:${op}`,
                    op,
                  ],
                },
                {
                  sql: "DELETE FROM records WHERE connection_id=? AND stream=? AND pk_hash=?",
                  params: [p.connection, input.record.stream, row.hash],
                },
                {
                  sql: `UPDATE record_changes SET stamp_o=(SELECT o FROM mutation_stamps WHERE op=?),stamp_r=?,explicit_delete=1,pk_values=? WHERE seq=(SELECT MAX(seq) FROM record_changes WHERE connection_id=? AND stream=? AND pk_hash=?)`,
                  params: [
                    op,
                    `application:${op}`,
                    row.keyValues,
                    p.connection,
                    input.record.stream,
                    row.hash,
                  ],
                },
              ]
            : [
                stageMutation({
                  operation: op,
                  stream: input.record.stream,
                  row: {
                    pkHash: row.hash,
                    recordKey: row.recordKey,
                    body: row.body,
                    bodySha256: row.bodySha256,
                  },
                  stamp: { operation: op, id: `application:${op}` },
                }),
                ...mergeIncoming(op, p.connection),
              ]),
          { sql: "DELETE FROM mutation_stamps WHERE op=?", params: [op] },
          {
            sql: "DELETE FROM blob_refs WHERE connection_id=? AND stream=? AND pk_hash=?",
            params: [p.connection, input.record.stream, row.hash],
          },
          ...p.blobs({
            op,
            connection: p.connection,
            generation: p.generation,
            stream: input.record.stream,
            pkHash: row.hash,
          }),
          {
            sql: "INSERT INTO application_receipts(source_id,mutation_id,request_hash,receipt,provenance,declaration_digest,emitted_at,signed_request) VALUES (?,?,?,?,?,?,?,?)",
            params: [
              p.source,
              input.mutationId,
              p.hash,
              JSON.stringify(result),
              JSON.stringify(p.authority.attribution),
              input.declaration.digest,
              input.record.emitted_at,
              JSON.stringify(input),
            ],
          },
        ];
        try {
          await deps.db.batch(withOrigin("local", statements));
        } catch (error) {
          if (String(error).includes("application_blob_ready"))
            fail("APPLICATION_BLOB_UNAVAILABLE", 400);
          if (String(error).includes("application_append_only"))
            fail("APPLICATION_APPEND_ONLY");
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

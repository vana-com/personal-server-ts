/**
 * What both hosts derive the same way before replication starts (host
 * contract §4.1). Desktop and the phone must agree on every value here, or
 * each refuses the other's batches, so the derivations live in core.
 */
import { sha256, stringToBytes } from "viem";
import type { DeclarationSnapshot } from "../pdpp/types.js";
import { compileRecordSchema } from "../storage/pdpp-records/schema.js";
import {
  canonicalJson,
  declarationBindingSchema,
  type DeclarationBinding,
  type EnvelopeExpectation,
} from "./envelope.js";
import type { MergeContext } from "./merge-plan.js";
import type { ReplicaEnvironment } from "./writer-identity.js";

/** Vana mainnet carries prod data; Moksha carries dev. */
const ENVIRONMENT_BY_CHAIN: Readonly<Record<number, ReplicaEnvironment>> = {
  1480: "prod",
  14800: "dev",
};

/**
 * The signed partition environment of a chain. `undefined` for any other
 * chain: replication then does not start, because a guessed environment
 * would put this device in a partition no peer shares.
 */
export function replicaEnvironmentForChain(
  chainId: number,
): ReplicaEnvironment | undefined {
  return ENVIRONMENT_BY_CHAIN[chainId];
}

/**
 * The owner as every replica statement and operation carries it. Hosts hold
 * checksummed addresses; the partition compares exact strings.
 */
export function replicaPartitionOwner(address: string): string {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address))
    throw new TypeError("invalid replica owner address");
  return address.toLowerCase();
}

const sha256Text = (text: string) =>
  `sha256:${sha256(stringToBytes(text)).slice(2)}`;

/** A stream's JSON Schema; `null` when the stream declares none. */
export type ReplicaStreamSchema = Record<string, unknown> | null;

/** One bound stream, with the schema its operations validate against. */
export interface RetainedReplicaDeclaration {
  sourceId: string;
  binding: DeclarationBinding;
  schema: ReplicaStreamSchema;
}

/** The `schemaDigest` a binding carries for a stream schema. */
export function replicaSchemaDigest(schema: ReplicaStreamSchema): string {
  return sha256Text(canonicalJson(schema));
}

/**
 * One binding per declared stream of each retained declaration: the exact
 * document digest and version, the stream's semantics and primary key, and a
 * digest of its JSON Schema (`null` when it declares none). Throws when a
 * stream cannot be bound; the host then does not start replication.
 *
 * A changed set is a rebinding (`rebinding.ts`): `beginBaseline` records a
 * new binding generation and keeps trusting the older bindings.
 */
export function replicaDeclarationBindings(
  snapshots: readonly DeclarationSnapshot[],
): RetainedReplicaDeclaration[] {
  return [...snapshots]
    .sort((a, b) => (a.source_id < b.source_id ? -1 : 1))
    .flatMap((snapshot) =>
      snapshot.streams.map((stream) => ({
        sourceId: snapshot.source_id,
        binding: declarationBindingSchema.parse({
          digest: `sha256:${snapshot.digest}`,
          version: snapshot.version,
          stream: stream.name,
          semantics: stream.semantics ?? "mutable_state",
          primaryKey: stream.primary_key,
          schemaDigest: replicaSchemaDigest(stream.schema ?? null),
        }),
        schema: stream.schema ?? null,
      })),
    );
}

/**
 * The bindings this boot writes under (`current`, for `beginBaseline`) and
 * the trusted set every replication check uses: `current` plus every binding
 * the database retained in an earlier generation (`history`, from
 * `declarationHistory()`). Own operations still in flight and peers that have
 * not upgraded yet write under those older bindings; trusting only `current`
 * would refuse them. A history entry without a schema, or whose schema does
 * not match its digest, is not trusted, so its operations wait.
 */
export function replicaDeclarationContext(
  owner: string,
  snapshots: readonly DeclarationSnapshot[],
  history: readonly (Omit<RetainedReplicaDeclaration, "schema"> & {
    schema?: ReplicaStreamSchema;
  })[] = [],
): {
  current: RetainedReplicaDeclaration[];
  expected: EnvelopeExpectation;
  declarations: MergeContext["declarations"];
} {
  const current = replicaDeclarationBindings(snapshots);
  const trusted = new Map<string, RetainedReplicaDeclaration>();
  for (const { schema, ...entry } of [...current, ...history])
    if (
      schema !== undefined &&
      replicaSchemaDigest(schema) === entry.binding.schemaDigest
    )
      trusted.set(canonicalJson([entry.sourceId, entry.binding]), {
        ...entry,
        schema,
      });
  const entries = [...trusted.values()];
  const validators = new Map<
    string,
    (data: Record<string, unknown>) => boolean
  >();
  // The same rule as the resource server: a stream without a schema states
  // no shape to check.
  const validatorFor = (entry: RetainedReplicaDeclaration) => {
    let validate = validators.get(entry.binding.schemaDigest);
    if (!validate) {
      const compiled = entry.schema
        ? compileRecordSchema(entry.schema)
        : undefined;
      validate = (data) => (compiled ? compiled(data) === true : true);
      validators.set(entry.binding.schemaDigest, validate);
    }
    return validate;
  };
  return {
    current,
    expected: {
      owner,
      declarations: entries.map(({ sourceId, binding }) => ({
        sourceId,
        binding,
      })),
    },
    declarations: entries.map((entry) => ({
      sourceId: entry.sourceId,
      binding: entry.binding,
      validateData: validatorFor(entry),
    })),
  };
}

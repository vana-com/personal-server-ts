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

/**
 * One binding per declared stream of each retained declaration: the exact
 * document digest and version, the stream's semantics and primary key, and a
 * digest of its JSON Schema (`null` when it declares none). Throws when a
 * stream cannot be bound; the host then does not start replication.
 *
 * The binding set is frozen by the first baseline (`beginBaseline`). A later
 * declaration upgrade changes it, and that database refuses it.
 */
export function replicaDeclarationBindings(
  snapshots: readonly DeclarationSnapshot[],
): { sourceId: string; binding: DeclarationBinding }[] {
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
          schemaDigest: sha256Text(canonicalJson(stream.schema ?? null)),
        }),
      })),
    );
}

/** The envelope expectation and receiver declarations for one owner. */
export function replicaDeclarationContext(
  owner: string,
  snapshots: readonly DeclarationSnapshot[],
): {
  expected: EnvelopeExpectation;
  declarations: MergeContext["declarations"];
} {
  const bindings = replicaDeclarationBindings(snapshots);
  const schemas = new Map(
    snapshots.flatMap((snapshot) =>
      snapshot.streams.map(
        (stream) =>
          [
            canonicalJson([snapshot.source_id, stream.name]),
            stream.schema,
          ] as const,
      ),
    ),
  );
  return {
    expected: { owner, declarations: bindings },
    // The same rule as the resource server: a stream without a schema states
    // no shape to check.
    declarations: bindings.map((entry) => {
      const schema = schemas.get(
        canonicalJson([entry.sourceId, entry.binding.stream]),
      );
      const validate = schema ? compileRecordSchema(schema) : undefined;
      return {
        ...entry,
        validateData: (data: Record<string, unknown>) =>
          validate ? validate(data) === true : true,
      };
    }),
  };
}

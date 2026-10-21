/**
 * The grantee read port: the only storage a non-owner read gets. Every body
 * it returns has passed the legacy disclosure policy on the bytes it serves.
 *
 * An index row can name one version while a different body is read: a
 * lookup by another key, a version written after the row was chosen, or one
 * deleted and written again at the same scope and collectedAt. Deciding on
 * the row alone therefore cannot be the authority. The port decides on what
 * it returns:
 *
 * - an envelope: on the envelope it read;
 * - blocks: from a sidecar whose manifest records the pinned generation of
 *   the authorized row, with every block matched to the manifest's digests;
 *   otherwise from one full read of the envelope, checked on its bytes;
 * - a stream: on the provenance storage derived from the published bytes,
 *   with the bytes checked against the row's digest of those same bytes as
 *   they stream, under a hard input cap. A row without a digest is decided
 *   on one bounded read of its bytes, and the stream is then checked
 *   against the digest of the bytes decided on.
 *
 * The port is a narrow, branded type. Only `granteeReadPort` mints one, and
 * it exposes only the reads non-owner paths use: `/v1/data`, the MCP read
 * client, TEE jobs and derivative questions take it instead of a storage
 * port, so a raw port cannot reach a non-owner by mistake (a compile error,
 * see `grantee-read-port.test.ts`). The owner reads the storage port.
 */

import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { authorizeLegacyRead } from "../policy/legacy-disclosure.js";
import type {
  DataStorageEntryLookup,
  DataStoragePort,
  EnvelopeStreamOptions,
} from "../ports/index.js";
import { buildDataBlocksAsync } from "./blocks/build.js";
import { blockRepresentationId } from "./blocks/representation.js";
import { boundEnvelopeDigest } from "./blocks/digest.js";
import { DataBlockStorageError } from "./blocks/errors.js";
import { readBuiltScopeBlocks } from "./blocks/page.js";
import type {
  DataBlockManifest,
  DataScopeBlock,
  ReadScopeBlocksResponse,
} from "./blocks/types.js";
import { envelopeGeneration } from "./hierarchy/generation.js";
import type { IndexEntry } from "./index/types.js";
import {
  projectedReads,
  projectionInput,
  type ProjectionReadOptions,
  type ProjectionSource,
  type ReadBudget,
} from "./legacy-projection.js";
import {
  generationMismatch,
  readBoundedText,
  verifiedStream,
} from "./verified-stream.js";

export { StoredEnvelopeReadError } from "./verified-stream.js";

declare const granteeRead: unique symbol;

/** The index row each minted `AuthorizedVersion` names. */
const authorizedRows = new WeakMap<
  AuthorizedVersion,
  Pick<IndexEntry, "id" | "scope" | "collectedAt">
>();

/**
 * The version a non-owner stream serves: an opaque handle on the index row
 * the read authorized, minted only by `GranteeReadPort.pinVersion`. It
 * names the row and carries nothing else: the port reads the row's
 * provenance and digest from storage when it streams, never from a caller.
 */
export class AuthorizedVersion {
  private readonly kind = "authorized-version";
  private constructor() {}
}

function mintVersion(
  entry: Pick<IndexEntry, "id" | "scope" | "collectedAt">,
): AuthorizedVersion {
  const version = Reflect.construct(AuthorizedVersion, []) as AuthorizedVersion;
  authorizedRows.set(version, {
    id: entry.id,
    scope: entry.scope,
    collectedAt: entry.collectedAt,
  });
  return version;
}

/** Who a legacy-surface read serves, with the storage that reader gets. */
export type ReaderSource =
  | { reader: "owner"; storage: DataStoragePort }
  | { reader: "grantee"; storage: GranteeReadPort };

/** The source a read by `reader` gets: the owner's port, or the grantee's. */
export function readerSource(
  reader: "owner" | "grantee",
  storage: DataStoragePort,
): ReaderSource {
  return reader === "owner"
    ? { reader, storage }
    : { reader, storage: granteeReadPort(storage) };
}

/**
 * A non-owner's reads of one storage port. Mint it with `granteeReadPort`;
 * nothing else can produce one.
 */
export interface GranteeReadPort {
  readonly [granteeRead]: true;
  /** Index metadata, as the storage port answers it. */
  findEntry(lookup: DataStorageEntryLookup): IndexEntry | undefined;
  /** The served envelope (legacy view of a projected scope), authorized. */
  readEnvelope(scope: string, collectedAt: string): Promise<DataFileEnvelope>;
  /** The stored envelope, without a read-time view, authorized. */
  readStoredEnvelope(
    scope: string,
    collectedAt: string,
  ): Promise<DataFileEnvelope>;
  /** The served envelope bytes, authorized on their parse. */
  readEnvelopeBytes?(scope: string, collectedAt: string): Promise<Uint8Array>;
  /** A handle on `entry`, the index row a read authorized. */
  pinVersion(
    entry: Pick<IndexEntry, "id" | "scope" | "collectedAt">,
  ): AuthorizedVersion;
  /**
   * The served envelope of `version`, streamed. Authorized before it opens,
   * on the row as storage holds it now; every stored input is read under
   * `maxBytes` and checked against its row. The stream fails past
   * `maxBytes` and, at its end, when the bytes are not the row's. Release
   * nothing until the stream has closed: a changed version is known only at
   * the end.
   */
  readEnvelopeStream?(
    version: AuthorizedVersion,
    options: { maxBytes: number },
  ): Promise<ReadableStream<Uint8Array>>;
  readScopeBlocks?: DataStoragePort["readScopeBlocks"];
  readBlockManifest?: DataStoragePort["readBlockManifest"];
}

function authorizeEnvelope(envelope: {
  data: unknown;
  producer?: unknown;
}): void {
  authorizeLegacyRead("grantee", { kind: "stored-envelope", envelope });
}

/** Binding and provenance are for the policy; a non-owner never sees them. */
function servedBlocks(
  result: ReadScopeBlocksResponse,
): ReadScopeBlocksResponse {
  const {
    pdppOrigin: _origin,
    envelopeDigest: _digest,
    redaction: _redaction,
    ...served
  } = result;
  return served;
}

function servedManifest(manifest: DataBlockManifest): DataBlockManifest {
  const {
    pdppOrigin: _origin,
    envelopeDigest: _digest,
    redaction: _redaction,
    blocks,
    ...served
  } = manifest;
  return {
    ...served,
    representationId: blockRepresentationId(manifest, "grantee"),
    blocks: blocks.map(({ digest: _blockDigest, ...ref }) => ref),
  };
}

const textDecoder = new TextDecoder();

/**
 * The bodies of `raw`, each authorized on what it returns. Index lookups
 * pass through. Only the reads a projection or a grantee path uses exist.
 */
function authorizedSource(raw: DataStoragePort): ProjectionSource {
  const rawStream = raw.readEnvelopeStream?.bind(raw);

  async function readAuthorized(
    scope: string,
    collectedAt: string,
    options?: ProjectionReadOptions,
  ): Promise<DataFileEnvelope> {
    // A pinned or budgeted read (a projection input of a non-owner stream)
    // reads the stored bytes under the budget and checks them against the
    // row before it parses them.
    if (options && rawStream) {
      return readPinnedEnvelope(
        () => rawStream(scope, collectedAt),
        options.pin,
        options.budget,
      );
    }
    const envelope = await raw.readEnvelope(scope, collectedAt);
    if (
      options?.pin?.generation !== undefined &&
      envelopeGeneration(envelope) !== options.pin.generation
    ) {
      throw generationMismatch();
    }
    authorizeEnvelope(envelope);
    return envelope;
  }

  const source: ProjectionSource = {
    findEntry: (lookup) => raw.findEntry(lookup),
    listVersions: (scope, options) => raw.listVersions(scope, options),
    readEnvelope: readAuthorized,
  };
  if (raw.readEnvelopeBytes) {
    const rawBytes = raw.readEnvelopeBytes.bind(raw);
    source.readEnvelopeBytes = async (scope, collectedAt) => {
      const bytes = await rawBytes(scope, collectedAt);
      authorizeEnvelope(JSON.parse(textDecoder.decode(bytes)));
      return bytes;
    };
  }
  if (rawStream) {
    source.readEnvelopeStream = (scope, collectedAt, options) =>
      readPinnedStream(
        () => rawStream(scope, collectedAt),
        options?.pin,
        options?.maxBytes ?? Number.POSITIVE_INFINITY,
      );
  }

  /**
   * Blocks served from one full read of the envelope, checked on those
   * bytes: the fallback when a sidecar is not bound to the pinned generation
   * (a sidecar from before binding, or a row with no generation). The blocks
   * are built in memory from the same bytes that were checked, so no later
   * change at the version path can reach the response.
   */
  async function readCheckedBlocks(
    scope: string,
    collectedAt: string,
    generation: string | undefined,
  ): Promise<{ manifest: DataBlockManifest; blocks: DataScopeBlock[] }> {
    // The generation is computed on the stored JSON as storage computed it
    // when it indexed the row, not on a schema-parsed copy.
    const envelope = raw.readEnvelopeBytes
      ? (JSON.parse(
          textDecoder.decode(await raw.readEnvelopeBytes(scope, collectedAt)),
        ) as DataFileEnvelope)
      : await raw.readEnvelope(scope, collectedAt);
    if (
      generation !== undefined &&
      envelopeGeneration(envelope) !== generation
    ) {
      throw new DataBlockStorageError(
        "generation_mismatch",
        `The stored version of ${scope} at ${collectedAt} changed after the read was authorized`,
      );
    }
    authorizeEnvelope(envelope);
    const schemaId = (envelope as { schemaId?: unknown }).schemaId;
    const built = await buildDataBlocksAsync({
      scope,
      collectedAt,
      ...(typeof schemaId === "string" ? { schemaId } : {}),
      content: envelope,
    });
    // Best effort: rebind the sidecar so later reads skip this full read.
    // Readers check the binding, so a repair that loses a race is harmless.
    if (generation !== undefined && raw.writeBlockManifest) {
      await raw
        .writeBlockManifest(scope, collectedAt, built.manifest, built.blocks)
        .catch(() => undefined);
    }
    return built;
  }

  if (raw.readScopeBlocks) {
    const rawBlocks = raw.readScopeBlocks.bind(raw);
    source.readScopeBlocks = async (scope, collectedAt, options) => {
      const { generation, ...readOptions } = options;
      // Storage checks each block against the manifest read in the same
      // call, and reports the manifest's binding only when every served
      // block matched. The pinned generation, not the provenance bit, is the
      // authority that these are the authorized version's bytes. A missing
      // sidecar fails here as it does for the owner.
      const result = await rawBlocks(scope, collectedAt, readOptions);
      if (
        generation !== undefined &&
        result.envelopeDigest === generation &&
        result.pdppOrigin !== undefined &&
        result.redaction !== undefined
      ) {
        authorizeLegacyRead("grantee", {
          kind: "stored-blocks",
          pdppOrigin: result.pdppOrigin,
        });
        return servedBlocks(result);
      }
      return servedBlocks(
        await readBuiltScopeBlocks(
          await readCheckedBlocks(scope, collectedAt, generation),
          readOptions,
        ),
      );
    };
  }
  if (raw.readBlockManifest) {
    const rawManifest = raw.readBlockManifest.bind(raw);
    source.readBlockManifest = async (scope, collectedAt, options) => {
      const generation = options?.generation;
      const manifest = await rawManifest(scope, collectedAt);
      // A version with no sidecar has no table of contents, as for the owner.
      if (!manifest) return null;
      if (
        generation !== undefined &&
        boundEnvelopeDigest(manifest) === generation &&
        manifest.pdppOrigin !== undefined &&
        manifest.redaction !== undefined
      ) {
        authorizeLegacyRead("grantee", {
          kind: "stored-blocks",
          pdppOrigin: manifest.pdppOrigin,
        });
        return servedManifest(manifest);
      }
      return servedManifest(
        (await readCheckedBlocks(scope, collectedAt, generation)).manifest,
      );
    };
  }
  return source;
}

/**
 * The stored envelope of the pinned row, parsed from one read under
 * `budget`: the bytes are counted and hashed as they arrive, and checked
 * against the row's digest (or, for a row without one, its generation)
 * before the envelope is authorized and returned.
 */
async function readPinnedEnvelope(
  open: () => Promise<ReadableStream<Uint8Array>>,
  pin: EnvelopeStreamOptions["pin"],
  budget: ReadBudget | undefined,
): Promise<DataFileEnvelope> {
  const read = await readBoundedText(
    await open(),
    budget?.remaining ?? Number.POSITIVE_INFINITY,
  );
  if (budget) budget.remaining -= read.byteLength;
  if (
    pin?.contentDigest !== undefined &&
    read.sha256Hex !== pin.contentDigest
  ) {
    throw generationMismatch();
  }
  const envelope = JSON.parse(read.text) as DataFileEnvelope;
  if (
    pin?.contentDigest === undefined &&
    pin?.generation !== undefined &&
    envelopeGeneration(envelope) !== pin.generation
  ) {
    throw generationMismatch();
  }
  authorizeEnvelope(envelope);
  return envelope;
}

/**
 * The stored bytes of the pinned version, streamed under `maxBytes`.
 *
 * A row with a content digest and provenance is decided on that provenance:
 * storage derived both from the same published bytes, and the stream fails
 * at its end unless the bytes it served hash to the digest. Nothing is
 * parsed or held.
 *
 * A row without them (rows indexed before the digest, or storage that does
 * not record it) has no binding from bytes to provenance, and provenance is
 * a property of the parsed envelope (`$pdpp` under `data`, or a PDPP
 * producer), as is the generation. So it is decided on one bounded read of
 * the bytes: decoded as they arrive and parsed once, never more than
 * `maxBytes`, and released before the stream opens. The stream is then
 * checked against the digest of the bytes decided on.
 */
async function readPinnedStream(
  open: () => Promise<ReadableStream<Uint8Array>>,
  pin: EnvelopeStreamOptions["pin"],
  maxBytes: number,
): Promise<ReadableStream<Uint8Array>> {
  if (pin?.contentDigest !== undefined && pin.pdppOrigin !== undefined) {
    authorizeLegacyRead("grantee", {
      kind: "digest-pinned-bytes",
      pdppOrigin: pin.pdppOrigin,
    });
    return verifiedStream(await open(), {
      maxBytes,
      sha256Hex: pin.contentDigest,
    });
  }
  const decided = await readBoundedText(await open(), maxBytes);
  const envelope = JSON.parse(decided.text) as DataFileEnvelope;
  if (
    pin?.generation !== undefined &&
    envelopeGeneration(envelope) !== pin.generation
  ) {
    throw generationMismatch();
  }
  authorizeEnvelope(envelope);
  return verifiedStream(await open(), {
    maxBytes,
    sha256Hex: decided.sha256Hex,
  });
}

/** Ports minted per storage port, so a projection keeps its caches. */
const minted = new WeakMap<DataStoragePort, GranteeReadPort>();

/**
 * The grantee read port of `storage`. A served port (see
 * `withLegacyProjection`) gets its projection rebuilt over an authorized
 * source, so the requested version and every joined sibling version are
 * authorized on their bytes; any other port is read as stored.
 */
export function granteeReadPort(storage: DataStoragePort): GranteeReadPort {
  const cached = minted.get(storage);
  if (cached) return cached;
  const projection = projectionInput(storage);
  const source = authorizedSource(projection?.raw ?? storage);
  const reads = projection
    ? projectedReads(source, projection.options)
    : { ...source, readStoredEnvelope: source.readEnvelope };
  const port: Omit<GranteeReadPort, typeof granteeRead> = {
    findEntry: (lookup) => storage.findEntry(lookup),
    readEnvelope: (scope, collectedAt) =>
      reads.readEnvelope(scope, collectedAt),
    readStoredEnvelope: (scope, collectedAt) =>
      reads.readStoredEnvelope(scope, collectedAt),
    pinVersion: mintVersion,
  };
  if (reads.readEnvelopeBytes) port.readEnvelopeBytes = reads.readEnvelopeBytes;
  const stream = reads.readEnvelopeStream;
  if (stream) {
    port.readEnvelopeStream = async (version, { maxBytes }) => {
      const named = authorizedRows.get(version);
      if (!named) {
        throw new TypeError("Not a version this port authorized");
      }
      // Trust comes from storage: the row as it is now, which must still be
      // the one authorized.
      const row = storage.findEntry({
        scope: named.scope,
        at: named.collectedAt,
      });
      if (
        !row ||
        row.id !== named.id ||
        row.scope !== named.scope ||
        row.collectedAt !== named.collectedAt
      ) {
        throw generationMismatch();
      }
      return stream(named.scope, named.collectedAt, { pin: row, maxBytes });
    };
  }
  if (reads.readScopeBlocks) port.readScopeBlocks = reads.readScopeBlocks;
  if (reads.readBlockManifest) port.readBlockManifest = reads.readBlockManifest;
  const branded = port as GranteeReadPort;
  minted.set(storage, branded);
  return branded;
}

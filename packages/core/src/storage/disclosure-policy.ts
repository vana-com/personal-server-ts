/**
 * A non-owner's view of a storage port: every body it returns has passed the
 * legacy disclosure policy on the bytes actually read.
 *
 * An index row can name one version while a different body is read: a
 * lookup by another key, a version written after the row was chosen, or one
 * deleted and written again at the same scope and collectedAt. Deciding on
 * the row therefore cannot be the authority. This view decides on what it
 * returns: the envelope it read, or blocks bound to the version the read was
 * authorized for. Blocks are served from a sidecar only when its manifest
 * records the pinned generation of that row and storage matched every block
 * to the manifest's digests; otherwise from one full read of the envelope,
 * checked on its bytes.
 *
 * `/v1/data`, MCP, TEE jobs and derivative questions read a non-owner's body
 * only through `storageForReader(storage, "grantee")`. The owner gets the
 * port unchanged.
 */

import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import {
  authorizeLegacyRead,
  type LegacyReader,
} from "../policy/legacy-disclosure.js";
import type { DataStoragePort } from "../ports/index.js";
import { previewEnvelopeValue } from "./preview.js";
import { buildDataBlocksAsync } from "./blocks/build.js";
import { blockRepresentationId } from "./blocks/representation.js";
import { boundEnvelopeDigest, trustedPdppOrigin } from "./blocks/digest.js";
import { DataBlockStorageError } from "./blocks/errors.js";
import { readBuiltScopeBlocks } from "./blocks/page.js";
import type {
  DataBlockManifest,
  DataScopeBlock,
  ReadScopeBlocksResponse,
} from "./blocks/types.js";
import { envelopeGeneration } from "./hierarchy/generation.js";

/** A served port's own non-owner view (see `withLegacyProjection`). */
export const GRANTEE_VIEW = Symbol.for(
  "personal-server-ts.storage.grantee-view",
);

const GUARDED = Symbol.for("personal-server-ts.storage.disclosure-guarded");

const textDecoder = new TextDecoder();

/** True for a port that already authorizes every body it returns. */
export function isGuarded(storage: DataStoragePort): boolean {
  return (storage as { [GUARDED]?: true })[GUARDED] === true;
}

function authorizeEnvelope(
  envelope: { data: unknown; producer?: unknown },
  reader: LegacyReader,
): void {
  authorizeLegacyRead(reader, { kind: "stored-envelope", envelope });
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
    pdppClassifier: _classifier,
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

/**
 * Wrap a raw storage port for a non-owner reader. Metadata (index lookups,
 * listings) passes through; every body is authorized on the bytes read.
 */
export function withDisclosurePolicy(
  raw: DataStoragePort,
  reader: LegacyReader = "grantee",
): DataStoragePort {
  if (isGuarded(raw)) return raw;

  async function readAuthorized(
    scope: string,
    collectedAt: string,
    as: LegacyReader = reader,
  ): Promise<DataFileEnvelope> {
    const envelope = await raw.readEnvelope(scope, collectedAt);
    authorizeEnvelope(envelope, as);
    return envelope;
  }

  const overrides: Partial<DataStoragePort> & { [GUARDED]: true } = {
    [GUARDED]: true,
    readEnvelope: readAuthorized,
  };
  if (raw.readEnvelopeBytes) {
    const rawBytes = raw.readEnvelopeBytes.bind(raw);
    overrides.readEnvelopeBytes = async (scope, collectedAt) => {
      const bytes = await rawBytes(scope, collectedAt);
      authorizeEnvelope(JSON.parse(textDecoder.decode(bytes)), reader);
      return bytes;
    };
  }
  if (raw.readEnvelopeStream) {
    const rawStream = raw.readEnvelopeStream.bind(raw);
    // The streamed bytes are checked whole before any of them leave, and
    // what is served is that checked copy, not a second read.
    overrides.readEnvelopeStream = async (scope, collectedAt) => {
      const chunks: Uint8Array[] = [];
      const chunkReader = (await rawStream(scope, collectedAt)).getReader();
      for (;;) {
        const { done, value } = await chunkReader.read();
        if (done) break;
        chunks.push(value);
      }
      const bytes = new Uint8Array(
        chunks.reduce((total, chunk) => total + chunk.byteLength, 0),
      );
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
      }
      authorizeEnvelope(JSON.parse(textDecoder.decode(bytes)), reader);
      return new ReadableStream<Uint8Array>({
        start(controller) {
          for (const chunk of chunks) controller.enqueue(chunk);
          controller.close();
        },
      });
    };
  }
  if (raw.readEnvelopePreview) {
    overrides.readEnvelopePreview = async (scope, collectedAt, options) =>
      previewEnvelopeValue(
        await readAuthorized(scope, collectedAt),
        options.maxBytes,
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
    // Blocks never take the own-write exception: a plain grantee.
    authorizeEnvelope(envelope, "grantee");
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
    overrides.readScopeBlocks = async (scope, collectedAt, options) => {
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
    overrides.readBlockManifest = async (scope, collectedAt, options) => {
      const generation = options?.generation;
      const manifest = await rawManifest(scope, collectedAt);
      // A version with no sidecar has no table of contents, as for the owner.
      if (!manifest) return null;
      const pdppOrigin = trustedPdppOrigin(manifest);
      if (
        generation !== undefined &&
        boundEnvelopeDigest(manifest) === generation &&
        pdppOrigin !== undefined &&
        manifest.redaction !== undefined
      ) {
        authorizeLegacyRead("grantee", {
          kind: "stored-blocks",
          pdppOrigin,
        });
        return servedManifest(manifest);
      }
      return servedManifest(
        (await readCheckedBlocks(scope, collectedAt, generation)).manifest,
      );
    };
  }

  return new Proxy(raw, {
    get(target, property) {
      if (Object.prototype.hasOwnProperty.call(overrides, property)) {
        return overrides[property as keyof typeof overrides];
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
    has(target, property) {
      return (
        Object.prototype.hasOwnProperty.call(overrides, property) ||
        Reflect.has(target, property)
      );
    },
  });
}

/**
 * The storage a read by `reader` gets. The owner reads the port unchanged; a
 * non-owner reads the port's own guarded view (a served port builds its
 * projection over a guarded raw port, so joined sibling scopes are checked
 * too), or a guarded wrap of a raw port.
 */
export function storageForReader(
  storage: DataStoragePort,
  reader: LegacyReader,
): DataStoragePort {
  if (reader === "owner") return storage;
  const view = (
    storage as { [GRANTEE_VIEW]?: (reader: LegacyReader) => DataStoragePort }
  )[GRANTEE_VIEW];
  if (view) return view(reader);
  return withDisclosurePolicy(storage, reader);
}

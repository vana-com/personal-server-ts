/**
 * A non-owner's view of a storage port: every body it returns has passed the
 * legacy disclosure policy on the bytes actually read.
 *
 * An index row can name one version while a different body is read: a
 * lookup by another key, a version written after the row was chosen, or one
 * deleted and written again at the same scope and collectedAt. Deciding on
 * the row therefore cannot be the authority. This view decides on what it
 * returns: the envelope it read, or the block manifest the blocks were read
 * from, which records the provenance of the envelope it was built from.
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

function authorizeEnvelope(envelope: {
  data: unknown;
  producer?: unknown;
}): void {
  authorizeLegacyRead("grantee", { kind: "stored-envelope", envelope });
}

/**
 * Wrap a raw storage port for a non-owner reader. Metadata (index lookups,
 * listings) passes through; every body is authorized on the bytes read.
 */
export function withDisclosurePolicy(raw: DataStoragePort): DataStoragePort {
  if (isGuarded(raw)) return raw;

  async function readAuthorized(
    scope: string,
    collectedAt: string,
  ): Promise<DataFileEnvelope> {
    const envelope = await raw.readEnvelope(scope, collectedAt);
    authorizeEnvelope(envelope);
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
      authorizeEnvelope(JSON.parse(textDecoder.decode(bytes)));
      return bytes;
    };
  }
  if (raw.readEnvelopeStream) {
    const rawStream = raw.readEnvelopeStream.bind(raw);
    // The streamed bytes are checked whole before any of them leave, and
    // what is served is that checked copy, not a second read.
    overrides.readEnvelopeStream = async (scope, collectedAt) => {
      const chunks: Uint8Array[] = [];
      const reader = (await rawStream(scope, collectedAt)).getReader();
      for (;;) {
        const { done, value } = await reader.read();
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
      authorizeEnvelope(JSON.parse(textDecoder.decode(bytes)));
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
  if (raw.readScopeBlocks) {
    const rawBlocks = raw.readScopeBlocks.bind(raw);
    overrides.readScopeBlocks = async (scope, collectedAt, options) => {
      const result = await rawBlocks(scope, collectedAt, options);
      // The manifest these blocks came from records the provenance of the
      // envelope it was built from. A manifest written before that field
      // existed is decided on the envelope instead.
      if (result.pdppOrigin === undefined) {
        await readAuthorized(scope, collectedAt);
      } else {
        authorizeLegacyRead("grantee", {
          kind: "stored-blocks",
          pdppOrigin: result.pdppOrigin,
        });
      }
      const { pdppOrigin: _origin, ...served } = result;
      return served;
    };
  }
  if (raw.readBlockManifest) {
    const rawManifest = raw.readBlockManifest.bind(raw);
    overrides.readBlockManifest = async (scope, collectedAt) => {
      const manifest = await rawManifest(scope, collectedAt);
      if (!manifest) return manifest;
      if (manifest.pdppOrigin === undefined) {
        await readAuthorized(scope, collectedAt);
      } else {
        authorizeLegacyRead("grantee", {
          kind: "stored-blocks",
          pdppOrigin: manifest.pdppOrigin,
        });
      }
      const { pdppOrigin: _origin, ...served } = manifest;
      return served;
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
  const view = (storage as { [GRANTEE_VIEW]?: () => DataStoragePort })[
    GRANTEE_VIEW
  ];
  if (view) return view();
  return withDisclosurePolicy(storage);
}

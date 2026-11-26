import {
  assertSupportedPdppVersion,
  listPdppRecords,
  resolveOwnerSource,
  type OwnedAccountStorageMode,
  type PdppRecordListPorts,
} from "@opendatalabs/personal-server-ts-core/api";
import { PdppError } from "@opendatalabs/personal-server-ts-core/errors/pdpp";
import type { LocalSync } from "@opendatalabs/personal-server-ts-core/localdb";
import type { PdppTokenContext } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import type { StreamDeclaration } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";

export interface LitePdppRecordsDeps {
  localSync: () => Promise<LocalSync>;
  accountStorageMode: OwnedAccountStorageMode;
  /** The runtime's existing owner credential check; throws when it fails. */
  authorizeOwner(request: Request): Promise<void>;
  /** The owner's subject: the address this runtime serves. */
  ownerAddress(): string | undefined;
}

/**
 * `GET /v1/streams/:stream/records` for a switched account: the shared core
 * handler over this runtime's linked `RecordQuery`. The owner credential is
 * the runtime's own; a source (`?source=<connector id>`) is required because
 * no credential here carries one.
 */
export async function handleLitePdppRecordList(
  request: Request,
  stream: string,
  deps: LitePdppRecordsDeps,
): Promise<Response> {
  const requestId = `req_${globalThis.crypto.randomUUID()}`;
  const headers: Record<string, string> = {
    "Request-Id": requestId,
    "Cache-Control": "private, no-store",
  };
  // Negotiated up front but reported only after the owner credential check:
  // an inactive credential still gets its own failure first (spec-core §8
  // "API versioning"), and no query runs under an unselected contract.
  let versionError: PdppError | undefined;
  try {
    headers["PDPP-Version"] = assertSupportedPdppVersion(
      request.headers.get("PDPP-Version"),
    );
  } catch (error) {
    if (!(error instanceof PdppError)) throw error;
    versionError = error;
  }
  await deps.authorizeOwner(request);
  if (versionError) {
    // No contract was selected, so the response carries no PDPP-Version.
    return Response.json(versionError.toJSON(requestId), {
      status: versionError.status,
      headers,
    });
  }
  try {
    const subjectId = deps.ownerAddress();
    if (!subjectId) {
      throw new PdppError(
        "authentication_error",
        "This runtime has no owner yet",
      );
    }
    const context: PdppTokenContext = {
      active: true,
      tokenKind: "owner",
      subjectId,
    };
    const local = await deps.localSync();
    // A connection's identity here is its connector id in the
    // identity-less namespace, the same link the Node host registers.
    const link = (connector: string) => ({ connector, namespace: "" });
    const linked = local.recordsFor(link);
    // The frozen two-horizon history serves owner lists and change sessions,
    // as on Node (spec-core §4, §8; RS items 7, 20, 21).
    const history = local.changesFor(link);
    const connectors = await local.declarations.connectors();
    // The port is synchronous: read each connector's streams once per request.
    const streams = new Map(
      await Promise.all(
        connectors.map(
          async (connector) =>
            [connector, await local.declarations.streamsOf(connector)] as const,
        ),
      ),
    );
    const ports: PdppRecordListPorts = {
      accountMode: deps.accountStorageMode,
      recordQuery: linked,
      recordHistory: (stream, options) => history(stream, options),
      declarations: liteDeclarations(connectors, streams),
      // Lite holds connector ids only, not canonical source ids. `source`
      // names a held connector exactly; any other string names no source here
      // and is refused as a source the caller may not read.
      ownerInstances: (_context, source) => {
        if (source === undefined || source === "") return [];
        const resolved = resolveOwnerSource(source, {
          sourceIdForConnector: (connector) =>
            connectors.includes(connector) ? connector : undefined,
        });
        return connectors.includes(resolved) ? [resolved] : [];
      },
    };
    const result = await listPdppRecords(ports, {
      url: request.url,
      stream,
      context,
      prefer: request.headers.get("prefer"),
    });
    return Response.json(result.body, { status: 200, headers });
  } catch (error) {
    if (!(error instanceof PdppError)) throw error;
    return Response.json(error.toJSON(requestId), {
      status: error.status,
      headers,
    });
  }
}

/**
 * A declaration here only answers whether the stream exists, as on Node:
 * `forInstance` for one connection, `get` for any connection in this store.
 */
function liteDeclarations(
  connectors: readonly string[],
  streams: ReadonlyMap<string, readonly string[]>,
): PdppRecordListPorts["declarations"] {
  const declaration = (stream: string): StreamDeclaration => ({
    name: stream,
    semantics: "mutable_state",
    primaryKey: [],
    // Lite holds no declared cursor_field: owner lists use key order.
    requiredFields: [],
  });
  const forInstance = (connector: string, stream: string) =>
    streams.get(connector)?.includes(stream) ? declaration(stream) : undefined;
  return {
    get: (stream) =>
      connectors.some((connector) => forInstance(connector, stream))
        ? declaration(stream)
        : undefined,
    forInstance,
    declares: (stream) =>
      connectors.some((connector) => forInstance(connector, stream)),
    list: () => [],
  };
}

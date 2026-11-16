import {
  listPdppRecords,
  type OwnedAccountStorageMode,
  type PdppRecordListPorts,
} from "@opendatalabs/personal-server-ts-core/api";
import { PdppError } from "@opendatalabs/personal-server-ts-core/errors/pdpp";
import type { LocalSync } from "@opendatalabs/personal-server-ts-core/localdb";
import { PDPP_VERSION } from "@opendatalabs/personal-server-ts-core/pdpp-version";
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
  const headers = {
    "Request-Id": requestId,
    "PDPP-Version": PDPP_VERSION,
    "Cache-Control": "private, no-store",
  };
  await deps.authorizeOwner(request);
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
    const linked = local.recordsFor((connector) => ({
      connector,
      namespace: "",
    }));
    const ports: PdppRecordListPorts = {
      accountMode: deps.accountStorageMode,
      recordQuery: linked,
      declarations: liteDeclarations(
        local.declarations,
        await local.declarations.connectors(),
      ),
      ownerInstances: (_context, source) =>
        source === undefined || source === "" ? [] : [source],
    };
    const result = await listPdppRecords(ports, {
      url: request.url,
      stream,
      context,
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
  declared: LocalSync["declarations"],
  connectors: readonly string[],
): PdppRecordListPorts["declarations"] {
  const declaration = (stream: string): StreamDeclaration => ({
    name: stream,
    semantics: "mutable_state",
    primaryKey: [],
    cursorField: "",
    requiredFields: [],
  });
  const forInstance = (connector: string, stream: string) =>
    declared.streamsOf(connector).includes(stream)
      ? declaration(stream)
      : undefined;
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

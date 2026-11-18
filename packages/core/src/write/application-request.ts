import type { PersonalServerApiAuthPort } from "../api/index.js";
import type {
  ApplicationEnvelope,
  ApplicationIntake,
} from "../localdb/application-intake.js";
import type { LegacyWriteMode } from "../api/legacy-write-gate.js";
import { accountModeUnknownResponse } from "../api/account-storage-mode.js";
import { ProtocolError } from "../errors/catalog.js";

const MAX_APPLICATION_BYTES = 50 * 1024 * 1024;

/** Canonical JSON is selected before legacy ingestion; selection grants no authority. */
export async function handleApplicationWriteRequest(
  request: Request,
  scope: string,
  deps: {
    readonly auth: PersonalServerApiAuthPort;
    readonly applications?: () => Promise<ApplicationIntake>;
    readonly accountStorageMode?: LegacyWriteMode;
  },
): Promise<Response | null> {
  if (
    request.method !== "POST" ||
    !request.headers
      .get("content-type")
      ?.toLowerCase()
      .includes("application/json")
  )
    return null;
  const reader = request.clone().body?.getReader();
  if (!reader) return null;
  const decoder = new TextDecoder();
  let bytes = 0;
  let text = "";
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.byteLength;
      if (bytes > MAX_APPLICATION_BYTES) return null;
      text += decoder.decode(part.value, { stream: true });
    }
    text += decoder.decode();
  } finally {
    reader.releaseLock();
  }
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return null;
  }
  if (
    !body ||
    typeof body !== "object" ||
    !("mutationId" in body) ||
    !("record" in body) ||
    !("declaration" in body)
  )
    return null;
  if (deps.accountStorageMode?.read() === "unknown" || !deps.accountStorageMode)
    return accountModeUnknownResponse();
  if (deps.accountStorageMode.read() !== "switched")
    throw new ProtocolError(
      409,
      "APPLICATION_WRITES_REQUIRE_STREAM_SYNC",
      "Canonical application writes require stream sync",
    );
  if (!deps.applications || !deps.auth.authorizeApplicationWrite)
    throw new ProtocolError(
      503,
      "APPLICATION_WRITES_UNAVAILABLE",
      "Canonical application writes are unavailable",
    );
  const applications = await deps.applications();
  const authorization = await deps.auth.authorizeApplicationWrite(
    { request, scope },
    applications,
    body as ApplicationEnvelope,
  );
  if (!authorization)
    throw new ProtocolError(
      401,
      "APPLICATION_SESSION_REQUIRED",
      "A verified application write session is required",
    );
  if ("receipt" in authorization)
    return Response.json(authorization.receipt, { status: 201 });
  try {
    return Response.json(await applications.commit(authorization.mutation), {
      status: 201,
    });
  } catch (error) {
    // A rejected batch rolled back. A successful commit never reaches here:
    // publication is a separate wake and cannot release a committed proof.
    await authorization.releaseProof?.();
    throw error;
  }
}

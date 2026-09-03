import {
  MASTER_KEY_MESSAGE,
  NodeECIESProvider,
  PERSONAL_SERVER_REGISTRATION_DEFAULT_VERIFYING_CONTRACT,
  buildPersonalServerRegistrationTypedData,
} from "@opendatalabs/vana-sdk/node";
import {
  buildMasterSignatureDelivery,
  encryptMasterSignatureDelivery,
  userPsId,
  verifyEnclaveIdentityEvidence,
  type EnclaveIdentityEvidence,
  type EnclaveTrustAnchors,
  type IdentityResponse,
  type MasterSignatureDelivery,
  type SealedSecretResponse,
  type SealedSecretSubmission,
} from "@opendatalabs/vana-sdk/protocol/identity";
import { getAddress, isHex, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { fakeGatewayAnchors } from "./print-fake-anchors.js";

const DEFAULT_GATEWAY_URL = "http://127.0.0.1:3000";
const DEFAULT_CHAIN_ID = 14_800;
const TWO_HOURS_SECONDS = 2 * 60 * 60;
const REVOCATION_WINDOW_SECONDS = 10 * 60;
const SECRET_HASH_RE = /^0x[0-9a-fA-F]{64}$/;
// Let the same driver reach Vercel-protected Gateway deployments.
const VERCEL_PROTECTION_BYPASS = process.env.VERCEL_PROTECTION_BYPASS;

interface RequestDetails {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: unknown;
}

interface ResponseDetails {
  status: number | string;
  body: unknown;
}

class StepFailure extends Error {
  constructor(
    message: string,
    readonly request: RequestDetails,
    readonly response: ResponseDetails,
  ) {
    super(message);
  }
}

interface HttpResult {
  request: RequestDetails;
  response: ResponseDetails & { status: number };
}

type StepState = "pass" | "fail" | "skip";

const stepStates = new Map<string, StepState>();
let failureCount = 0;

function asPositiveInteger(raw: string | undefined, fallback: number): number {
  const value = raw === undefined ? fallback : Number(raw);
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`Expected a positive integer, received ${raw ?? value}`);
  }
  return value;
}

function format(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function printFailure(error: unknown): void {
  if (error instanceof StepFailure) {
    console.log(`  request: ${error.request.method} ${error.request.url}`);
    if (error.request.headers) {
      console.log(`  request headers: ${format(error.request.headers)}`);
    }
    if (error.request.body !== undefined) {
      console.log(`  request body: ${format(error.request.body)}`);
    }
    console.log(`  status: ${error.response.status}`);
    console.log(`  body: ${format(error.response.body)}`);
    console.log(`  diagnosis: ${error.message}`);
    return;
  }

  console.log("  request: local setup");
  console.log("  status: LOCAL_ERROR");
  console.log(
    `  body: ${error instanceof Error ? error.message : format(error)}`,
  );
}

async function runStep(
  id: string,
  name: string,
  dependencies: string[],
  action: () => Promise<string | void>,
): Promise<void> {
  if (
    dependencies.some((dependency) => stepStates.get(dependency) !== "pass")
  ) {
    stepStates.set(id, "skip");
    console.log(`SKIP  ${id}. ${name}  dependency failed`);
    return;
  }

  const startedAt = performance.now();
  try {
    const detail = await action();
    stepStates.set(id, "pass");
    console.log(
      `PASS  ${id}. ${name}  ${Math.round(performance.now() - startedAt)}ms${detail ? `  ${detail}` : ""}`,
    );
  } catch (error) {
    stepStates.set(id, "fail");
    failureCount += 1;
    console.log(
      `FAIL  ${id}. ${name}  ${Math.round(performance.now() - startedAt)}ms`,
    );
    printFailure(error);
  }
}

async function requestJson(
  method: string,
  url: string,
  body?: unknown,
  headers?: Record<string, string>,
): Promise<HttpResult> {
  const request: RequestDetails = {
    method,
    url,
    ...(headers ? { headers } : {}),
    ...(body === undefined ? {} : { body }),
  };

  let response: Response;
  try {
    response = await fetch(url, {
      method,
      headers: {
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        ...(VERCEL_PROTECTION_BYPASS
          ? { "x-vercel-protection-bypass": VERCEL_PROTECTION_BYPASS }
          : {}),
        ...headers,
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  } catch (error) {
    const cause =
      error instanceof Error && error.cause instanceof Error
        ? `: ${error.cause.message}`
        : "";
    throw new StepFailure(`Gateway connection failed${cause}`, request, {
      status: "CONNECTION_ERROR",
      body: error instanceof Error ? error.message : String(error),
    });
  }

  const text = await response.text();
  let responseBody: unknown = text;
  if (text.length > 0) {
    try {
      responseBody = JSON.parse(text) as unknown;
    } catch {
      // Keep non-JSON response text for the diagnostic.
    }
  }

  return {
    request,
    response: { status: response.status, body: responseBody },
  };
}

function requireResponse(
  result: HttpResult,
  status: number | readonly number[],
  validate: (body: unknown) => boolean,
  diagnosis: string,
): unknown {
  const statuses = Array.isArray(status) ? status : [status];
  if (
    !statuses.includes(result.response.status) ||
    !validate(result.response.body)
  ) {
    throw new StepFailure(diagnosis, result.request, result.response);
  }
  return result.response.body;
}

function record(value: unknown): Record<string, unknown> | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  return value as Record<string, unknown>;
}

function identityResponse(value: unknown): IdentityResponse | undefined {
  const body = record(value);
  const identity = record(body?.identity);
  if (
    !body ||
    !identity ||
    typeof body.serverUrl !== "string" ||
    typeof identity.address !== "string" ||
    typeof identity.publicKey !== "string" ||
    typeof identity.userPsId !== "string"
  ) {
    return undefined;
  }
  return value as IdentityResponse;
}

function sealedResponse(value: unknown): SealedSecretResponse | undefined {
  const body = record(value);
  if (
    body?.sealed !== true ||
    typeof body.secretHash !== "string" ||
    !SECRET_HASH_RE.test(body.secretHash)
  ) {
    return undefined;
  }
  return value as SealedSecretResponse;
}

function localFailure(
  name: string,
  body: unknown,
  diagnosis: string,
): StepFailure {
  return new StepFailure(
    diagnosis,
    { method: "LOCAL", url: name },
    { status: "LOCAL", body },
  );
}

async function main(): Promise<void> {
  const gatewayUrl = (process.env.GATEWAY_URL ?? DEFAULT_GATEWAY_URL).replace(
    /\/$/,
    "",
  );
  // Optional second Gateway (pointed at another node) for the seal step: proves
  // a secret encrypted to node A's key is unsealed by node B under one app id.
  const sealGatewayUrl = (process.env.SEAL_GATEWAY_URL ?? gatewayUrl).replace(
    /\/+$/,
    "",
  );
  const chainId = asPositiveInteger(process.env.CHAIN_ID, DEFAULT_CHAIN_ID);
  const fakeAnchors = fakeGatewayAnchors();
  const anchors: EnclaveTrustAnchors = {
    kmsRootPubkey: (process.env.ENCLAVE_KMS_ROOT_PUBKEY ??
      fakeAnchors.kmsRootPubkey) as Hex,
    appIds: (process.env.ENCLAVE_APP_ID_ALLOWLIST ?? fakeAnchors.appId)
      .split(",")
      .map((appId) => appId.trim() as Hex),
  };
  const privateKey = (process.env.OWNER_PRIVATE_KEY ??
    generatePrivateKey()) as Hex;
  if (!isHex(privateKey) || privateKey.length !== 66) {
    throw new Error("OWNER_PRIVATE_KEY must be a 32-byte 0x-prefixed hex key");
  }
  const owner = privateKeyToAccount(privateKey);
  const expectedUserPsId = userPsId(chainId, owner.address);
  const verifyingContract = getAddress(
    process.env.DATA_PORTABILITY_SERVER_CONTRACT ??
      PERSONAL_SERVER_REGISTRATION_DEFAULT_VERIFYING_CONTRACT,
  );

  let prepared: IdentityResponse | undefined;
  let serverId: Hex | undefined;
  let epochOneSubmission: SealedSecretSubmission | undefined;
  let epochOneSecretHash: Hex | undefined;

  const prepareBody = { ownerAddress: owner.address, chainId };
  await runStep("1", "prepare identity", [], async () => {
    const result = await requestJson(
      "POST",
      `${gatewayUrl}/v1/identity`,
      prepareBody,
    );
    const parsed = identityResponse(result.response.body);
    requireResponse(
      result,
      200,
      () =>
        parsed !== undefined &&
        parsed.created === true &&
        parsed.state === "prepared" &&
        parsed.identity.epoch === 1 &&
        parsed.identity.userPsId.toLowerCase() ===
          expectedUserPsId.toLowerCase(),
      "Expected a newly prepared epoch-1 identity matching userPsId(chainId, owner)",
    );
    prepared = parsed;
  });

  await runStep("2", "verify enclave evidence", ["1"], async () => {
    try {
      await verifyEnclaveIdentityEvidence(prepared!.identity, anchors, {
        ownerAddress: owner.address,
        chainId,
        epoch: 1,
      });
    } catch (error) {
      throw localFailure(
        "verifyEnclaveIdentityEvidence(identity, anchors, expected)",
        error instanceof Error ? error.message : String(error),
        "SDK rejected the enclave evidence",
      );
    }
  });

  await runStep("3", "register identity", ["1", "2"], async () => {
    const typedData = buildPersonalServerRegistrationTypedData({
      ownerAddress: owner.address,
      serverAddress: prepared!.identity.address,
      serverPublicKey: prepared!.identity.publicKey,
      serverUrl: prepared!.serverUrl,
      chainId,
      verifyingContract,
    });
    const signature = await owner.signTypedData(typedData);
    const requestBody = { version: "v2", message: typedData.message } as const;
    const result = await requestJson(
      "POST",
      `${gatewayUrl}/v1/identity/${expectedUserPsId}/register`,
      requestBody,
      { Authorization: `Web3Signed ${signature}` },
    );
    const responseBody = record(result.response.body);
    requireResponse(
      result,
      201,
      () =>
        typeof responseBody?.serverId === "string" &&
        responseBody.state === "registered" &&
        responseBody.serverStatus === "pending",
      "Expected a newly registered pending server",
    );
    serverId = responseBody!.serverId as Hex;
  });

  await runStep(
    "4a",
    "reject a different owner signature",
    ["1", "3"],
    async () => {
      const otherOwner = privateKeyToAccount(generatePrivateKey());
      const badSignature = await otherOwner.signMessage({
        message: MASTER_KEY_MESSAGE,
      });
      const goodSignature = await owner.signMessage({
        message: MASTER_KEY_MESSAGE,
      });
      const baseDelivery = await buildMasterSignatureDelivery(
        prepared!.identity,
        goodSignature,
      );
      const delivery: MasterSignatureDelivery = {
        ...baseDelivery,
        masterSignature: badSignature,
      };
      const ciphertext = await encryptMasterSignatureDelivery(
        delivery,
        prepared!.identity.publicKey,
        new NodeECIESProvider(),
      );
      const submission: SealedSecretSubmission = {
        userPsId: expectedUserPsId,
        epoch: 1,
        enclaveAddress: prepared!.identity.address,
        ciphertext,
      };
      const result = await requestJson(
        "POST",
        `${sealGatewayUrl}/v1/identity/${expectedUserPsId}/secret`,
        submission,
      );
      const body = record(result.response.body);
      requireResponse(
        result,
        422,
        () => body?.code === "OWNER_MISMATCH",
        "Expected the agent/gateway to reject the different signer as OWNER_MISMATCH",
      );
    },
  );

  await runStep("4b", "reject a stale delivery", ["1", "3"], async () => {
    const masterSignature = await owner.signMessage({
      message: MASTER_KEY_MESSAGE,
    });
    const delivery = await buildMasterSignatureDelivery(
      prepared!.identity,
      masterSignature,
      Math.floor(Date.now() / 1000) - TWO_HOURS_SECONDS,
    );
    const ciphertext = await encryptMasterSignatureDelivery(
      delivery,
      prepared!.identity.publicKey,
      new NodeECIESProvider(),
    );
    const submission: SealedSecretSubmission = {
      userPsId: expectedUserPsId,
      epoch: 1,
      enclaveAddress: prepared!.identity.address,
      ciphertext,
    };
    const result = await requestJson(
      "POST",
      `${sealGatewayUrl}/v1/identity/${expectedUserPsId}/secret`,
      submission,
    );
    const code = record(result.response.body)?.code;
    requireResponse(
      result,
      [400, 401, 409, 422],
      () => typeof code === "string" && code !== "SECRET_MISMATCH",
      "Expected the agent to reject the stale delivery before gateway secret idempotency; SECRET_MISMATCH means the request did not exercise the agent",
    );
    return `code=${code as string}`;
  });

  await runStep("4", "seal master signature", ["1", "2", "3"], async () => {
    const masterSignature = await owner.signMessage({
      message: MASTER_KEY_MESSAGE,
    });
    const delivery = await buildMasterSignatureDelivery(
      prepared!.identity,
      masterSignature,
    );
    const ciphertext = await encryptMasterSignatureDelivery(
      delivery,
      prepared!.identity.publicKey,
      new NodeECIESProvider(),
    );
    epochOneSubmission = {
      userPsId: expectedUserPsId,
      epoch: 1,
      enclaveAddress: prepared!.identity.address,
      ciphertext,
    };
    const result = await requestJson(
      "POST",
      `${sealGatewayUrl}/v1/identity/${expectedUserPsId}/secret`,
      epochOneSubmission,
    );
    const parsed = sealedResponse(result.response.body);
    requireResponse(
      result,
      201,
      () => parsed !== undefined,
      "Expected a newly sealed secret with a 32-byte secretHash",
    );
    epochOneSecretHash = parsed!.secretHash;
  });

  await runStep("5", "read sealed identity", ["4"], async () => {
    const query = new URLSearchParams({
      owner: owner.address,
      chainId: String(chainId),
    });
    const result = await requestJson(
      "GET",
      `${gatewayUrl}/v1/identity?${query.toString()}`,
    );
    const parsed = identityResponse(result.response.body);
    requireResponse(
      result,
      200,
      () => parsed?.state === "sealed" && parsed.sealed === true,
      "Expected the identity to be sealed",
    );
  });

  await runStep("6", "idempotent prepare and seal", ["1", "4"], async () => {
    const prepareResult = await requestJson(
      "POST",
      `${gatewayUrl}/v1/identity`,
      prepareBody,
    );
    const repeatedIdentity = identityResponse(prepareResult.response.body);
    requireResponse(
      prepareResult,
      200,
      () =>
        repeatedIdentity?.created === false &&
        repeatedIdentity.identity.address.toLowerCase() ===
          prepared!.identity.address.toLowerCase(),
      "Expected prepare to return the same identity with created=false",
    );

    const secretResult = await requestJson(
      "POST",
      `${sealGatewayUrl}/v1/identity/${expectedUserPsId}/secret`,
      epochOneSubmission,
    );
    const repeatedSecret = sealedResponse(secretResult.response.body);
    requireResponse(
      secretResult,
      200,
      () =>
        repeatedSecret?.secretHash.toLowerCase() ===
        epochOneSecretHash!.toLowerCase(),
      "Expected seal to return the same secretHash with status 200",
    );
  });

  await runStep("7", "reject tampered app id locally", ["1"], async () => {
    const tampered: EnclaveIdentityEvidence = {
      ...prepared!.identity,
      appId: `0x${prepared!.identity.appId
        .slice(2)
        .replace(/^./, (digit) => (digit === "0" ? "1" : "0"))}` as Hex,
    };
    try {
      await verifyEnclaveIdentityEvidence(tampered, anchors, {
        ownerAddress: owner.address,
        chainId,
        epoch: 1,
      });
    } catch {
      return;
    }
    throw localFailure(
      "verifyEnclaveIdentityEvidence(tamperedEvidence, anchors, expected)",
      "resolved without throwing",
      "Expected local evidence verification to reject the tampered appId",
    );
  });

  await runStep(
    "8",
    "revoke and rotate identity epoch",
    ["1", "3", "4"],
    async () => {
      const deadline =
        Math.floor(Date.now() / 1000) + REVOCATION_WINDOW_SECONDS;
      const deregistrationTypedData = {
        domain: {
          name: "Vana Data Portability",
          version: "1",
          chainId,
          verifyingContract,
        },
        types: {
          ServerDeregistration: [
            { name: "ownerAddress", type: "address" },
            { name: "serverAddress", type: "address" },
            { name: "serverId", type: "bytes32" },
            { name: "deadline", type: "uint256" },
          ],
        },
        primaryType: "ServerDeregistration",
        message: {
          ownerAddress: owner.address,
          serverAddress: prepared!.identity.address,
          serverId: serverId!,
          deadline: BigInt(deadline),
        },
      } as const;
      const signature = await owner.signTypedData(deregistrationTypedData);
      const revokeResult = await requestJson(
        "DELETE",
        `${gatewayUrl}/v1/servers/${prepared!.identity.address}`,
        { ownerAddress: owner.address, deadline },
        { Authorization: `Web3Signed ${signature}` },
      );
      requireResponse(
        revokeResult,
        200,
        () => record(revokeResult.response.body)?.success === true,
        "Expected server deregistration to succeed",
      );

      const prepareResult = await requestJson(
        "POST",
        `${gatewayUrl}/v1/identity`,
        prepareBody,
      );
      const epochTwo = identityResponse(prepareResult.response.body);
      requireResponse(
        prepareResult,
        200,
        () =>
          epochTwo?.created === true &&
          epochTwo.identity.epoch === 2 &&
          epochTwo.identity.address.toLowerCase() !==
            prepared!.identity.address.toLowerCase(),
        "Expected revocation to produce a distinct epoch-2 identity",
      );

      const retiredSecretResult = await requestJson(
        "POST",
        `${sealGatewayUrl}/v1/identity/${expectedUserPsId}/secret`,
        epochOneSubmission,
      );
      requireResponse(
        retiredSecretResult,
        409,
        () => true,
        "Expected 409 IDENTITY_RETIRED for the epoch-1 ciphertext; gateway api/v1/identity/[userPsId]/secret.ts:46-55 looks up the latest epoch with findLatest and incorrectly returns 400 FIELD_MISMATCH",
      );
    },
  );

  process.exitCode = failureCount === 0 ? 0 : 1;
}

main().catch((error: unknown) => {
  console.error(
    `Identity E2E setup failed: ${error instanceof Error ? error.message : String(error)}`,
  );
  process.exitCode = 1;
});

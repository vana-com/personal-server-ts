import { describe, expect, it } from "vitest";
import { keccak256, toBytes, verifyMessage } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { createFakeDstackClient } from "../dstack/fake.js";
import { userPsId } from "../identity/paths.js";
import { deriveEnclaveAccount } from "../identity/wallet.js";
import { createAgentServer, type AgentJobsControl } from "./http.js";
import {
  buildAccessRecord,
  canonicalJson,
  type AccessRecordInput,
  type SignedAccessRecord,
} from "./access-records.js";

const SECRET = "agent-test-secret";
const SANDBOX_TOKEN = "sandbox-access-token";
const FAKE_APP_ID = "0000000000000000000000000000000000000004";
const NODE_ID = "node-access";
const CHAIN_ID = 14_800;
const EPOCH = 3;
const ACCESS_RECORDS_PATH = "/agent/v1/access-records";
const OWNER = privateKeyToAccount(keccak256(toBytes("access-records:owner")));
const GRANTEE = "0x1111111111111111111111111111111111111111";
const USER_PS_ID = userPsId(CHAIN_ID, OWNER.address);

const SERVED: AccessRecordInput = {
  action: "read",
  chainId: CHAIN_ID,
  grantId: "grant-1",
  granteeAddress: GRANTEE,
  logId: "log-1",
  occurredAt: "2026-09-09T00:00:00.000Z",
  outcome: "served",
  scope: "instagram.profile",
  source: "mcp",
  tool: "read_scope",
};

const DENIED: AccessRecordInput = {
  ...SERVED,
  denyReason: "scope_not_granted",
  grantId: "none",
  logId: "log-2",
  outcome: "denied",
};

function jobsControl(
  posted: SignedAccessRecord[][],
  identity: { userPsId: `0x${string}`; epoch: number } | null = {
    userPsId: USER_PS_ID,
    epoch: EPOCH,
  },
): AgentJobsControl {
  return {
    nodeId: NODE_ID,
    storageApiUrl: "https://storage.example",
    activeCount: () => 0,
    draining: () => false,
    drain: async () => undefined,
    sandboxDebug: false,
    listSandboxes: async () => [],
    sandboxLogs: async () => undefined,
    lookupSandboxJob: () => ({ kind: "unauthorized" }),
    lookupSandbox: (token) => (token === SANDBOX_TOKEN ? identity : null),
    postAccessRecords: async (records) => {
      posted.push(records);
    },
    prewarm: () => undefined,
  };
}

async function withServer(
  jobs: AgentJobsControl,
  run: (origin: string) => Promise<void>,
): Promise<void> {
  const server = createAgentServer({
    client: createFakeDstackClient({ appId: FAKE_APP_ID }),
    secret: SECRET,
    jobs,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("test server did not bind a TCP port");
  }
  try {
    await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
}

function post(
  origin: string,
  body: unknown,
  token = SANDBOX_TOKEN,
): Promise<Response> {
  return fetch(`${origin}${ACCESS_RECORDS_PATH}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

describe("canonical access record JSON", () => {
  it("sorts keys, omits absent fields, and adds no whitespace", () => {
    const record = buildAccessRecord(
      DENIED,
      { userPsId: USER_PS_ID, epoch: EPOCH },
      NODE_ID,
    );
    expect(canonicalJson(record)).toBe(
      `{"action":"read","chainId":14800,"denyReason":"scope_not_granted",` +
        `"epoch":3,"grantId":"none","granteeAddress":"${GRANTEE}",` +
        `"logId":"log-2","nodeId":"${NODE_ID}",` +
        `"occurredAt":"2026-09-09T00:00:00.000Z","outcome":"denied",` +
        `"scope":"instagram.profile","source":"mcp","tool":"read_scope",` +
        `"userPsId":"${USER_PS_ID}"}`,
    );
  });

  it("is stable regardless of the order fields arrived in", () => {
    const identity = { userPsId: USER_PS_ID, epoch: EPOCH };
    const shuffled = Object.fromEntries(
      Object.entries(SERVED).reverse(),
    ) as AccessRecordInput;
    expect(canonicalJson(buildAccessRecord(shuffled, identity, NODE_ID))).toBe(
      canonicalJson(buildAccessRecord(SERVED, identity, NODE_ID)),
    );
  });
});

describe("agent access records route", () => {
  it("signs each record with the enclave account and forwards the batch", async () => {
    const posted: SignedAccessRecord[][] = [];
    await withServer(jobsControl(posted), async (origin) => {
      const response = await post(origin, { records: [SERVED, DENIED] });
      expect(response.status).toBe(202);
      expect(await response.json()).toEqual({ accepted: 2 });
    });

    expect(posted).toHaveLength(1);
    const account = await deriveEnclaveAccount(
      createFakeDstackClient({ appId: FAKE_APP_ID }),
      USER_PS_ID,
      EPOCH,
    );
    for (const { payload, signature } of posted[0]) {
      expect(payload.userPsId).toBe(USER_PS_ID);
      expect(payload.epoch).toBe(EPOCH);
      expect(payload.nodeId).toBe(NODE_ID);
      expect(payload).not.toHaveProperty("ownerAddress");
      expect(payload).not.toHaveProperty("signature");
      await expect(
        verifyMessage({
          address: account.address,
          message: canonicalJson(payload),
          signature,
        }),
      ).resolves.toBe(true);
    }
  });

  it("rejects an unknown sandbox token", async () => {
    await withServer(jobsControl([]), async (origin) => {
      const response = await post(origin, { records: [SERVED] }, "wrong-token");
      expect(response.status).toBe(401);
    });
  });

  it("rejects a request with no bearer token", async () => {
    await withServer(jobsControl([]), async (origin) => {
      const response = await fetch(`${origin}${ACCESS_RECORDS_PATH}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ records: [SERVED] }),
      });
      expect(response.status).toBe(401);
    });
  });

  it("rejects more records than one batch allows", async () => {
    const posted: SignedAccessRecord[][] = [];
    await withServer(jobsControl(posted), async (origin) => {
      const records = Array.from({ length: 51 }, (_value, index) => ({
        ...SERVED,
        logId: `log-${index}`,
      }));
      const response = await post(origin, { records });
      expect(response.status).toBe(400);
    });
    expect(posted).toHaveLength(0);
  });

  it("rejects a body over the agent's size limit", async () => {
    await withServer(jobsControl([]), async (origin) => {
      const response = await post(origin, {
        records: [{ ...SERVED, scope: "x".repeat(70 * 1024) }],
      });
      expect(response.status).toBe(413);
    });
  });

  it("rejects a denial with no reason", async () => {
    await withServer(jobsControl([]), async (origin) => {
      const response = await post(origin, {
        records: [{ ...DENIED, denyReason: undefined }],
      });
      expect(response.status).toBe(400);
    });
  });

  it("rejects a record whose grantee is not an address", async () => {
    await withServer(jobsControl([]), async (origin) => {
      const response = await post(origin, {
        records: [{ ...SERVED, granteeAddress: "not-an-address" }],
      });
      expect(response.status).toBe(400);
    });
  });
});

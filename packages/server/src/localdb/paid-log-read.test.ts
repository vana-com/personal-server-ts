import { afterEach, describe, expect, it, vi } from "vitest";
import { world, closeWorldDrivers, LOG } from "./log-world.test-utils.js";
import { privateKeyToAccount } from "viem/accounts";
import {
  dataRegistryDomain,
  escrowPaymentDomain,
  GENERIC_PAYMENT_TYPES,
  RECORD_DATA_ACCESS_TYPES,
} from "@opendatalabs/vana-sdk/browser";
import {
  handleX402Cycle,
  type X402CycleInput,
} from "../../../core/src/api/index.js";
import { encodePaymentHeader } from "../../../core/src/payment/x402.js";
import { computeDataPointId } from "../../../core/src/sync/data-point-id.js";
import { OWNER } from "./log-world.test-utils.js";
import { createLocalResolver } from "../../../core/src/localdb/resolve.js";
import type { ResolveInput } from "../../../core/src/stream-sync-read/service.js";

async function payRegisteredView(served: { scope: string; version: number }) {
  const builder = privateKeyToAccount(`0x${"11".repeat(32)}`);
  const server = privateKeyToAccount(`0x${"22".repeat(32)}`);
  const config = {
    chainId: 14800,
    contracts: {
      dataRegistry: "0x0000000000000000000000000000000000000001",
      dataPortabilityEscrow: "0x0000000000000000000000000000000000000005",
    },
  } as Parameters<typeof dataRegistryDomain>[0];
  const paymentFetch = vi.fn(async (_url: string, init: RequestInit) => {
    const forwarded = JSON.parse(init.body as string);
    expect(forwarded.accessRecord.dataPointId).toBe(
      computeDataPointId(OWNER, LOG),
    );
    expect(forwarded.accessRecord.version).toBe("2");
    return Response.json({ success: true });
  });
  const input = {
    scope: "pdpp.fixture.s0",
    servedEntry: served,
    grantId: `0x${"ee".repeat(32)}`,
    builder: builder.address,
    gateway: {
      getGrant: async () => ({
        paymentStatus: "pending",
        fee: {
          asset: "0x0000000000000000000000000000000000000000",
          registrationFee: "1000000000000000",
          dataAccessFee: "10000000000000000",
          totalDue: "11000000000000000",
        },
      }),
    },
    gatewayConfig: config,
    gatewayUrl: "https://gateway.test",
    deps: {
      serverOwner: OWNER,
      serverAddress: server.address,
      paymentFetch,
      serverSigner: {
        signRecordDataAccess: (message: never) =>
          server.signTypedData({
            domain: dataRegistryDomain(config),
            types: RECORD_DATA_ACCESS_TYPES,
            primaryType: "RecordDataAccess",
            message,
          }),
      },
    },
    request: new Request("https://server.test/pdpp.fixture.s0"),
  } as unknown as X402CycleInput;
  const challenge = await handleX402Cycle(input);
  if (challenge.kind !== "challenge") throw new Error("expected challenge");
  const accept = challenge.body.accepts[0]!;
  const signature = await builder.signTypedData({
    domain: escrowPaymentDomain(config),
    types: GENERIC_PAYMENT_TYPES,
    primaryType: "GenericPayment",
    message: {
      ...accept.message,
      amount: BigInt(accept.message.amount),
      paymentNonce: BigInt(accept.message.paymentNonce),
    },
  });
  input.request = new Request(input.request.url, {
    headers: {
      "x-payment": encodePaymentHeader({
        x402Version: 1,
        scheme: "vana-escrow-grant",
        network: "vana:14800",
        payload: {
          message: accept.message,
          signature,
          accessRecord: accept.accessRecord,
        },
      }),
    },
  });
  expect(await handleX402Cycle(input)).toMatchObject({ kind: "ok" });
  expect(paymentFetch).toHaveBeenCalledOnce();
  if (process.env.PAYMENT_FIXTURE_PATH) {
    const { writeFileSync } = await import("node:fs");
    const [, init] = paymentFetch.mock.calls[0]!;
    writeFileSync(
      process.env.PAYMENT_FIXTURE_PATH,
      JSON.stringify(
        {
          owner: OWNER,
          server: server.address,
          scope: LOG,
          body: JSON.parse(init.body as string),
          headers: init.headers,
        },
        null,
        2,
      ) + "\n",
    );
  }
}

const read = (scope = "pdpp.fixture.s0") =>
  ({
    scope,
    connection: null,
    cursor: null,
    legacyFile: false,
    isOwnerView: false,
    requireRegistered: true,
  }) as ResolveInput;
afterEach(closeWorldDrivers);

describe("paid reads of registered log folds", () => {
  it("does not block a covered stream on unpublished edits of another stream", async () => {
    const w = await world({ streams: 2 });
    const a = await w.device("a");
    await a.run("first", [
      { stream: "s0", id: 1, v: 1 },
      { stream: "s1", id: 1, v: 1 },
    ]);
    await a.sync.publish();
    await a.run("second", [{ stream: "s1", id: 1, v: 2 }], {
      selected: ["s1"],
    });
    const post = vi
      .spyOn(a.deps.registry, "postBatch")
      .mockRejectedValue(new Error("offline"));
    const decision = await a.sync.resolver.resolve(read());
    expect(decision).toMatchObject({
      kind: "view",
      served: { scope: LOG, version: 1 },
    });
    expect(post).not.toHaveBeenCalled();
    if (decision.kind === "view") await decision.body.cancel();
  });
  it("stops waiting when the request ends while shared publication is in flight", async () => {
    const w = await world({ streams: 1 });
    let blocked = false;
    let release: () => void = () => {};
    let reached: () => void = () => {};
    const uploading = new Promise<void>((resolve) => {
      reached = resolve;
    });
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const a = await w.device("a", {
      beforePut: async () => {
        if (blocked) {
          reached();
          await gate;
        }
      },
    });
    await a.run("first", [{ stream: "s0", id: 1, v: 1 }]);
    await a.sync.publish();
    await a.run("second", [{ stream: "s0", id: 1, v: 2 }]);
    blocked = true;
    const controller = new AbortController();
    const pending = a.sync.resolver.resolve({
      ...read(),
      signal: controller.signal,
    });
    try {
      await uploading;
      controller.abort();
      expect(await pending).toMatchObject({ kind: "read_aborted" });
    } finally {
      release();
      await a.sync.publish();
    }
    expect(await a.position()).toBe(2);
  });
  it("publishes a replacement despite a deleted sibling", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("first", [{ stream: "s0", id: 1, v: 1 }]);
    await a.deps.db.batch([
      {
        sql: "INSERT INTO connections (connection_id, connector, ns, generation, control_state, deleted_at) VALUES ('old', 'fixture', 'aaaaaaaaaaaaaaaa', 1, 'deleted', 1)",
      },
    ]);
    const decision = await a.sync.resolver.resolve(read());
    expect(decision).toMatchObject({
      kind: "view",
      served: { scope: LOG, version: 1 },
    });
    if (decision.kind === "view") {
      expect(await new Response(decision.body).json()).toMatchObject({
        data: { records: [{ id: 1, v: 1 }] },
      });
    }
    expect(await a.position()).toBe(1);
  });
  it("publishes the first local image before charging a new connection", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("first", [{ stream: "s0", id: 1, v: 1 }]);
    const decision = await a.sync.resolver.resolve(read());
    expect(decision).toMatchObject({
      kind: "view",
      served: { scope: LOG, version: 1 },
    });
    if (decision.kind === "view") await decision.body.cancel();
  });
  it("honors the request's existing abort signal without publishing", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("first", [{ stream: "s0", id: 1, v: 1 }]);
    await a.sync.publish();
    await a.run("second", [{ stream: "s0", id: 1, v: 2 }]);
    const post = vi.spyOn(a.deps.registry, "postBatch");
    const decision = await a.sync.resolver.resolve({
      ...read(),
      signal: AbortSignal.abort(),
    });
    expect(decision).toMatchObject({ kind: "read_aborted" });
    expect(post).not.toHaveBeenCalled();
  });
  it("binds a covered stream to the accepted log position, not its local counter", async () => {
    const w = await world({ streams: 2 });
    const a = await w.device("a");
    await a.run("first", [
      { stream: "s0", id: 1, v: 1 },
      { stream: "s1", id: 1, v: 1 },
    ]);
    await a.sync.publish();
    await a.run("second", [{ stream: "s1", id: 1, v: 2 }], {
      selected: ["s1"],
    });
    await a.sync.publish();
    const decision = await a.sync.resolver.resolve(read());
    expect(decision).toMatchObject({
      kind: "view",
      served: { scope: LOG, version: 2 },
    });
    if (decision.kind === "view") await payRegisteredView(decision.served!);
    if (decision.kind === "view")
      expect(await new Response(decision.body).json()).toMatchObject({
        scope: "pdpp.fixture.s0",
        data: { records: [{ id: 1, v: 1 }] },
      });
  });

  it("publishes a newer local row before choosing the receipt position", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("first", [{ stream: "s0", id: 1, v: 1 }]);
    await a.sync.publish();
    await a.run("second", [{ stream: "s0", id: 1, v: 2 }]);
    const decision = await a.sync.resolver.resolve(read());
    expect(decision).toMatchObject({
      kind: "view",
      served: { scope: LOG, version: 2 },
    });
    expect(await a.position()).toBe(2);
    if (decision.kind === "view")
      expect(await new Response(decision.body).json()).toMatchObject({
        data: { records: [{ id: 1, v: 2 }] },
      });
  });

  it("refuses rather than attest an old position when publication fails", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("first", [{ stream: "s0", id: 1, v: 1 }]);
    await a.sync.publish();
    await a.run("second", [{ stream: "s0", id: 1, v: 2 }]);
    vi.spyOn(a.deps.registry, "postBatch").mockRejectedValue(
      new Error("offline"),
    );
    expect(await a.sync.resolver.resolve(read())).toMatchObject({
      kind: "read_not_registered",
    });
    expect(await a.position()).toBe(1);
  });

  it("checks every alias input, including a child stream whose head did not advance", async () => {
    const w = await world({ streams: 2 });
    const a = await w.device("a");
    await a.run("first", [
      { stream: "s0", id: 1, v: 1 },
      { stream: "s1", id: 1, v: 1 },
    ]);
    await a.sync.publish();
    await a.run("second", [{ stream: "s1", id: 1, v: 2 }], {
      selected: ["s1"],
    });
    vi.spyOn(a.deps.registry, "postBatch").mockRejectedValue(
      new Error("offline"),
    );
    const resolver = createLocalResolver(a.deps, {
      query: a.sync.query,
      aliasQuery: a.sync.query,
      aliasScopes: () => ["fixture.alias"],
      aliasTargets: () => [
        {
          connector: "fixture",
          streams: ["s0", "s1"],
          project: () => ({ ok: true, payload: {} }),
        },
      ],
    });
    expect(await resolver.resolve(read("fixture.alias"))).toMatchObject({
      kind: "read_not_registered",
    });
  });

  it("refuses a deleted logical stream without trying publication", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("first", [{ stream: "s0", id: 1, v: 1 }]);
    await a.sync.publish();
    await a.db.batch([
      { sql: "UPDATE stream_state SET last_delete_version=head_version" },
    ]);
    const post = vi.spyOn(a.deps.registry, "postBatch");
    expect(await a.sync.resolver.resolve(read())).toMatchObject({
      kind: "unavailable",
      reason: "deleted",
    });
    expect(post).not.toHaveBeenCalled();
  });
});

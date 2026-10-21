import { afterEach, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { createOwnerComposition } from "./pdpp-replica-owner-composition.js";
import {
  computeS256Challenge,
  PDPP_DATA_ACCESS_TYPE_V02,
} from "@opendatalabs/personal-server-ts-core/pdpp";

const roots: string[] = [];
const hosts: Awaited<ReturnType<typeof createOwnerComposition>>[] = [];
afterEach(async () => {
  for (const host of hosts.splice(0)) await host.close();
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});
const origin = "http://127.0.0.1:3286";
const accountOrigin = "http://localhost:3084";
async function setup() {
  const root = mkdtempSync(join(homedir(), ".tmp/composition-test-"));
  roots.push(root);
  const owner = createTestWallet(0);
  const host = await createOwnerComposition({
    root,
    owner: owner.address,
    origin,
    accountOrigin,
    clientId: "exact-requester",
    redirectUri: "http://localhost:3284/callback",
  });
  hosts.push(host);
  return { host, owner };
}
const sourceId = "https://replica-journey.invalid/declaration";

it("refuses owner token issuance without normal wallet proof and requires a signed source body", async () => {
  const { host, owner } = await setup();
  const path = "/pdpp/v1/owner/token";
  const body = JSON.stringify({ source_id: sourceId });
  for (const authorization of [undefined, "Bearer fake", "Web3Signed 0x00"]) {
    const response = await host.app.request(path, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(authorization && { authorization }),
      },
      body,
    });
    expect(response.status).toBe(401);
  }
  const authorization = await buildWeb3SignedHeader({
    wallet: owner,
    aud: origin,
    method: "POST",
    uri: path,
    body: new TextEncoder().encode(body),
  });
  const valid = await host.app.request(path, {
    method: "POST",
    headers: { authorization, "content-type": "application/json" },
    body,
  });
  expect(valid.status).toBe(200);
  const credential = (await valid.json()).access_token;
  expect(typeof credential).toBe("string");
  const state = JSON.stringify(
    await (await host.app.request("/composition/state")).json(),
  );
  expect(state).not.toContain(credential);
  expect(JSON.parse(state).owner_proof_received).toBe(true);
  const missingBody = JSON.stringify({});
  const missingProof = await buildWeb3SignedHeader({
    wallet: owner,
    aud: origin,
    method: "POST",
    uri: path,
    body: new TextEncoder().encode(missingBody),
  });
  expect(
    (
      await host.app.request(path, {
        method: "POST",
        headers: {
          authorization: missingProof,
          "content-type": "application/json",
        },
        body: missingBody,
      })
    ).status,
  ).toBe(400);
  const foreignProof = await buildWeb3SignedHeader({
    wallet: createTestWallet(1),
    aud: origin,
    method: "POST",
    uri: path,
    body: new TextEncoder().encode(body),
  });
  expect(
    (
      await host.app.request(path, {
        method: "POST",
        headers: {
          authorization: foreignProof,
          "content-type": "application/json",
        },
        body,
      })
    ).status,
  ).toBe(401);
});

it("accepts only fixed owner signatures once, including concurrent submissions, with exact Account CORS", async () => {
  const { host, owner } = await setup();
  const requests = (await (await host.app.request("/composition/state")).json())
    .signing_requests;
  expect(requests).toHaveLength(3);
  const send = (body: unknown, from = accountOrigin) =>
    host.app.request("/composition/signatures", {
      method: "POST",
      headers: { origin: from, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  const master = requests.find(
    (r: { method: string }) => r.method === "personal_sign",
  );
  expect((await send({ request_id: master.request_id })).status).toBe(400);
  expect(
    (
      await send({
        request_id: master.request_id,
        signature: await createTestWallet(1).signMessage(master.message),
      })
    ).status,
  ).toBe(401);
  const signature = await owner.signMessage(master.message);
  expect(
    (
      await send(
        { request_id: master.request_id, signature },
        "http://evil.invalid",
      )
    ).status,
  ).toBe(403);
  expect(
    (
      await send({
        request_id: master.request_id,
        signature,
        message: "arbitrary",
      })
    ).status,
  ).toBe(400);
  const results = await Promise.all([
    send({ request_id: master.request_id, signature }),
    send({ request_id: master.request_id, signature }),
  ]);
  expect(results.map((r) => r.status).sort()).toEqual([200, 409]);
  expect(
    (await send({ request_id: master.request_id, signature })).status,
  ).toBe(409);
  for (const request of requests.filter(
    (r: { method: string }) => r.method === "eth_signTypedData_v4",
  )) {
    const signed = await owner.signTypedData(request.typed_data);
    expect(
      (await send({ request_id: request.request_id, signature: signed }))
        .status,
    ).toBe(200);
    const state = await (await host.app.request("/composition/state")).text();
    expect(state).not.toContain(signed);
    expect(state).not.toContain(signature);
  }
  expect(
    (await (await host.app.request("/composition/state")).json())
      .signing_requests,
  ).toEqual([]);
});

it("uses one configured issuer, exact registered callback and PKCE; never proxies writes or arbitrary paths", async () => {
  const { host, owner } = await setup();
  const metadata = await (
    await host.app.request("/.well-known/oauth-authorization-server/pdpp/v1")
  ).json();
  expect(metadata.issuer).toBe(origin);
  expect(metadata.token_endpoint).toBe(origin + "/pdpp/v1/token");
  expect(metadata.code_challenge_methods_supported).toEqual(["S256"]);
  expect(
    (await host.app.request("/pdpp/v1/streams/messages/records")).status,
  ).toBe(503);
  expect(
    (
      await host.app.request("/pdpp/v1/streams/messages/records/ingest", {
        method: "POST",
      })
    ).status,
  ).toBe(404);
  expect((await host.app.request("/pdpp/v1/arbitrary")).status).toBe(404);
  const body = JSON.stringify({ source_id: sourceId });
  const proof = await buildWeb3SignedHeader({
    wallet: owner,
    aud: origin,
    method: "POST",
    uri: "/pdpp/v1/owner/token",
    body: new TextEncoder().encode(body),
  });
  const token = (
    await (
      await host.app.request("/pdpp/v1/owner/token", {
        method: "POST",
        headers: { authorization: proof, "content-type": "application/json" },
        body,
      })
    ).json()
  ).access_token;
  const request = {
    client_id: "exact-requester",
    redirect_uri: "http://localhost:3284/callback",
    state: "real-test",
    code_challenge: computeS256Challenge(
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    ),
    code_challenge_method: "S256",
    authorization_details: [
      {
        type: PDPP_DATA_ACCESS_TYPE_V02,
        source: { id: sourceId },
        purpose_code: "https://replica-app.invalid/purposes/acceptance",
        access_mode: "continuous",
        retention: { max_duration: "P1D", on_expiry: "delete" },
        streams: [
          {
            name: "messages",
            necessity: "required",
            fields: ["text", "collected_at", "blob_ref"],
            minimum: { fields: ["text"] },
          },
        ],
      },
    ],
  };
  const authorize = (selection: unknown) =>
    host.app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(selection),
    });
  expect(
    (
      await authorize({
        ...request,
        redirect_uri: "http://localhost:3284/callback?unregistered=true",
      })
    ).status,
  ).toBe(400);
  expect(
    (await authorize({ ...request, client_id: "unregistered-requester" }))
      .status,
  ).toBe(400);
  expect(
    (await authorize({ ...request, code_challenge: undefined })).status,
  ).toBe(400);
  expect((await authorize(request)).status).toBe(201);
});

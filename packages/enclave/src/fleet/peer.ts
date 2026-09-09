import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  type KeyObject,
} from "node:crypto";
import type { DstackClient } from "../dstack/client.js";
import type { FleetPeerIdentity, FleetWorkerPort } from "./contracts.js";
export interface FleetPeerEvidence {
  quote: string;
  eventLog?: string;
}
export type FleetPeerVerifier = (
  evidence: FleetPeerEvidence,
  reportData: Uint8Array,
  identity: FleetPeerIdentity,
) => Promise<void>;
interface Hello {
  identity: FleetPeerIdentity;
  publicKey: string;
  nonce: string;
}
interface Challenge {
  client: Hello;
  server: Hello;
  sessionId: string;
}
interface Packet {
  ciphertext: string;
  tag: string;
}
interface PeerOptions {
  identity: FleetPeerIdentity;
  client: DstackClient;
  verifyPeer: FleetPeerVerifier;
}
const HANDSHAKE_MS = 30_000;
const MAX_BYTES = 8 * 1024 * 1024;
async function beforeDeadline<T>(
  operation: Promise<T>,
  deadline: number,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new Error("Peer deadline expired")),
          Math.max(0, deadline - Date.now()),
        );
        timer.unref();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function hello(identity: FleetPeerIdentity): { hello: Hello; key: KeyObject } {
  const keys = generateKeyPairSync("x25519");
  return {
    hello: {
      identity,
      publicKey: keys.publicKey
        .export({ type: "spki", format: "der" })
        .toString("base64"),
      nonce: randomBytes(32).toString("hex"),
    },
    key: keys.privateKey,
  };
}
function digest(c: Challenge): Buffer {
  return createHash("sha512")
    .update("vana.fleet.peer.v1\0")
    .update(JSON.stringify(c))
    .digest();
}
function keys(
  privateKey: KeyObject,
  remote: Hello,
  c: Challenge,
): { request: Buffer; response: Buffer } {
  const publicKey = createPublicKey({
    key: Buffer.from(remote.publicKey, "base64"),
    type: "spki",
    format: "der",
  });
  if (publicKey.asymmetricKeyType !== "x25519")
    throw new Error("Invalid peer key");
  const secret = diffieHellman({ privateKey, publicKey });
  try {
    return {
      request: Buffer.from(
        hkdfSync("sha256", secret, digest(c), "vana.fleet.request.v1", 32),
      ),
      response: Buffer.from(
        hkdfSync("sha256", secret, digest(c), "vana.fleet.response.v1", 32),
      ),
    };
  } finally {
    secret.fill(0);
  }
}
function encrypt(value: unknown, key: Buffer, aad: Buffer): Packet {
  // Each fresh handshake permits exactly one message in each direction. Keys
  // are domain separated; the fixed nonce is never reused under the same key.
  const cipher = createCipheriv("aes-256-gcm", key, Buffer.alloc(12));
  cipher.setAAD(aad);
  const clear = Buffer.from(JSON.stringify(value));
  try {
    if (clear.length > MAX_BYTES) throw new Error("Peer body too large");
    return {
      ciphertext: Buffer.concat([
        cipher.update(clear),
        cipher.final(),
      ]).toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
    };
  } finally {
    clear.fill(0);
  }
}
function decrypt(packet: Packet, key: Buffer, aad: Buffer): unknown {
  if (
    typeof packet.ciphertext !== "string" ||
    packet.ciphertext.length > MAX_BYTES * 1.4
  )
    throw new Error("Invalid peer packet");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.alloc(12));
  decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(packet.tag, "base64"));
  const clear = Buffer.concat([
    decipher.update(Buffer.from(packet.ciphertext, "base64")),
    decipher.final(),
  ]);
  try {
    return JSON.parse(clear.toString());
  } finally {
    clear.fill(0);
  }
}
async function evidence(
  client: DstackClient,
  c: Challenge,
): Promise<FleetPeerEvidence> {
  const q = await client.quote(digest(c));
  return {
    quote: Buffer.from(q.quote).toString("base64"),
    ...(q.eventLog ? { eventLog: q.eventLog } : {}),
  };
}
async function json(request: Request): Promise<unknown> {
  const reader = request.body?.getReader();
  if (!reader) throw new Error("Missing body");
  let size = 0;
  const chunks: Uint8Array[] = [];
  try {
    for (;;) {
      const result = await reader.read();
      if (result.done) break;
      size += result.value.length;
      if (size > MAX_BYTES * 1.5) {
        await reader.cancel();
        throw new Error("Peer body too large");
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  return JSON.parse(Buffer.concat(chunks).toString());
}
/** Dedicated listener; no bearer/plaintext RPC fallback. One-shot sessions avoid replay and nonce reuse. */
export function createFleetPeerServer(
  options: PeerOptions & {
    dispatch: (
      method: string,
      body: unknown,
      peer: FleetPeerIdentity,
    ) => Promise<unknown>;
  },
): (request: Request) => Promise<Response> {
  const sessions = new Map<
    string,
    { challenge: Challenge; key: KeyObject; expires: number }
  >();
  return async (request) => {
    try {
      if (request.method !== "POST") return new Response(null, { status: 404 });
      const path = new URL(request.url).pathname;
      if (path === "/fleet-peer/v1/challenge") {
        for (const [id, s] of sessions)
          if (s.expires <= Date.now()) sessions.delete(id);
        if (sessions.size >= 256) return new Response(null, { status: 429 });
        const client = (await json(request)) as Hello;
        if (
          !client?.identity ||
          typeof client.nonce !== "string" ||
          !/^[a-f0-9]{64}$/.test(client.nonce) ||
          typeof client.publicKey !== "string" ||
          client.publicKey.length > 256
        )
          throw new Error("Invalid hello");
        const local = hello(options.identity);
        const challenge = {
          client,
          server: local.hello,
          sessionId: randomBytes(32).toString("hex"),
        };
        sessions.set(challenge.sessionId, {
          challenge,
          key: local.key,
          expires: Date.now() + HANDSHAKE_MS,
        });
        return Response.json({
          challenge,
          evidence: await evidence(options.client, challenge),
        });
      }
      if (path !== "/fleet-peer/v1/call")
        return new Response(null, { status: 404 });
      const body = (await json(request)) as {
        sessionId: string;
        evidence: FleetPeerEvidence;
        packet: Packet;
      };
      const session = sessions.get(body.sessionId);
      sessions.delete(body.sessionId);
      if (!session || session.expires <= Date.now())
        throw new Error("Expired/replayed session");
      await beforeDeadline(
        options.verifyPeer(
          body.evidence,
          digest(session.challenge),
          session.challenge.client.identity,
        ),
        session.expires,
      );
      if (session.expires <= Date.now()) throw new Error("Attestation expired");
      const shared = keys(
        session.key,
        session.challenge.client,
        session.challenge,
      );
      try {
        const call = decrypt(
          body.packet,
          shared.request,
          digest(session.challenge),
        ) as { method: string; body: unknown };
        if (typeof call.method !== "string")
          throw new Error("Invalid RPC method");
        const result =
          call.method === "describe"
            ? { identity: options.identity }
            : await options.dispatch(
                call.method,
                call.body,
                session.challenge.client.identity,
              );
        return Response.json({
          packet: encrypt(result, shared.response, digest(session.challenge)),
        });
      } finally {
        shared.request.fill(0);
        shared.response.fill(0);
      }
    } catch {
      return Response.json({ error: "peer_request_rejected" }, { status: 403 });
    }
  };
}
export function createFleetPeerClient(
  options: PeerOptions & {
    baseUrl: string;
    expectedPeer?: FleetPeerIdentity;
    fetch?: typeof fetch;
  },
) {
  const base = new URL(options.baseUrl);
  if (base.protocol !== "https:")
    throw new Error("Peer reachability must use HTTPS");
  const post = async (path: string, body: unknown, deadline: number) => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error("Peer RPC deadline expired");
    const response = await (options.fetch ?? fetch)(new URL(path, base), {
      method: "POST",
      redirect: "error",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(remaining),
    });
    if (!response.ok) throw new Error("Peer rejected request");
    return json(
      new Request("https://peer-response.invalid", {
        method: "POST",
        body: response.body,
        duplex: "half",
      } as RequestInit),
    );
  };
  return {
    async call<T = unknown>(method: string, body: unknown): Promise<T> {
      const started = Date.now();
      const budget =
        method === "renew"
          ? 8_000
          : method === "describe"
            ? 30_000
            : [
                  "activity",
                  "readiness",
                  "worker.identity",
                  "worker.seal",
                ].includes(method)
              ? 20_000
              : 120_000;
      const deadline = started + budget;
      const local = hello(options.identity);
      const received = (await post(
        "/fleet-peer/v1/challenge",
        local.hello,
        Math.min(deadline, started + HANDSHAKE_MS),
      )) as { challenge: Challenge; evidence: FleetPeerEvidence };
      const c = received.challenge;
      if (
        JSON.stringify(c.client) !== JSON.stringify(local.hello) ||
        typeof c.sessionId !== "string" ||
        !/^[a-f0-9]{64}$/.test(c.sessionId)
      )
        throw new Error("Peer handshake substitution");
      await beforeDeadline(
        options.verifyPeer(received.evidence, digest(c), c.server.identity),
        Math.min(deadline, started + HANDSHAKE_MS),
      );
      if (options.expectedPeer) {
        if (
          Object.entries(options.expectedPeer).some(
            ([key, value]) =>
              c.server.identity[key as keyof FleetPeerIdentity] !== value,
          )
        )
          throw new Error("Unexpected peer destination");
      } else if (method !== "describe") {
        throw new Error("An exact peer destination is required for RPC");
      }
      if (Date.now() - started >= HANDSHAKE_MS)
        throw new Error("Attestation expired");
      const proof = await beforeDeadline(
        evidence(options.client, c),
        Math.min(deadline, started + HANDSHAKE_MS),
      );
      if (Date.now() >= Math.min(deadline, started + HANDSHAKE_MS))
        throw new Error("Peer handshake deadline expired");
      const shared = keys(local.key, c.server, c);
      try {
        const result = (await post(
          "/fleet-peer/v1/call",
          {
            sessionId: c.sessionId,
            evidence: proof,
            packet: encrypt({ method, body }, shared.request, digest(c)),
          },
          deadline,
        )) as { packet: Packet };
        return decrypt(result.packet, shared.response, digest(c)) as T;
      } finally {
        shared.request.fill(0);
        shared.response.fill(0);
      }
    },
  };
}
export function fleetWorkerPort(
  client: ReturnType<typeof createFleetPeerClient>,
): FleetWorkerPort {
  return {
    activity: (a) => client.call("activity", a),
    prepare: (r) => client.call("prepare", r),
    readiness: (r) => client.call("readiness", r),
    renew: (a) => client.call("renew", a),
    execute: (r) => client.call("execute", r),
    release: (a) => client.call("release", a),
  };
}

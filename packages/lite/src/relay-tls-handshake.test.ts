import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { Duplex } from "node:stream";
import tls from "node:tls";
import forge from "node-forge";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  initSync,
  TlsServer,
} from "./browser-tls-rustls/browser_tls_rustls.js";

/**
 * Real TLS against the committed `browser_tls_rustls_bg.wasm`, with no mock.
 * A Node `tls.connect` client talks to the wasm `TlsServer` through the same
 * byte pump `relay-tls.ts` and `relay.ts` use: ciphertext in through
 * `process_tls`, plaintext out through `write_plaintext`, and every `tls`
 * byte the server returns goes back to the client. This pins the behavior the
 * relay depends on, so a rebuilt binary must reproduce it.
 */

interface Step {
  plaintext: Uint8Array;
  tls: Uint8Array;
  handshaking: boolean;
}

interface Identity {
  name: string;
  certPem: string;
  keyPem: string;
}

const NEWLINE = 0x0a;
const DEFAULT_INPUT_PIECE_BYTES = 1024;
// relay.ts writes responses in chunks of this size and closes on the last one.
const RESPONSE_CHUNK_BYTES = 16 * 1024;

beforeAll(() => {
  initSync({
    module: readFileSync(
      new URL(
        "./browser-tls-rustls/browser_tls_rustls_bg.wasm",
        import.meta.url,
      ),
    ),
  });
});

/** Request body with no newline except the last byte, so the server knows when it is complete. */
function makeRequest(size: number): Buffer {
  const body = Buffer.alloc(size);
  for (let i = 0; i < size - 1; i += 1) {
    const byte = (i * 31 + 7) % 256;
    body[i] = byte === NEWLINE ? NEWLINE + 1 : byte;
  }
  body[size - 1] = NEWLINE;
  return body;
}

function pem(label: string, der: Buffer): string {
  const lines = der.toString("base64").match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

function der(tag: number, ...parts: Buffer[]): Buffer {
  const body = Buffer.concat(parts);
  const length =
    body.length < 0x80
      ? Buffer.from([body.length])
      : Buffer.from([0x82, body.length >> 8, body.length & 0xff]);
  return Buffer.concat([Buffer.from([tag]), length, body]);
}

function utcTime(date: Date): Buffer {
  const text = date
    .toISOString()
    .replace(/[-:T]/g, "")
    .replace(/\.\d+Z$/, "Z")
    .slice(2);
  return der(0x17, Buffer.from(text, "ascii"));
}

/** Self-signed ECDSA P-256 certificate for `localhost`, built with node:crypto only. */
function ecIdentity(name: string, keyFormat: "pkcs8" | "sec1"): Identity {
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const ecdsaWithSha256 = der(
    0x30,
    der(0x06, Buffer.from("2a8648ce3d040302", "hex")),
  );
  const subject = der(
    0x30,
    der(
      0x31,
      der(
        0x30,
        der(0x06, Buffer.from("550403", "hex")),
        der(0x0c, Buffer.from("localhost", "ascii")),
      ),
    ),
  );
  const notBefore = new Date(Date.now() - 60_000);
  const notAfter = new Date(Date.now() + 24 * 60 * 60 * 1000);
  const subjectAltName = der(
    0xa3,
    der(
      0x30,
      der(
        0x30,
        der(0x06, Buffer.from("551d11", "hex")),
        der(0x04, der(0x30, der(0x82, Buffer.from("localhost", "ascii")))),
      ),
    ),
  );
  const tbs = der(
    0x30,
    der(0xa0, der(0x02, Buffer.from([2]))),
    der(0x02, Buffer.from([1])),
    ecdsaWithSha256,
    subject,
    der(0x30, utcTime(notBefore), utcTime(notAfter)),
    subject,
    publicKey.export({ type: "spki", format: "der" }),
    subjectAltName,
  );
  const signature = sign("sha256", tbs, privateKey);
  const certificate = der(
    0x30,
    tbs,
    ecdsaWithSha256,
    der(0x03, Buffer.concat([Buffer.from([0]), signature])),
  );
  return {
    name,
    certPem: pem("CERTIFICATE", certificate),
    keyPem: exportKey(privateKey, keyFormat),
  };
}

function exportKey(key: KeyObject, format: "pkcs8" | "sec1"): string {
  return key.export({ type: format, format: "pem" }).toString();
}

/** The same shape relay-tls.ts produces for its self-signed fallback: a PKCS#1 RSA key. */
function rsaIdentity(): Identity {
  const keys = forge.pki.rsa.generateKeyPair({ bits: 2048 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + 24 * 60 * 60 * 1000);
  const attrs = [{ name: "commonName", value: "localhost" }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: "basicConstraints", cA: false },
    { name: "keyUsage", digitalSignature: true, keyEncipherment: true },
    { name: "extKeyUsage", serverAuth: true },
    { name: "subjectAltName", altNames: [{ type: 2, value: "localhost" }] },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return {
    name: "rsa-pkcs1",
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

interface EchoResult {
  echoed: Buffer;
  steps: Step[];
  protocol: string | null;
  authorized: boolean;
  /** The client saw the server's close_notify (a clean end), not a reset. */
  endedCleanly: boolean;
  clientError: Error | undefined;
}

/**
 * Handshake, send `request`, read back an echo, and close.
 *
 * The client's ciphertext reaches `process_tls` in pieces of at most
 * `inputPieceBytes`. The default is small enough for every build of the
 * binary. `Infinity` with `coalesce` delivers several TLS records in ONE
 * `process_tls` call, like a relay frame that carries more than one record.
 */
async function echoThroughWasm(
  identity: Identity,
  options: {
    maxVersion: "TLSv1.2" | "TLSv1.3";
    request: Buffer;
    inputPieceBytes?: number;
    coalesce?: boolean;
  },
): Promise<EchoResult> {
  const server = new TlsServer(identity.certPem, identity.keyPem);
  const steps: Step[] = [];
  let received = Buffer.alloc(0);
  let responded = false;

  const pieceBytes = options.inputPieceBytes ?? DEFAULT_INPUT_PIECE_BYTES;
  const serve = (pipe: Duplex, ciphertext: Buffer) => {
    for (let at = 0; at < ciphertext.length; at += pieceBytes) {
      servePiece(pipe, ciphertext.subarray(at, at + pieceBytes));
    }
  };
  const servePiece = (pipe: Duplex, ciphertext: Buffer) => {
    const step = server.process_tls(new Uint8Array(ciphertext)) as Step;
    steps.push(step);
    if (step.tls.length > 0) pipe.push(Buffer.from(step.tls));
    received = Buffer.concat([received, step.plaintext]);
    if (responded || received.at(-1) !== NEWLINE) return;
    responded = true;
    for (let at = 0; at < received.length; at += RESPONSE_CHUNK_BYTES) {
      const chunk = received.subarray(at, at + RESPONSE_CHUNK_BYTES);
      const last = at + RESPONSE_CHUNK_BYTES >= received.length;
      const out = server.write_plaintext(new Uint8Array(chunk), last) as Step;
      if (out.tls.length > 0) pipe.push(Buffer.from(out.tls));
    }
  };

  const pipe = new Duplex({
    read() {},
    write(chunk: Buffer, _encoding, callback) {
      try {
        serve(pipe, chunk);
      } catch (error) {
        callback(error as Error);
        return;
      }
      if (options.coalesce) setImmediate(callback);
      else callback();
    },
    writev(chunks, callback) {
      try {
        serve(pipe, Buffer.concat(chunks.map(({ chunk }) => chunk as Buffer)));
      } catch (error) {
        callback(error as Error);
        return;
      }
      callback();
    },
    final(callback) {
      pipe.push(null);
      callback();
    },
  });

  const client = tls.connect({
    socket: pipe,
    servername: "localhost",
    ca: identity.certPem,
    minVersion: options.maxVersion,
    maxVersion: options.maxVersion,
  });

  const echoed: Buffer[] = [];
  let protocol: string | null = null;
  let authorized = false;
  let endedCleanly = false;
  let clientError: Error | undefined;
  const done = new Promise<void>((resolve) => {
    client.on("secureConnect", () => {
      protocol = client.getProtocol();
      authorized = client.authorized;
      client.write(options.request);
    });
    client.on("data", (data: Buffer) => echoed.push(data));
    client.on("end", () => {
      endedCleanly = clientError === undefined;
      client.end();
    });
    client.on("error", (error) => {
      clientError = error;
    });
    client.on("close", () => resolve());
  });
  const timer = setTimeout(
    () => client.destroy(new Error("TLS echo timed out")),
    10_000,
  );
  await done;
  clearTimeout(timer);
  const result: EchoResult = {
    echoed: Buffer.concat(echoed),
    steps,
    protocol,
    authorized,
    endedCleanly,
    clientError,
  };
  server.free();
  return result;
}

describe("browser TLS server (real wasm, real TLS client)", () => {
  const identities: Identity[] = [];
  beforeAll(() => {
    identities.push(
      rsaIdentity(),
      ecIdentity("ec-pkcs8", "pkcs8"),
      ecIdentity("ec-sec1", "sec1"),
    );
  });
  afterAll(() => {
    identities.length = 0;
  });

  const cases = [
    ["rsa-pkcs1", "TLSv1.3"],
    ["rsa-pkcs1", "TLSv1.2"],
    ["ec-pkcs8", "TLSv1.3"],
    ["ec-pkcs8", "TLSv1.2"],
    ["ec-sec1", "TLSv1.3"],
  ] as const;

  it.each(cases)(
    "%s over %s: handshakes, echoes 100 KB, and closes with close_notify",
    async (name, maxVersion) => {
      const identity = identities.find((entry) => entry.name === name)!;
      const request = makeRequest(100_000);

      const result = await echoThroughWasm(identity, { maxVersion, request });

      expect(result.clientError).toBeUndefined();
      expect(result.protocol).toBe(maxVersion);
      expect(result.authorized).toBe(true);
      expect(result.echoed.equals(request)).toBe(true);
      expect(result.endedCleanly).toBe(true);

      // The shape relay-tls.ts reads: byte arrays and a boolean, per step.
      for (const step of result.steps) {
        expect(Object.keys(step).sort()).toEqual(
          ["handshaking", "plaintext", "tls"].sort(),
        );
        expect(step.plaintext).toBeInstanceOf(Uint8Array);
        expect(step.tls).toBeInstanceOf(Uint8Array);
        expect(typeof step.handshaking).toBe("boolean");
      }
      // The server starts mid-handshake and sends its flight before it ends.
      expect(result.steps[0].handshaking).toBe(true);
      expect(result.steps[0].plaintext.length).toBe(0);
      expect(
        result.steps.some((step) => step.handshaking && step.tls.length > 0),
      ).toBe(true);
      // Once the client's Finished arrives, the handshake is over.
      expect(result.steps.some((step) => !step.handshaking)).toBe(true);
      expect(result.steps.at(-1)?.handshaking).toBe(false);
    },
  );

  it("accepts several TLS records in one process_tls call", async () => {
    const identity = identities.find((entry) => entry.name === "ec-pkcs8")!;
    const request = makeRequest(150_000);

    const result = await echoThroughWasm(identity, {
      maxVersion: "TLSv1.3",
      request,
      inputPieceBytes: Infinity,
      coalesce: true,
    });

    expect(result.clientError).toBeUndefined();
    expect(result.echoed.equals(request)).toBe(true);
    expect(result.endedCleanly).toBe(true);
    // Prove the pump delivered more than one record at once.
    expect(result.steps.some((step) => step.plaintext.length > 16 * 1024)).toBe(
      true,
    );
  });

  it("rejects a missing certificate or key with a string error", () => {
    const identity = identities[0];
    for (const [cert, key] of [
      ["", identity.keyPem],
      [identity.certPem, ""],
    ]) {
      let thrown: unknown;
      try {
        new TlsServer(cert, key);
      } catch (error) {
        thrown = error;
      }
      expect(typeof thrown).toBe("string");
    }
  });

  it("throws a string, not a step, for bytes that are not TLS", () => {
    const server = new TlsServer(identities[1].certPem, identities[1].keyPem);
    let thrown: unknown;
    try {
      server.process_tls(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]));
    } catch (error) {
      thrown = error;
    }
    expect(typeof thrown).toBe("string");
    expect(thrown).toMatch(/corrupt message/);
    server.free();
  });
});

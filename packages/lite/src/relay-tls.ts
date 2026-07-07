import forge from "node-forge";
import initRustls, {
  TlsServer as RustlsServer,
} from "./browser-tls-rustls/browser_tls_rustls.js";
import type {
  PsLiteRelayTlsFactory,
  PsLiteRelayTlsPrepareInput,
  PsLiteRelayTlsStep,
  PsLiteRelayTlsStream,
  PsLiteRelayTlsStreamInput,
} from "./relay.js";

const TLS_IDENTITY_CACHE_KEY = "personal-server-lite-tls-identity-v1";
const DEFAULT_PUBLIC_SUFFIX = "34.16.49.200.sslip.io";
const DEFAULT_ISSUE_CERT_TIMEOUT_MS = 60_000;

export interface RustlsPsLiteRelayTlsOptions {
  controlUrl: string;
  publicSuffix?: string;
  certIssuerUrl?: string;
  storage?: Storage;
  logger?: (line: string) => void;
  /**
   * Max time to wait on the relay's /issue-cert endpoint before treating this
   * attempt as failed and serving the self-signed fallback. A hung issuer
   * (observed live, BUI-666: the endpoint accepts the POST and never responds
   * while relay-side ACME is wedged) would otherwise leave the identity
   * promise pending forever — and every incoming TLS handshake awaits that
   * promise, so the public endpoint serves zero bytes while the control
   * session looks healthy.
   *
   * Default 60s. This MUST exceed a real ACME issuance, not undercut it: a
   * genuine DNS-01 issuance takes tens of seconds (measured ~26s live on
   * psrelay; TXT propagation can push it toward a minute). An earlier 8s
   * default (meant to undercut the DCR completion probe) aborted every real
   * issuance before it finished, so the cert was NEVER minted and the endpoint
   * stayed self-signed / unreachable — turning the rare wedged-issuer hang into
   * a guaranteed failure. The completion probe polls (every ~2s for minutes),
   * so the right behavior is to let issuance finish: early probes fail on the
   * self-signed fallback, then once the cert lands the endpoint is reachable
   * and a later probe succeeds. Only a truly wedged issuer (never responds)
   * should hit this timeout, and 60s still bounds that.
   */
  issueCertTimeoutMs?: number;
}

export interface PsLiteRelayTlsIdentity {
  certPem: string;
  keyPem: string;
  hostname: string;
  source: "acme" | "self-signed" | "cached-acme";
  trusted: boolean;
}

let rustlsInitPromise: Promise<unknown> | undefined;

export function createRustlsPsLiteRelayTlsFactory(
  options: RustlsPsLiteRelayTlsOptions,
): PsLiteRelayTlsFactory {
  // Only a TRUSTED (ACME) identity is memoized for the factory's lifetime. A
  // self-signed fallback must NOT be: it means issuance failed on this attempt
  // (no issueToken yet, /issue-cert error, ACME timeout), and locking it in
  // would strand the tab on an untrusted cert forever — even after a reconnect
  // delivers a fresh issueToken (BUI-664). The relay factory outlives every
  // reconnect, so a first-attempt fallback used to pin the whole session to
  // self-signed. Leaving it unmemoized lets the next prepare/createStream retry
  // issuance (or hit the persisted ACME cache once it succeeds).
  let trustedIdentity: PsLiteRelayTlsIdentity | undefined;
  let inFlight: Promise<PsLiteRelayTlsIdentity> | undefined;
  let inFlightToken: string | undefined;

  async function resolveIdentity(
    input: PsLiteRelayTlsPrepareInput,
  ): Promise<PsLiteRelayTlsIdentity> {
    if (trustedIdentity) {
      return trustedIdentity;
    }
    // Coalesce concurrent callers onto one attempt, but clear on settle so a
    // failed (self-signed) attempt doesn't block the next retry. A caller that
    // brings a fresh issueToken must NOT join an in-flight attempt made with
    // different (or no) credentials: that attempt can settle self-signed even
    // though this caller could mint a trusted cert, and the first strict-TLS
    // stream after recovery would still get the untrusted identity. Such a
    // caller starts its own attempt; the superseded one settles harmlessly.
    const token = input.issueToken ?? "";
    if (!inFlight || (token && token !== inFlightToken)) {
      const attempt = createTlsIdentity(input, options).finally(() => {
        if (inFlight === attempt) {
          inFlight = undefined;
          inFlightToken = undefined;
        }
      });
      inFlight = attempt;
      inFlightToken = token;
    }
    const identity = await inFlight;
    if (identity.trusted) {
      trustedIdentity = identity;
    } else if (trustedIdentity) {
      // A concurrent tokened attempt settled trusted while this caller was
      // awaiting a fallback attempt — serve the trusted identity instead of
      // handing one last stream a self-signed cert.
      return trustedIdentity;
    } else {
      options.logger?.(
        `serving self-signed cert for ${identity.hostname}; ACME issuance unavailable this attempt, will retry on the next stream/reconnect`,
      );
    }
    return identity;
  }

  return {
    async prepare(input: PsLiteRelayTlsPrepareInput) {
      await resolveIdentity(input);
    },
    async createStream(input: PsLiteRelayTlsStreamInput) {
      await ensureRustls();
      const identity = await resolveIdentity(input);
      const tls = new RustlsServer(identity.certPem, identity.keyPem);
      return createRustlsStream(tls);
    },
  };
}

export function psLiteRelayPublicHost(
  sessionId: string,
  publicSuffix = DEFAULT_PUBLIC_SUFFIX,
): string {
  return `${sessionId}.${publicSuffix.replace(/^\./, "")}`;
}

export function psLiteRelayPublicUrl(
  sessionId: string,
  publicSuffix = DEFAULT_PUBLIC_SUFFIX,
): string {
  return `https://${psLiteRelayPublicHost(sessionId, publicSuffix)}`;
}

function createRustlsStream(tls: RustlsServer): PsLiteRelayTlsStream {
  return {
    processTls(payload) {
      return normalizeTlsStep(tls.process_tls(payload));
    },
    writePlaintext(payload, endStream) {
      return normalizeTlsStep(tls.write_plaintext(payload, endStream));
    },
    close() {
      tls.free();
    },
  };
}

function ensureRustls() {
  rustlsInitPromise ??= initRustls();
  return rustlsInitPromise;
}

function normalizeTlsStep(value: unknown): PsLiteRelayTlsStep {
  const step = value as Partial<PsLiteRelayTlsStep>;
  return {
    plaintext:
      step.plaintext instanceof Uint8Array ? step.plaintext : new Uint8Array(),
    tls: step.tls instanceof Uint8Array ? step.tls : new Uint8Array(),
    handshaking: Boolean(step.handshaking),
  };
}

async function createTlsIdentity(
  input: PsLiteRelayTlsPrepareInput,
  options: RustlsPsLiteRelayTlsOptions,
): Promise<PsLiteRelayTlsIdentity> {
  const hostname = psLiteRelayPublicHost(input.sessionId, options.publicSuffix);
  const cached = readCachedTlsIdentity(hostname, options.storage);
  if (cached) {
    return cached;
  }

  // Fetch the relay's shared wildcard cert+key for this session (POST
  // /session-cert). This replaces per-session ACME: the relay issues one
  // `*.<suffix>` cert and hands it to every session, so there is no per-session
  // DNS-01 challenge, no TXT-propagation race, and no Let's Encrypt rate-limit
  // exposure. The wildcard SAN covers our `<sessionId>.<suffix>` hostname.
  const wildcard = await requestSessionCertificate({
    issuerUrl: resolveSessionCertUrl(options),
    sessionId: input.sessionId,
    issueToken: input.issueToken ?? "",
    hostname,
    storage: options.storage,
    logger: options.logger,
    timeoutMs: options.issueCertTimeoutMs ?? DEFAULT_ISSUE_CERT_TIMEOUT_MS,
  });
  if (wildcard) {
    return wildcard;
  }

  // Unmemoized self-signed fallback (BUI-664): the relay was unreachable or the
  // wildcard was unavailable this attempt; retry issuance on the next stream.
  const keys = await generateKeyPair();
  const keyPem = forge.pki.privateKeyToPem(keys.privateKey);
  return createSelfSignedIdentity(hostname, keyPem, keys);
}

function generateKeyPair(): Promise<forge.pki.rsa.KeyPair> {
  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair(
      { bits: 2048, workers: -1 },
      (error, keyPair) => {
        if (error || !keyPair) {
          reject(error ?? new Error("failed to generate keypair"));
          return;
        }
        resolve(keyPair);
      },
    );
  });
}

function createCsrPem(hostname: string, keys: forge.pki.rsa.KeyPair) {
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = keys.publicKey;
  csr.setSubject([{ name: "commonName", value: hostname }]);
  csr.setAttributes([
    {
      name: "extensionRequest",
      extensions: [
        {
          name: "subjectAltName",
          altNames: [{ type: 2, value: hostname }],
        },
      ],
    },
  ]);
  csr.sign(keys.privateKey, forge.md.sha256.create());
  return forge.pki.certificationRequestToPem(csr);
}

function createSelfSignedIdentity(
  hostname: string,
  keyPem: string,
  keys: forge.pki.rsa.KeyPair,
): PsLiteRelayTlsIdentity {
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = Array.from(
    crypto.getRandomValues(new Uint8Array(12)),
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + 24 * 60 * 60 * 1000);
  const attrs = [{ name: "commonName", value: hostname }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: "basicConstraints", cA: false },
    { name: "keyUsage", digitalSignature: true, keyEncipherment: true },
    { name: "extKeyUsage", serverAuth: true },
    {
      name: "subjectAltName",
      altNames: [{ type: 2, value: hostname }],
    },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  return {
    certPem: forge.pki.certificateToPem(cert),
    keyPem,
    hostname,
    source: "self-signed",
    trusted: false,
  };
}

interface AcmeIssueRequest {
  issuerUrl: string;
  sessionId: string;
  csrPem: string;
  keyPem: string;
  issueToken: string;
  hostname: string;
  storage?: Storage;
  logger?: (line: string) => void;
  timeoutMs: number;
}

async function requestAcmeCertificate(
  input: AcmeIssueRequest,
): Promise<PsLiteRelayTlsIdentity | undefined> {
  if (!input.issueToken) {
    input.logger?.(
      "ACME issuer token unavailable; using self-signed certificate",
    );
    return undefined;
  }

  try {
    return await withIssueCertTimeout(issueCertificate(input), input.timeoutMs);
  } catch (error) {
    input.logger?.(error instanceof Error ? error.message : String(error));
    input.logger?.(
      "ACME certificate request failed; using self-signed certificate",
    );
    return undefined;
  }
}

async function issueCertificate(
  input: AcmeIssueRequest,
): Promise<PsLiteRelayTlsIdentity | undefined> {
  const response = await fetch(input.issuerUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      sessionId: input.sessionId,
      csrPem: input.csrPem,
      issueToken: input.issueToken,
    }),
    // Belt: cancels the request in flight where supported. The
    // withIssueCertTimeout race is the load-bearing guard — a fetch whose
    // implementation ignores `signal` must still not wedge identity
    // resolution.
    signal: issueCertAbortSignal(input.timeoutMs),
  });

  if (!response.ok) {
    const detail = await response.text();
    input.logger?.(
      `ACME issuer unavailable (${response.status}); using self-signed certificate`,
    );
    input.logger?.(detail.slice(0, 240));
    return undefined;
  }

  const payload = (await response.json()) as { certPem?: string };
  if (!payload.certPem) {
    input.logger?.(
      "ACME issuer returned no certificate; using self-signed certificate",
    );
    return undefined;
  }

  const identity: PsLiteRelayTlsIdentity = {
    certPem: payload.certPem,
    keyPem: input.keyPem,
    hostname: input.hostname,
    source: "acme",
    trusted: true,
  };
  try {
    cacheTlsIdentity(identity, input.storage);
  } catch (error) {
    // A failed cache write (e.g. QuotaExceededError — PS-Lite tabs are
    // heavy localStorage users) must not discard a successful issuance:
    // falling into the outer catch would serve self-signed AND mint a
    // fresh LE cert per stream, burning the duplicate-certificate limit.
    input.logger?.(
      `failed to persist issued certificate (${error instanceof Error ? error.message : String(error)}); continuing with the in-memory identity`,
    );
  }
  return identity;
}

function issueCertAbortSignal(timeoutMs: number): AbortSignal | undefined {
  return typeof AbortSignal !== "undefined" &&
    typeof AbortSignal.timeout === "function"
    ? AbortSignal.timeout(timeoutMs)
    : undefined;
}

function withIssueCertTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(
        new Error(
          `certificate issuer did not respond within ${timeoutMs}ms (hung /issue-cert)`,
        ),
      );
    }, timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

function resolveCertIssuerUrl(options: RustlsPsLiteRelayTlsOptions) {
  if (options.certIssuerUrl) {
    return options.certIssuerUrl.replace(/\/+$/, "");
  }

  const url = new URL(options.controlUrl);
  url.protocol = url.protocol === "wss:" ? "https:" : "http:";
  url.pathname = "/issue-cert";
  url.search = "";
  url.hash = "";
  return url.toString();
}

function resolveSessionCertUrl(options: RustlsPsLiteRelayTlsOptions) {
  const base = options.certIssuerUrl
    ? options.certIssuerUrl.replace(/\/+$/, "").replace(/\/issue-cert$/, "")
    : (() => {
        const url = new URL(options.controlUrl);
        url.protocol = url.protocol === "wss:" ? "https:" : "http:";
        url.pathname = "";
        url.search = "";
        url.hash = "";
        return url.toString().replace(/\/+$/, "");
      })();
  return `${base}/session-cert`;
}

/**
 * Fetch the relay's shared wildcard cert+key for this browser session. Unlike
 * the per-session ACME path, the relay already holds the cert, so this is a
 * fast lookup with no DNS challenge. Returns undefined (self-signed fallback)
 * on any failure, mirroring requestAcmeCertificate.
 */
async function requestSessionCertificate(input: {
  issuerUrl: string;
  sessionId: string;
  issueToken: string;
  hostname: string;
  storage?: Storage;
  logger?: (line: string) => void;
  timeoutMs: number;
}): Promise<PsLiteRelayTlsIdentity | undefined> {
  if (!input.issueToken) {
    input.logger?.(
      "session issue token unavailable; using self-signed certificate",
    );
    return undefined;
  }

  try {
    return await withIssueCertTimeout(fetchSessionCert(input), input.timeoutMs);
  } catch (error) {
    input.logger?.(error instanceof Error ? error.message : String(error));
    input.logger?.(
      "session certificate request failed; using self-signed certificate",
    );
    return undefined;
  }
}

async function fetchSessionCert(input: {
  issuerUrl: string;
  sessionId: string;
  issueToken: string;
  hostname: string;
  storage?: Storage;
  logger?: (line: string) => void;
  timeoutMs: number;
}): Promise<PsLiteRelayTlsIdentity | undefined> {
  const response = await fetch(input.issuerUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      sessionId: input.sessionId,
      issueToken: input.issueToken,
    }),
    signal: issueCertAbortSignal(input.timeoutMs),
  });

  if (!response.ok) {
    const detail = await response.text();
    input.logger?.(
      `session-cert unavailable (${response.status}); using self-signed certificate`,
    );
    input.logger?.(detail.slice(0, 240));
    return undefined;
  }

  const payload = (await response.json()) as {
    certPem?: string;
    keyPem?: string;
  };
  if (!payload.certPem || !payload.keyPem) {
    input.logger?.(
      "session-cert returned no certificate; using self-signed certificate",
    );
    return undefined;
  }

  const identity: PsLiteRelayTlsIdentity = {
    certPem: payload.certPem,
    keyPem: payload.keyPem,
    hostname: input.hostname,
    source: "acme",
    trusted: true,
  };
  try {
    cacheTlsIdentity(identity, input.storage);
  } catch (error) {
    input.logger?.(
      `failed to persist session certificate (${error instanceof Error ? error.message : String(error)}); continuing with the in-memory identity`,
    );
  }
  return identity;
}

function readCachedTlsIdentity(
  hostname: string,
  storage = globalThis.localStorage,
): PsLiteRelayTlsIdentity | undefined {
  try {
    const raw = storage.getItem(`${TLS_IDENTITY_CACHE_KEY}:${hostname}`);
    if (!raw) {
      return undefined;
    }

    const identity = JSON.parse(raw) as PsLiteRelayTlsIdentity;
    if (
      identity.hostname !== hostname ||
      !identity.certPem ||
      !identity.keyPem ||
      identity.source !== "acme"
    ) {
      return undefined;
    }

    const notAfter = firstCertificateNotAfter(identity.certPem);
    if (notAfter.getTime() - Date.now() < 24 * 60 * 60 * 1000) {
      return undefined;
    }

    return {
      ...identity,
      source: "cached-acme",
      trusted: true,
    };
  } catch {
    return undefined;
  }
}

function cacheTlsIdentity(
  identity: PsLiteRelayTlsIdentity,
  storage = globalThis.localStorage,
) {
  if (identity.source !== "acme") {
    return;
  }
  storage.setItem(
    `${TLS_IDENTITY_CACHE_KEY}:${identity.hostname}`,
    JSON.stringify(identity),
  );
}

function firstCertificateNotAfter(certPem: string) {
  const match = certPem.match(
    /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/,
  );
  if (!match) {
    return new Date(0);
  }
  return forge.pki.certificateFromPem(match[0]).validity.notAfter;
}

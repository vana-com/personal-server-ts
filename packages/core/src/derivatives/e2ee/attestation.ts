/**
 * Attested key fetch for E2EE v2: GET `/aci/attestation?nonce=<64 hex>` on
 * the inference base URL (the Vana relay in production, which must pass the
 * route through unchanged), verify the ACI binding chain structurally, and
 * select the X25519 E2EE key from the quote-bound keyset.
 *
 * The fetch through the relay carries the same `Authorization: Web3Signed`
 * header the chat completion does (GET, no body) when a `requestSigner` is
 * configured, since the relay gates its passthrough routes on the caller
 * being the owner or an active registered server. The direct Phala fallback
 * is a different origin with no such gate and stays unsigned.
 *
 * What is verified here (ACI spec sections 3.1, 3.2, 4, 9.1):
 *   - api_version aci/1, tee_type tdx, service advertises E2EE version 2
 *   - sha256(JCS(workload_keyset)) equals workload_keyset_digest
 *   - sha256 of the section 3.2 statement built from that digest and OUR
 *     nonce equals attestation.report_data (freshness + keyset binding)
 *   - the TDX evidence's quote_report_data carries report_data zero-padded
 *   - now < not_after, and not_after is not implausibly far away
 *   - the selected key has the X25519 suite algo and a 32-byte public key
 *
 * What is NOT verified here: the hardware quote itself (DCAP/TDX signature
 * chain to the Intel root, RTMR replay, compose-hash provenance). That is
 * the `verifyEvidence` hook: the Node server can plug in a DCAP verifier
 * (e.g. @phala/aci-verifier); without it the key is trusted on the TLS
 * origin of the report plus the structural chain above.
 * TODO(e2ee-quote-verification): wire a DCAP quote verifier in the server.
 */

import type { RequestSigner } from "../../signing/request-signer.js";
import { canonicalJsonBytes } from "./jcs.js";
import {
  E2EE_ALGO_X25519,
  bytesToHex,
  parseX25519PublicKey,
  randomBytes,
} from "./suite.js";

export const ACI_API_VERSION = "aci/1";
export const ACI_REPORT_DATA_PURPOSE = "aci.report_data.v1";
export const E2EE_VERSION = "2";
/** The relay-independent origin of the Phala gateway, used as a fallback. */
export const PHALA_GATEWAY_BASE_URL = "https://inference.phala.com/v1";

const MAX_KEYSET_LIFETIME_S = 400 * 24 * 3600;
const DEFAULT_FETCH_TIMEOUT_MS = 15_000;

export interface AciKeysetEntry {
  key_id: string;
  algo: string;
  public_key: string;
}

export interface AciWorkloadKeyset {
  subject: string | null;
  not_after: number;
  receipt_signing_keys: AciKeysetEntry[];
  e2ee_public_keys: AciKeysetEntry[];
  tls_public_keys: Array<{ spki_sha256: string; domain?: string }>;
  [key: string]: unknown;
}

export interface AciAttestationReport {
  api_version: string;
  workload_keyset_digest: string;
  attestation: {
    tee_type: string;
    workload_keyset: AciWorkloadKeyset;
    report_data: string;
    source_provenance?: Record<string, unknown> | null;
    evidence?: Record<string, unknown>;
    [key: string]: unknown;
  };
  service_capabilities?: {
    supported_e2ee_versions?: string[];
    serving?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface GatewayE2eeKey {
  algo: string;
  keyId: string;
  /** Raw 32-byte X25519 key the request fields are encrypted to. */
  publicKey: Uint8Array;
  /** The keyset entry's `public_key` verbatim: the `X-Model-Pub-Key` value. */
  publicKeyHex: string;
  /** `workload_keyset_digest` of the verified report (the pin). */
  keysetDigest: string;
  notAfter: number;
  /** Where the report was fetched from. */
  source: string;
  report: AciAttestationReport;
}

export type E2eeAttestationErrorCode =
  | "fetch_failed"
  | "malformed_report"
  | "keyset_digest_mismatch"
  | "report_data_mismatch"
  | "keyset_expired"
  | "e2ee_unsupported"
  | "no_e2ee_key"
  | "evidence_rejected"
  | "request_signing_failed";

/** Carries no request data; safe to log and to surface as a compute error. */
export class E2eeAttestationError extends Error {
  constructor(
    public readonly code: E2eeAttestationErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "E2eeAttestationError";
  }
}

export interface FetchGatewayE2eeKeyOptions {
  /** Chat completions base, e.g. `https://relay.example/v1`. */
  baseUrl: string;
  /**
   * Signs the report fetch from `baseUrl` as this personal server (the relay
   * gates the passthrough route). Never used for the fallback origin.
   */
  requestSigner?: RequestSigner;
  fetch?: typeof fetch;
  /** Milliseconds since epoch (default Date.now). */
  clock?: () => number;
  /** Nonce source; tests pin it. */
  random?: (length: number) => Uint8Array;
  /** Require this `key_id` in addition to the algo (default: algo only). */
  expectedKeyId?: string;
  /** Hardware evidence verification hook (see the module comment). */
  verifyEvidence?: (report: AciAttestationReport) => Promise<void>;
  /**
   * When the base URL answers 404/405 for the attestation route (a relay
   * without the passthrough yet) the report is fetched from here instead;
   * `null` disables the fallback. Default: the Phala gateway origin.
   */
  fallbackBaseUrl?: string | null;
  timeoutMs?: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", buffer);
  return bytesToHex(new Uint8Array(digest));
}

/** ACI section 3.1: `"sha256:" || hex(sha256(JCS(workload_keyset)))`. */
export async function workloadKeysetDigest(
  keyset: AciWorkloadKeyset,
): Promise<string> {
  return `sha256:${await sha256Hex(canonicalJsonBytes(keyset))}`;
}

/** ACI section 3.2: the statement bytes are fixed; no JSON escaping needed. */
export async function reportDataFor(
  keysetDigest: string,
  nonce: string | null,
): Promise<string> {
  const nonceJson = nonce === null ? "null" : `"${nonce}"`;
  const statement = `{"keyset_digest":"${keysetDigest}","nonce":${nonceJson},"purpose":"${ACI_REPORT_DATA_PURPOSE}"}`;
  return sha256Hex(new TextEncoder().encode(statement));
}

function parseReport(body: unknown): AciAttestationReport {
  if (
    !isRecord(body) ||
    typeof body.api_version !== "string" ||
    typeof body.workload_keyset_digest !== "string" ||
    !isRecord(body.attestation) ||
    typeof body.attestation.tee_type !== "string" ||
    typeof body.attestation.report_data !== "string" ||
    !isRecord(body.attestation.workload_keyset)
  ) {
    throw new E2eeAttestationError(
      "malformed_report",
      "attestation report is missing required fields",
    );
  }
  const keyset = body.attestation.workload_keyset;
  if (
    typeof keyset.not_after !== "number" ||
    !Array.isArray(keyset.e2ee_public_keys)
  ) {
    throw new E2eeAttestationError(
      "malformed_report",
      "workload keyset is missing not_after or e2ee_public_keys",
    );
  }
  return body as unknown as AciAttestationReport;
}

/**
 * Structural verification of a report against the nonce it was requested
 * with (ACI section 9.1 steps 2 and 3, plus the E2EE v2 capability). Throws
 * E2eeAttestationError; returns the verified keyset digest.
 */
export async function verifyAciReportBinding(
  report: AciAttestationReport,
  nonce: string,
  nowSeconds: number,
): Promise<string> {
  if (report.api_version !== ACI_API_VERSION) {
    throw new E2eeAttestationError(
      "malformed_report",
      `unsupported attestation api_version ${report.api_version}`,
    );
  }
  if (report.attestation.tee_type !== "tdx") {
    throw new E2eeAttestationError(
      "malformed_report",
      `unsupported tee_type ${report.attestation.tee_type}`,
    );
  }
  const versions = report.service_capabilities?.supported_e2ee_versions;
  if (!Array.isArray(versions) || !versions.includes(E2EE_VERSION)) {
    throw new E2eeAttestationError(
      "e2ee_unsupported",
      "service does not advertise E2EE version 2",
    );
  }
  const keyset = report.attestation.workload_keyset;
  const digest = await workloadKeysetDigest(keyset);
  if (digest !== report.workload_keyset_digest) {
    throw new E2eeAttestationError(
      "keyset_digest_mismatch",
      "workload_keyset_digest does not match the embedded keyset",
    );
  }
  const expectedReportData = await reportDataFor(digest, nonce);
  const reportData = report.attestation.report_data.toLowerCase();
  if (reportData !== expectedReportData) {
    throw new E2eeAttestationError(
      "report_data_mismatch",
      "report_data does not bind the keyset digest and our nonce",
    );
  }
  const quoteReportData = report.attestation.evidence?.quote_report_data;
  if (typeof quoteReportData === "string") {
    const slot = quoteReportData.toLowerCase();
    if (
      slot.length !== 128 ||
      !slot.startsWith(reportData) ||
      !/^0+$/.test(slot.slice(64))
    ) {
      throw new E2eeAttestationError(
        "report_data_mismatch",
        "quote report-data slot does not carry report_data zero-padded",
      );
    }
  }
  if (!(nowSeconds < keyset.not_after)) {
    throw new E2eeAttestationError(
      "keyset_expired",
      "workload keyset has expired",
    );
  }
  if (keyset.not_after - nowSeconds > MAX_KEYSET_LIFETIME_S) {
    throw new E2eeAttestationError(
      "keyset_expired",
      "workload keyset not_after is implausibly far in the future",
    );
  }
  return digest;
}

/** The X25519 suite entry (spec section 7: clients select keys by algo). */
export function selectX25519Key(
  keyset: AciWorkloadKeyset,
  expectedKeyId?: string,
): { entry: AciKeysetEntry; publicKey: Uint8Array } {
  for (const entry of keyset.e2ee_public_keys) {
    if (!isRecord(entry) || entry.algo !== E2EE_ALGO_X25519) continue;
    if (typeof entry.public_key !== "string") continue;
    if (expectedKeyId !== undefined && entry.key_id !== expectedKeyId) {
      continue;
    }
    let publicKey: Uint8Array;
    try {
      publicKey = parseX25519PublicKey(entry.public_key);
    } catch {
      throw new E2eeAttestationError(
        "no_e2ee_key",
        "the X25519 E2EE key in the keyset is malformed",
      );
    }
    return { entry, publicKey };
  }
  throw new E2eeAttestationError(
    "no_e2ee_key",
    expectedKeyId
      ? `keyset has no ${E2EE_ALGO_X25519} key with key_id ${expectedKeyId}`
      : `keyset has no ${E2EE_ALGO_X25519} key`,
  );
}

function attestationUrl(baseUrl: string, nonce: string): string {
  return `${baseUrl.replace(/\/+$/, "")}/aci/attestation?nonce=${nonce}`;
}

/**
 * Sign the report fetch as this server. A signer that cannot sign is a
 * permanent failure: the request is never sent unsigned.
 */
async function authorizationFor(
  signer: RequestSigner,
  url: URL,
): Promise<string> {
  try {
    return await signer.signRequest({
      aud: url.origin,
      method: "GET",
      // The nonce lives in the query string, so the query is part of the
      // signed uri: a captured header cannot be replayed for another nonce.
      uri: `${url.pathname}${url.search}`,
    });
  } catch (err) {
    const name = err instanceof Error ? err.name : "Error";
    throw new E2eeAttestationError(
      "request_signing_failed",
      `attestation request could not be signed (${name})`,
    );
  }
}

async function fetchReport(
  doFetch: typeof fetch,
  url: string,
  timeoutMs: number,
  requestSigner?: RequestSigner,
): Promise<{ status: number; body: unknown }> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (requestSigner) {
    headers.Authorization = await authorizationFor(requestSigner, new URL(url));
  }
  let response: Response;
  try {
    response = await doFetch(url, {
      method: "GET",
      headers,
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    const name = err instanceof Error ? err.name : "Error";
    throw new E2eeAttestationError(
      "fetch_failed",
      `attestation fetch failed before a response (${name})`,
    );
  }
  if (!response.ok) {
    return { status: response.status, body: null };
  }
  try {
    return { status: response.status, body: await response.json() };
  } catch {
    throw new E2eeAttestationError(
      "malformed_report",
      "attestation response was not JSON",
    );
  }
}

/**
 * Fetch, verify and select the gateway's E2EE key. Fail closed: any
 * verification failure throws and no key is returned.
 */
export async function fetchGatewayE2eeKey(
  options: FetchGatewayE2eeKeyOptions,
): Promise<GatewayE2eeKey> {
  const doFetch = options.fetch ?? fetch;
  const clock = options.clock ?? Date.now;
  const random = options.random ?? randomBytes;
  const timeoutMs = options.timeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
  const nonce = bytesToHex(random(32));
  const fallback =
    options.fallbackBaseUrl === undefined
      ? PHALA_GATEWAY_BASE_URL
      : options.fallbackBaseUrl;

  let source = options.baseUrl;
  let fetched = await fetchReport(
    doFetch,
    attestationUrl(source, nonce),
    timeoutMs,
    options.requestSigner,
  );
  if (
    (fetched.status === 404 || fetched.status === 405) &&
    fallback !== null &&
    fallback.replace(/\/+$/, "") !== source.replace(/\/+$/, "")
  ) {
    source = fallback;
    // The fallback is the provider's own origin: it takes no server
    // signature, so the report is fetched from it unsigned.
    fetched = await fetchReport(
      doFetch,
      attestationUrl(source, nonce),
      timeoutMs,
    );
  }
  if (fetched.body === null) {
    throw new E2eeAttestationError(
      "fetch_failed",
      `attestation fetch failed with status ${fetched.status}`,
    );
  }
  const report = parseReport(fetched.body);
  const nowSeconds = Math.floor(clock() / 1000);
  const keysetDigest = await verifyAciReportBinding(report, nonce, nowSeconds);
  const { entry, publicKey } = selectX25519Key(
    report.attestation.workload_keyset,
    options.expectedKeyId,
  );
  if (options.verifyEvidence) {
    try {
      await options.verifyEvidence(report);
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      throw new E2eeAttestationError(
        "evidence_rejected",
        `attestation evidence rejected: ${reason}`,
      );
    }
  }
  return {
    algo: entry.algo,
    keyId: entry.key_id,
    publicKey,
    publicKeyHex: entry.public_key,
    keysetDigest,
    notAfter: report.attestation.workload_keyset.not_after,
    source,
    report,
  };
}

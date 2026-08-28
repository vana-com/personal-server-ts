import { describe, expect, it, vi } from "vitest";
import {
  parseWeb3SignedHeader,
  verifyWeb3Signed,
} from "@opendatalabs/vana-sdk/browser";
import {
  LIVE_ACI_ATTESTATION_CLOCK_S,
  LIVE_ACI_ATTESTATION_NONCE,
  LIVE_ACI_ATTESTATION_REPORT,
  LIVE_ACI_X25519_PUBLIC_KEY_HEX,
} from "../../test-utils/e2ee-fixtures.js";
import { createFakeE2eeGateway } from "../../test-utils/e2ee-gateway.js";
import {
  E2eeAttestationError,
  PHALA_GATEWAY_BASE_URL,
  fetchGatewayE2eeKey,
  reportDataFor,
  selectX25519Key,
  verifyAciReportBinding,
  workloadKeysetDigest,
  type AciAttestationReport,
} from "./attestation.js";
import { bytesToHex, hexToBytes } from "./suite.js";
import { createRequestSigner } from "../../signing/request-signer.js";
import { createTestWallet } from "../../test-utils/index.js";

const liveReport = () =>
  JSON.parse(
    JSON.stringify(LIVE_ACI_ATTESTATION_REPORT),
  ) as AciAttestationReport;
const liveNonceBytes = () => hexToBytes(LIVE_ACI_ATTESTATION_NONCE);
const liveClock = () => LIVE_ACI_ATTESTATION_CLOCK_S * 1000;

function fetchReplying(status: number, body: unknown) {
  return vi.fn(
    async () =>
      new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
      }),
  ) as unknown as typeof fetch;
}

describe("ACI attestation binding (live inference.phala.com report)", () => {
  it("recomputes the keyset digest and report_data chain from the real report", async () => {
    const report = liveReport();
    const digest = await workloadKeysetDigest(
      report.attestation.workload_keyset,
    );
    expect(digest).toBe(report.workload_keyset_digest);
    expect(await reportDataFor(digest, LIVE_ACI_ATTESTATION_NONCE)).toBe(
      report.attestation.report_data,
    );
    await expect(
      verifyAciReportBinding(
        report,
        LIVE_ACI_ATTESTATION_NONCE,
        LIVE_ACI_ATTESTATION_CLOCK_S,
      ),
    ).resolves.toBe(digest);
  });

  it("selects the X25519 key by algo and keeps the published hex verbatim", () => {
    const { entry, publicKey } = selectX25519Key(
      liveReport().attestation.workload_keyset,
    );
    expect(entry.key_id).toBe("dstack-kms-e2ee-x25519-v1");
    expect(entry.algo).toBe("x25519-aes-256-gcm-hkdf-sha256");
    expect(entry.public_key).toBe(LIVE_ACI_X25519_PUBLIC_KEY_HEX);
    expect(bytesToHex(publicKey)).toBe(LIVE_ACI_X25519_PUBLIC_KEY_HEX);
    expect(() =>
      selectX25519Key(liveReport().attestation.workload_keyset, "other-id"),
    ).toThrow(E2eeAttestationError);
  });

  it("rejects a report whose nonce is not ours (replayed report)", async () => {
    await expect(
      verifyAciReportBinding(
        liveReport(),
        "00".repeat(32),
        LIVE_ACI_ATTESTATION_CLOCK_S,
      ),
    ).rejects.toMatchObject({ code: "report_data_mismatch" });
  });

  it("rejects a keyset that was swapped under the quote", async () => {
    const report = liveReport();
    report.attestation.workload_keyset.e2ee_public_keys[1]!.public_key =
      "11".repeat(32);
    await expect(
      verifyAciReportBinding(
        report,
        LIVE_ACI_ATTESTATION_NONCE,
        LIVE_ACI_ATTESTATION_CLOCK_S,
      ),
    ).rejects.toMatchObject({ code: "keyset_digest_mismatch" });
  });

  it("rejects a quote whose report-data slot does not carry report_data", async () => {
    const report = liveReport();
    report.attestation.evidence!.quote_report_data = "ab".repeat(64);
    await expect(
      verifyAciReportBinding(
        report,
        LIVE_ACI_ATTESTATION_NONCE,
        LIVE_ACI_ATTESTATION_CLOCK_S,
      ),
    ).rejects.toMatchObject({ code: "report_data_mismatch" });
  });

  it("rejects an expired keyset, one too far in the future, and no E2EE v2", async () => {
    const notAfter = liveReport().attestation.workload_keyset.not_after;
    await expect(
      verifyAciReportBinding(
        liveReport(),
        LIVE_ACI_ATTESTATION_NONCE,
        notAfter,
      ),
    ).rejects.toMatchObject({ code: "keyset_expired" });
    await expect(
      verifyAciReportBinding(
        liveReport(),
        LIVE_ACI_ATTESTATION_NONCE,
        notAfter - 500 * 24 * 3600,
      ),
    ).rejects.toMatchObject({ code: "keyset_expired" });
    const report = liveReport();
    report.service_capabilities = { supported_e2ee_versions: ["3"] };
    await expect(
      verifyAciReportBinding(
        report,
        LIVE_ACI_ATTESTATION_NONCE,
        LIVE_ACI_ATTESTATION_CLOCK_S,
      ),
    ).rejects.toMatchObject({ code: "e2ee_unsupported" });
  });
});

describe("fetchGatewayE2eeKey", () => {
  it("fetches the report through the base URL with a fresh nonce and pins the digest", async () => {
    const doFetch = fetchReplying(200, liveReport());
    const key = await fetchGatewayE2eeKey({
      baseUrl: "https://relay.test/v1/",
      fetch: doFetch,
      clock: liveClock,
      random: liveNonceBytes,
    });
    expect(key.publicKeyHex).toBe(LIVE_ACI_X25519_PUBLIC_KEY_HEX);
    expect(key.keyId).toBe("dstack-kms-e2ee-x25519-v1");
    expect(key.keysetDigest).toBe(
      LIVE_ACI_ATTESTATION_REPORT.workload_keyset_digest,
    );
    expect(key.source).toBe("https://relay.test/v1/");
    const [url, init] = (doFetch as unknown as ReturnType<typeof vi.fn>).mock
      .calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(
      `https://relay.test/v1/aci/attestation?nonce=${LIVE_ACI_ATTESTATION_NONCE}`,
    );
    expect(init.method).toBe("GET");
  });

  it("falls back to the Phala origin when the relay has no attestation route", async () => {
    const calls: string[] = [];
    const doFetch = (async (input: string | URL | Request) => {
      const url = String(input);
      calls.push(url);
      if (url.startsWith("https://relay.test/")) {
        return new Response("not found", { status: 404 });
      }
      return new Response(JSON.stringify(liveReport()), { status: 200 });
    }) as unknown as typeof fetch;
    const key = await fetchGatewayE2eeKey({
      baseUrl: "https://relay.test/v1",
      fetch: doFetch,
      clock: liveClock,
      random: liveNonceBytes,
    });
    expect(key.source).toBe(PHALA_GATEWAY_BASE_URL);
    expect(calls).toEqual([
      `https://relay.test/v1/aci/attestation?nonce=${LIVE_ACI_ATTESTATION_NONCE}`,
      `${PHALA_GATEWAY_BASE_URL}/aci/attestation?nonce=${LIVE_ACI_ATTESTATION_NONCE}`,
    ]);
    // With the fallback disabled the 404 is final.
    await expect(
      fetchGatewayE2eeKey({
        baseUrl: "https://relay.test/v1",
        fetch: doFetch,
        clock: liveClock,
        random: liveNonceBytes,
        fallbackBaseUrl: null,
      }),
    ).rejects.toMatchObject({ code: "fetch_failed" });
  });

  it("signs the fetch through the relay and leaves the fallback unsigned", async () => {
    const wallet = createTestWallet(11);
    const seen: Array<{ url: string; authorization: string | null }> = [];
    const doFetch = (async (
      input: string | URL | Request,
      init?: RequestInit,
    ) => {
      const url = String(input);
      const headers = new Headers(init?.headers);
      seen.push({ url, authorization: headers.get("authorization") });
      if (url.startsWith("https://relay.test/")) {
        return new Response("not found", { status: 404 });
      }
      return new Response(JSON.stringify(liveReport()), { status: 200 });
    }) as unknown as typeof fetch;
    await fetchGatewayE2eeKey({
      baseUrl: "https://relay.test/v1/inference",
      requestSigner: createRequestSigner({
        address: wallet.address,
        publicKey: "0x04" as `0x${string}`,
        signTypedData: vi.fn(),
        signMessage: (message: string) => wallet.signMessage(message),
      }),
      fetch: doFetch,
      clock: liveClock,
      random: liveNonceBytes,
    });
    const uri = `/v1/inference/aci/attestation?nonce=${LIVE_ACI_ATTESTATION_NONCE}`;
    const header = seen[0].authorization ?? "";
    const { payload } = parseWeb3SignedHeader(header);
    expect(payload.aud).toBe("https://relay.test");
    expect(payload.method).toBe("GET");
    // The nonce is inside the signed uri, and a GET has no body to hash.
    expect(payload.uri).toBe(uri);
    const verified = await verifyWeb3Signed({
      headerValue: header,
      expectedOrigin: "https://relay.test",
      expectedMethod: "GET",
      expectedPath: uri,
    });
    expect(verified.signer.toLowerCase()).toBe(wallet.address.toLowerCase());
    // The direct Phala fallback is a different origin with no such gate.
    expect(seen[1].url.startsWith(PHALA_GATEWAY_BASE_URL)).toBe(true);
    expect(seen[1].authorization).toBeNull();
  });

  it("fails closed, and permanently, when the report fetch cannot be signed", async () => {
    const doFetch = fetchReplying(200, liveReport());
    await expect(
      fetchGatewayE2eeKey({
        baseUrl: "https://relay.test/v1",
        requestSigner: {
          signRequest: () => Promise.reject(new Error("wallet locked")),
        },
        fetch: doFetch,
        clock: liveClock,
        random: liveNonceBytes,
      }),
    ).rejects.toMatchObject({ code: "request_signing_failed" });
    expect(doFetch).not.toHaveBeenCalled();
  });

  it("fails closed on transport errors, non-JSON and rejected evidence", async () => {
    await expect(
      fetchGatewayE2eeKey({
        baseUrl: "https://relay.test/v1",
        fetch: (async () => {
          throw new TypeError("fetch failed");
        }) as unknown as typeof fetch,
      }),
    ).rejects.toMatchObject({ code: "fetch_failed" });
    await expect(
      fetchGatewayE2eeKey({
        baseUrl: "https://relay.test/v1",
        fetch: (async () =>
          new Response("<html>", { status: 200 })) as unknown as typeof fetch,
      }),
    ).rejects.toMatchObject({ code: "malformed_report" });
    await expect(
      fetchGatewayE2eeKey({
        baseUrl: "https://relay.test/v1",
        fetch: fetchReplying(200, liveReport()),
        clock: liveClock,
        random: liveNonceBytes,
        verifyEvidence: async () => {
          throw new Error("quote signature invalid");
        },
      }),
    ).rejects.toMatchObject({
      code: "evidence_rejected",
      message: "attestation evidence rejected: quote signature invalid",
    });
  });

  it("works against the fake gateway's freshly built report", async () => {
    const gateway = await createFakeE2eeGateway();
    const key = await fetchGatewayE2eeKey({
      baseUrl: "https://relay.test/v1",
      fetch: gateway.fetch,
    });
    expect(key.keysetDigest).toBe(await gateway.keysetDigest());
    expect(key.publicKeyHex).toBe(
      gateway.keyset.e2ee_public_keys[1]!.public_key,
    );
  });
});

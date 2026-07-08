import { describe, expect, it } from "vitest";

import { classifySyncFailure, inferPayloadKind } from "./issues.js";

const BASE_INPUT = {
  fileId: "file-001",
  schemaId: "schema-001",
  syncRunId: "sync-run-001",
  now: new Date("2026-06-05T12:00:00.000Z"),
};

describe("sync issue classification", () => {
  it("classifies transient download failures as retryable", () => {
    const error = Object.assign(new Error("storage unavailable"), {
      name: "StorageDownloadError",
      status: 503,
    });

    const result = classifySyncFailure({
      ...BASE_INPUT,
      error,
      stage: "download",
      storageBackend: "mock-storage",
    });

    expect(result.issue).toMatchObject({
      fileId: "file-001",
      schemaId: "schema-001",
      stage: "download",
      errorClass: "StorageDownloadError",
      message: "Download failed with a retryable storage or network error",
      disposition: "transient",
      retryable: true,
      firstSeenAt: "2026-06-05T12:00:00.000Z",
      lastSeenAt: "2026-06-05T12:00:00.000Z",
    });
    expect(result.telemetry).toMatchObject({
      event: "sync.download.failure",
      stage: "download",
      disposition: "transient",
      retryable: true,
      storageBackend: "mock-storage",
    });
  });

  it("classifies a download 404 embedded in the error message as deterministic", () => {
    // The SDK's vana-storage provider throws StorageError with the HTTP
    // status only in the message ("vana-storage download failed: 404 Not
    // Found") — no numeric status property. A 404 blob can never heal by
    // retrying, so it must classify deterministic.
    const error = Object.assign(
      new Error("vana-storage download failed: 404 Not Found"),
      { name: "StorageError" },
    );

    const result = classifySyncFailure({
      ...BASE_INPUT,
      error,
      stage: "download",
    });

    expect(result.issue).toMatchObject({
      stage: "download",
      disposition: "deterministic",
      retryable: false,
      message: "Download failed with a non-retryable storage response",
    });
  });

  it("keeps a download 503 embedded in the error message transient", () => {
    const error = Object.assign(
      new Error("vana-storage download failed: 503 Service Unavailable"),
      { name: "StorageError" },
    );

    const result = classifySyncFailure({
      ...BASE_INPUT,
      error,
      stage: "download",
    });

    expect(result.issue).toMatchObject({
      stage: "download",
      disposition: "transient",
      retryable: true,
    });
  });

  it("keeps auth blips and edge errors transient — only 404/410 are deterministic", () => {
    // Downloads are Web3Signed off the local clock, so 401/403 windows are
    // recoverable; storage sits behind Cloudflare, so 52x edge errors are
    // too. Neither may permanently quarantine a record on first sight —
    // the retry memory's attempt cap bounds them instead.
    for (const line of [
      "vana-storage download failed: 401 Unauthorized",
      "vana-storage download failed: 403 Forbidden",
      "vana-storage download failed: 520 Web Server Returned an Unknown Error",
    ]) {
      const result = classifySyncFailure({
        ...BASE_INPUT,
        error: Object.assign(new Error(line), { name: "StorageError" }),
        stage: "download",
      });
      expect(result.issue).toMatchObject({
        disposition: "transient",
        retryable: true,
      });
    }

    const gone = classifySyncFailure({
      ...BASE_INPUT,
      error: Object.assign(
        new Error("vana-storage download failed: 410 Gone"),
        { name: "StorageError" },
      ),
      stage: "download",
    });
    expect(gone.issue).toMatchObject({
      disposition: "deterministic",
      retryable: false,
    });
  });

  it("keeps download network errors without a status transient", () => {
    // Network errors embed the cause description, which can contain digits
    // (IPs, ports) that must not be misread as an HTTP status.
    const error = Object.assign(
      new Error(
        "vana-storage download network error: connect ECONNREFUSED 127.0.0.1:8080",
      ),
      { name: "StorageError" },
    );

    const result = classifySyncFailure({
      ...BASE_INPUT,
      error,
      stage: "download",
    });

    expect(result.issue).toMatchObject({
      stage: "download",
      disposition: "transient",
      retryable: true,
    });
  });

  it("classifies OpenPGP parse failures as deterministic corrupt payloads", () => {
    const result = classifySyncFailure({
      ...BASE_INPUT,
      error: new Error("Armored OpenPGP message could not be parsed"),
      stage: "openpgp_parse",
      payloadKind: "html",
      encryptedSizeBytes: 42,
    });

    expect(result.issue).toMatchObject({
      stage: "openpgp_parse",
      payloadKind: "html",
      encryptedSizeBytes: 42,
      disposition: "deterministic",
      retryable: false,
    });
    expect(result.telemetry).toMatchObject({
      stage: "openpgp_parse",
      payloadKind: "html",
      encryptedSizeBytes: 42,
      disposition: "deterministic",
      retryable: false,
    });
  });

  it("classifies decrypt failures as deterministic corrupt or invalid files", () => {
    const result = classifySyncFailure({
      ...BASE_INPUT,
      error: new Error(
        "Error decrypting message: Session key decryption failed.",
      ),
      stage: "decrypt",
      payloadKind: "openpgp",
      encryptedSizeBytes: 2048,
    });

    expect(result.issue).toMatchObject({
      stage: "decrypt",
      payloadKind: "openpgp",
      encryptedSizeBytes: 2048,
      disposition: "deterministic",
      retryable: false,
    });
  });

  it("classifies JSON parse failures as deterministic invalid plaintext", () => {
    const result = classifySyncFailure({
      ...BASE_INPUT,
      error: new SyntaxError(
        "Unexpected token '<', \"<html>\" is not valid JSON",
      ),
      stage: "json_parse",
      payloadKind: "html",
      encryptedSizeBytes: 512,
    });

    expect(result.issue).toMatchObject({
      stage: "json_parse",
      errorClass: "SyntaxError",
      payloadKind: "html",
      disposition: "deterministic",
      retryable: false,
    });
  });

  it("classifies envelope validation failures as deterministic invalid envelopes", () => {
    const result = classifySyncFailure({
      ...BASE_INPUT,
      error: Object.assign(
        new Error("Invalid input: expected string at scope"),
        {
          name: "ZodError",
        },
      ),
      stage: "envelope_validate",
      payloadKind: "json",
    });

    expect(result.issue).toMatchObject({
      stage: "envelope_validate",
      errorClass: "ZodError",
      payloadKind: "json",
      disposition: "deterministic",
      retryable: false,
    });
  });

  it("omits decrypted payload contents from issues and telemetry", () => {
    const unsafeRecordValue = "private-user-record-value";
    const result = classifySyncFailure({
      ...BASE_INPUT,
      error: new Error(`Invalid envelope near ${unsafeRecordValue}`),
      stage: "envelope_validate",
      scope: "instagram.profile",
      payloadKind: "json",
      appVersion: "app-1",
      personalServerVersion: "server-1",
    });

    expect(JSON.stringify(result.issue)).not.toContain(unsafeRecordValue);
    expect(JSON.stringify(result.telemetry)).not.toContain(unsafeRecordValue);
    expect(result.telemetry).toEqual({
      event: "sync.download.failure",
      syncRunId: "sync-run-001",
      fileId: "file-001",
      schemaId: "schema-001",
      scope: "instagram.profile",
      stage: "envelope_validate",
      payloadKind: "json",
      encryptedSizeBytes: undefined,
      errorClass: "Error",
      disposition: "deterministic",
      retryable: false,
      appVersion: "app-1",
      personalServerVersion: "server-1",
      storageBackend: undefined,
    });
  });

  it("detects payload kind from small generated fixtures", () => {
    expect(inferPayloadKind("-----BEGIN PGP MESSAGE-----\nabc")).toBe(
      "openpgp",
    );
    expect(inferPayloadKind('{"version":"1.0"}')).toBe("json");
    expect(inferPayloadKind("<!doctype html><html></html>")).toBe("html");
    expect(inferPayloadKind("   ")).toBe("empty");
    expect(inferPayloadKind(new Uint8Array([0x00, 0xff]))).toBe("binary");
  });
});

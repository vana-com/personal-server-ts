/**
 * `INFERENCE_REQUEST_FIELDS` and `inference.requestFields`.
 *
 * The load-bearing assertion here is the FIRST one: leaving both the env var
 * and the config key alone must produce byte-identical request bodies to what
 * shipped before this option existed. The Phala routing hint is part of the
 * production request, and the request bytes are what the Web3Signed signature
 * covers — a change here is a change to what gets signed.
 */

import { describe, expect, it } from "vitest";

import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  createOpenAiCompatibleInferenceProvider,
  DEFAULT_INFERENCE_REQUEST_FIELDS,
} from "@opendatalabs/personal-server-ts-core/derivatives";

import { parseRequestFields } from "./bootstrap.js";

const PHALA_HINT = { provider: { aci_verified: true, zdr: true } };

describe("inference.requestFields default is unchanged", () => {
  it("config defaults to the Phala routing hint", () => {
    const config = ServerConfigSchema.parse({});
    expect(config.inference.requestFields).toEqual(PHALA_HINT);
  });

  it("matches the provider's own compiled-in default exactly", () => {
    // If these two ever drift, an operator relying on the config default gets
    // a different body than an operator relying on the provider default.
    expect(ServerConfigSchema.parse({}).inference.requestFields).toEqual(
      DEFAULT_INFERENCE_REQUEST_FIELDS,
    );
  });

  it("unset env leaves the configured fields untouched", () => {
    expect(parseRequestFields(undefined, PHALA_HINT)).toEqual(PHALA_HINT);
  });

  it("sends a body identical to the pre-change default", async () => {
    const bodies: string[] = [];
    const provider = createOpenAiCompatibleInferenceProvider({
      baseUrl: "https://relay.example/v1",
      model: "z-ai/glm-5.2",
      apiKey: "k",
      // exactly what bootstrap now passes when nothing is overridden
      requestFields: ServerConfigSchema.parse({}).inference.requestFields,
      fetch: (async (_url: string, init: RequestInit) => {
        bodies.push(String(init.body));
        return new Response(
          JSON.stringify({
            id: "1",
            choices: [{ index: 0, message: { content: "ok" } }],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }) as unknown as typeof fetch,
    });

    await provider.chat({
      model: "z-ai/glm-5.2",
      messages: [{ role: "user", content: "hi" }],
    });

    const body = JSON.parse(bodies[0]!) as Record<string, unknown>;
    expect(body.provider).toEqual({ aci_verified: true, zdr: true });
    expect(body.model).toBe("z-ai/glm-5.2");
    expect(body.max_tokens).toBe(2048);
  });
});

describe("parseRequestFields", () => {
  it("`none` clears the fields", () => {
    expect(parseRequestFields("none", PHALA_HINT)).toEqual({});
    expect(parseRequestFields("NONE", PHALA_HINT)).toEqual({});
  });

  it("an empty string clears the fields", () => {
    expect(parseRequestFields("", PHALA_HINT)).toEqual({});
    expect(parseRequestFields("   ", PHALA_HINT)).toEqual({});
  });

  it("`{}` clears the fields", () => {
    expect(parseRequestFields("{}", PHALA_HINT)).toEqual({});
  });

  it("parses a JSON object", () => {
    expect(parseRequestFields('{"a":1,"b":{"c":true}}', PHALA_HINT)).toEqual({
      a: 1,
      b: { c: true },
    });
  });

  it("throws on malformed JSON rather than sending the wrong body", () => {
    expect(() => parseRequestFields("{not json", PHALA_HINT)).toThrow(
      /must be a JSON object/,
    );
  });

  it.each([["[1,2]"], ["null"], ['"a string"'], ["42"]])(
    "rejects non-object JSON: %s",
    (raw) => {
      expect(() => parseRequestFields(raw, PHALA_HINT)).toThrow(
        /must be a JSON object/,
      );
    },
  );

  it("cleared fields produce a body with no provider hint", async () => {
    const bodies: string[] = [];
    const provider = createOpenAiCompatibleInferenceProvider({
      baseUrl: "https://generativelanguage.googleapis.com/v1beta/openai",
      model: "gemini-3.7-flash",
      apiKey: "k",
      requestFields: parseRequestFields("none", PHALA_HINT),
      fetch: (async (_url: string, init: RequestInit) => {
        bodies.push(String(init.body));
        return new Response(
          JSON.stringify({
            id: "1",
            choices: [{ index: 0, message: { content: "ok" } }],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }) as unknown as typeof fetch,
    });

    await provider.chat({
      model: "gemini-3.7-flash",
      messages: [{ role: "user", content: "hi" }],
    });

    const body = JSON.parse(bodies[0]!) as Record<string, unknown>;
    expect(body).not.toHaveProperty("provider");
    expect(Object.keys(body).sort()).toEqual([
      "max_tokens",
      "messages",
      "model",
    ]);
  });

  it("a bearer key still suppresses request signing", async () => {
    // Regression guard on the property that makes a direct provider work at
    // all: with apiKey set, no Web3Signed header is produced.
    const headers: Headers[] = [];
    const provider = createOpenAiCompatibleInferenceProvider({
      baseUrl: "https://generativelanguage.googleapis.com/v1beta/openai",
      model: "gemini-3.7-flash",
      apiKey: "gem-key",
      requestFields: {},
      requestSigner: () => {
        throw new Error("signer must not be called when an apiKey is set");
      },
      fetch: (async (_url: string, init: RequestInit) => {
        headers.push(new Headers(init.headers));
        return new Response(
          JSON.stringify({
            id: "1",
            choices: [{ index: 0, message: { content: "ok" } }],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }) as unknown as typeof fetch,
    });

    await provider.chat({
      model: "gemini-3.7-flash",
      messages: [{ role: "user", content: "hi" }],
    });

    expect(headers[0]!.get("Authorization")).toBe("Bearer gem-key");
  });
});

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import browser from "./declarations/oura-browser.collection-profile.json";
import provenance from "./declarations/oura-browser.provenance.json";
import {
  legacyScopeToPdppSelection,
  OURA_BROWSER_BINDINGS,
  projectPdppRecordsToLegacyPayload,
} from "./index.js";

describe("Oura browser source bindings", () => {
  it("uses the published 0.1.2 profile and provenance", () => {
    expect(browser).toMatchObject({
      connector_key: "oura-browser",
      connector_id: "https://registry.pdpp.dev/connectors/oura-browser",
      version: "0.1.2",
    });
    expect(provenance.source.revision).toBe(
      "2dc347e9b8146c74c1e57e682761f08fbf0edb70",
    );
    expect(provenance.outputs["collection-profile.json"]).toBe(
      `sha256:${createHash("sha256")
        .update(
          readFileSync(
            new URL(
              "./declarations/oura-browser.collection-profile.json",
              import.meta.url,
            ),
          ),
        )
        .digest("hex")}`,
    );
    const sleep = browser.streams.find((stream) => stream.name === "sleep");
    expect(sleep?.primary_key).toEqual(["id"]);
    expect(sleep?.schema.properties.record_type?.enum).toEqual([
      "sleep_session",
      "daily_score",
    ]);
    expect(sleep?.schema.required).toEqual(
      expect.arrayContaining(["id", "day"]),
    );
  });

  it("uses the published Oura Browser source and retained scope selections", () => {
    for (const [scope, binding] of OURA_BROWSER_BINDINGS) {
      const stream = binding.pdppStreams[0];
      expect(binding.provenance[0], scope).toEqual({
        kind: "oci",
        ref: "ghcr.io/pdp-connect/connector/oura-browser:0.1.2",
        digest:
          "sha256:ddc901015996e4ae67030bcd9ec809aa368b1b69d94b8ed5515d1be0a886975d",
        path: `collection-profile.json#streams[name=${stream}]`,
      });
      expect(
        legacyScopeToPdppSelection(scope, { profileKey: "oura-browser" }),
      ).toEqual({
        ok: true,
        selection: {
          source: "https://registry.pdpp.dev/connectors/oura-browser",
          streams: binding.pdppStreams,
        },
      });
    }
  });

  it("rejects missing streams and required record fields", () => {
    expect(
      projectPdppRecordsToLegacyPayload("oura.activity", [], {
        fetchedStreams: [],
        profileKey: "oura-browser",
      }),
    ).toMatchObject({ ok: false, error: { kind: "missing_stream" } });
    expect(
      projectPdppRecordsToLegacyPayload(
        "oura.activity",
        [{ stream: "activity", data: { id: "day-1" } }],
        { fetchedStreams: ["activity"], profileKey: "oura-browser" },
      ),
    ).toMatchObject({
      ok: false,
      error: { kind: "incomplete_scope", scope: "oura.activity" },
    });
  });
});

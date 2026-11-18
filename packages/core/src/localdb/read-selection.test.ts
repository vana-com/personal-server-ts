import { describe, expect, it } from "vitest";
import { chooseCandidate, type Candidate } from "./read-selection.js";

function candidate(
  connector: string,
  registered: number,
  partial = false,
): Candidate {
  return {
    target: { connector, streams: ["items"] },
    connection: {
      connection_id: connector,
      connector,
      ns: "",
      generation: 1,
      control_state: "active",
      deleted_at: null,
    },
    streams: [
      {
        connection_id: connector,
        installed_version: 1,
        stream: "items",
        profile_key: null,
        profile_version: null,
        primary_key: '["id"]',
        complete: partial ? 0 : 1,
        last_delete_version: 0,
        head_version: 1,
        head_generation: 1,
        head_data_hash: "hash",
        head_blob: "blob",
        version: 1,
        generation: 1,
        version_blob: "blob",
        version_complete: partial ? 0 : 1,
        observed_at: registered,
        kind: "applied",
      },
    ],
    registered,
    partialStreams: partial ? ["items"] : [],
  };
}

describe("chooseCandidate", () => {
  it("prefers a complete legacy target over a newer partial canonical target", () => {
    const canonical = candidate("canonical", 3000, true);
    const legacy = candidate("legacy", 2000);
    legacy.target = {
      ...legacy.target,
      alias: {
        connector: "legacy",
        streams: ["items"],
        project: () => ({ ok: true, payload: {} }),
      },
    };
    for (const candidates of [
      [canonical, legacy],
      [legacy, canonical],
    ]) {
      expect(chooseCandidate(candidates)).toBe(legacy);
    }
    expect(
      chooseCandidate([candidate("canonical", 3000), legacy])?.target.connector,
    ).toBe("canonical");
  });

  it.each([false, true])(
    "preserves recency and connector ordering for equally partial candidates: %s",
    (partial) => {
      const older = candidate("a", 1000, partial);
      const newer = candidate("z", 2000, partial);
      const tied = candidate("b", 2000, partial);
      expect(chooseCandidate([older, newer])).toBe(newer);
      expect(chooseCandidate([newer, older, tied])).toBe(tied);
    },
  );
});

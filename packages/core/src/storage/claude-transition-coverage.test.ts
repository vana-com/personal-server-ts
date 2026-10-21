import { expect, it } from "vitest";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { coversClaudeTransition } from "./legacy-scope-view.js";

const previous = {
  scope: "claude.conversations",
  collectedAt: "2026-10-20T00:00:00Z",
  data: {
    organizationId: "team",
    source: "export",
    profile: { name: "Reader", plan: "Team" },
    total: 1,
    messageTotal: 1,
    conversations: [
      {
        id: "existing",
        title: "Goethe",
        messages: [{ id: "message", content: "Keep this" }],
      },
    ],
  },
} as unknown as DataFileEnvelope;

it("requires existing messages and the same organization before replacing the saved export", async () => {
  const current = { envelope: structuredClone(previous), revision: "live" };
  current.envelope.collectedAt = "2026-10-21T00:00:00Z";
  current.envelope.data.source = "live-session";
  current.envelope.data.profile = { name: null, plan: "Team" };
  expect(await coversClaudeTransition(current, previous)).toBe(true);
  expect(current.envelope.data.profile).toEqual({
    name: "Reader",
    plan: "Team",
  });
  expect(current.revision).not.toBe("live");
  current.envelope.data.conversations = [];
  expect(await coversClaudeTransition(current, previous)).toBe(false);
  current.envelope.data.conversations = previous.data.conversations;
  current.envelope.data.organizationId = "other-workspace";
  expect(await coversClaudeTransition(current, previous)).toBe(false);
});

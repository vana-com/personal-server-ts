import { describe, expect, it } from "vitest";
import { projectPdppRecordsToLegacyPayload } from "./index.js";
import type { PdppRecord } from "./types.js";

const profile: PdppRecord = {
  stream: "account_profile",
  data: {
    id: "org-1",
    organization_id: "org-1",
    full_name: null,
    plan: null,
    name_source: "none",
    metadata_status: "absent",
  },
};
const project: PdppRecord = {
  stream: "projects",
  data: {
    id: "p1",
    name: "Research",
    creator: { uuid: "u1", full_name: "Owner", secret: "drop" },
    is_private: true,
    is_starter_project: false,
    is_archived: true,
    archived_at: "2026-01-01T00:00:00Z",
    raw_docs: [{ filename: "notes.md", content: "Text", secret: "drop" }],
  },
};
const options = {
  fetchedStreams: ["account_profile", "projects", "project_documents"],
};

describe("Claude 0.1.3 project detail", () => {
  it("retains only declared raw fields in the legacy detail", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "claude.projects",
      [profile, project],
      options,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const entry = (
      result.payload.projects as { detail: Record<string, unknown> }[]
    )[0];
    expect(entry.detail).toMatchObject({
      creator: { uuid: "u1", full_name: "Owner" },
      is_private: true,
      is_starter_project: false,
      archived_at: "2026-01-01T00:00:00Z",
      raw_docs: [{ filename: "notes.md", content: "Text" }],
    });
    expect(entry.detail).not.toHaveProperty("secret");
    expect(entry.detail.creator as Record<string, unknown>).not.toHaveProperty(
      "secret",
    );
    expect(
      (entry.detail.raw_docs as Record<string, unknown>[])[0],
    ).not.toHaveProperty("secret");
  });

  it("rejects malformed declared raw fields", () => {
    const invalid = {
      ...project,
      data: { ...project.data, is_private: "yes" },
    };
    expect(
      projectPdppRecordsToLegacyPayload(
        "claude.projects",
        [profile, invalid],
        options,
      ),
    ).toMatchObject({
      ok: false,
      error: { kind: "invalid_value", scope: "claude.projects" },
    });
  });
});

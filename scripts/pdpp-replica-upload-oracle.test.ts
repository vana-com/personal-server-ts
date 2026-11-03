import { describe, expect, it } from "vitest";
import { assertLostUploadRetried } from "./pdpp-replica-live-journey.js";

const historicalDuplicate = [
  { key: "old", sha256: "old-digest", acknowledged: true },
  { key: "old", sha256: "old-digest", acknowledged: true },
];
const loss = {
  key: "new",
  sha256: "new-digest",
  acknowledged: false,
  lostReplyId: "injected-loss",
};

describe("lost upload reply evidence", () => {
  it("does not accept a historical duplicate when no failure was injected", () => {
    expect(() =>
      assertLostUploadRetried(historicalDuplicate, "injected-loss"),
    ).toThrow();
  });

  it("requires an acknowledged retry after the exact injected loss", () => {
    const retry = { key: "new", sha256: "new-digest", acknowledged: true };
    const observed = assertLostUploadRetried(
      [...historicalDuplicate, loss, retry],
      "injected-loss",
    );
    expect(observed).toMatchObject({ key: "new", sha256: "new-digest" });
  });

  it("rejects an old same-key duplicate without a later retry", () => {
    expect(() =>
      assertLostUploadRetried(
        [
          { key: "new", sha256: "new-digest", acknowledged: true },
          { key: "new", sha256: "new-digest", acknowledged: true },
          loss,
        ],
        "injected-loss",
      ),
    ).toThrow();
  });

  it("does not treat a later upload with different bytes as the retry", () => {
    expect(() =>
      assertLostUploadRetried(
        [
          ...historicalDuplicate,
          loss,
          { key: "new", sha256: "changed-digest", acknowledged: true },
        ],
        "injected-loss",
      ),
    ).toThrow();
  });

  it("requires the selected injection to happen exactly once", () => {
    expect(() =>
      assertLostUploadRetried(
        [loss, loss, { key: "new", sha256: "new-digest", acknowledged: true }],
        "injected-loss",
      ),
    ).toThrow();
  });
});

import { expect, it } from "vitest";
import { createMemorySyncStateStore } from "./sync-state.js";

const entry = (id: string, owner: string, expiresAt: number, now: number) => ({
  id,
  owner,
  state: "{}",
  expiresAt,
  now,
  maxPerOwner: 10,
});

it("sweeps every owner's expired states, not only the writer's", () => {
  const states = createMemorySyncStateStore();
  for (const owner of ["a", "b", "c"]) states.put(entry(owner, owner, 10, 0));
  // Owners a-c never return; owner d writes after their states expired.
  states.put(entry("d", "d", 100, 20));
  expect(states.size()).toBe(1);
});

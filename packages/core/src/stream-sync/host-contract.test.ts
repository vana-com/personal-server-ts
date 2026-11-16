import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  localDatabaseName,
  LOCAL_DATABASE_NAME_PATTERN,
} from "../localdb/name.js";
import {
  END_ACCEPTANCE,
  END_OUTCOMES,
  END_RESULTS,
  endResultIsAccepted,
  hostContract,
} from "./host-contract.js";
import { RUN_INTAKE_ERROR_STATUS, RunIntakeError } from "./intake.js";

const file = JSON.parse(
  readFileSync(
    new URL("../../contracts/host-contract.json", import.meta.url),
    "utf8",
  ),
) as unknown;

describe("the host contract file", () => {
  // A host reads this file, not the TypeScript. If this fails, run
  // `npm run contracts:write` and commit the file with the change.
  it("is what the server's own constants produce", () => {
    expect(file).toEqual(hostContract());
  });

  it("names every run-intake refusal with the status the server answers", () => {
    const names = (file as ReturnType<typeof hostContract>).runIntake.errors;
    expect(names.map((error) => error.name).sort()).toEqual(
      Object.keys(RUN_INTAKE_ERROR_STATUS).sort(),
    );
    for (const { name, status } of names) {
      expect(new RunIntakeError(name as never).status, name).toBe(status);
    }
  });
});

describe("endResultIsAccepted", () => {
  // The table is the rule; the function reads it. This pins what each of the
  // 5 x 5 x 2 answers means, so a table edit shows as a changed answer.
  const accepted = [
    ["queued", "succeeded", true],
    ["queued", "succeeded", false],
    ["queued", "partial", true],
    ["queued", "partial", false],
    ["queued", "retry_pending", true],
    ["queued", "retry_pending", false],
    ["checkpoint_only", "retry_pending", true],
    ["checkpoint_only", "retry_pending", false],
    ["checkpoint_only", "succeeded", false],
    ["no_checkpoint", "retry_pending", true],
    ["no_checkpoint", "retry_pending", false],
    ["no_checkpoint", "succeeded", false],
  ] as const;

  it.each(
    END_RESULTS.flatMap((result) =>
      END_OUTCOMES.flatMap((outcome) =>
        [true, false].map((recordsSent) => ({ outcome, recordsSent, result })),
      ),
    ),
  )("$result after $outcome (records sent: $recordsSent)", (answer) => {
    const expected = accepted.some(
      ([result, outcome, sent]) =>
        result === answer.result &&
        outcome === answer.outcome &&
        sent === answer.recordsSent,
    );
    expect(
      endResultIsAccepted(answer.result, answer.outcome, answer.recordsSent),
    ).toBe(expected);
  });

  it("never accepts an answer or outcome it does not know", () => {
    expect(endResultIsAccepted("saved", "succeeded", false)).toBe(false);
    expect(endResultIsAccepted("queued", "done", false)).toBe(false);
    expect(endResultIsAccepted(undefined, undefined, false)).toBe(false);
  });

  it("only names results and outcomes the server can answer", () => {
    for (const rule of END_ACCEPTANCE) {
      expect(END_RESULTS).toContain(rule.result);
      for (const outcome of rule.outcomes) {
        expect(END_OUTCOMES).toContain(outcome);
      }
    }
  });
});

describe("the local database name pattern", () => {
  const owner = "0x1234567890abcdef1234567890abcdef12345678";

  it.each([
    "moksha",
    "vana:14800:https://gateway.example.org",
    "vana:1480:http://127.0.0.1:8080",
  ])("matches the name core derives for %s", (network) => {
    expect(localDatabaseName(owner, network)).toMatch(
      LOCAL_DATABASE_NAME_PATTERN,
    );
  });

  it.each([
    "vana--" + "a".repeat(32),
    "vana-moksha-" + "a".repeat(31),
    "vana-moksha-" + "A".repeat(32),
    "x-moksha-" + "a".repeat(32),
    "vana-mok sha-" + "a".repeat(32),
    "vana-moksha-" + "a".repeat(32) + "\n",
  ])("refuses %j", (name) => {
    expect(name).not.toMatch(LOCAL_DATABASE_NAME_PATTERN);
  });
});

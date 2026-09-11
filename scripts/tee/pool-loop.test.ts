import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
// The loop is plain ESM so it can run from an operator laptop without a build.

// @ts-expect-error - untyped operator script; the decision function is pure.
import {
  ACTION,
  adoptState,
  decidePoolActions,
  PHASE,
  REASON,
  revertMember,
  tick,
} from "./pool-loop.mjs";

const LOOP_PATH = fileURLToPath(new URL("./pool-loop.mjs", import.meta.url));
const NOW = Date.parse("2026-09-10T12:00:00.000Z");
const MINUTE = 60_000;
const CAPACITY = 4;

const member = (nodeId: string, cvmId: string, extra: object = {}) => ({
  nodeId,
  cvmId,
  publicUrl: `https://${nodeId}.invalid`,
  capacity: CAPACITY,
  bundleExpiresAt: null,
  ...extra,
});

const MEMBERS = [
  member("worker-1", "cvm-1"),
  member("worker-2", "cvm-2"),
  member("worker-3", "cvm-3"),
];

const admitted = (nodeId: string, extra: object = {}) => ({
  nodeId,
  nodeIncarnation: `${nodeId}-1`,
  capacity: CAPACITY,
  draining: false,
  unavailable: false,
  lastAdmission: { code: "ADMITTED", since: "", attempts: 1 },
  ...extra,
});

const declared = (nodeId: string, extra: object = {}) => ({
  nodeId,
  nodeIncarnation: "",
  capacity: CAPACITY,
  draining: false,
  unavailable: true,
  lastAdmission: null,
  ...extra,
});

/** An admission the controller raised after the loop's own command: only this
 * proves the flag describes the machine as it runs now. */
const readmitted = (nodeId: string, at: number, extra: object = {}) =>
  admitted(nodeId, {
    lastAdmission: {
      code: "ADMITTED",
      since: new Date(at).toISOString(),
      attempts: 1,
    },
    ...extra,
  });

const placements = (nodeId: string, count: number) =>
  Array.from({ length: count }, (_, index) => ({
    owner: { chainId: 14800, userPsId: `owner-${index}`, identityEpoch: 1 },
    generation: 1,
    assignment: {
      nodeId,
      leaseExpiresAt: new Date(NOW + 60 * MINUTE).toISOString(),
    },
  }));

/** Rows whose lease lapsed. The controller reaps them on its next renew tick;
 * until then the loop must still read the slots they hold as free. */
const expired = (nodeId: string, count: number) =>
  placements(nodeId, count).map((row) => ({
    ...row,
    assignment: {
      ...row.assignment,
      leaseExpiresAt: new Date(NOW - MINUTE).toISOString(),
    },
  }));

function status(nodes: object[], rows: object[] = [], config: object = {}) {
  return {
    controllerTerm: 1,
    paused: false,
    config: { issuedAt: "", expiresAt: null, ...config },
    nodes,
    placements: rows,
  };
}

const runningState = (nodeId: string, extra: object = {}) => ({
  phase: PHASE.running,
  since: NOW - 60 * MINUTE,
  restarts: 0,
  ...extra,
});

const types = (actions: { type: string }[]) => actions.map((a) => a.type);

describe("decidePoolActions", () => {
  it("takes no action while the controller is unreachable or paused", () => {
    for (const snapshot of [null, status([], []) as object]) {
      const paused = snapshot === null ? null : { ...snapshot, paused: true };
      const { actions } = decidePoolActions({
        now: NOW,
        members: MEMBERS,
        status: paused,
        state: {},
      });

      expect(types(actions)).toEqual([ACTION.alert]);
      expect(actions[0].reason).toBe(
        paused === null
          ? REASON.controllerUnreachable
          : REASON.controllerPaused,
      );
    }
  });

  it("freezes when the controller bundle expires within the hour", () => {
    const { actions } = decidePoolActions({
      now: NOW,
      members: MEMBERS,
      status: status([admitted("worker-1")], [], {
        expiresAt: new Date(NOW + 59 * MINUTE).toISOString(),
      }),
      state: { nodes: { "worker-1": runningState("worker-1") } },
    });

    expect(actions).toEqual([
      { type: ACTION.alert, reason: REASON.controllerExpiring, nodeId: null },
    ]);
  });

  it("starts one stopped member only after the saturation debounce", () => {
    const snapshot = status(
      [admitted("worker-1"), admitted("worker-2"), declared("worker-3")],
      [
        ...placements("worker-1", CAPACITY),
        ...placements("worker-2", CAPACITY),
      ],
    );
    const state = {
      nodes: {
        "worker-1": runningState("worker-1"),
        "worker-2": runningState("worker-2"),
      },
    };

    const first = decidePoolActions({
      now: NOW,
      members: MEMBERS,
      status: snapshot,
      state,
    });
    expect(types(first.actions)).toEqual([]);
    expect(first.state.saturatedSince).toBe(NOW);

    const second = decidePoolActions({
      now: NOW + MINUTE,
      members: MEMBERS,
      status: snapshot,
      state: first.state,
    });
    expect(second.actions).toEqual([
      { type: ACTION.start, nodeId: "worker-3", cvmId: "cvm-3" },
    ]);
    expect(second.state.nodes["worker-3"].phase).toBe(PHASE.starting);
  });

  it("never counts an unreaped expired placement against free capacity", () => {
    const snapshot = status(
      [admitted("worker-1"), admitted("worker-2"), declared("worker-3")],
      [...expired("worker-1", CAPACITY), ...expired("worker-2", CAPACITY)],
    );
    const state = {
      nodes: {
        "worker-1": runningState("worker-1"),
        "worker-2": runningState("worker-2"),
      },
    };

    const first = decidePoolActions({
      now: NOW,
      members: MEMBERS,
      status: snapshot,
      state,
    });
    const second = decidePoolActions({
      now: NOW + MINUTE,
      members: MEMBERS,
      status: snapshot,
      state: first.state,
    });

    expect(types(first.actions)).toEqual([]);
    expect(first.state.saturatedSince).toBeUndefined();
    expect(types(second.actions)).toEqual([]);
  });

  it("refuses to start beyond MAX_RUNNING and reports it", () => {
    const members = [
      ...MEMBERS,
      member("worker-4", "cvm-4"),
      member("worker-5", "cvm-5"),
    ];
    const nodes = ["worker-1", "worker-2", "worker-3", "worker-4"];
    const state = {
      saturatedSince: NOW - 2 * MINUTE,
      nodes: Object.fromEntries(nodes.map((id) => [id, runningState(id)])),
    };

    const { actions } = decidePoolActions({
      now: NOW,
      members,
      status: status(
        [...nodes.map((id) => admitted(id)), declared("worker-5")],
        nodes.flatMap((id) => placements(id, CAPACITY)),
      ),
      state,
    });

    expect(actions).toEqual([
      { type: ACTION.alert, reason: REASON.maxRunning, nodeId: null },
    ]);
  });

  it("admits a healthy started member and never calls the Gateway", () => {
    const { actions, state } = decidePoolActions({
      now: NOW,
      members: MEMBERS,
      status: status([admitted("worker-1"), declared("worker-3")]),
      health: {
        "worker-3": { status: 200, composeHash: "abc", configExpiresAt: null },
      },
      state: {
        nodes: {
          "worker-1": runningState("worker-1"),
          "worker-3": {
            phase: PHASE.starting,
            since: NOW - MINUTE,
            restarts: 0,
          },
        },
      },
    });

    expect(actions).toEqual([{ type: ACTION.admit, nodeId: "worker-3" }]);
    expect(state.nodes["worker-3"].phase).toBe(PHASE.admitWait);
  });

  it("restarts once on a double mr-kms rejection, then quarantines", () => {
    const snapshot = status([
      admitted("worker-1"),
      declared("worker-3", {
        lastAdmission: {
          code: "PEER_EVENTS_REJECTED",
          since: "",
          attempts: 4,
        },
      }),
    ]);
    const health = {
      "worker-3": { status: 200, configExpiresAt: null },
    };
    const state = {
      nodes: {
        "worker-1": runningState("worker-1"),
        "worker-3": {
          phase: PHASE.admitWait,
          since: NOW - MINUTE,
          restarts: 0,
        },
      },
    };

    const first = decidePoolActions({
      now: NOW,
      members: MEMBERS,
      status: snapshot,
      health,
      state,
    });
    expect(first.actions).toEqual([
      { type: ACTION.alert, reason: REASON.doubleMrKms, nodeId: "worker-3" },
      { type: ACTION.restart, nodeId: "worker-3", cvmId: "cvm-3" },
    ]);
    expect(first.state.nodes["worker-3"].restarts).toBe(1);

    const second = decidePoolActions({
      now: NOW + MINUTE,
      members: MEMBERS,
      status: snapshot,
      health,
      state: first.state,
    });
    // Quarantining drops the pool below MIN_RUNNING, so the floor replaces it.
    expect(types(second.actions)).toEqual([
      ACTION.alert,
      ACTION.stop,
      ACTION.alert,
      ACTION.start,
    ]);
    expect(second.state.nodes["worker-3"].phase).toBe(PHASE.quarantined);
    expect(second.state.nodes["worker-2"].phase).toBe(PHASE.starting);
  });

  it("restarts a member that never reaches admission within the deadline", () => {
    const { actions } = decidePoolActions({
      now: NOW,
      members: MEMBERS,
      status: status([admitted("worker-1"), declared("worker-3")]),
      health: { "worker-3": null },
      state: {
        nodes: {
          "worker-1": runningState("worker-1"),
          "worker-3": {
            phase: PHASE.starting,
            since: NOW - 9 * MINUTE,
            restarts: 0,
          },
        },
      },
    });

    expect(actions).toEqual([
      { type: ACTION.alert, reason: REASON.admitDeadline, nodeId: "worker-3" },
      { type: ACTION.restart, nodeId: "worker-3", cvmId: "cvm-3" },
    ]);
  });

  // 2026-09-10 slice 5: pool.json still pinned the pre-roll hashes, so the loop
  // restarted and then quarantined a worker the controller was happy to admit.
  it("warns on a stale pool.json pin but still admits the member", () => {
    const { actions } = decidePoolActions({
      now: NOW,
      members: [
        MEMBERS[0]!,
        MEMBERS[1]!,
        { ...MEMBERS[2]!, composeHash: "pre-roll" },
      ],
      status: status([admitted("worker-1"), declared("worker-3")]),
      health: {
        "worker-3": {
          status: 200,
          composeHash: "rolled",
          configExpiresAt: null,
        },
      },
      state: {
        nodes: {
          "worker-1": runningState("worker-1"),
          "worker-3": { phase: PHASE.starting, since: NOW, restarts: 0 },
        },
      },
    });

    expect(actions).toEqual([
      {
        type: ACTION.alert,
        reason: REASON.composeMismatch,
        nodeId: "worker-3",
      },
      { type: ACTION.admit, nodeId: "worker-3" },
    ]);
  });

  describe("the compose hash the controller admitted", () => {
    const runningPair = (worker3: object) => ({
      "worker-1": runningState("worker-1"),
      "worker-2": runningState("worker-2"),
      "worker-3": runningState("worker-3", worker3),
    });
    const health = (composeHash: string) => ({
      "worker-3": { status: 200, composeHash, configExpiresAt: null },
    });
    const snapshot = (at: number) =>
      status([
        admitted("worker-1"),
        admitted("worker-2"),
        readmitted("worker-3", at),
      ]);

    it("records the hash health reports under the standing admission", () => {
      const { actions, state } = decidePoolActions({
        now: NOW,
        members: MEMBERS,
        status: snapshot(NOW - 10 * MINUTE),
        health: health("rolled"),
        state: { nodes: runningPair({}) },
      });

      expect(actions).toEqual([]);
      expect(state.nodes["worker-3"]).toMatchObject({
        admittedComposeHash: "rolled",
      });
    });

    it("re-references a roll's fresh admission instead of alerting", () => {
      const { actions, state } = decidePoolActions({
        now: NOW,
        members: MEMBERS,
        status: snapshot(NOW - MINUTE),
        health: health("rolled"),
        state: {
          nodes: runningPair({
            admittedComposeHash: "pre-roll",
            admissionSince: new Date(NOW - 10 * MINUTE).toISOString(),
          }),
        },
      });

      expect(actions).toEqual([]);
      expect(state.nodes["worker-3"].admittedComposeHash).toBe("rolled");
    });

    it("alerts when the image moves under an unchanged admission", () => {
      const { actions } = decidePoolActions({
        now: NOW,
        members: MEMBERS,
        status: snapshot(NOW - 10 * MINUTE),
        health: health("unexpected"),
        state: {
          nodes: runningPair({
            admittedComposeHash: "admitted",
            admissionSince: new Date(NOW - 10 * MINUTE).toISOString(),
          }),
        },
      });

      expect(actions).toEqual([
        {
          type: ACTION.alert,
          reason: REASON.composeMismatch,
          nodeId: "worker-3",
        },
      ]);
    });
  });

  // 2026-09-10 slice 5, 00:01:24Z-00:03:20Z: the controller's own 30 s re-attest
  // admitted the started member before the loop's admit-wait sent its resume,
  // so it sat ADMITTED with `draining` still set and offered no slots for 116 s.
  describe("a drain flag left standing on a serving member", () => {
    const started = (extra: object = {}) => ({
      nodes: {
        "worker-1": runningState("worker-1"),
        "worker-2": runningState("worker-2"),
        "worker-3": {
          phase: PHASE.starting,
          since: NOW,
          restarts: 0,
          startedByLoop: true,
          ...extra,
        },
      },
    });

    it("resumes a member the controller admitted first, exactly once", () => {
      const { actions, state } = decidePoolActions({
        now: NOW + MINUTE,
        members: MEMBERS,
        status: status([
          admitted("worker-1"),
          admitted("worker-2"),
          readmitted("worker-3", NOW + 30_000, { draining: true }),
        ]),
        state: started(),
      });

      expect(actions).toEqual([
        { type: ACTION.alert, reason: REASON.stickyDrain, nodeId: "worker-3" },
        { type: ACTION.admit, nodeId: "worker-3" },
      ]);
      expect(state.nodes["worker-3"]).toMatchObject({
        phase: PHASE.running,
        resumeSent: true,
      });
    });

    it("resumes a landed start even with no drain flag to clear", () => {
      const { actions } = decidePoolActions({
        now: NOW + MINUTE,
        members: MEMBERS,
        status: status([
          admitted("worker-1"),
          admitted("worker-2"),
          readmitted("worker-3", NOW + 30_000),
        ]),
        state: started(),
      });

      expect(actions).toEqual([{ type: ACTION.admit, nodeId: "worker-3" }]);
    });

    it("alerts once per episode while it keeps re-issuing the resume", () => {
      const { actions, state } = decidePoolActions({
        now: NOW,
        members: MEMBERS,
        status: status([
          admitted("worker-1"),
          admitted("worker-2", { draining: true }),
          admitted("worker-3"),
        ]),
        state: {
          nodes: {
            "worker-1": runningState("worker-1"),
            "worker-2": runningState("worker-2", { resumeSent: true }),
            "worker-3": runningState("worker-3"),
          },
        },
      });

      expect(actions).toEqual([{ type: ACTION.admit, nodeId: "worker-2" }]);
      expect(state.nodes["worker-2"].resumeSent).toBe(true);
    });

    it("leaves the loop's own drain alone", () => {
      const { actions } = decidePoolActions({
        now: NOW,
        members: MEMBERS,
        status: status([
          admitted("worker-1"),
          admitted("worker-2"),
          admitted("worker-3", { draining: true }),
        ]),
        state: {
          nodes: {
            "worker-1": runningState("worker-1"),
            "worker-2": runningState("worker-2"),
            "worker-3": {
              phase: PHASE.draining,
              since: NOW - MINUTE,
              restarts: 0,
            },
          },
        },
      });

      expect(actions).toEqual([
        { type: ACTION.stop, nodeId: "worker-3", cvmId: "cvm-3" },
      ]);
    });
  });

  it("drains the longest idle member above MIN_RUNNING and never below it", () => {
    const nodes = ["worker-1", "worker-2", "worker-3"];
    const idle = (nodeId: string, idleSince: number) =>
      runningState(nodeId, { idleSince });
    const state = {
      nodes: {
        "worker-1": idle("worker-1", NOW - 20 * MINUTE),
        "worker-2": idle("worker-2", NOW - 40 * MINUTE),
        "worker-3": idle("worker-3", NOW - 30 * MINUTE),
      },
    };

    const first = decidePoolActions({
      now: NOW,
      members: MEMBERS,
      status: status(nodes.map((id) => admitted(id))),
      state,
    });
    expect(first.actions).toEqual([{ type: ACTION.drain, nodeId: "worker-2" }]);

    // With only MIN_RUNNING members left, an idle member is kept warm.
    const second = decidePoolActions({
      now: NOW,
      members: MEMBERS,
      status: status([admitted("worker-1"), admitted("worker-3")]),
      state: {
        nodes: {
          "worker-1": idle("worker-1", NOW - 20 * MINUTE),
          "worker-3": idle("worker-3", NOW - 30 * MINUTE),
        },
      },
    });
    expect(second.actions).toEqual([]);
  });

  it("stops a draining member only once it is drained and has no live lease", () => {
    const draining = {
      phase: PHASE.draining,
      since: NOW - MINUTE,
      restarts: 0,
    };
    const members = MEMBERS;
    // A drain only happens above MIN_RUNNING, so two other members stay up and
    // the warm floor asks for nothing once this one stops.
    const others = {
      "worker-1": runningState("worker-1"),
      "worker-3": runningState("worker-3"),
    };

    const busy = decidePoolActions({
      now: NOW,
      members,
      status: status(
        [
          admitted("worker-1"),
          admitted("worker-2", { draining: true }),
          admitted("worker-3"),
        ],
        placements("worker-2", 1),
      ),
      state: { nodes: { ...others, "worker-2": draining } },
    });
    expect(busy.actions).toEqual([]);

    const clear = decidePoolActions({
      now: NOW,
      members,
      status: status([
        admitted("worker-1"),
        admitted("worker-2", { draining: true }),
        admitted("worker-3"),
      ]),
      state: { nodes: { ...others, "worker-2": draining } },
    });
    expect(clear.actions).toEqual([
      { type: ACTION.stop, nodeId: "worker-2", cvmId: "cvm-2" },
    ]);
    expect(clear.state.nodes["worker-2"]).toMatchObject({
      phase: PHASE.stopped,
      cooldownUntil: NOW + 5 * MINUTE,
    });
  });

  it("leaves a member running when its drain overruns the timeout", () => {
    const { actions, state } = decidePoolActions({
      now: NOW,
      members: MEMBERS,
      status: status(
        [admitted("worker-1"), admitted("worker-2")],
        placements("worker-2", 1),
      ),
      state: {
        nodes: {
          "worker-1": runningState("worker-1"),
          "worker-2": {
            phase: PHASE.draining,
            since: NOW - 4 * MINUTE,
            restarts: 0,
          },
        },
      },
    });

    expect(actions).toEqual([
      { type: ACTION.alert, reason: REASON.drainTimeout, nodeId: "worker-2" },
    ]);
    expect(state.nodes["worker-2"].phase).toBe(PHASE.running);
  });

  it("refuses to start a member whose own bundle is about to expire", () => {
    const expiring = {
      ...MEMBERS[2]!,
      bundleExpiresAt: new Date(NOW + 20 * MINUTE).toISOString(),
    };
    const { actions } = decidePoolActions({
      now: NOW,
      members: [MEMBERS[0]!, MEMBERS[1]!, expiring],
      status: status(
        [admitted("worker-1"), admitted("worker-2"), declared("worker-3")],
        [
          ...placements("worker-1", CAPACITY),
          ...placements("worker-2", CAPACITY),
        ],
      ),
      state: {
        saturatedSince: NOW - 2 * MINUTE,
        nodes: {
          "worker-1": runningState("worker-1"),
          "worker-2": runningState("worker-2"),
        },
      },
    });

    expect(actions).toEqual([
      { type: ACTION.alert, reason: REASON.noCandidate, nodeId: null },
    ]);
  });

  it("never credits the capacity of a member the controller cannot reach", () => {
    // The ops plan's own state: W1/W2 saturated, W3 admitted earlier and since
    // stopped. Crediting its four slots as free made the loop take no action.
    const { actions, state } = decidePoolActions({
      now: NOW,
      members: MEMBERS,
      status: status(
        [
          admitted("worker-1"),
          admitted("worker-2"),
          admitted("worker-3", { unavailable: true }),
        ],
        [
          ...placements("worker-1", CAPACITY),
          ...placements("worker-2", CAPACITY),
        ],
      ),
      state: {
        saturatedSince: NOW - 2 * MINUTE,
        nodes: {
          "worker-1": runningState("worker-1"),
          "worker-2": runningState("worker-2"),
          "worker-3": {
            phase: PHASE.stopped,
            since: NOW - 10 * MINUTE,
            restarts: 1,
          },
        },
      },
    });

    expect(actions).toEqual([
      { type: ACTION.start, nodeId: "worker-3", cvmId: "cvm-3" },
    ]);
    expect(state.nodes["worker-3"]).toMatchObject({
      phase: PHASE.starting,
      restarts: 1,
    });
  });

  it("starts members up to MIN_RUNNING before any saturation", () => {
    const cold = status(["worker-1", "worker-2", "worker-3"].map(declared));

    const first = decidePoolActions({
      now: NOW,
      members: MEMBERS,
      status: cold,
      state: {},
    });
    expect(first.actions).toEqual([
      { type: ACTION.start, nodeId: "worker-1", cvmId: "cvm-1" },
    ]);
    expect(first.state.saturatedSince).toBeUndefined();

    const second = decidePoolActions({
      now: NOW,
      members: MEMBERS,
      status: cold,
      state: first.state,
    });
    expect(second.actions).toEqual([
      { type: ACTION.start, nodeId: "worker-2", cvmId: "cvm-2" },
    ]);

    // Two members are coming up, which is the floor: nothing more is started.
    const third = decidePoolActions({
      now: NOW,
      members: MEMBERS,
      status: cold,
      state: second.state,
    });
    expect(third.actions).toEqual([]);
  });

  it("keeps the restart budget across an admitted tick", () => {
    const { state } = decidePoolActions({
      now: NOW,
      members: MEMBERS,
      status: status([
        admitted("worker-1"),
        admitted("worker-2"),
        readmitted("worker-3", NOW - MINUTE),
      ]),
      state: {
        nodes: {
          "worker-1": runningState("worker-1"),
          "worker-2": runningState("worker-2"),
          "worker-3": {
            phase: PHASE.admitWait,
            since: NOW - 10 * MINUTE,
            restarts: 1,
          },
        },
      },
    });

    expect(state.nodes["worker-3"]).toMatchObject({
      phase: PHASE.running,
      restarts: 1,
    });
  });

  it("never restarts a member that still serves a live lease", () => {
    const { actions, state } = decidePoolActions({
      now: NOW,
      members: MEMBERS,
      status: status(
        [
          admitted("worker-1"),
          admitted("worker-2"),
          admitted("worker-3", { unavailable: true }),
        ],
        placements("worker-3", 1),
      ),
      state: {
        nodes: {
          "worker-1": runningState("worker-1"),
          "worker-2": runningState("worker-2"),
          "worker-3": {
            phase: PHASE.admitWait,
            since: NOW - 9 * MINUTE,
            restarts: 0,
          },
        },
      },
    });

    expect(actions.map((action) => action.reason)).toEqual([
      REASON.admitDeadline,
      REASON.restartBlocked,
    ]);
    expect(state.nodes["worker-3"]).toMatchObject({
      phase: PHASE.admitWait,
      restarts: 0,
    });
  });

  it("ignores an admission record raised before the current boot", () => {
    const { actions } = decidePoolActions({
      now: NOW,
      members: MEMBERS,
      status: status([
        admitted("worker-1"),
        admitted("worker-2"),
        declared("worker-3", {
          lastAdmission: {
            code: "PEER_EVENTS_REJECTED",
            since: new Date(NOW - 5 * MINUTE).toISOString(),
            attempts: 2,
          },
        }),
      ]),
      health: { "worker-3": { status: 200, configExpiresAt: null } },
      state: {
        nodes: {
          "worker-1": runningState("worker-1"),
          "worker-2": runningState("worker-2"),
          "worker-3": {
            phase: PHASE.starting,
            since: NOW - MINUTE,
            restarts: 1,
          },
        },
      },
    });

    expect(actions).toEqual([{ type: ACTION.admit, nodeId: "worker-3" }]);
  });

  it("keeps the previous phase when a CVM command does not run", () => {
    const previous = {
      saturatedSince: NOW - 2 * MINUTE,
      nodes: {
        "worker-1": runningState("worker-1"),
        "worker-2": runningState("worker-2"),
        "worker-3": {
          phase: PHASE.stopped,
          since: NOW - 10 * MINUTE,
          restarts: 0,
        },
      },
    };
    const { actions, state } = decidePoolActions({
      now: NOW,
      members: MEMBERS,
      status: status(
        [admitted("worker-1"), admitted("worker-2"), declared("worker-3")],
        [
          ...placements("worker-1", CAPACITY),
          ...placements("worker-2", CAPACITY),
        ],
      ),
      state: previous,
    });
    expect(state.nodes["worker-3"].phase).toBe(PHASE.starting);

    revertMember(state, previous, actions[0].nodeId);

    expect(state.nodes["worker-3"]).toEqual(previous.nodes["worker-3"]);
    expect(state.saturatedSince).toBe(previous.saturatedSince);
  });

  // 2026-09-10 soak, 20:19:40Z-20:30:20Z: the loop stopped worker-3, the
  // controller kept reporting it admitted for 34 s, the tick inside that window
  // rewrote `stopped` to `running`, and 8 min later the admit deadline restarted
  // a machine that was stopped on purpose.
  describe("a stop the controller has not caught up with", () => {
    const stopped = (extra: object = {}) => ({
      nodes: {
        "worker-1": runningState("worker-1"),
        "worker-2": runningState("worker-2"),
        "worker-3": {
          phase: PHASE.stopped,
          since: NOW,
          restarts: 0,
          cooldownUntil: NOW + 5 * MINUTE,
          ...extra,
        },
      },
    });

    it("keeps the stopped phase while the admitted flag is still standing", () => {
      const { actions, state } = decidePoolActions({
        now: NOW + 30_000,
        members: MEMBERS,
        status: status(["worker-1", "worker-2", "worker-3"].map(admitted)),
        state: stopped(),
      });

      expect(actions).toEqual([]);
      expect(state.nodes["worker-3"]).toMatchObject({
        phase: PHASE.stopped,
        since: NOW,
        restarts: 0,
      });
    });

    it("never spends the restart budget on a member it stopped itself", () => {
      // The tick that used to fire ADMIT_DEADLINE_EXCEEDED: 9 min after the
      // stop, with the controller's demotion long since arrived.
      const { actions, state } = decidePoolActions({
        now: NOW + 9 * MINUTE,
        members: MEMBERS,
        status: status([
          admitted("worker-1"),
          admitted("worker-2"),
          admitted("worker-3", { unavailable: true }),
        ]),
        health: { "worker-3": { status: 200, configExpiresAt: null } },
        state: stopped(),
      });

      expect(actions).toEqual([]);
      expect(state.nodes["worker-3"]).toMatchObject({
        phase: PHASE.stopped,
        restarts: 0,
      });
    });

    it("reclaims a stopped member only on an admission raised after the stop", () => {
      const past = decidePoolActions({
        now: NOW + 4 * MINUTE,
        members: MEMBERS,
        status: status([
          admitted("worker-1"),
          admitted("worker-2"),
          readmitted("worker-3", NOW - MINUTE),
        ]),
        state: stopped(),
      });
      expect(past.state.nodes["worker-3"].phase).toBe(PHASE.stopped);

      const back = decidePoolActions({
        now: NOW + 4 * MINUTE,
        members: MEMBERS,
        status: status([
          admitted("worker-1"),
          admitted("worker-2"),
          readmitted("worker-3", NOW + MINUTE),
        ]),
        state: stopped(),
      });
      expect(back.state.nodes["worker-3"].phase).toBe(PHASE.running);
    });
  });

  // A roll left an operator hand-editing `since` after restoring phase by
  // hand; the controller is the only authority on an admission it granted.
  describe("adopts admission times from the controller", () => {
    it("corrects a hand-stamped since newer than the controller's own admission", () => {
      const { actions, state } = decidePoolActions({
        now: NOW,
        members: MEMBERS,
        status: status([
          admitted("worker-1"),
          admitted("worker-2"),
          readmitted("worker-3", NOW - 10 * MINUTE),
        ]),
        state: {
          nodes: {
            "worker-1": runningState("worker-1"),
            "worker-2": runningState("worker-2"),
            "worker-3": { phase: PHASE.admitWait, since: NOW, restarts: 0 },
          },
        },
      });

      expect(actions).toEqual([]);
      expect(state.nodes["worker-3"]).toMatchObject({
        phase: PHASE.running,
        since: NOW - 10 * MINUTE,
      });
    });

    it("also corrects since when the hand-edited phase already reads running", () => {
      const { actions, state } = decidePoolActions({
        now: NOW,
        members: MEMBERS,
        status: status([
          admitted("worker-1"),
          admitted("worker-2"),
          readmitted("worker-3", NOW - 10 * MINUTE),
        ]),
        state: {
          nodes: {
            "worker-1": runningState("worker-1"),
            "worker-2": runningState("worker-2"),
            "worker-3": { phase: PHASE.running, since: NOW, restarts: 0 },
          },
        },
      });

      expect(actions).toEqual([]);
      expect(state.nodes["worker-3"].since).toBe(NOW - 10 * MINUTE);
    });

    it("keeps a loop-issued start's own since even when newer than the controller's record", () => {
      const { actions, state } = decidePoolActions({
        now: NOW,
        members: MEMBERS,
        status: status([
          admitted("worker-1"),
          admitted("worker-2"),
          readmitted("worker-3", NOW - 10 * MINUTE),
        ]),
        health: { "worker-3": { status: 200, configExpiresAt: null } },
        state: {
          nodes: {
            "worker-1": runningState("worker-1"),
            "worker-2": runningState("worker-2"),
            "worker-3": {
              phase: PHASE.admitWait,
              since: NOW,
              restarts: 0,
              startedByLoop: true,
            },
          },
        },
      });

      // Not adopted: this loop-issued start is confirmed by outliving the
      // controller's flag, never by copying its timestamp.
      expect(actions).toEqual([{ type: ACTION.admit, nodeId: "worker-3" }]);
      expect(state.nodes["worker-3"]).toMatchObject({
        phase: PHASE.admitWait,
        since: NOW,
        startedByLoop: true,
      });
    });

    // `restartOrQuarantine` never sets `startedByLoop`, so the loop's own hard
    // restart was previously confirmed by whatever admission the controller
    // still held - one raised before the machine rebooted.
    const restarted = (at: number) => ({
      phase: PHASE.admitWait,
      since: NOW,
      restarts: 1,
      loopStartedAt: at,
    });

    it("ignores an admission raised before the loop's own restart", () => {
      const { state } = decidePoolActions({
        now: NOW,
        members: MEMBERS,
        status: status([
          admitted("worker-1"),
          admitted("worker-2"),
          readmitted("worker-3", NOW - 10 * MINUTE),
        ]),
        state: {
          nodes: {
            "worker-1": runningState("worker-1"),
            "worker-2": runningState("worker-2"),
            "worker-3": restarted(NOW - 4 * MINUTE),
          },
        },
      });

      expect(state.nodes["worker-3"]).toMatchObject({
        phase: PHASE.admitWait,
        since: NOW,
      });
    });

    it("adopts an admission the restarted member earned afterwards", () => {
      const { state } = decidePoolActions({
        now: NOW,
        members: MEMBERS,
        status: status([
          admitted("worker-1"),
          admitted("worker-2"),
          readmitted("worker-3", NOW - 2 * MINUTE),
        ]),
        state: {
          nodes: {
            "worker-1": runningState("worker-1"),
            "worker-2": runningState("worker-2"),
            "worker-3": restarted(NOW - 4 * MINUTE),
          },
        },
      });

      expect(state.nodes["worker-3"]).toMatchObject({
        phase: PHASE.running,
        since: NOW - 2 * MINUTE,
      });
    });
  });

  // Same soak, 20:30:55Z: scale-down drained worker-1 - the always-on
  // tdx.small - because defect 1 had just rebooted the two mediums, leaving W1
  // the longest idle. MIN_RUNNING counts machines, so it never noticed.
  describe("pinned members", () => {
    const PINNED = [
      member("worker-1", "cvm-1", { pinned: true }),
      member("worker-2", "cvm-2", { pinned: true }),
      member("worker-3", "cvm-3"),
    ];
    const idle = (nodeId: string, minutes: number) =>
      runningState(nodeId, { idleSince: NOW - minutes * MINUTE });

    it("drains a non-pinned member even when a pinned one is idler", () => {
      const { actions } = decidePoolActions({
        now: NOW,
        members: PINNED,
        status: status(
          ["worker-1", "worker-2", "worker-3"].map((id) => admitted(id)),
        ),
        state: {
          nodes: {
            "worker-1": idle("worker-1", 40),
            "worker-2": idle("worker-2", 30),
            "worker-3": idle("worker-3", 20),
          },
        },
      });

      expect(actions).toEqual([{ type: ACTION.drain, nodeId: "worker-3" }]);
    });

    it("keeps a pinned member up once it is the only idle one left", () => {
      const { actions } = decidePoolActions({
        now: NOW,
        members: PINNED,
        status: status(
          ["worker-1", "worker-2", "worker-3"].map((id) => admitted(id)),
        ),
        state: {
          nodes: {
            "worker-1": idle("worker-1", 40),
            "worker-2": idle("worker-2", 30),
            "worker-3": runningState("worker-3", { idleSince: NOW }),
          },
        },
      });

      expect(actions).toEqual([]);
    });

    it("wakes a stopped pinned member while the numeric floor is satisfied", () => {
      // The pool the soak drifted to: three running, the always-on small one
      // stopped. `warm >= MIN_RUNNING`, so only the pin brings it back.
      const { actions, state } = decidePoolActions({
        now: NOW,
        members: [...PINNED, member("worker-4", "cvm-4")],
        status: status([
          admitted("worker-1", { unavailable: true }),
          admitted("worker-2"),
          admitted("worker-3"),
          admitted("worker-4"),
        ]),
        state: {
          nodes: {
            "worker-1": {
              phase: PHASE.stopped,
              since: NOW - 10 * MINUTE,
              restarts: 1,
            },
            "worker-2": idle("worker-2", 20),
            "worker-3": idle("worker-3", 20),
            "worker-4": idle("worker-4", 20),
          },
        },
      });

      // The drain of the idlest non-pinned member rides along; worker-2 is not
      // a candidate for it.
      expect(actions).toEqual([
        { type: ACTION.start, nodeId: "worker-1", cvmId: "cvm-1" },
        { type: ACTION.drain, nodeId: "worker-3" },
      ]);
      expect(state.nodes["worker-1"]).toMatchObject({
        phase: PHASE.starting,
        restarts: 1,
      });
    });

    it("leaves a quarantined pinned member alone", () => {
      const { actions } = decidePoolActions({
        now: NOW,
        members: PINNED,
        status: status([
          admitted("worker-1", { unavailable: true }),
          admitted("worker-2"),
          admitted("worker-3"),
        ]),
        state: {
          nodes: {
            "worker-1": {
              phase: PHASE.quarantined,
              since: NOW - 10 * MINUTE,
              restarts: 1,
            },
            "worker-2": runningState("worker-2", { idleSince: NOW }),
            "worker-3": runningState("worker-3", { idleSince: NOW }),
          },
        },
      });

      expect(actions).toEqual([]);
    });

    it("gives a landed start a fresh restart budget", () => {
      const { state } = decidePoolActions({
        now: NOW + MINUTE,
        members: PINNED,
        status: status([
          readmitted("worker-1", NOW + 30_000),
          admitted("worker-2"),
          admitted("worker-3"),
        ]),
        state: {
          nodes: {
            "worker-1": {
              phase: PHASE.starting,
              since: NOW,
              restarts: 1,
              startedByLoop: true,
            },
            "worker-2": runningState("worker-2", { idleSince: NOW }),
            "worker-3": runningState("worker-3", { idleSince: NOW }),
          },
        },
      });

      expect(state.nodes["worker-1"]).toMatchObject({
        phase: PHASE.running,
        restarts: 0,
      });
      expect(state.nodes["worker-1"].startedByLoop).toBeUndefined();
    });
  });
});

describe("adoptState", () => {
  // Startup reconciliation, so a restart after a roll needs no state edits.
  it("adopts an ADMITTED member into running and an unavailable one into stopped", () => {
    const state = adoptState({
      now: NOW,
      members: MEMBERS,
      status: status([
        readmitted("worker-1", NOW - 5 * MINUTE),
        admitted("worker-2", { unavailable: true }),
        admitted("worker-3", { unavailable: true }),
      ]),
      state: {
        nodes: {
          "worker-1": {
            phase: PHASE.stopped,
            since: NOW - MINUTE,
            restarts: 0,
          },
          "worker-2": {
            phase: PHASE.admitWait,
            since: NOW - MINUTE,
            restarts: 0,
          },
          "worker-3": {
            phase: PHASE.starting,
            since: NOW - 30_000,
            restarts: 0,
          },
        },
      },
    });

    expect(state.nodes["worker-1"]).toMatchObject({
      phase: PHASE.running,
      since: NOW - 5 * MINUTE,
    });
    expect(state.nodes["worker-2"]).toMatchObject({ phase: PHASE.stopped });
    // A member mid-boot is left for the loop's own next tick to decide.
    expect(state.nodes["worker-3"]).toMatchObject({ phase: PHASE.starting });
  });

  // The controller's admissions map is in memory and `declare` re-marks every
  // persisted node unavailable for ~30 s after its own boot, so right after a
  // roll - the window the README tells the operator to restart the loop in -
  // every member reads unavailable with no admission.
  it("never demotes a running member merely because the controller shows no admission", () => {
    const input = {
      now: NOW,
      members: MEMBERS,
      status: status(
        MEMBERS.map((each) => declared(each.nodeId)),
        placements("worker-1", 1),
      ),
      state: {
        nodes: {
          "worker-1": runningState("worker-1"),
          "worker-2": runningState("worker-2"),
          "worker-3": runningState("worker-3"),
        },
      },
    };

    const state = adoptState(input);

    for (const each of MEMBERS)
      expect(state.nodes[each.nodeId]).toMatchObject({
        phase: PHASE.running,
        since: NOW - 60 * MINUTE,
      });
    // ... and no `phala cvms start` is issued against machines that are up.
    expect(types(decidePoolActions({ ...input, state }).actions)).not.toContain(
      ACTION.start,
    );
  });

  it("still demotes an unavailable member holding no live lease", () => {
    const state = adoptState({
      now: NOW,
      members: MEMBERS,
      status: status([declared("worker-1")]),
      state: {
        nodes: {
          "worker-1": {
            phase: PHASE.admitWait,
            since: NOW - MINUTE,
            restarts: 0,
          },
        },
      },
    });

    expect(state.nodes["worker-1"]).toMatchObject({ phase: PHASE.stopped });
  });

  it("leaves state untouched when the controller is unreachable", () => {
    const previous = { nodes: { "worker-1": runningState("worker-1") } };
    const state = adoptState({
      now: NOW,
      members: MEMBERS,
      status: null,
      state: previous,
    });

    expect(state).toEqual(previous);
  });
});

describe("tick", () => {
  it("never writes the state file in dry-run mode", async () => {
    const dir = mkdtempSync(join(tmpdir(), "pool-loop-dry-run-"));
    const statePath = join(dir, "pool-loop-state.json");
    // Compact, unindented on purpose: writeState always emits 2-space JSON,
    // so any real write - even of unchanged content - would flip these bytes.
    const fixture = JSON.stringify({
      nodes: { "worker-1": runningState("worker-1") },
    });
    writeFileSync(statePath, fixture);

    try {
      await tick({
        // Not a valid base URL: readStatus fails before any network call.
        adminUrl: "invalid",
        adminToken: () => "test-token",
        members: [member("worker-1", "cvm-1")],
        warned: new Set(),
        statePath,
        dryRun: true,
        once: true,
      });

      expect(readFileSync(statePath, "utf8")).toBe(fixture);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

// The admin bearer rides every request and authorizes admit, drain, quiesce,
// migrate and prepare-rollback; the controller listens as plain HTTP behind the
// dstack TLS gateway, so a hand-edited http:// URL is that token in cleartext.
describe("controllerAdminUrl", () => {
  const run = (controllerAdminUrl: string) => {
    const dir = mkdtempSync(join(tmpdir(), "pool-loop-admin-url-"));
    try {
      const poolPath = join(dir, "pool.json");
      writeFileSync(
        poolPath,
        JSON.stringify({
          controllerAdminUrl,
          members: [member("worker-1", "cvm-1")],
        }),
      );
      return spawnSync(process.execPath, [LOOP_PATH, "--once", "--dry-run"], {
        encoding: "utf8",
        env: { ...process.env, VANA_POOL_PATH: poolPath },
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };

  it("refuses a plaintext admin URL before the first tick", () => {
    const result = run("http://controller.invalid");

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("controllerAdminUrl must be an https URL");
  });

  it("accepts an https admin URL", () => {
    expect(run("https://controller.invalid").stderr).not.toContain(
      "controllerAdminUrl must be an https URL",
    );
  });
});

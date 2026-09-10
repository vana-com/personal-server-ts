import { describe, expect, it } from "vitest";
// The loop is plain ESM so it can run from an operator laptop without a build.

// @ts-expect-error - untyped operator script; the decision function is pure.
import { ACTION, decidePoolActions, PHASE, REASON } from "./pool-loop.mjs";

const NOW = Date.parse("2026-09-10T12:00:00.000Z");
const MINUTE = 60_000;
const CAPACITY = 4;

const member = (nodeId: string, cvmId: string) => ({
  nodeId,
  cvmId,
  publicUrl: `https://${nodeId}.invalid`,
  capacity: CAPACITY,
  bundleExpiresAt: null,
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

const placements = (nodeId: string, count: number) =>
  Array.from({ length: count }, (_, index) => ({
    owner: { chainId: 14800, userPsId: `owner-${index}`, identityEpoch: 1 },
    generation: 1,
    assignment: {
      nodeId,
      leaseExpiresAt: new Date(NOW + 60 * MINUTE).toISOString(),
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
    expect(types(second.actions)).toEqual([
      ACTION.alert,
      ACTION.stop,
      ACTION.alert,
    ]);
    expect(second.state.nodes["worker-3"].phase).toBe(PHASE.quarantined);
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

  it("never admits a member whose compose hash is not the pinned one", () => {
    const { actions } = decidePoolActions({
      now: NOW,
      members: [
        MEMBERS[0]!,
        MEMBERS[1]!,
        { ...MEMBERS[2]!, composeHash: "expected" },
      ],
      status: status([admitted("worker-1"), declared("worker-3")]),
      health: {
        "worker-3": {
          status: 200,
          composeHash: "other",
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

    expect(types(actions)).toEqual([ACTION.alert, ACTION.restart]);
    expect(actions[0].reason).toBe(REASON.composeMismatch);
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

    const busy = decidePoolActions({
      now: NOW,
      members,
      status: status(
        [admitted("worker-1"), admitted("worker-2", { draining: true })],
        placements("worker-2", 1),
      ),
      state: { nodes: { "worker-2": draining } },
    });
    expect(busy.actions).toEqual([]);

    const clear = decidePoolActions({
      now: NOW,
      members,
      status: status([
        admitted("worker-1"),
        admitted("worker-2", { draining: true }),
      ]),
      state: { nodes: { "worker-2": draining } },
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
});

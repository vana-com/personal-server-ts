#!/usr/bin/env node
/**
 * External warm-pool loop for the Moksha personal-server TEE fleet.
 *
 * It starts and stops pre-declared pool members on Phala and drives their
 * admission through the controller's private admin listener. It never talks to
 * the Gateway: Gateway admit forwards no `resume` and Gateway drain is a
 * one-way transition to removed.
 *
 *   phala start ──► [starting] ──health 200──► [admit-wait] ──admitted──► [running]
 *        ▲              │                          │                        │
 *        │              └── 8 min ─► restart once ─┘                  live=0 15 min
 *        │                              │                                   │
 *   [stopped] ◄── stop (draining && live=0) ── [draining] ◄── controller drain
 *        ▲                                                                  │
 *        └───────────────── second failure ─► [quarantined] ◄───────────────┘
 *
 * Inputs (never committed): ~/.vana/pool.json describes the members; every
 * credential is read from the login keychain per command and is never written
 * to a file. Durable phase state lives in ~/.vana/pool-loop-state.json.
 *
 *   node scripts/tee/pool-loop.mjs [--once] [--dry-run]
 */
import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SECOND_MS = 1_000;
const MINUTE_MS = 60 * SECOND_MS;
const HOUR_MS = 60 * MINUTE_MS;

const TICK_MS = 15 * SECOND_MS;
const SCALE_UP_DEBOUNCE_MS = 60 * SECOND_MS;
const IDLE_MS = 15 * MINUTE_MS;
const ADMIT_DEADLINE_MS = 8 * MINUTE_MS;
const COOLDOWN_MS = 5 * MINUTE_MS;
/** Longer than the controller's 120 s drain grace, so a drain can finish. */
const DRAIN_TIMEOUT_MS = 180 * SECOND_MS;
const MIN_RUNNING = 2;
const MAX_RUNNING = 4;
/** Freeze rather than move owners onto a controller about to lose its bundle. */
const CONTROLLER_EXPIRY_FLOOR_MS = HOUR_MS;
const MEMBER_EXPIRY_FLOOR_MS = 30 * MINUTE_MS;
const REQUEST_TIMEOUT_MS = 10 * SECOND_MS;
const HTTP_OK = 200;
const MAX_RESTARTS = 1;

const DEFAULT_POOL_PATH = join(homedir(), ".vana", "pool.json");
const DEFAULT_STATE_PATH = join(homedir(), ".vana", "pool-loop-state.json");
const ADMIN_TOKEN_SERVICE = "vana-fleet-admin";
const AGENT_SECRET_SERVICE_PREFIX = "vana-fleet-agent-";
const STATUS_ROUTE = "/fleet/v1/status";
const ADMIT_ROUTE = "/fleet/v1/admit";
const DRAIN_ROUTE = "/fleet/v1/drain";
const HEALTH_ROUTE = "/agent/v1/health";
const STATE_FILE_MODE = 0o600;
const STATE_DIRECTORY_MODE = 0o700;

/** Double mr-kms: the member booted, but its event log has 11 runtime events. */
const DOUBLE_MR_KMS_CODE = "PEER_EVENTS_REJECTED";

export const PHASE = Object.freeze({
  stopped: "stopped",
  starting: "starting",
  admitWait: "admit-wait",
  running: "running",
  draining: "draining",
  quarantined: "quarantined",
});

export const ACTION = Object.freeze({
  start: "start",
  stop: "stop",
  restart: "restart",
  admit: "admit",
  drain: "drain",
  alert: "alert",
});

export const REASON = Object.freeze({
  controllerUnreachable: "CONTROLLER_UNREACHABLE",
  controllerPaused: "CONTROLLER_PAUSED",
  controllerExpiring: "CONTROLLER_BUNDLE_EXPIRING",
  memberExpiring: "MEMBER_BUNDLE_EXPIRING",
  composeMismatch: "COMPOSE_HASH_MISMATCH",
  admitDeadline: "ADMIT_DEADLINE_EXCEEDED",
  doubleMrKms: "DOUBLE_MR_KMS",
  drainTimeout: "DRAIN_TIMEOUT",
  maxRunning: "MAX_RUNNING_REACHED",
  noCandidate: "NO_STARTABLE_MEMBER",
  quarantined: "MEMBER_QUARANTINED",
  stopBlocked: "STOP_BLOCKED",
});

// ---------------------------------------------------------------- decisions

const alert = (reason, nodeId = null) => ({
  type: ACTION.alert,
  reason,
  nodeId,
});

const isRunning = (view) => view.entry.phase === PHASE.running;

/** A stopped member is only startable while its own signed bundle stays valid
 * for long enough to be worth booting; null expiry is deployment-lived. */
function bundleStartable(member, now) {
  if (!member.bundleExpiresAt) return true;
  return Date.parse(member.bundleExpiresAt) - now >= MEMBER_EXPIRY_FLOOR_MS;
}

function healthUsable(health, now) {
  if (!health || health.status !== HTTP_OK) return false;
  if (!health.configExpiresAt) return true;
  return Date.parse(health.configExpiresAt) - now >= MEMBER_EXPIRY_FLOOR_MS;
}

/** Scale-down stop guard. Never stop a machine the controller has not fully
 * drained, and never while any placement lease on it is still live. */
const drainedStoppable = (view) =>
  view.node?.draining === true && view.live === 0;

/** Quarantine stop guard. A member that never attested holds no placement. */
const neverAdmittedStoppable = (view) =>
  (!view.node || view.node.unavailable === true) && view.live === 0;

function enter(entry, phase, now) {
  entry.phase = phase;
  entry.since = now;
}

function restartOrQuarantine(view, ctx, reason) {
  const { entry, member } = view;
  ctx.actions.push(alert(reason, member.nodeId));

  if ((entry.restarts ?? 0) < MAX_RESTARTS) {
    ctx.actions.push({
      type: ACTION.restart,
      nodeId: member.nodeId,
      cvmId: member.cvmId,
    });
    entry.restarts = (entry.restarts ?? 0) + 1;
    enter(entry, PHASE.starting, ctx.now);
    return;
  }

  if (!neverAdmittedStoppable(view)) {
    ctx.actions.push(alert(REASON.stopBlocked, member.nodeId));
    return;
  }
  ctx.actions.push({
    type: ACTION.stop,
    nodeId: member.nodeId,
    cvmId: member.cvmId,
  });
  ctx.actions.push(alert(REASON.quarantined, member.nodeId));
  enter(entry, PHASE.quarantined, ctx.now);
}

function advanceAdmission(view, ctx) {
  const { entry, member, health } = view;

  if (!healthUsable(health, ctx.now)) {
    if (health && health.status === HTTP_OK)
      restartOrQuarantine(view, ctx, REASON.memberExpiring);
    else if (ctx.now - entry.since >= ADMIT_DEADLINE_MS)
      restartOrQuarantine(view, ctx, REASON.admitDeadline);
    return;
  }

  // An unexpected image must never be admitted, however healthy it looks.
  if (member.composeHash && health.composeHash !== member.composeHash) {
    restartOrQuarantine(view, ctx, REASON.composeMismatch);
    return;
  }

  // A second mr-kms event is a boot artefact one restart clears.
  if (view.node?.lastAdmission?.code === DOUBLE_MR_KMS_CODE) {
    restartOrQuarantine(view, ctx, REASON.doubleMrKms);
    return;
  }

  if (ctx.now - entry.since >= ADMIT_DEADLINE_MS) {
    restartOrQuarantine(view, ctx, REASON.admitDeadline);
    return;
  }

  // resume:true clears a planned drain; only the controller admit does that.
  ctx.actions.push({ type: ACTION.admit, nodeId: member.nodeId });
  if (entry.phase !== PHASE.admitWait) entry.phase = PHASE.admitWait;
}

function advanceDrain(view, ctx) {
  const { entry, member } = view;

  if (drainedStoppable(view)) {
    ctx.actions.push({
      type: ACTION.stop,
      nodeId: member.nodeId,
      cvmId: member.cvmId,
    });
    enter(entry, PHASE.stopped, ctx.now);
    entry.cooldownUntil = ctx.now + COOLDOWN_MS;
    delete entry.idleSince;
    return;
  }

  if (ctx.now - entry.since < DRAIN_TIMEOUT_MS) return;

  // Leave the member serving rather than cutting live work off.
  ctx.actions.push(alert(REASON.drainTimeout, member.nodeId));
  enter(entry, PHASE.running, ctx.now);
  delete entry.idleSince;
}

function advanceMember(view, ctx) {
  const { entry } = view;
  const admitted = !!view.node && view.node.unavailable !== true;

  if (entry.phase === PHASE.draining) {
    advanceDrain(view, ctx);
    return;
  }

  if (admitted) {
    if (entry.phase !== PHASE.running) enter(entry, PHASE.running, ctx.now);
    entry.restarts = 0;
    if (view.live > 0) delete entry.idleSince;
    else entry.idleSince ??= ctx.now;
    return;
  }

  if (entry.phase === PHASE.stopped || entry.phase === PHASE.quarantined)
    return;

  // A member that was running and is now unavailable re-enters admission.
  if (entry.phase === PHASE.running) enter(entry, PHASE.admitWait, ctx.now);
  advanceAdmission(view, ctx);
}

function scaleUp(views, ctx, state) {
  const running = views.filter(isRunning);
  const pending = views.some(
    (view) =>
      view.entry.phase === PHASE.starting ||
      view.entry.phase === PHASE.admitWait,
  );
  const free = running.reduce(
    (total, view) => total + Math.max(0, view.capacity - view.live),
    0,
  );

  if (free > 0 || pending) {
    delete state.saturatedSince;
    return;
  }

  state.saturatedSince ??= ctx.now;
  if (ctx.now - state.saturatedSince < SCALE_UP_DEBOUNCE_MS) return;

  if (running.length >= ctx.limits.maxRunning) {
    ctx.actions.push(alert(REASON.maxRunning));
    return;
  }

  const candidate = views.find(
    (view) =>
      view.entry.phase === PHASE.stopped &&
      (view.entry.cooldownUntil ?? 0) <= ctx.now &&
      bundleStartable(view.member, ctx.now),
  );
  if (!candidate) {
    ctx.actions.push(alert(REASON.noCandidate));
    return;
  }

  ctx.actions.push({
    type: ACTION.start,
    nodeId: candidate.member.nodeId,
    cvmId: candidate.member.cvmId,
  });
  enter(candidate.entry, PHASE.starting, ctx.now);
  candidate.entry.restarts = 0;
  delete state.saturatedSince;
}

function scaleDown(views, ctx) {
  const running = views.filter(isRunning);
  if (running.length <= ctx.limits.minRunning) return;

  const idle = running
    .filter(
      (view) =>
        view.live === 0 &&
        view.entry.idleSince !== undefined &&
        ctx.now - view.entry.idleSince >= IDLE_MS,
    )
    .sort((a, b) => a.entry.idleSince - b.entry.idleSince);
  const victim = idle[0];
  if (!victim) return;

  // The controller owns teardown; the reply and its timeout are ignored.
  ctx.actions.push({ type: ACTION.drain, nodeId: victim.member.nodeId });
  enter(victim.entry, PHASE.draining, ctx.now);
}

/**
 * Pure tick decision: a controller status snapshot plus member health becomes a
 * list of actions and the next durable state. It performs no I/O, so the whole
 * policy is testable without `phala` or a live fleet.
 */
export function decidePoolActions(input) {
  const { now, members, status, health = {} } = input;
  const limits = {
    minRunning: MIN_RUNNING,
    maxRunning: MAX_RUNNING,
    ...input.limits,
  };
  const state = structuredClone(input.state ?? {});
  state.nodes ??= {};
  const ctx = { now, limits, actions: [] };

  if (!status) {
    ctx.actions.push(alert(REASON.controllerUnreachable));
    return { actions: ctx.actions, state };
  }
  if (status.paused) {
    ctx.actions.push(alert(REASON.controllerPaused));
    return { actions: ctx.actions, state };
  }

  const controllerExpiry = status.config?.expiresAt
    ? Date.parse(status.config.expiresAt)
    : null;
  if (
    controllerExpiry !== null &&
    controllerExpiry - now < CONTROLLER_EXPIRY_FLOOR_MS
  ) {
    ctx.actions.push(alert(REASON.controllerExpiring));
    return { actions: ctx.actions, state };
  }

  const records = new Map(status.nodes.map((node) => [node.nodeId, node]));
  const liveOn = (nodeId) =>
    status.placements.filter(
      (row) =>
        row.assignment?.nodeId === nodeId &&
        Date.parse(row.assignment.leaseExpiresAt) > now,
    ).length;

  const views = members.map((member) => {
    const entry = (state.nodes[member.nodeId] ??= {
      phase: PHASE.stopped,
      since: now,
      restarts: 0,
    });
    const node = records.get(member.nodeId) ?? null;
    return {
      member,
      entry,
      node,
      live: liveOn(member.nodeId),
      capacity: node?.capacity ?? member.capacity,
      health: health[member.nodeId] ?? null,
    };
  });

  for (const view of views) advanceMember(view, ctx);
  scaleUp(views, ctx, state);
  scaleDown(views, ctx);

  return { actions: ctx.actions, state };
}

// ----------------------------------------------------------------------- I/O

function log(fields) {
  console.error(JSON.stringify({ at: new Date().toISOString(), ...fields }));
}

/** Read a credential from the login keychain per command; never cached to disk. */
function keychainSecret(service) {
  const result = spawnSync(
    "security",
    ["find-generic-password", "-w", "-s", service],
    { encoding: "utf8" },
  );
  if (result.status !== 0) return undefined;
  return result.stdout.trim() || undefined;
}

function phala(args, dryRun) {
  if (dryRun) {
    log({ level: "info", dryRun: true, phala: args });
    return true;
  }

  const result = spawnSync("phala", args, { encoding: "utf8" });
  if (result.error) {
    log({ level: "error", phala: args, error: result.error.message });
    return false;
  }
  if (result.status !== 0) {
    log({ level: "error", phala: args, status: result.status });
    return false;
  }
  return true;
}

const cvmCommand = (cvmId, operation) => [
  "api",
  "POST",
  `/cvms/${cvmId}/${operation}`,
];

async function adminPost(context, route, body) {
  const response = await fetch(new URL(route, context.adminUrl), {
    method: "POST",
    headers: {
      authorization: `Bearer ${context.adminToken()}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (!response.ok)
    throw new Error(`Controller ${route} returned ${response.status}`);
  return response.json();
}

async function readStatus(context) {
  try {
    return await adminPost(context, STATUS_ROUTE, {});
  } catch (error) {
    log({ level: "warn", route: STATUS_ROUTE, error: String(error) });
    return null;
  }
}

async function readHealth(member) {
  const secret = keychainSecret(
    member.agentSecretService ??
      `${AGENT_SECRET_SERVICE_PREFIX}${member.nodeId}`,
  );
  if (!secret) return null;

  try {
    const response = await fetch(new URL(HEALTH_ROUTE, member.publicUrl), {
      headers: { authorization: `Bearer ${secret}` },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!response.ok) return { status: response.status };
    return { status: response.status, ...(await response.json()) };
  } catch {
    return null;
  }
}

async function applyAction(action, context) {
  if (action.type === ACTION.alert) {
    log({ level: "warn", ...action });
    return;
  }

  log({ level: "info", dryRun: context.dryRun, ...action });
  if (action.type === ACTION.admit) {
    if (context.dryRun) return;
    // resume:true is the only path that clears a planned drain.
    await adminPost(context, ADMIT_ROUTE, {
      nodeId: action.nodeId,
      resume: true,
    }).catch((error) => log({ level: "warn", error: String(error) }));
    return;
  }

  if (action.type === ACTION.drain) {
    if (context.dryRun) return;
    // Teardown may outlast the request; the reply and its timeout are ignored.
    await adminPost(context, DRAIN_ROUTE, { nodeId: action.nodeId }).catch(
      () => undefined,
    );
    return;
  }

  phala(cvmCommand(action.cvmId, action.type), context.dryRun);
}

function readJson(path, fallback) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT" && fallback !== undefined) return fallback;
    throw error;
  }
}

function writeState(path, state) {
  mkdirSync(dirname(path), { recursive: true, mode: STATE_DIRECTORY_MODE });
  const temporary = `${path}.tmp`;
  writeFileSync(temporary, JSON.stringify(state, null, 2), {
    mode: STATE_FILE_MODE,
  });
  renameSync(temporary, path);
}

async function tick(context) {
  const status = await readStatus(context);
  const health = Object.fromEntries(
    await Promise.all(
      context.members.map(async (member) => [
        member.nodeId,
        status ? await readHealth(member) : null,
      ]),
    ),
  );

  const { actions, state } = decidePoolActions({
    now: Date.now(),
    members: context.members,
    status,
    health,
    state: readJson(context.statePath, {}),
  });

  for (const action of actions) await applyAction(action, context);
  writeState(context.statePath, state);
}

function loadContext(argv) {
  const poolPath = process.env.VANA_POOL_PATH ?? DEFAULT_POOL_PATH;
  const pool = readJson(poolPath);
  const members = Array.isArray(pool) ? pool : pool.members;
  const adminUrl =
    process.env.VANA_FLEET_ADMIN_URL ??
    (Array.isArray(pool) ? undefined : pool.controllerAdminUrl);
  if (!Array.isArray(members) || !adminUrl)
    throw new Error(`${poolPath} must supply controllerAdminUrl and members`);

  return {
    members,
    adminUrl,
    adminToken: () => {
      const token = keychainSecret(ADMIN_TOKEN_SERVICE);
      if (!token)
        throw new Error(`Keychain item ${ADMIN_TOKEN_SERVICE} missing`);
      return token;
    },
    statePath: process.env.VANA_POOL_STATE_PATH ?? DEFAULT_STATE_PATH,
    dryRun: argv.includes("--dry-run"),
    once: argv.includes("--once"),
  };
}

async function main() {
  const context = loadContext(process.argv.slice(2));
  log({ level: "info", message: "Pool loop started", dryRun: context.dryRun });

  for (;;) {
    await tick(context);
    if (context.once) return;
    await new Promise((resolve) => setTimeout(resolve, TICK_MS));
  }
}

// Importing this module for tests must not start the loop.
function invokedDirectly() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  main().catch((error) => {
    log({ level: "error", error: String(error) });
    process.exitCode = 1;
  });
}

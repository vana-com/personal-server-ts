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
import { randomUUID } from "node:crypto";
import {
  closeSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeSync,
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
const LOCK_SUFFIX = ".lock";

/** A member is addressed by name in a `phala api` path and in a URL base, so
 * both identifiers stay inside the DNS-label charset. */
const NODE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
const CVM_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/;
const HTTPS_PROTOCOL = "https:";

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
  restartBlocked: "RESTART_BLOCKED",
  unknownMember: "MEMBER_NOT_IN_STATUS",
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
    // A restart is a hard CVM cycle. One failed renew RPC is enough to mark a
    // member unavailable, so never cycle it while it still serves live leases.
    if (view.live > 0) {
      ctx.actions.push(alert(REASON.restartBlocked, member.nodeId));
      return;
    }

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

/** The controller's verdict on the member as it runs now. A record raised
 * before this phase began described the previous boot, so a member that has
 * just been restarted is not judged on the failure that restarted it. */
function currentAdmission(view) {
  const admission = view.node?.lastAdmission;
  if (!admission) return null;

  const since = Date.parse(admission.since);
  return Number.isFinite(since) && since < view.entry.since ? null : admission;
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
  if (currentAdmission(view)?.code === DOUBLE_MR_KMS_CODE) {
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
    // The restart budget spans the whole boot, not one admission: a member that
    // flaps must reach the quarantine, so only a scale-up start clears it.
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

const startable = (views, ctx) =>
  views.find(
    (view) =>
      view.entry.phase === PHASE.stopped &&
      (view.entry.cooldownUntil ?? 0) <= ctx.now &&
      bundleStartable(view.member, ctx.now),
  );

function startMember(view, ctx, state) {
  ctx.actions.push({
    type: ACTION.start,
    nodeId: view.member.nodeId,
    cvmId: view.member.cvmId,
  });
  enter(view.entry, PHASE.starting, ctx.now);
  // A fresh boot gets a fresh restart budget; nothing else resets it.
  view.entry.restarts = 0;
  delete state.saturatedSince;
}

function scaleUp(views, ctx, state) {
  const running = views.filter(isRunning);
  const pending = views.filter(
    (view) =>
      view.entry.phase === PHASE.starting ||
      view.entry.phase === PHASE.admitWait,
  );
  const free = running.reduce(
    (total, view) => total + Math.max(0, view.capacity - view.live),
    0,
  );

  // The warm floor comes before saturation. After a quarantine or a cold start
  // the pool must climb back to MIN_RUNNING without first waiting out a full
  // debounce of saturation and then a boot. A draining member still serves, so
  // it counts until it actually stops.
  const draining = views.filter((view) => view.entry.phase === PHASE.draining);
  const warm = running.length + pending.length + draining.length;
  if (warm < ctx.limits.minRunning) {
    const cold = startable(views, ctx);
    if (cold) {
      startMember(cold, ctx, state);
      return;
    }
  }

  if (free > 0 || pending.length > 0) {
    delete state.saturatedSince;
    return;
  }

  state.saturatedSince ??= ctx.now;
  if (ctx.now - state.saturatedSince < SCALE_UP_DEBOUNCE_MS) return;

  if (running.length >= ctx.limits.maxRunning) {
    ctx.actions.push(alert(REASON.maxRunning));
    return;
  }

  const candidate = startable(views, ctx);
  if (!candidate) {
    ctx.actions.push(alert(REASON.noCandidate));
    return;
  }

  startMember(candidate, ctx, state);
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

// The CLI refuses a bare method argument: it must arrive through -X.
const cvmCommand = (cvmId, operation) => [
  "api",
  `/cvms/${cvmId}/${operation}`,
  "-X",
  "POST",
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

/** Whether the action reached the world. Only a phala CLI call can report
 * false: an admit is retried next tick and a drain outlives its request. */
async function applyAction(action, context) {
  if (action.type === ACTION.alert) {
    log({ level: "warn", ...action });
    return true;
  }

  log({ level: "info", dryRun: context.dryRun, ...action });
  if (action.type === ACTION.admit) {
    if (context.dryRun) return true;
    // resume:true is the only path that clears a planned drain.
    await adminPost(context, ADMIT_ROUTE, {
      nodeId: action.nodeId,
      resume: true,
    }).catch((error) => log({ level: "warn", error: String(error) }));
    return true;
  }

  if (action.type === ACTION.drain) {
    if (context.dryRun) return true;
    // Teardown may outlast the request; the reply and its timeout are ignored.
    await adminPost(context, DRAIN_ROUTE, { nodeId: action.nodeId }).catch(
      () => undefined,
    );
    return true;
  }

  return phala(cvmCommand(action.cvmId, action.type), context.dryRun);
}

/** A CVM command that never ran leaves the fleet as it was, so the phase,
 * cooldown and debounce this tick committed for that member are fiction.
 * Restoring them re-issues the same decision on the next tick. */
export function revertMember(state, previous, nodeId) {
  const prior = previous.nodes?.[nodeId];
  if (prior) state.nodes[nodeId] = structuredClone(prior);
  else delete state.nodes[nodeId];

  if (previous.saturatedSince === undefined) delete state.saturatedSince;
  else state.saturatedSince = previous.saturatedSince;
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
  // A unique name cannot collide with another writer's temporary, and the
  // fsync makes the rename publish a complete file rather than an empty one.
  const temporary = `${path}.${randomUUID()}.tmp`;
  try {
    const handle = openSync(temporary, "wx", STATE_FILE_MODE);
    try {
      writeSync(handle, JSON.stringify(state, null, 2));
      fsyncSync(handle);
    } finally {
      closeSync(handle);
    }
    renameSync(temporary, path);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
}

const running = (pid) => {
  if (!Number.isInteger(pid) || pid < 1) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM means the pid exists but belongs to another user.
    return error.code === "EPERM";
  }
};

/** One loop per state file. `wx` is atomic, so two loops cannot both take the
 * lock; a lock left behind by a crash names a pid that no longer exists. */
function acquireLock(statePath) {
  const path = `${statePath}${LOCK_SUFFIX}`;
  mkdirSync(dirname(path), { recursive: true, mode: STATE_DIRECTORY_MODE });

  let handle;
  try {
    handle = openSync(path, "wx", STATE_FILE_MODE);
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    const owner = Number.parseInt(readFileSync(path, "utf8").trim(), 10);
    if (running(owner))
      throw new Error(`Pool loop ${owner} already holds ${path}`);

    log({ level: "warn", message: "Clearing a stale pool lock", path, owner });
    rmSync(path, { force: true });
    handle = openSync(path, "wx", STATE_FILE_MODE);
  }

  try {
    writeSync(handle, `${process.pid}\n`);
  } finally {
    closeSync(handle);
  }
  process.on("exit", () => rmSync(path, { force: true }));
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

  warnUnknownMembers(context, status);

  const previous = readJson(context.statePath, {});
  const { actions, state } = decidePoolActions({
    now: Date.now(),
    members: context.members,
    status,
    health,
    state: previous,
  });

  for (const action of actions) {
    const applied = await applyAction(action, context);
    if (!applied) revertMember(state, previous, action.nodeId);
  }
  writeState(context.statePath, state);
}

const httpsUrl = (value) => {
  try {
    return new URL(value).protocol === HTTPS_PROTOCOL;
  } catch {
    return false;
  }
};

/** pool.json is hand-edited. A typo in cvmId would retarget a stop at another
 * machine, and publicUrl becomes the base of every health request, so both are
 * checked before the first tick rather than at the first spawn. */
function assertMember(member, index, poolPath) {
  const invalid =
    !member ||
    !NODE_ID_PATTERN.test(member.nodeId ?? "") ||
    !CVM_ID_PATTERN.test(member.cvmId ?? "") ||
    !httpsUrl(member.publicUrl) ||
    !Number.isSafeInteger(member.capacity) ||
    member.capacity < 1;
  if (invalid)
    throw new Error(
      `${poolPath} member ${index} needs a nodeId, cvmId, https publicUrl and capacity`,
    );
}

/** A member the controller's signed config does not list can be started but
 * never admitted, which otherwise looks like a boot that simply never finishes. */
function warnUnknownMembers(context, status) {
  if (!status) return;

  const known = new Set(status.nodes.map((node) => node.nodeId));
  for (const member of context.members) {
    if (known.has(member.nodeId) || context.warned.has(member.nodeId)) continue;

    context.warned.add(member.nodeId);
    log({ level: "warn", reason: REASON.unknownMember, nodeId: member.nodeId });
  }
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
  members.forEach((member, index) => assertMember(member, index, poolPath));

  return {
    members,
    warned: new Set(),
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
  acquireLock(context.statePath);
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

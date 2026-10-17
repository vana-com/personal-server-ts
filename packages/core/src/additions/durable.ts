import {
  AdditionsBudget,
  AdditionsBudgetExceeded as BudgetExceeded,
  type ByteBudget,
} from "./budget.js";
import { z } from "zod";
import { getAddress, keccak256, stringToHex } from "viem";
import {
  createDataFileEnvelope,
  DataFileEnvelopeSchema,
  decryptWithPassword,
  deriveScopeKey,
  encryptWithPassword,
  type GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import type { StorageAdapter } from "../storage/adapters/interface.js";
import type { ServerSigner } from "../signing/signer.js";
import {
  foldVersion,
  extractRecordKeys,
  readScopeFirstSeenLedger,
  type ScopeFirstSeenLedger,
  type VersionToFold,
} from "./first-added.js";
import {
  summarizeAdditions,
  ADDITIONS_SUMMARY_MAX_BYTES,
  type AdditionsCoverage,
  type AdditionsSummary,
} from "./summary.js";
import {
  fingerprintVersionInventory,
  type VersionInventory,
  type VersionInventoryClient,
  type InventoryVersion,
} from "./version-inventory.js";
import { isSystemScope } from "../policy/reserved-scopes.js";

export const ADDITIONS_SUMMARY_SCOPE = "vana.system.additions";
const decimal = z.string().regex(/^(0|[1-9]\d*)$/);
const slotSchema = z.object({
  expectedVersion: decimal,
  dataHash: z.string(),
  metadataHash: z.string(),
  status: z.string(),
  addedAt: z.string(),
  isTombstone: z.boolean(),
});
const documentSchema = z.object({
  version: z.literal(1),
  owner: z.string(),
  network: z.string(),
  scope: z.string(),
  through: decimal,
  currentTotal: z.number().int().nonnegative(),
  slots: z.array(slotSchema),
  ledger: z.unknown(),
});
type LedgerDocument = Omit<z.infer<typeof documentSchema>, "ledger"> & {
  ledger: ScopeFirstSeenLedger | null;
  repairHead?: true;
};

/** The separate hash namespace cannot collide with a literal source suffix. */
export function additionsLedgerScope(scope: string): string {
  const literal = `${ADDITIONS_SUMMARY_SCOPE}.${scope}`;
  return new TextEncoder().encode(literal).byteLength <= 256
    ? literal
    : `vana.system.additions-hash.${keccak256(stringToHex(scope)).slice(2)}`;
}

export interface DurableAdditionsOptions {
  ownerAddress: string;
  /** Include chain and Gateway origin. A service instance belongs to one owner/network. */
  network: string;
  inventory: VersionInventoryClient;
  storageAdapter: StorageAdapter;
  masterKey: Uint8Array;
  signer: Pick<ServerSigner, "signAddData">;
  gateway: Pick<GatewayClient, "registerDataPoint">;
  /** Full PS defaults remain unlimited. Bounded hosts must also supply boundedWork. */
  byteBudget?: number;
  /** Host operations must cancel and settle all work before returning on abort.
   * Crypto must enforce a plaintext limit before decompression/allocation.
   * No SDK whole-object fallback is allowed under a finite budget.
   */
  boundedWork?: {
    /** Clear an interrupted-publication intent only after commitment verification. */
    confirmed?(scope: string, budget: ByteBudget): Promise<void>;
    decrypt(
      encrypted: Uint8Array,
      password: string,
      budget: ByteBudget,
    ): Promise<Uint8Array>;
    publish(
      scope: string,
      data: Record<string, unknown>,
      budget: ByteBudget,
    ): Promise<{
      expectedVersion: string;
      dataHash: string;
      metadataHash: string;
    }>;
  };
  timeBudgetMs?: number;
  /** Session driver cancellation. All bounded operations share this signal. */
  signal?: AbortSignal;
  /** Existing durable delete pipeline, including exact-key cleanup/retry. */
  deleteSystemScope?: (scope: string) => Promise<void>;
}

export interface DurableAdditionsService {
  summarize(input: {
    timezone: string;
    days: number;
    now: Date;
  }): Promise<AdditionsSummary>;
  recordUpload(
    version: VersionToFold | Pick<VersionToFold, "scope">,
    proof?: { envelope: unknown; encryptedSize: number },
  ): Promise<void>;
  deleteScope(scope: string): Promise<void>;
}

class InaccessibleLedger extends Error {}
class BoundedWorkUnavailable extends Error {}
class ReadBudget extends AdditionsBudget {
  readonly limited: boolean;
  constructor(
    options: Pick<
      DurableAdditionsOptions,
      "byteBudget" | "timeBudgetMs" | "signal"
    >,
    parent?: ReadBudget,
  ) {
    super(options.byteBudget, options.timeBudgetMs, options.signal, parent);
    this.limited =
      options.byteBudget !== undefined || options.timeBudgetMs !== undefined;
  }
  /** A failed source unit cannot spend the bytes held for its durable prefix. */
  excluding(reserved: number): ReadBudget {
    return new ReadBudget(
      {
        byteBudget: Math.max(0, this.remaining - reserved),
        timeBudgetMs: Number.isFinite(this.remainingMilliseconds)
          ? Math.max(0, Math.floor(this.remainingMilliseconds - 2000))
          : undefined,
        signal: this.signal,
      },
      this,
    );
  }
  check(bytes = 0) {
    this.charge(bytes);
  }
  get readOptions() {
    return { signal: this.signal, ...(this.limited ? { budget: this } : {}) };
  }
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}
function sameCommitment(a: InventoryVersion, b: InventoryVersion): boolean {
  return (
    a.expectedVersion === b.expectedVersion &&
    a.dataHash.toLowerCase() === b.dataHash.toLowerCase() &&
    a.metadataHash.toLowerCase() === b.metadataHash.toLowerCase() &&
    a.isTombstone === b.isTombstone
  );
}
function sameSlot(a: InventoryVersion, b: InventoryVersion): boolean {
  return sameCommitment(a, b) && a.status === b.status;
}
function sameInventory(a: VersionInventory, b: VersionInventory): boolean {
  return (
    JSON.stringify(a.head) === JSON.stringify(b.head) &&
    a.versions.length === b.versions.length &&
    a.versions.every((slot, i) => sameSlot(slot, b.versions[i]!))
  );
}
function settled(slot: { status: string }): boolean {
  return slot.status === "confirmed" || slot.status === "finalized";
}
function sourceData(data: unknown): Record<string, unknown> | null {
  if (data === null || typeof data !== "object" || Array.isArray(data))
    return null;
  return Object.fromEntries(Object.entries(data));
}

/**
 * Revalidates commitments, rather than trusting a numeric watermark or a local
 * mutex. Persisted lost/lower-prefix writes are repaired from the next inventory.
 */
export function createDurableAdditions(
  options: DurableAdditionsOptions,
): DurableAdditionsService {
  const owner = options.ownerAddress.toLowerCase();
  const { inventory, storageAdapter } = options;

  async function readEnvelope(
    scope: string,
    slot: InventoryVersion,
    budget: ReadBudget,
  ) {
    budget.check();
    if (
      budget.limited &&
      (!storageAdapter.downloadBounded || !options.boundedWork)
    )
      throw new BoundedWorkUnavailable(
        "Abortable bounded crypto/storage capability unavailable",
      );
    const url = storageAdapter.urlForKey(`${scope}/${slot.expectedVersion}`);
    const encrypted =
      budget.limited && storageAdapter.downloadBounded
        ? await storageAdapter.downloadBounded(url, budget)
        : await storageAdapter.download(url);
    if (!budget.limited) budget.check(encrypted.byteLength);
    const password = hex(deriveScopeKey(options.masterKey, scope));
    const plaintext =
      budget.limited && options.boundedWork
        ? await options.boundedWork.decrypt(encrypted, password, budget)
        : await decryptWithPassword(encrypted, password);
    budget.check(plaintext.byteLength);
    if (keccak256(plaintext).toLowerCase() !== slot.dataHash.toLowerCase())
      throw new Error("Additions content commitment mismatch");
    budget.check(plaintext.byteLength * 3);
    const envelope = DataFileEnvelopeSchema.parse(
      JSON.parse(new TextDecoder().decode(plaintext)),
    );
    const metadataHash = keccak256(
      stringToHex(
        JSON.stringify({
          scope,
          collectedAt: envelope.collectedAt,
          sizeBytes: encrypted.byteLength,
        }),
      ),
    );
    if (
      envelope.scope !== scope ||
      !Number.isFinite(Date.parse(envelope.collectedAt)) ||
      metadataHash.toLowerCase() !== slot.metadataHash.toLowerCase()
    )
      throw new Error("Additions metadata commitment mismatch");
    budget.check();
    return envelope;
  }

  async function current(scope: string, budget: ReadBudget) {
    budget.check();
    const snapshot = await inventory.list(scope, budget.readOptions);
    budget.check();
    const head = snapshot.head;
    if (!head || head.deletedAt !== null) return null;
    const slot = snapshot.versions.find(
      (row) =>
        row.expectedVersion === head.expectedVersion &&
        !row.isTombstone &&
        row.dataHash === head.dataHash &&
        row.metadataHash === head.metadataHash,
    );
    if (!slot) throw new Error("Additions head missing from inventory");
    return { snapshot, envelope: await readEnvelope(scope, slot, budget) };
  }

  async function readDocument(
    scope: string,
    budget: ReadBudget,
  ): Promise<LedgerDocument | null> {
    const systemScope = additionsLedgerScope(scope);
    const snapshot = await inventory.list(systemScope, budget.readOptions);
    if (!snapshot.head || snapshot.head.deletedAt !== null) return null;
    const boundary =
      snapshot.versions.filter((row) => row.isTombstone).at(-1)
        ?.expectedVersion ?? "0";
    let inaccessible = false;
    for (const slot of [...snapshot.versions].reverse()) {
      if (
        BigInt(slot.expectedVersion) <= BigInt(boundary) ||
        BigInt(slot.expectedVersion) > BigInt(snapshot.head.expectedVersion) ||
        slot.isTombstone
      )
        continue;
      let envelope;
      try {
        envelope = await readEnvelope(systemScope, slot, budget);
      } catch (error) {
        if (error instanceof BudgetExceeded || budget.signal?.aborted)
          throw error;
        inaccessible = true;
        continue;
      }
      const parsed = documentSchema.safeParse(envelope.data);
      if (
        !parsed.success ||
        parsed.data.owner !== owner ||
        parsed.data.network !== options.network ||
        parsed.data.scope !== scope
      )
        continue;
      const ledger =
        parsed.data.ledger === null
          ? null
          : readScopeFirstSeenLedger(parsed.data.ledger);
      if (parsed.data.ledger !== null && (!ledger || ledger.scope !== scope))
        continue;
      return {
        ...parsed.data,
        ledger,
        ...(slot.expectedVersion !== snapshot.head.expectedVersion
          ? { repairHead: true as const }
          : {}),
      };
    }
    if (inaccessible)
      throw new InaccessibleLedger(
        "No readable committed additions ledger version",
      );
    return null;
  }

  async function publish(
    scope: string,
    data: Record<string, unknown>,
    budget: ReadBudget,
  ) {
    budget.check();
    if (budget.limited) {
      if (!options.boundedWork)
        throw new BoundedWorkUnavailable(
          "Bounded checkpoint publication unavailable",
        );
      const proof = await options.boundedWork.publish(scope, data, budget);
      budget.check();
      const check = await inventory.list(scope, budget.readOptions);
      const slot = check.versions.find(
        (row) =>
          row.expectedVersion === proof.expectedVersion &&
          row.dataHash === proof.dataHash &&
          row.metadataHash === proof.metadataHash,
      );
      if (!slot)
        throw new Error("Bounded checkpoint registration was replaced");
      const envelope = await readEnvelope(scope, slot, budget);
      if (JSON.stringify(envelope.data) !== JSON.stringify(data))
        throw new Error("Bounded checkpoint content was replaced");
      budget.check();
      await options.boundedWork.confirmed?.(scope, budget);
      return;
    }
    const snapshot = await inventory.list(scope, budget.readOptions);
    const version =
      BigInt(snapshot.versions.at(-1)?.expectedVersion ?? "0") + 1n;
    const envelope = createDataFileEnvelope(
      scope,
      new Date().toISOString(),
      data,
    );
    const plaintext = new TextEncoder().encode(JSON.stringify(envelope));
    const encrypted = await encryptWithPassword(
      plaintext,
      hex(deriveScopeKey(options.masterKey, scope)),
    );
    const dataHash = keccak256(plaintext);
    const metadataHash = keccak256(
      stringToHex(
        JSON.stringify({
          scope,
          collectedAt: envelope.collectedAt,
          sizeBytes: encrypted.byteLength,
        }),
      ),
    );
    await storageAdapter.upload(`${scope}/${version}`, encrypted);
    const signature = await options.signer.signAddData({
      ownerAddress: getAddress(owner),
      scope,
      dataHash,
      metadataHash,
      expectedVersion: version,
    });
    await options.gateway.registerDataPoint({
      ownerAddress: owner,
      scope,
      dataHash,
      metadataHash,
      expectedVersion: String(version),
      signature,
    });
    // A concurrent upload can replace the bytes at this shared version key
    // independently of registration. Never claim durability without checking.
    const check = await inventory.list(scope, budget.readOptions);
    const registered = check.versions.find(
      (slot) =>
        slot.expectedVersion === String(version) &&
        slot.dataHash === dataHash &&
        slot.metadataHash === metadataHash,
    );
    if (!registered)
      throw new Error(
        "Concurrent additions publication replaced the registration",
      );
    await readEnvelope(scope, registered, budget);
  }

  async function recover(
    scope: string,
    budget: ReadBudget,
    uploaded?: {
      version: VersionToFold;
      proof?: { envelope: unknown; encryptedSize: number };
    },
  ): Promise<{
    ledger: ScopeFirstSeenLedger | null;
    through: string;
    inventory: string;
    currentTotal: number;
    coverage: AdditionsCoverage;
  }> {
    budget.check();
    const snapshot = await inventory.list(scope, budget.readOptions);
    budget.check();
    const head = snapshot.head;
    if (!head || head.deletedAt !== null) {
      const tombstone = head
        ? snapshot.versions.find(
            (slot) =>
              slot.expectedVersion === head.expectedVersion &&
              slot.dataHash === head.dataHash &&
              slot.metadataHash === head.metadataHash &&
              slot.isTombstone &&
              settled(slot),
          )
        : null;
      const check = await inventory.list(scope, budget.readOptions);
      return {
        ledger: null,
        inventory: fingerprintVersionInventory(snapshot),
        currentTotal: 0,
        through: head?.expectedVersion ?? "0",
        coverage: !sameInventory(snapshot, check)
          ? "behind"
          : head
            ? settled(head) && tombstone
              ? "complete"
              : "partial"
            : snapshot.versions.length
              ? "partial"
              : "complete",
      };
    }
    const end = BigInt(head.expectedVersion);
    const rows = snapshot.versions.filter(
      (slot) => BigInt(slot.expectedVersion) <= end,
    );
    const boundary = rows
      .filter((slot) => slot.isTombstone && settled(slot))
      .at(-1);
    const after = BigInt(boundary?.expectedVersion ?? "0");
    const relevant = rows.filter(
      (slot) => BigInt(slot.expectedVersion) > after,
    );
    let existing: LedgerDocument | null = null;
    let inaccessibleExisting = false;
    try {
      existing = await readDocument(scope, budget);
    } catch (error) {
      if (error instanceof BudgetExceeded || budget.signal?.aborted)
        throw error;
      inaccessibleExisting = true;
    }
    const prefixValid =
      existing !== null &&
      existing.slots.length <= relevant.length &&
      existing.slots.every((slot, i) => sameCommitment(slot, relevant[i]!)) &&
      existing.through ===
        (existing.slots.at(-1)?.expectedVersion ?? String(after));
    let ledger = prefixValid ? existing!.ledger : null;
    const folded = prefixValid ? relevant.slice(0, existing!.slots.length) : [];
    let currentTotal = prefixValid ? existing!.currentTotal : 0;
    let through = folded.at(-1)?.expectedVersion ?? String(after);
    let expected = after + 1n;
    const headSlot = relevant.find(
      (slot) =>
        slot.expectedVersion === head.expectedVersion &&
        slot.dataHash === head.dataHash &&
        slot.metadataHash === head.metadataHash,
    );
    let coverage: AdditionsCoverage =
      headSlot && settled(head) ? "complete" : "partial";
    for (const slot of relevant) {
      if (BigInt(slot.expectedVersion) !== expected || !settled(slot))
        coverage = "partial";
      expected = BigInt(slot.expectedVersion) + 1n;
    }
    const checkpointBytes = (
      candidate: ScopeFirstSeenLedger | null,
      count: number,
    ) =>
      128 * 1024 +
      128 *
        new TextEncoder().encode(
          JSON.stringify({
            ledger: candidate,
            slots: relevant.slice(0, count),
            owner,
            network: options.network,
            scope,
            through,
            currentTotal,
          }),
        ).byteLength;
    for (const slot of relevant.slice(folded.length)) {
      try {
        // Keep publication capacity in the same owner-wide allowance. Exhaustion
        // of the child leaves the already-folded prefix publishable.
        const unitBudget = budget.limited
          ? budget.excluding(checkpointBytes(ledger, folded.length))
          : budget;
        unitBudget.check();
        if (BigInt(slot.expectedVersion) !== BigInt(through) + 1n)
          coverage = "partial";
        // Mutable slots are provisional; failed/unknown slots cannot advance the prefix.
        if (
          slot.status === "failed" ||
          !["confirmed", "finalized", "pending", "submitting"].includes(
            slot.status,
          )
        ) {
          coverage = "partial";
          break;
        }
        if (slot.isTombstone) {
          coverage = "partial";
          break;
        }
        let version: VersionToFold;
        const proof = uploaded?.proof;
        const inMemory = proof
          ? DataFileEnvelopeSchema.safeParse(proof.envelope)
          : null;
        const bytes = proof
          ? new TextEncoder().encode(JSON.stringify(proof.envelope))
          : null;
        const metadata =
          inMemory?.success && proof
            ? keccak256(
                stringToHex(
                  JSON.stringify({
                    scope,
                    collectedAt: inMemory.data.collectedAt,
                    sizeBytes: proof.encryptedSize,
                  }),
                ),
              )
            : null;
        if (
          inMemory?.success &&
          bytes &&
          inMemory.data.scope === scope &&
          keccak256(bytes) === slot.dataHash &&
          metadata === slot.metadataHash
        ) {
          const data = sourceData(inMemory.data.data);
          if (!data) throw new Error("Unsupported source envelope");
          version = { scope, collectedAt: inMemory.data.collectedAt, data };
        } else {
          const envelope = await readEnvelope(scope, slot, unitBudget);
          const data = sourceData(envelope.data);
          if (!data) throw new Error("Unsupported source envelope");
          version = { scope, collectedAt: envelope.collectedAt, data };
        }
        const hadBaseline = ledger !== null && ledger.baseline !== null;
        const candidate = await foldVersion(ledger, version);
        unitBudget.check();
        if (
          budget.limited &&
          checkpointBytes(candidate, folded.length + 1) > budget.remaining
        )
          throw new BudgetExceeded(
            "Checkpoint cannot fit remaining recovery allowance",
          );
        ledger = candidate;
        currentTotal =
          (await extractRecordKeys(scope, version.data))?.total ?? 1;
        // Reimport baseline and incomplete starts have unknown arrivals.
        if (ledger && (after > 0n || relevant[0]?.expectedVersion !== "1")) {
          ledger.partial = true;
          if (!hadBaseline && ledger.baseline !== null)
            ledger.unknownArrivalKeys = Object.keys(ledger.records);
        }
        folded.push(slot);
        through = slot.expectedVersion;
      } catch (error) {
        coverage =
          error instanceof BudgetExceeded || budget.signal?.aborted
            ? "behind"
            : "partial";
        break;
      }
    }
    if (BigInt(through) !== end && coverage === "complete")
      coverage = "partial";
    if (ledger?.incomplete || ledger?.skipped) coverage = "partial";
    // The pages above are separate snapshots. Never certify against an old view.
    if (!budget.signal?.aborted) {
      const check = await inventory.list(scope, budget.readOptions);
      if (!sameInventory(snapshot, check))
        return {
          ledger: null,
          inventory: fingerprintVersionInventory(snapshot),
          through: "0",
          currentTotal: 0,
          coverage: "behind",
        };
    }
    const document: LedgerDocument = {
      version: 1,
      owner,
      network: options.network,
      scope,
      through,
      currentTotal,
      slots: folded,
      ledger,
    };
    // Never replace durable permanent evidence with a failed invalidation replay.
    if (
      ((!existing && !inaccessibleExisting) ||
        prefixValid ||
        coverage === "complete") &&
      JSON.stringify(document) !== JSON.stringify(existing)
    ) {
      // A write failure affects durability, never hides the verified in-memory result.
      try {
        await publish(additionsLedgerScope(scope), { ...document }, budget);
      } catch {
        coverage = coverage === "complete" ? "behind" : coverage;
      }
    }
    return {
      ledger,
      through,
      currentTotal,
      coverage,
      inventory: fingerprintVersionInventory(snapshot),
    };
  }

  return {
    async summarize(input) {
      const budget = new ReadBudget(options);
      if (
        budget.limited &&
        (!options.boundedWork || !storageAdapter.downloadBounded)
      )
        return summarizeAdditions({
          ...input,
          ledgers: [],
          coverage: "unavailable",
        });
      const ledgers: ScopeFirstSeenLedger[] = [];
      const through: Record<string, string> = {};
      const provenance: Record<string, string> = {};
      let coverage: AdditionsCoverage = "complete";
      let scopes: string[] = [];
      try {
        scopes = (await inventory.listScopes(budget.readOptions))
          .filter((scope) => !isSystemScope(scope))
          .sort();
        for (const scope of scopes) {
          const result = await recover(scope, budget);
          if (result.ledger)
            ledgers.push({
              ...result.ledger,
              latest: { ...result.ledger.latest, total: result.currentTotal },
            });
          through[scope] = result.through;
          provenance[scope] = result.inventory;
          if (
            result.coverage === "behind" ||
            (result.coverage === "partial" && coverage === "complete")
          )
            coverage = result.coverage;
        }
        const check = (await inventory.listScopes(budget.readOptions))
          .filter((scope) => !isSystemScope(scope))
          .sort();
        if (JSON.stringify(scopes) !== JSON.stringify(check))
          coverage = "behind";
      } catch (error) {
        coverage =
          error instanceof BudgetExceeded || budget.signal?.aborted
            ? "behind"
            : "unavailable";
      }
      const result = await summarizeAdditions({
        ...input,
        ledgers,
        coverage,
        through,
        inventory: provenance,
      });
      // Publish one portable UTC summary on reads, never on every source upload.
      if (coverage === "complete" || coverage === "partial") {
        try {
          const portable = await summarizeAdditions({
            ...input,
            timezone: "UTC",
            ledgers,
            coverage,
            through,
            inventory: provenance,
          });
          const serialized = JSON.stringify(portable);
          if (
            new TextEncoder().encode(serialized).byteLength >
            ADDITIONS_SUMMARY_MAX_BYTES
          )
            throw new Error(
              "Portable additions summary exceeds browser size limit",
            );
          budget.check(serialized.length * 2);
          let previous: Awaited<ReturnType<typeof current>> = null;
          try {
            previous = await current(ADDITIONS_SUMMARY_SCOPE, budget);
          } catch (error) {
            if (error instanceof BudgetExceeded || budget.signal?.aborted)
              throw error;
          }
          if (
            JSON.stringify(previous?.envelope.data) !== JSON.stringify(portable)
          ) {
            budget.check();
            await new Promise((resolve) =>
              setTimeout(
                resolve,
                Math.floor(crypto.getRandomValues(new Uint8Array(1))[0]! / 8),
              ),
            );
            await publish(ADDITIONS_SUMMARY_SCOPE, { ...portable }, budget);
          }
        } catch {
          result.coverage = "behind";
        }
      }
      try {
        budget.check();
      } catch {
        result.coverage = "behind";
      }
      return result;
    },
    async recordUpload(version, proof) {
      if (isSystemScope(version.scope)) return;
      // Optional optimization only. Correctness always comes from read recovery.
      try {
        const budget = new ReadBudget(options);
        // Bounded recovery reads committed bytes through the bounded transport;
        // never parse or serialize an unbounded caller-owned upload hint.
        if (budget.limited) proof = undefined;
        if (
          budget.limited &&
          (!options.boundedWork || !storageAdapter.downloadBounded)
        )
          return;
        const snapshot = await inventory.list(
          version.scope,
          budget.readOptions,
        );
        const head = snapshot.head;
        if (!head || head.deletedAt !== null) return;
        if (
          proof &&
          keccak256(
            new TextEncoder().encode(JSON.stringify(proof.envelope)),
          ) !== head.dataHash
        )
          return;
        const previous = await readDocument(version.scope, budget);
        const boundary =
          snapshot.versions
            .filter((slot) => slot.isTombstone && settled(slot))
            .at(-1)?.expectedVersion ?? "0";
        const startsFresh =
          BigInt(head.expectedVersion) === BigInt(boundary) + 1n;
        if (
          !startsFresh &&
          (!previous ||
            BigInt(previous.through) + 1n !== BigInt(head.expectedVersion))
        )
          return;
        const uploaded =
          !budget.limited && "collectedAt" in version && "data" in version
            ? { version, proof }
            : undefined;
        await recover(version.scope, budget, uploaded);
      } catch {
        /* Next reader retries. */
      }
    },
    async deleteScope(scope) {
      if (isSystemScope(scope)) return;
      if (!options.deleteSystemScope)
        throw new Error("Durable additions deletion is unavailable");
      await options.deleteSystemScope(additionsLedgerScope(scope));
      // Invalidate the portable summary immediately. The next reader rebuilds
      // from authoritative source tombstones and cannot show deleted counts.
      await options.deleteSystemScope(ADDITIONS_SUMMARY_SCOPE);
    },
  };
}

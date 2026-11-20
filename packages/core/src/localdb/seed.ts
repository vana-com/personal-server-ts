import {
  controlScope,
  IDENTITYLESS_NS,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { withScopeLock } from "../additions/scope-lock.js";
import { createImportLedger } from "./import-ledger.js";
import { importLegacySource } from "./legacy-import.js";
import { importFingerprint } from "./import-fingerprint.js";
import { syncBeforeBegin } from "./bootstrap.js";
import type { LocalSyncDeps } from "./deps.js";
import type { ImportSource } from "./legacy-import-types.js";
import { manifestArtifact } from "../stream-sync/artifacts.js";
import { ProtocolError } from "../errors/catalog.js";
import {
  SeedUploadError,
  checkSeedNames,
  type SeedStaging,
  type SeedDescriptor,
  type SeedStreamState,
} from "../stream-sync/seed-staging.js";
import type { SeedReceipt } from "../stream-sync/ports.js";

export interface LocalSeedCapability {
  readonly writer: {
    importStaged(connector: string): Promise<void>;
    seedStatus(connector: string): Promise<{
      targetKnown: boolean;
      receipts: Readonly<Record<string, SeedReceipt>>;
    }>;
  };
  readonly staging: SeedStaging;
}

/** In-process equivalent of Desktop's descriptor-first streamed NDJSON PUT.
 * Hosts supply verified manifests, durable staging and the existing database.
 * A committed receipt makes repeats a no-op without consuming their body. */
export interface SeedIntake {
  status(connector: string): Promise<{
    targetKnown: boolean;
    streams: Readonly<Record<string, SeedStreamState>>;
  }>;
  put(
    connector: string,
    stream: string,
    body: AsyncIterable<Uint8Array>,
  ): Promise<
    | { readonly state: "merged" }
    | {
        readonly state: "staged";
        readonly records: number;
        readonly invalid: number;
      }
  >;
}

export function createSeedIntake(seed: LocalSeedCapability): SeedIntake {
  const intake: SeedIntake = {
    async status(connector) {
      checkSeedNames(connector, "s");
      const status = await seed.writer.seedStatus(connector);
      const streams: Record<string, SeedStreamState> = {};
      for (const [stream, staged] of Object.entries(
        await seed.staging.staged(connector),
      ))
        streams[stream] = {
          state: "staged",
          records: staged.records,
          invalid: staged.invalid,
        };
      for (const [stream, state] of Object.entries(status.receipts)) {
        if (streams[stream]) await seed.staging.drop(connector, stream);
        streams[stream] = { state };
      }
      return { targetKnown: status.targetKnown, streams };
    },
    async put(connector, stream, body) {
      checkSeedNames(connector, stream);
      const receipt = (await seed.writer.seedStatus(connector)).receipts[
        stream
      ];
      if (receipt !== undefined) {
        await seed.staging.drop(connector, stream);
        return { state: receipt };
      }
      const staged = await seed.staging.stage(connector, stream, body);
      await seed.writer.importStaged(connector);
      return {
        state: "staged",
        records: staged.records,
        invalid: staged.invalid,
      };
    },
  };
  // Serialize the whole receipt-check/stage/import sequence. The inner SQL
  // and staging lock has a separate key, because scope locks are not reentrant.
  return {
    status: (connector) =>
      withScopeLock(`stream-seed-request:${connector}`, () =>
        intake.status(connector),
      ),
    put: (connector, stream, body) =>
      withScopeLock(`stream-seed-request:${connector}`, () =>
        intake.put(connector, stream, body),
      ),
  };
}

/** Host staging feeds the same SQL seed importer as native
 * legacy access. The host supplies its one open database and verified artifacts.
 * The staging lock keeps a stream's immutable upload alive across both passes. */
export function createLocalSeed(options: {
  getDeps(): Promise<LocalSyncDeps>;
  manifests(): Iterable<string>;
  staging: SeedStaging;
}): LocalSeedCapability {
  const { staging } = options;
  const lock = <T>(connector: string, work: () => Promise<T>) =>
    withScopeLock(`stream-seed:${connector}`, work);
  const sourceName = (install: string, connector: string) =>
    JSON.stringify([install, connector]);
  function declarationFor(
    connector: string,
    stream: string,
    upload: Pick<SeedDescriptor, "profile" | "primaryKey">,
  ) {
    const artifacts = [...options.manifests()].flatMap((document) => {
      const artifact = manifestArtifact(document);
      return artifact &&
        artifact.declarations.connector === connector &&
        artifact.declarations.version === upload.profile.version
        ? [artifact]
        : [];
    });
    const declaration =
      artifacts.length === 1
        ? artifacts[0]!.declarations.streams.find((s) => s.name === stream)
        : undefined;
    if (
      !declaration ||
      (upload.profile.key !== null && upload.profile.key !== connector) ||
      JSON.stringify(declaration.primaryKey) !==
        JSON.stringify(upload.primaryKey)
    )
      throw new SeedUploadError(
        "SEED_BAD_DESCRIPTOR",
        "the staged stream does not match a verified artifact",
      );
    return declaration;
  }
  async function status(connector: string) {
    const deps = await options.getDeps();
    const connectionId = controlScope(connector, IDENTITYLESS_NS);
    return deps.queue.run(connectionId, "end", async () => {
      const locked: LocalSyncDeps = {
        ...deps,
        queue: {
          run: (id, kind, work) =>
            id === connectionId ? work() : deps.queue.run(id, kind, work),
        },
      };
      const [cached] = await deps.db.query<{
        deleted_at: number | null;
        control_state: string;
        deleting: number;
      }>(
        `SELECT deleted_at, control_state, EXISTS(SELECT 1 FROM delete_intents WHERE connector = ?) AS deleting FROM connections WHERE connection_id = ?`,
        [connector, connectionId],
      );
      if (
        (cached?.deleted_at !== null && cached?.deleted_at !== undefined) ||
        cached?.control_state === "deleted" ||
        cached?.deleting
      )
        throw new ProtocolError(
          410,
          "CONNECTION_DELETED",
          "The connection was deleted",
        );
      const refreshed = await syncBeforeBegin(locked, connector);
      const connection = refreshed.connection;
      if (connection?.controlState === "deleted")
        throw new ProtocolError(
          410,
          "CONNECTION_DELETED",
          "The connection was deleted",
        );
      const targetKnown =
        !!connection && ["active", "absent"].includes(connection.controlState);
      const install = await staging.installId();
      const ledger = createImportLedger(deps.db);
      const receipts: Record<string, "merged"> = {};
      const source = staging.source(install, async () => ({
        receipts: {},
        skipped: [],
      }));
      await source.streams(connector);
      for (const [stream, upload] of Object.entries(
        await staging.staged(connector),
      )) {
        const prior = await ledger.get(
          sourceName(install, connector),
          connectionId,
          stream,
        );
        if (
          prior &&
          ["imported", "verified", "retired", "excluded"].includes(prior.state)
        ) {
          receipts[stream] = "merged";
          continue;
        }
        if (!targetKnown) continue;
        const declaration = declarationFor(connector, stream, upload);
        const imported: ImportSource = {
          source: sourceName(install, connector),
          owner: deps.ownerAddress,
          network: (
            await deps.db.query<{ network: string }>(
              "SELECT network FROM db_meta WHERE id = 1",
            )
          )[0]!.network,
          revision: upload.upload,
          target: {
            connectionId,
            connector,
            stream,
            primaryKey: declaration.primaryKey,
            semantics: declaration.semantics,
            incremental: declaration.incremental !== false,
          },
          exclusions: [],
          records: () => source.records(connector, stream),
        };
        const result = await importLegacySource(locked, ledger, imported);
        if (
          result.kind === "refused" &&
          result.reason === "seed_window_closed"
        ) {
          // A real write already owns this stream. The old data is skipped
          // for good: an excluded receipt is final and is never re-imported.
          await deps.db.batch([
            ...ledger.statements({
              ...(await importFingerprint((async function* () {})())),
              source: imported.source,
              revision: imported.revision,
              connectionId,
              stream,
              generation: 1,
              highestSeq: 0,
              state: "excluded",
              reason: "seed_window_closed",
              at: deps.now(),
            }),
          ]);
          receipts[stream] = "merged";
          continue;
        }
        if (result.kind === "refused") {
          if (result.reason === "connection_deleted")
            throw new ProtocolError(
              410,
              "CONNECTION_DELETED",
              "The connection was deleted",
            );
          throw new ProtocolError(409, "SEED_IMPORT_REFUSED", result.reason);
        }
        receipts[stream] = "merged";
      }
      // Finished imports and authoritative exclusions remain receipts after
      // staging cleanup and restart. An excluded seed must never be re-imported.
      const stored = await deps.db.query<{ stream: string }>(
        "SELECT stream FROM import_ledger WHERE source = ? AND connection_id = ? AND state IN ('imported','verified','retired','excluded')",
        [sourceName(install, connector), connectionId],
      );
      for (const row of stored) receipts[row.stream] = "merged";
      return { targetKnown, receipts };
    });
  }
  return {
    writer: {
      seedStatus: (connector) => lock(connector, () => status(connector)),
      importStaged: (connector) =>
        lock(connector, async () => {
          await status(connector);
        }),
    },
    staging: {
      ...staging,
      stage: (connector, stream, body) =>
        lock(connector, async () => {
          await options.getDeps();
          return staging.stage(connector, stream, body, (descriptor) => {
            declarationFor(connector, stream, descriptor);
          });
        }),
      drop: (connector, stream) =>
        lock(connector, () => staging.drop(connector, stream)),
    },
  };
}

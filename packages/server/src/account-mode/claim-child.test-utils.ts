/**
 * Test helper for `file-record-store.ownership.test.ts`: a separate process
 * that tries to claim one account-mode record folder, reports on stdout, and
 * then stays alive (holding the folder if it got it) until it is killed.
 *
 * Output, one line each:
 * - `READY`    the claim succeeded; a record named `c<pid>` was saved
 * - `OWNED`    the claim was refused because another runtime owns the folder
 * - `ERROR <message>` anything else
 * - `RELEASED` after the line `release` arrived on stdin and the lease was let go
 * - `TOUCHED` after the line `touch <file>` arrived on stdin and this process
 *   opened, read and closed that file in every way other code does:
 *   Node `fs` handles, a whole-file read, a second SQLite connection, and the
 *   store's own `load` and `save`.
 */
import { closeSync, openSync, readFileSync } from "node:fs";
import Database from "better-sqlite3";
import {
  ModeStoreOwnedError,
  type DurableModeRecord,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { createFileModeRecordStore } from "./file-record-store.js";

const dir = process.argv[2]!;
const store = createFileModeRecordStore(dir);
const RECORD: DurableModeRecord = {
  switched: true,
  switchedAt: 1,
  cleanOffAt: null,
  offFetchStartMono: null,
  bootId: "child",
  importPending: false,
};

const say = (line: string) => process.stdout.write(`${line}\n`);

async function touch(file: string): Promise<void> {
  closeSync(openSync(file, "r+"));
  closeSync(openSync(file, "r"));
  readFileSync(file);
  const db = new Database(file);
  db.exec("PRAGMA user_version = 7");
  db.close();
  await store.load();
  await store.save(`t${process.pid}`, RECORD, null);
}

try {
  const lease = await store.claim();
  await store.load();
  await store.save(`c${process.pid}`, RECORD, null);
  say("READY");
  let input = "";
  process.stdin.on("data", (chunk: Buffer) => {
    input += chunk.toString();
    for (let i = input.indexOf("\n"); i >= 0; i = input.indexOf("\n")) {
      const command = input.slice(0, i);
      input = input.slice(i + 1);
      if (command === "release") {
        void lease.release().then(() => say("RELEASED"));
      } else if (command.startsWith("touch ")) {
        void touch(command.slice("touch ".length)).then(() => say("TOUCHED"));
      }
    }
  });
} catch (error) {
  if (error instanceof ModeStoreOwnedError) {
    say("OWNED");
    process.exit(0);
  }
  say(`ERROR ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}
setInterval(() => {}, 1_000);

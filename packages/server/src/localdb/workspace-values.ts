import { randomUUID } from "node:crypto";
import {
  createSqlWorkspaceValues,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
/** Node uses bounded chunk rows: better-sqlite3 exposes no blob_open API. */
export const createWorkspaceValues = (
  db: SqlDriver,
  frameCapacityBytes?: number,
) => createSqlWorkspaceValues(db, randomUUID, frameCapacityBytes);

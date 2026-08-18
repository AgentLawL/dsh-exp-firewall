import { chmodSync, mkdirSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'

import { FirewallError } from './types/errors.ts'

/** Current incompatible SQLite schema version. */
export const SCHEMA_VERSION = 1
/** Durable SQLite filename inside the configured private data directory. */
export const DATABASE_FILENAME = 'exp-firewall.sqlite3'

const REQUIRED_TABLES = [
  'claim_supporters',
  'claims',
  'events',
  'observations',
  'operations',
  'verification_leases',
] as const
const REQUIRED_INDEXES = ['one_active_lease', 'one_current_claim'] as const

const SCHEMA_SQL = `
CREATE TABLE observations(
  id TEXT PRIMARY KEY,
  operation_id TEXT NOT NULL UNIQUE,
  session_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  tool_call_id TEXT,
  scope TEXT NOT NULL,
  action_kind TEXT NOT NULL CHECK(action_kind IN ('command', 'file-read')),
  fingerprint TEXT NOT NULL,
  preview TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK(outcome IN ('success', 'failure')),
  failure_code TEXT,
  evidence_epoch TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  observed_at TEXT NOT NULL
);

CREATE TABLE claims(
  id TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  action_kind TEXT NOT NULL CHECK(action_kind IN ('command', 'file-read')),
  fingerprint TEXT NOT NULL,
  evidence_epoch TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  preview TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN (
    'suspected', 'corroborated', 'stale', 'verifying', 'contradicted', 'resolved', 'superseded'
  )),
  supporter_count INTEGER NOT NULL CHECK(supporter_count >= 0),
  revision INTEGER NOT NULL CHECK(revision >= 1),
  is_current INTEGER NOT NULL CHECK(is_current IN (0, 1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE claim_supporters(
  claim_id TEXT NOT NULL REFERENCES claims(id),
  principal_id TEXT NOT NULL,
  last_observed_at TEXT NOT NULL,
  PRIMARY KEY(claim_id, principal_id)
);

CREATE TABLE verification_leases(
  id TEXT PRIMARY KEY,
  claim_id TEXT NOT NULL REFERENCES claims(id),
  owner_principal_id TEXT NOT NULL,
  evidence_epoch TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  outcome TEXT CHECK(outcome IN ('success', 'failure', 'released')),
  settled_at TEXT
);

CREATE TABLE events(
  id TEXT PRIMARY KEY,
  operation_id TEXT NOT NULL,
  claim_id TEXT REFERENCES claims(id),
  kind TEXT NOT NULL,
  body_json TEXT NOT NULL,
  occurred_at TEXT NOT NULL
);

CREATE TABLE operations(
  id TEXT PRIMARY KEY,
  request_hash TEXT NOT NULL,
  result_json TEXT,
  created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX one_current_claim
  ON claims(scope, fingerprint)
  WHERE is_current = 1;

CREATE UNIQUE INDEX one_active_lease
  ON verification_leases(claim_id)
  WHERE outcome IS NULL;
`

function mapOpenFailure(error: unknown): FirewallError {
  if (error instanceof FirewallError) return error
  return new FirewallError('STORE_CORRUPT', 'Unable to open or validate the Exp Firewall database; restore or remove the configured data store.')
}

function readSchemaVersion(database: DatabaseSync): number {
  const row = database.prepare('PRAGMA user_version').get() as { user_version?: unknown } | undefined
  if (row === undefined || !Number.isSafeInteger(row.user_version)) {
    throw new FirewallError('STORE_CORRUPT', 'The database does not expose a valid schema version.')
  }
  return row.user_version as number
}

function initializeSchema(database: DatabaseSync): void {
  database.exec('BEGIN IMMEDIATE')
  try {
    const version = readSchemaVersion(database)
    if (version === 0) {
      database.exec(SCHEMA_SQL)
      database.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`)
    } else if (version !== SCHEMA_VERSION) {
      throw new FirewallError(
        'STORE_CORRUPT',
        `Unsupported Exp Firewall schema version ${version}; use a compatible package or a fresh data directory.`,
      )
    }
    database.exec('COMMIT')
  } catch (error) {
    try {
      database.exec('ROLLBACK')
    } catch {
      // SQLite may already have rolled back the failed schema transaction.
    }
    throw error
  }
}

function validateSchemaObjects(database: DatabaseSync): void {
  const integrity = database.prepare('PRAGMA quick_check').get() as { quick_check?: unknown } | undefined
  if (integrity?.quick_check !== 'ok') {
    throw new FirewallError('STORE_CORRUPT', 'SQLite integrity validation failed; restore or replace the data store.')
  }
  const rows = database
    .prepare("SELECT type, name FROM sqlite_master WHERE type IN ('table', 'index')")
    .all() as Array<{ type: string; name: string }>
  const tables = new Set(rows.filter((row) => row.type === 'table').map((row) => row.name))
  const indexes = new Set(rows.filter((row) => row.type === 'index').map((row) => row.name))
  if (REQUIRED_TABLES.some((table) => !tables.has(table)) || REQUIRED_INDEXES.some((index) => !indexes.has(index))) {
    throw new FirewallError('STORE_CORRUPT', 'The database schema is incomplete; restore or replace the data store.')
  }
}

/** Open versioned schema handle used by later transactional Store tasks. */
export class SqliteDatabase {
  /** Absolute database path. */
  readonly path: string
  /** Low-level connection; transaction ownership remains inside Store modules. */
  readonly connection: DatabaseSync
  #closed = false

  /**
   * Wrap an initialized SQLite connection.
   * @param path - Absolute database path.
   * @param connection - Validated SQLite connection.
   */
  constructor(path: string, connection: DatabaseSync) {
    this.path = path
    this.connection = connection
  }

  /** Close the connection idempotently. */
  close(): void {
    if (this.#closed) return
    this.#closed = true
    this.connection.close()
  }
}

/**
 * Create or validate the private WAL-mode SQLite database.
 * @param dataDir - Configured Store directory.
 * @returns Open validated schema handle.
 */
export function openSqliteDatabase(dataDir: string): SqliteDatabase {
  const absoluteDataDirectory = resolve(dataDir)
  mkdirSync(absoluteDataDirectory, { recursive: true, mode: 0o700 })
  chmodSync(absoluteDataDirectory, 0o700)
  const databasePath = join(absoluteDataDirectory, DATABASE_FILENAME)

  let database: DatabaseSync | undefined
  try {
    database = new DatabaseSync(databasePath)
    chmodSync(databasePath, 0o600)
    database.exec('PRAGMA busy_timeout = 2000')
    database.exec('PRAGMA foreign_keys = ON')
    const mode = database.prepare('PRAGMA journal_mode = WAL').get() as { journal_mode?: unknown } | undefined
    if (String(mode?.journal_mode).toLowerCase() !== 'wal') {
      throw new FirewallError('STORE_CORRUPT', 'SQLite refused WAL mode for the configured data store.')
    }

    const version = readSchemaVersion(database)
    if (version === 0) {
      initializeSchema(database)
    } else if (version !== SCHEMA_VERSION) {
      throw new FirewallError(
        'STORE_CORRUPT',
        `Unsupported Exp Firewall schema version ${version}; use a compatible package or a fresh data directory.`,
      )
    }
    validateSchemaObjects(database)
    return new SqliteDatabase(databasePath, database)
  } catch (error) {
    if (database !== undefined) {
      try {
        database.close()
      } catch {
        // A corrupt connection may already be unusable; the original typed failure wins.
      }
    }
    throw mapOpenFailure(error)
  }
}

import { chmod, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { afterEach, describe, expect, it } from 'vitest'

import { DATABASE_FILENAME, openSqliteDatabase, SCHEMA_VERSION } from '../src/store-sqlite.ts'
import { FirewallError } from '../src/types/errors.ts'

const temporaryDirectories: string[] = []

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'exp-firewall-schema-'))
  temporaryDirectories.push(directory)
  return directory
}

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })))
})

describe('SQLite schema and file safety', () => {
  it('creates version 1, six tables, two partial unique indexes, and WAL mode', async () => {
    const directory = await temporaryDirectory()
    const store = openSqliteDatabase(directory)
    try {
      expect(store.connection.prepare('PRAGMA user_version').get()).toMatchObject({ user_version: SCHEMA_VERSION })
      expect(store.connection.prepare('PRAGMA journal_mode').get()).toMatchObject({ journal_mode: 'wal' })
      const tables = store.connection
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .all()
      expect(tables).toEqual([
        { name: 'claim_supporters' },
        { name: 'claims' },
        { name: 'events' },
        { name: 'observations' },
        { name: 'operations' },
        { name: 'verification_leases' },
      ])
      const indexSql = store.connection
        .prepare("SELECT name, sql FROM sqlite_master WHERE name IN ('one_current_claim', 'one_active_lease') ORDER BY name")
        .all() as Array<{ name: string; sql: string }>
      expect(indexSql).toHaveLength(2)
      expect(indexSql[0]?.sql).toContain('WHERE outcome IS NULL')
      expect(indexSql[1]?.sql).toContain('WHERE is_current = 1')
    } finally {
      store.close()
    }
  })

  it('reopens and validates an existing compatible database', async () => {
    const directory = await temporaryDirectory()
    openSqliteDatabase(directory).close()
    const reopened = openSqliteDatabase(directory)
    expect(reopened.connection.prepare('PRAGMA quick_check').get()).toMatchObject({ quick_check: 'ok' })
    reopened.close()
  })

  it('rejects an unknown schema version without rewriting it', async () => {
    const directory = await temporaryDirectory()
    const path = join(directory, DATABASE_FILENAME)
    const database = new DatabaseSync(path)
    database.exec('PRAGMA user_version = 2')
    database.close()

    expect(() => openSqliteDatabase(directory)).toThrowError(FirewallError)
    const unchanged = new DatabaseSync(path)
    expect(unchanged.prepare('PRAGMA user_version').get()).toMatchObject({ user_version: 2 })
    unchanged.close()
  })

  it('rejects corrupt database bytes with STORE_CORRUPT', async () => {
    const directory = await temporaryDirectory()
    await writeFile(join(directory, DATABASE_FILENAME), 'not a sqlite database')
    try {
      openSqliteDatabase(directory)
      throw new Error('expected corrupt database rejection')
    } catch (error) {
      expect(error).toBeInstanceOf(FirewallError)
      expect((error as FirewallError).code).toBe('STORE_CORRUPT')
    }
  })

  it.runIf(process.platform !== 'win32')('enforces 0700 directory and 0600 database modes', async () => {
    const directory = await temporaryDirectory()
    await chmod(directory, 0o755)
    const store = openSqliteDatabase(directory)
    store.close()
    expect((await stat(directory)).mode & 0o777).toBe(0o700)
    expect((await stat(join(directory, DATABASE_FILENAME))).mode & 0o777).toBe(0o600)
  })

  it('leaves a valid SQLite header on disk after close', async () => {
    const directory = await temporaryDirectory()
    const store = openSqliteDatabase(directory)
    store.close()
    const bytes = await readFile(join(directory, DATABASE_FILENAME))
    expect(bytes.subarray(0, 16).toString('utf8')).toBe('SQLite format 3\u0000')
  })
})

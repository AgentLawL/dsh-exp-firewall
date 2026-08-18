import { spawn } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'

import { resolveConfig } from '../src/config.ts'
import { SqliteExperienceFirewallStore } from '../src/store-service.ts'
import { openSqliteDatabase } from '../src/store-sqlite.ts'
import { claimId, observation } from './helpers.ts'

const directories: string[] = []
const workerPath = resolve('tests/fixtures/store-worker.mjs')

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'exp-firewall-process-'))
  directories.push(directory)
  return directory
}

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })))
})

function runWorker(input: Record<string, unknown>): Promise<{ code: number; output: unknown; stderr: string }> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, ['--experimental-strip-types', workerPath, JSON.stringify(input)], {
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    child.stdout.setEncoding('utf8').on('data', (chunk) => (stdout += chunk))
    child.stderr.setEncoding('utf8').on('data', (chunk) => (stderr += chunk))
    child.once('error', reject)
    child.once('exit', (code) => {
      const trimmed = stdout.trim()
      resolvePromise({ code: code ?? -1, output: trimmed.length === 0 ? undefined : JSON.parse(trimmed), stderr })
    })
  })
}

async function seedCorroborated(dataDir: string): Promise<void> {
  const store = new SqliteExperienceFirewallStore(resolveConfig({ mode: 'enforce', dataDir }))
  try {
    for (const [id, principal, at] of [
      ['seed-a', 'a', '2026-08-18T00:00:00.000Z'],
      ['seed-b', 'b', '2026-08-18T00:00:01.000Z'],
    ] as const) {
      const value = observation({ id, principal, at, outcome: 'failure', failureCode: 'FS_NOT_FOUND' })
      await store.record({
        operationId: value.operationId,
        observation: value,
        newClaimId: claimId(id === 'seed-a' ? 'claim-process' : 'unused'),
        now: at,
      })
    }
  } finally {
    await store.shutdown()
  }
}

describe('process-level Store concurrency and recovery', () => {
  it('serializes concurrent first failures into one current corroborated Claim', async () => {
    const dataDir = await temporaryDirectory()
    openSqliteDatabase(dataDir).close()
    const common = { action: 'record', dataDir, observedAt: '2026-08-18T00:00:00.000Z' }
    const results = await Promise.all([
      runWorker({ ...common, observationId: 'process-a', operationId: 'op-process-a', principalId: 'a', claimId: 'claim-a' }),
      runWorker({ ...common, observationId: 'process-b', operationId: 'op-process-b', principalId: 'b', claimId: 'claim-b' }),
    ])
    expect(results.map((result) => result.code), JSON.stringify(results)).toEqual([0, 0])
    const store = new SqliteExperienceFirewallStore(resolveConfig({ mode: 'enforce', dataDir }))
    try {
      const claims = await store.listClaims({ limit: 10 })
      expect(claims.items).toHaveLength(1)
      expect(claims.items[0]).toMatchObject({ status: 'corroborated', supporterCount: 2, isCurrent: true })
    } finally {
      await store.shutdown()
    }
  })

  it('returns one original result for concurrent identical operation replay', async () => {
    const dataDir = await temporaryDirectory()
    const input = {
      action: 'record',
      dataDir,
      observationId: 'same-observation',
      operationId: 'same-operation',
      principalId: 'a',
      claimId: 'same-claim',
      observedAt: '2026-08-18T00:00:00.000Z',
    }
    const results = await Promise.all([runWorker(input), runWorker(input)])
    expect(results.map((result) => result.code)).toEqual([0, 0])
    expect(results[0]?.output).toEqual(results[1]?.output)
    const database = openSqliteDatabase(dataDir)
    expect(database.connection.prepare('SELECT COUNT(*) AS count FROM operations').get()).toMatchObject({ count: 1 })
    expect(database.connection.prepare('SELECT COUNT(*) AS count FROM observations').get()).toMatchObject({ count: 1 })
    database.close()
  })

  it('grants exactly one active Lease during a two-process Evidence-change race', async () => {
    const dataDir = await temporaryDirectory()
    await seedCorroborated(dataDir)
    const common = {
      action: 'decide',
      dataDir,
      claimId: 'claim-process',
      now: '2026-08-18T00:00:02.000Z',
      expiresAt: '2026-08-18T00:01:00.000Z',
    }
    const results = await Promise.all([
      runWorker({ ...common, operationId: 'op-lease-c', principalId: 'c', leaseId: 'lease-c' }),
      runWorker({ ...common, operationId: 'op-lease-d', principalId: 'd', leaseId: 'lease-d' }),
    ])
    expect(results.map((result) => result.code)).toEqual([0, 0])
    expect(results.map((result) => (result.output as { kind: string }).kind).sort()).toEqual(['verify', 'wait'])
    const database = openSqliteDatabase(dataDir)
    expect(
      database.connection.prepare('SELECT COUNT(*) AS count FROM verification_leases WHERE outcome IS NULL').get(),
    ).toMatchObject({ count: 1 })
    database.close()
  })

  it('rolls back an interrupted transaction and accepts later writes after integrity check', async () => {
    const dataDir = await temporaryDirectory()
    openSqliteDatabase(dataDir).close()
    const crashed = await runWorker({ action: 'crash', dataDir })
    expect(crashed.code).toBe(17)
    const database = openSqliteDatabase(dataDir)
    expect(database.connection.prepare('PRAGMA integrity_check').get()).toMatchObject({ integrity_check: 'ok' })
    expect(database.connection.prepare('SELECT COUNT(*) AS count FROM operations').get()).toMatchObject({ count: 0 })
    database.close()

    const result = await runWorker({
      action: 'record',
      dataDir,
      observationId: 'after-crash',
      operationId: 'op-after-crash',
      principalId: 'a',
      claimId: 'claim-after-crash',
      observedAt: '2026-08-18T00:00:01.000Z',
    })
    expect(result.code).toBe(0)
  })
})

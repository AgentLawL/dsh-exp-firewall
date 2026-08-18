import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'

import { resolveConfig } from '../src/config.ts'
import { evidenceEpoch } from '../src/evidence.ts'
import { SqliteExperienceFirewallStore } from '../src/store-service.ts'
import { openSqliteDatabase } from '../src/store-sqlite.ts'
import { FirewallError } from '../src/types/errors.ts'
import { claimId, fp, leaseId, observation, operationId, principalId } from './helpers.ts'

const directories: string[] = []
const oldEvidence = [{ kind: 'file-state' as const, key: '/target', state: 'absent' as const }]
const newEvidence = [{ kind: 'file-state' as const, key: '/target', state: 'present' as const, version: 'v1' }]

async function createStore(mode: 'observe' | 'warn' | 'enforce' = 'enforce'): Promise<SqliteExperienceFirewallStore> {
  const dataDir = await mkdtemp(join(tmpdir(), 'exp-firewall-service-'))
  directories.push(dataDir)
  return new SqliteExperienceFirewallStore(resolveConfig({ mode, dataDir }))
}

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })))
})

async function corroborate(store: SqliteExperienceFirewallStore): Promise<void> {
  const first = observation({
    id: 'persist-a',
    principal: 'a',
    at: '2026-08-18T00:00:00.000Z',
    outcome: 'failure',
    failureCode: 'FS_NOT_FOUND',
  })
  const second = observation({
    id: 'persist-b',
    principal: 'b',
    at: '2026-08-18T00:00:01.000Z',
    outcome: 'failure',
    failureCode: 'FS_NOT_FOUND',
  })
  await store.record({ operationId: first.operationId, observation: first, newClaimId: claimId('claim-persisted'), now: first.observedAt })
  await store.record({ operationId: second.operationId, observation: second, newClaimId: claimId('unused'), now: second.observedAt })
}

describe('SQLite ExperienceFirewallService', () => {
  it('atomically persists Observations, independent support, Claim transitions, receipts, events, and counters', async () => {
    const store = await createStore()
    try {
      const first = observation({
        id: 'persist-a',
        principal: 'a',
        at: '2026-08-18T00:00:00.000Z',
        outcome: 'failure',
        failureCode: 'FS_NOT_FOUND',
      })
      const request = {
        operationId: first.operationId,
        observation: first,
        newClaimId: claimId('claim-persisted'),
        now: first.observedAt,
      }
      expect(await store.record(request)).toMatchObject({ duplicate: false, claim: { status: 'suspected' } })
      expect(await store.record(request)).toEqual(await store.record(request))

      const retry = observation({
        id: 'persist-a-retry',
        principal: 'a',
        at: '2026-08-18T00:00:00.500Z',
        outcome: 'failure',
        failureCode: 'FS_NOT_FOUND',
      })
      await store.record({ operationId: retry.operationId, observation: retry, newClaimId: claimId('unused-a'), now: retry.observedAt })
      const second = observation({
        id: 'persist-b',
        principal: 'b',
        at: '2026-08-18T00:00:01.000Z',
        outcome: 'failure',
        failureCode: 'FS_NOT_FOUND',
      })
      await store.record({ operationId: second.operationId, observation: second, newClaimId: claimId('unused-b'), now: second.observedAt })

      expect(await store.summary()).toMatchObject({ corroboratedClaims: 1, suspectedClaims: 0 })
      const claimPage = await store.listClaims({ limit: 1 })
      expect(claimPage.items).toMatchObject([
        { id: 'claim-persisted', status: 'corroborated', supporterCount: 2, revision: 2 },
      ])
      expect(claimPage.items[0]).not.toHaveProperty('evidence')

      const decision = await store.decide({
        operationId: operationId('op-deny'),
        scope: '/workspace',
        actionKind: 'file-read',
        fingerprint: fp,
        principalId: principalId('c'),
        evidence: oldEvidence,
        now: '2026-08-18T00:00:02.000Z',
      })
      expect(decision).toEqual({ kind: 'deny', reason: 'corroborated', claimId: 'claim-persisted' })
      expect(await store.summary()).toMatchObject({ callsDenied: 1, verificationWaits: 0, crossAgentHits: 1 })

      const detail = await store.getClaim(claimId('claim-persisted'))
      expect(detail?.observations).toHaveLength(3)
      expect(detail).not.toHaveProperty('command')
      expect(await store.listEvents({ claimId: claimId('claim-persisted'), limit: 2 })).toMatchObject({
        items: [{}, {}],
        nextCursor: '2',
      })
    } finally {
      await store.shutdown()
    }
  })

  it('serializes Evidence invalidation, lease competition, wait, and successful settlement', async () => {
    const store = await createStore()
    try {
      await corroborate(store)
      const lease = {
        id: leaseId('lease-persisted'),
        claimId: claimId('claim-persisted'),
        ownerPrincipalId: principalId('c'),
        evidenceEpoch: evidenceEpoch(newEvidence),
        expiresAt: '2026-08-18T00:01:00.000Z',
      }
      expect(
        await store.decide({
          operationId: operationId('op-verify'),
          scope: '/workspace',
          actionKind: 'file-read',
          fingerprint: fp,
          principalId: principalId('c'),
          evidence: newEvidence,
          now: '2026-08-18T00:00:02.000Z',
          candidateLease: lease,
        }),
      ).toEqual({ kind: 'verify', reason: 'evidence-changed', claimId: 'claim-persisted', leaseId: 'lease-persisted' })

      expect(
        await store.decide({
          operationId: operationId('op-wait'),
          scope: '/workspace',
          actionKind: 'file-read',
          fingerprint: fp,
          principalId: principalId('d'),
          evidence: newEvidence,
          now: '2026-08-18T00:00:03.000Z',
        }),
      ).toMatchObject({ kind: 'wait', owner: 'c', reason: 'verification-in-progress' })
      expect(await store.summary()).toMatchObject({ staleClaims: 1, leasesGranted: 1, verificationWaits: 1 })

      const success = observation({
        id: 'verify-persisted',
        principal: 'c',
        at: '2026-08-18T00:00:04.000Z',
        outcome: 'success',
        evidence: newEvidence,
      })
      expect(
        await store.settleLease({
          operationId: success.operationId,
          leaseId: lease.id,
          ownerPrincipalId: principalId('c'),
          observation: success,
          newClaimId: claimId('unused'),
          now: success.observedAt,
        }),
      ).toMatchObject({ lease: { outcome: 'success' }, claim: { status: 'resolved', revision: 5 } })
      expect(await store.summary()).toMatchObject({ resolvedClaims: 1, staleClaims: 0 })
    } finally {
      await store.shutdown()
    }
  })

  it('invalidates affected Claims from a background filesystem Witness and ignores unknown keys', async () => {
    const store = await createStore()
    try {
      await corroborate(store)
      expect(
        await store.invalidateClaims({
          operationId: operationId('op-unrelated-evidence'),
          evidence: [{ kind: 'file-state', key: '/other', state: 'absent' }],
          now: '2026-08-18T00:00:02.000Z',
        }),
      ).toEqual({ claimIds: [] })
      expect(
        await store.invalidateClaims({
          operationId: operationId('op-related-evidence'),
          evidence: newEvidence,
          now: '2026-08-18T00:00:03.000Z',
        }),
      ).toEqual({ claimIds: ['claim-persisted'] })
      expect(await store.summary()).toMatchObject({ corroboratedClaims: 0, staleClaims: 1 })
    } finally {
      await store.shutdown()
    }
  })

  it('persists failed verification as a superseded old Claim plus revision-1 replacement', async () => {
    const store = await createStore()
    try {
      await corroborate(store)
      const lease = {
        id: leaseId('lease-failure'),
        claimId: claimId('claim-persisted'),
        ownerPrincipalId: principalId('c'),
        evidenceEpoch: evidenceEpoch(newEvidence),
        expiresAt: '2026-08-18T00:01:00.000Z',
      }
      await store.decide({
        operationId: operationId('op-verify-failure-start'),
        scope: '/workspace',
        actionKind: 'file-read',
        fingerprint: fp,
        principalId: principalId('c'),
        evidence: newEvidence,
        now: '2026-08-18T00:00:02.000Z',
        candidateLease: lease,
      })
      const failure = observation({
        id: 'verify-failure-persisted',
        principal: 'c',
        at: '2026-08-18T00:00:03.000Z',
        outcome: 'failure',
        failureCode: 'FS_NOT_FOUND',
        evidence: newEvidence,
      })
      const result = await store.settleLease({
        operationId: failure.operationId,
        leaseId: lease.id,
        ownerPrincipalId: principalId('c'),
        observation: failure,
        newClaimId: claimId('claim-new-epoch'),
        now: failure.observedAt,
      })
      expect(result).toMatchObject({
        lease: { outcome: 'failure' },
        claim: { status: 'superseded', isCurrent: false },
        replacementClaim: { id: 'claim-new-epoch', status: 'suspected', revision: 1, supporterCount: 1 },
      })
      expect((await store.listClaims({ limit: 10 })).items).toHaveLength(2)
    } finally {
      await store.shutdown()
    }
  })

  it('enforces lease ownership, exact expiry, release semantics, and idempotent shutdown', async () => {
    const store = await createStore()
    await corroborate(store)
    const lease = {
      id: leaseId('lease-release'),
      claimId: claimId('claim-persisted'),
      ownerPrincipalId: principalId('c'),
      evidenceEpoch: evidenceEpoch(newEvidence),
      expiresAt: '2026-08-18T00:01:00.000Z',
    }
    await store.decide({
      operationId: operationId('op-lease-release-start'),
      scope: '/workspace',
      actionKind: 'file-read',
      fingerprint: fp,
      principalId: principalId('c'),
      evidence: newEvidence,
      now: '2026-08-18T00:00:02.000Z',
      candidateLease: lease,
    })
    await expect(
      store.releaseLease({
        kind: 'release-lease',
        operationId: operationId('op-wrong-release'),
        leaseId: lease.id,
        ownerPrincipalId: principalId('d'),
        cause: 'released',
        now: '2026-08-18T00:00:03.000Z',
      }),
    ).rejects.toMatchObject({ code: 'LEASE_NOT_OWNER' })
    expect(
      await store.releaseLease({
        kind: 'release-lease',
        operationId: operationId('op-expire'),
        leaseId: lease.id,
        cause: 'expired',
        now: lease.expiresAt,
      }),
    ).toMatchObject({ lease: { outcome: 'released' }, claim: { status: 'stale' } })

    const controller = new AbortController()
    controller.abort(new Error('cancelled'))
    await expect(store.listClaims({ signal: controller.signal })).rejects.toThrow('cancelled')
    await store.shutdown()
    await store.shutdown()
    await expect(store.summary()).rejects.toBeInstanceOf(FirewallError)
  })

  it('retries SQLite busy within the deadline and terminates after the deadline', async () => {
    const dataDir = await mkdtemp(join(tmpdir(), 'exp-firewall-busy-'))
    directories.push(dataDir)
    const store = new SqliteExperienceFirewallStore(
      resolveConfig({ mode: 'enforce', dataDir, storeBusyDeadlineMs: 150 }),
    )
    const blocker = openSqliteDatabase(dataDir)
    blocker.connection.exec('BEGIN IMMEDIATE')
    const release = setTimeout(() => blocker.connection.exec('COMMIT'), 60)
    try {
      const value = observation({
        id: 'busy-success',
        principal: 'a',
        at: '2026-08-18T00:00:00.000Z',
        outcome: 'failure',
        failureCode: 'FS_NOT_FOUND',
      })
      await expect(
        store.record({ operationId: value.operationId, observation: value, newClaimId: claimId('busy-claim'), now: value.observedAt }),
      ).resolves.toMatchObject({ duplicate: false })

      blocker.connection.exec('BEGIN IMMEDIATE')
      const failing = observation({
        id: 'busy-failure',
        principal: 'b',
        at: '2026-08-18T00:00:01.000Z',
        outcome: 'failure',
        failureCode: 'FS_NOT_FOUND',
      })
      const startedAt = Date.now()
      await expect(
        store.record({
          operationId: failing.operationId,
          observation: failing,
          newClaimId: claimId('unused'),
          now: failing.observedAt,
        }),
      ).rejects.toMatchObject({ code: 'STORE_BUSY' })
      expect(Date.now() - startedAt).toBeGreaterThanOrEqual(100)
      blocker.connection.exec('ROLLBACK')
    } finally {
      clearTimeout(release)
      try {
        blocker.connection.exec('ROLLBACK')
      } catch {
        // The test may already have committed or rolled back the blocker transaction.
      }
      blocker.close()
      await store.shutdown()
    }
  })

  it('stops new mutations, drains an accepted write, and closes only after it settles', async () => {
    const dataDir = await mkdtemp(join(tmpdir(), 'exp-firewall-drain-'))
    directories.push(dataDir)
    const store = new SqliteExperienceFirewallStore(
      resolveConfig({ mode: 'enforce', dataDir, storeBusyDeadlineMs: 200 }),
    )
    const blocker = openSqliteDatabase(dataDir)
    blocker.connection.exec('BEGIN IMMEDIATE')
    const value = observation({
      id: 'drained-write',
      principal: 'a',
      at: '2026-08-18T00:00:00.000Z',
      outcome: 'failure',
      failureCode: 'FS_NOT_FOUND',
    })
    const write = store.record({
      operationId: value.operationId,
      observation: value,
      newClaimId: claimId('drained-claim'),
      now: value.observedAt,
    })
    const shutdown = store.shutdown()
    const rejected = observation({
      id: 'late-write',
      principal: 'b',
      at: '2026-08-18T00:00:01.000Z',
      outcome: 'failure',
      failureCode: 'FS_NOT_FOUND',
    })
    await expect(
      store.record({
        operationId: rejected.operationId,
        observation: rejected,
        newClaimId: claimId('late-claim'),
        now: rejected.observedAt,
      }),
    ).rejects.toBeInstanceOf(FirewallError)
    setTimeout(() => blocker.connection.exec('COMMIT'), 50)
    await expect(write).resolves.toMatchObject({ duplicate: false })
    await shutdown
    blocker.close()
    await expect(store.summary()).rejects.toBeInstanceOf(FirewallError)
  })
})

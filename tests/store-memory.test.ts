import { describe, expect, it } from 'vitest'

import { resolveConfig } from '../src/config.ts'
import { evidenceEpoch } from '../src/evidence.ts'
import { MemoryStore, replayMemoryScenario } from '../src/store-memory.ts'
import type { ReducerCommand } from '../src/store.ts'
import { claimId, fp, leaseId, observation, operationId, principalId } from './helpers.ts'

const t0 = '2026-08-18T00:00:00.000Z'
const t1 = '2026-08-18T00:00:01.000Z'
const t2 = '2026-08-18T00:00:02.000Z'
const changedEvidence = [{ kind: 'file-state' as const, key: '/target', state: 'present' as const, version: 'v1' }]

function fixtureCommands(): ReducerCommand[] {
  const first = observation({ id: 'one', principal: 'a', at: t0, outcome: 'failure', failureCode: 'FS_NOT_FOUND' })
  const second = observation({ id: 'two', principal: 'b', at: t1, outcome: 'failure', failureCode: 'FS_NOT_FOUND' })
  return [
    {
      kind: 'record-observation',
      operationId: first.operationId,
      observation: first,
      newClaimId: claimId('claim-a'),
      now: t0,
      observationTtlMs: 300_000,
      minIndependentSupporters: 2,
    },
    {
      kind: 'record-observation',
      operationId: second.operationId,
      observation: second,
      newClaimId: claimId('unused'),
      now: t1,
      observationTtlMs: 300_000,
      minIndependentSupporters: 2,
    },
    {
      kind: 'invalidate-evidence',
      operationId: operationId('op-invalidate'),
      scope: '/workspace',
      fingerprint: fp,
      currentEvidence: changedEvidence,
      now: t2,
    },
  ]
}

describe('MemoryStore', () => {
  it('replays identical input into identical Claim and event output', () => {
    const config = resolveConfig({ mode: 'enforce' })
    expect(replayMemoryScenario(config, fixtureCommands())).toEqual(replayMemoryScenario(config, fixtureCommands()))
  })

  it('drives consensus, denial, changed Evidence, lease ownership, and resolution', () => {
    const config = resolveConfig({ mode: 'enforce' })
    const store = new MemoryStore(config)
    for (const command of fixtureCommands()) {
      expect(store.dispatch(command).kind).toBe('applied')
    }
    expect(store.snapshot().claims[0]).toMatchObject({ status: 'stale', revision: 3 })

    const lease = {
      id: leaseId('lease-a'),
      claimId: claimId('claim-a'),
      ownerPrincipalId: principalId('c'),
      evidenceEpoch: evidenceEpoch(changedEvidence),
      expiresAt: '2026-08-18T00:01:00.000Z',
    }
    const verifierDecision = store.decide({
      operationId: operationId('op-decide-c'),
      scope: '/workspace',
      actionKind: 'file-read',
      fingerprint: fp,
      principalId: principalId('c'),
      evidence: changedEvidence,
      now: t2,
      candidateLease: lease,
    })
    expect(verifierDecision.decision).toMatchObject({ kind: 'verify', leaseId: 'lease-a' })

    const waiterDecision = store.decide({
      operationId: operationId('op-decide-d'),
      scope: '/workspace',
      actionKind: 'file-read',
      fingerprint: fp,
      principalId: principalId('d'),
      evidence: changedEvidence,
      now: t2,
    })
    expect(waiterDecision.decision).toMatchObject({ kind: 'wait', reason: 'verification-in-progress' })

    const success = observation({
      id: 'verify-success',
      principal: 'c',
      at: '2026-08-18T00:00:03.000Z',
      outcome: 'success',
      evidence: changedEvidence,
    })
    const settled = store.settleLease({
      operationId: success.operationId,
      leaseId: lease.id,
      ownerPrincipalId: principalId('c'),
      observation: success,
      newClaimId: claimId('unused'),
      now: success.observedAt,
    })
    expect(settled.kind).toBe('applied')
    expect(store.snapshot().claims[0]).toMatchObject({ status: 'resolved', revision: 5 })

    const projection = store.scenarioSnapshot()
    expect(projection.decisions.map((entry) => entry.decision.kind)).toEqual(['verify', 'wait'])
    expect(projection.events.map((event) => event.kind)).toContain('lease-settled')
  })
})

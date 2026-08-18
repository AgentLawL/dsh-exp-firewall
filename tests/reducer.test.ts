import { describe, expect, it } from 'vitest'

import { reduceFirewall } from '../src/reducer.ts'
import { createEmptyState, type FirewallState, type ReducerCommand } from '../src/store.ts'
import type { VerificationLease } from '../src/types/domain.ts'
import { claimId, fp, leaseId, observation, operationId, principalId } from './helpers.ts'

const t0 = '2026-08-18T00:00:00.000Z'
const t1 = '2026-08-18T00:00:01.000Z'
const t2 = '2026-08-18T00:00:02.000Z'
const changedEvidence = [{ kind: 'file-state' as const, key: '/target', state: 'present' as const, version: 'v1' }]

function apply(state: FirewallState, command: ReducerCommand): FirewallState {
  const result = reduceFirewall(state, command)
  expect(result.kind).toBe('applied')
  if (result.kind !== 'applied') throw new Error('expected applied transition')
  return result.state
}

function record(
  state: FirewallState,
  value: ReturnType<typeof observation>,
  newClaim = claimId(`claim-${value.id}`),
  now = value.observedAt,
  ttl = 300_000,
): FirewallState {
  return apply(state, {
    kind: 'record-observation',
    operationId: value.operationId,
    observation: value,
    newClaimId: newClaim,
    now,
    observationTtlMs: ttl,
    minIndependentSupporters: 2,
  })
}

function suspectedState(): FirewallState {
  return record(
    createEmptyState(),
    observation({ id: 'one', principal: 'a', at: t0, outcome: 'failure', failureCode: 'FS_NOT_FOUND' }),
    claimId('claim-a'),
  )
}

function corroboratedState(): FirewallState {
  return record(
    suspectedState(),
    observation({ id: 'two', principal: 'b', at: t1, outcome: 'failure', failureCode: 'FS_NOT_FOUND' }),
    claimId('unused'),
  )
}

function staleState(): FirewallState {
  return apply(corroboratedState(), {
    kind: 'invalidate-evidence',
    operationId: operationId('op-invalidate'),
    scope: '/workspace',
    fingerprint: fp,
    currentEvidence: changedEvidence,
    now: t2,
  })
}

function verifyingState(): { state: FirewallState; lease: VerificationLease } {
  const lease: VerificationLease = {
    id: leaseId('lease-a'),
    claimId: claimId('claim-a'),
    ownerPrincipalId: principalId('verifier'),
    evidenceEpoch: observation({
      id: 'temp',
      principal: 'verifier',
      at: t2,
      outcome: 'success',
      evidence: changedEvidence,
    }).evidenceEpoch,
    expiresAt: '2026-08-18T00:01:00.000Z',
  }
  return {
    lease,
    state: apply(staleState(), {
      kind: 'grant-lease',
      operationId: operationId('op-grant'),
      claimId: claimId('claim-a'),
      lease,
      now: t2,
    }),
  }
}

describe('Claim reducer', () => {
  it('creates a suspected Claim and one independent supporter on first structured failure', () => {
    const state = suspectedState()
    expect(state.observations).toHaveLength(1)
    expect(state.claims).toMatchObject([
      { id: 'claim-a', status: 'suspected', supporterCount: 1, revision: 1, isCurrent: true },
    ])
    expect(state.supporters).toMatchObject([{ claimId: 'claim-a', principalId: 'a' }])
    expect(state.events.map((event) => event.kind)).toEqual(['observation-recorded', 'claim-created'])
  })

  it('keeps repeated failures visible without giving one Principal another vote', () => {
    const state = record(
      suspectedState(),
      observation({ id: 'retry', principal: 'a', at: t1, outcome: 'failure', failureCode: 'FS_NOT_FOUND' }),
    )
    expect(state.observations).toHaveLength(2)
    expect(state.supporters).toHaveLength(1)
    expect(state.claims[0]).toMatchObject({ status: 'suspected', supporterCount: 1, revision: 1 })
  })

  it('corroborates at the independent-support threshold with one revision increment', () => {
    const state = corroboratedState()
    expect(state.supporters).toHaveLength(2)
    expect(state.claims[0]).toMatchObject({ status: 'corroborated', supporterCount: 2, revision: 2 })
    expect(state.events.at(-1)).toMatchObject({
      kind: 'claim-transition',
      from: 'suspected',
      to: 'corroborated',
      revision: 2,
    })
  })

  it('excludes support at the exact TTL deadline', () => {
    const state = record(
      suspectedState(),
      observation({ id: 'boundary', principal: 'b', at: t1, outcome: 'failure', failureCode: 'FS_NOT_FOUND' }),
      claimId('unused'),
      t1,
      1_000,
    )
    expect(state.supporters).toHaveLength(2)
    expect(state.claims[0]).toMatchObject({ status: 'suspected', supporterCount: 1, revision: 1 })
  })

  it('does not combine failures from different Evidence epochs', () => {
    const state = record(
      suspectedState(),
      observation({
        id: 'other-epoch',
        principal: 'b',
        at: t1,
        outcome: 'failure',
        failureCode: 'FS_NOT_FOUND',
        evidence: changedEvidence,
      }),
    )
    expect(state.claims[0]).toMatchObject({ status: 'suspected', supporterCount: 1, revision: 1 })
    expect(state.supporters).toHaveLength(1)
  })

  it('records an unstructured failure without creating or supporting a Claim', () => {
    const value = observation({ id: 'unknown', principal: 'a', at: t0, outcome: 'failure' })
    const state = record(createEmptyState(), value)
    expect(state.observations).toHaveLength(1)
    expect(state.claims).toHaveLength(0)
  })

  it('contradicts an active Claim on a matching success and leaves success-without-Claim alone', () => {
    const contradicted = record(
      corroboratedState(),
      observation({ id: 'success', principal: 'c', at: t2, outcome: 'success' }),
    )
    expect(contradicted.claims[0]).toMatchObject({ status: 'contradicted', revision: 3, isCurrent: true })

    const noClaim = record(
      createEmptyState(),
      observation({ id: 'success-only', principal: 'a', at: t0, outcome: 'success' }),
    )
    expect(noClaim.claims).toHaveLength(0)
    expect(noClaim.observations).toHaveLength(1)
  })

  it('supersedes a terminal current Claim only when a later structured failure arrives', () => {
    const contradicted = record(
      suspectedState(),
      observation({ id: 'success', principal: 'b', at: t1, outcome: 'success' }),
    )
    const state = record(
      contradicted,
      observation({ id: 'new-failure', principal: 'c', at: t2, outcome: 'failure', failureCode: 'FS_NOT_FOUND' }),
      claimId('claim-new'),
    )
    expect(state.claims).toMatchObject([
      { id: 'claim-a', status: 'superseded', revision: 3, isCurrent: false },
      { id: 'claim-new', status: 'suspected', revision: 1, isCurrent: true },
    ])
  })

  it('marks only active Claims stale for proven change and ignores unknown Evidence', () => {
    const unknown = apply(corroboratedState(), {
      kind: 'invalidate-evidence',
      operationId: operationId('op-unknown'),
      scope: '/workspace',
      fingerprint: fp,
      currentEvidence: [],
      now: t2,
    })
    expect(unknown.claims[0]).toMatchObject({ status: 'corroborated', revision: 2 })

    const stale = staleState()
    expect(stale.claims[0]).toMatchObject({ status: 'stale', revision: 3 })
  })

  it('grants one lease and rejects another active lease', () => {
    const { state } = verifyingState()
    expect(state.claims[0]).toMatchObject({ status: 'verifying', revision: 4 })
    expect(state.leases).toHaveLength(1)

    const result = reduceFirewall(state, {
      kind: 'grant-lease',
      operationId: operationId('op-race'),
      claimId: claimId('claim-a'),
      lease: { ...state.leases[0]!, id: leaseId('lease-b') },
      now: t2,
    })
    expect(result).toMatchObject({ kind: 'rejected', error: { code: 'INVARIANT_VIOLATION' } })
  })

  it.each(['released', 'expired'] as const)('returns verifying to stale when a lease is %s', (cause) => {
    const { state, lease } = verifyingState()
    const now = cause === 'expired' ? lease.expiresAt : t2
    const result = reduceFirewall(state, {
      kind: 'release-lease',
      operationId: operationId(`op-${cause}`),
      leaseId: lease.id,
      ...(cause === 'released' ? { ownerPrincipalId: lease.ownerPrincipalId } : {}),
      cause,
      now,
    })
    expect(result.kind).toBe('applied')
    if (result.kind === 'applied') {
      expect(result.claim).toMatchObject({ status: 'stale', revision: 5 })
      expect(result.lease).toMatchObject({ outcome: 'released', settledAt: now })
    }
  })

  it('rejects early expiry and release by a different owner', () => {
    const { state, lease } = verifyingState()
    expect(
      reduceFirewall(state, {
        kind: 'release-lease',
        operationId: operationId('op-early'),
        leaseId: lease.id,
        cause: 'expired',
        now: t2,
      }),
    ).toMatchObject({ kind: 'rejected', error: { code: 'INVARIANT_VIOLATION' } })
    expect(
      reduceFirewall(state, {
        kind: 'release-lease',
        operationId: operationId('op-wrong'),
        leaseId: lease.id,
        ownerPrincipalId: principalId('other'),
        cause: 'released',
        now: t2,
      }),
    ).toMatchObject({ kind: 'rejected', error: { code: 'LEASE_NOT_OWNER' } })
  })

  it('resolves the old Claim after successful verification', () => {
    const { state, lease } = verifyingState()
    const result = reduceFirewall(state, {
      kind: 'settle-lease',
      operationId: operationId('op-verify-success'),
      leaseId: lease.id,
      ownerPrincipalId: lease.ownerPrincipalId,
      observation: observation({
        id: 'verify-success',
        principal: 'verifier',
        at: '2026-08-18T00:00:03.000Z',
        outcome: 'success',
        evidence: changedEvidence,
      }),
      newClaimId: claimId('unused'),
      now: '2026-08-18T00:00:03.000Z',
    })
    expect(result.kind).toBe('applied')
    if (result.kind === 'applied') {
      expect(result.claim).toMatchObject({ status: 'resolved', revision: 5, isCurrent: true })
      expect(result.lease).toMatchObject({ outcome: 'success' })
    }
  })

  it('supersedes the old Claim and creates revision 1 after failed verification', () => {
    const { state, lease } = verifyingState()
    const result = reduceFirewall(state, {
      kind: 'settle-lease',
      operationId: operationId('op-verify-failure'),
      leaseId: lease.id,
      ownerPrincipalId: lease.ownerPrincipalId,
      observation: observation({
        id: 'verify-failure',
        principal: 'verifier',
        at: '2026-08-18T00:00:03.000Z',
        outcome: 'failure',
        failureCode: 'FS_NOT_FOUND',
        evidence: changedEvidence,
      }),
      newClaimId: claimId('claim-new-epoch'),
      now: '2026-08-18T00:00:03.000Z',
    })
    expect(result.kind).toBe('applied')
    if (result.kind === 'applied') {
      expect(result.state.claims).toMatchObject([
        { id: 'claim-a', status: 'superseded', revision: 5, isCurrent: false },
        { id: 'claim-new-epoch', status: 'suspected', revision: 1, supporterCount: 1, isCurrent: true },
      ])
      expect(result.state.supporters.at(-1)).toMatchObject({
        claimId: 'claim-new-epoch',
        principalId: 'verifier',
      })
    }
  })

  it('returns typed owner and expiry errors during settlement', () => {
    const { state, lease } = verifyingState()
    const value = observation({
      id: 'verify',
      principal: 'verifier',
      at: t2,
      outcome: 'success',
      evidence: changedEvidence,
    })
    expect(
      reduceFirewall(state, {
        kind: 'settle-lease',
        operationId: value.operationId,
        leaseId: lease.id,
        ownerPrincipalId: principalId('other'),
        observation: value,
        newClaimId: claimId('unused'),
        now: t2,
      }),
    ).toMatchObject({ kind: 'rejected', error: { code: 'LEASE_NOT_OWNER' } })
    expect(
      reduceFirewall(state, {
        kind: 'settle-lease',
        operationId: value.operationId,
        leaseId: lease.id,
        ownerPrincipalId: lease.ownerPrincipalId,
        observation: value,
        newClaimId: claimId('unused'),
        now: lease.expiresAt,
      }),
    ).toMatchObject({ kind: 'rejected', error: { code: 'LEASE_EXPIRED' } })
  })

  it('makes duplicate Observation delivery a no-op', () => {
    const first = observation({ id: 'one', principal: 'a', at: t0, outcome: 'failure', failureCode: 'FS_NOT_FOUND' })
    const state = record(createEmptyState(), first, claimId('claim-a'))
    const result = reduceFirewall(state, {
      kind: 'record-observation',
      operationId: first.operationId,
      observation: first,
      newClaimId: claimId('other'),
      now: t0,
      observationTtlMs: 300_000,
      minIndependentSupporters: 2,
    })
    expect(result).toMatchObject({ kind: 'duplicate', events: [] })
    expect(result.state).toEqual(state)
  })
})

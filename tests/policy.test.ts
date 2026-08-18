import { describe, expect, it } from 'vitest'

import { evidenceEpoch } from '../src/evidence.ts'
import {
  actionPolicyEnforced,
  mapDeploymentPolicy,
  recommendPolicy,
  type PolicyRecommendation,
} from '../src/policy.ts'
import type { ClaimSupporter, PolicyRequest } from '../src/store.ts'
import type { Claim, EvidenceWitness, VerificationLease } from '../src/types/domain.ts'
import { claimId, fp, leaseId, principalId } from './helpers.ts'

const now = '2026-08-18T00:00:10.000Z'
const matchingEvidence: EvidenceWitness[] = [{ kind: 'file-state', key: '/target', state: 'absent' }]
const changedEvidence: EvidenceWitness[] = [
  { kind: 'file-state', key: '/target', state: 'present', version: 'v1' },
]

function claim(status: Claim['status'], evidence = matchingEvidence): Claim {
  return {
    id: claimId('claim-a'),
    scope: '/workspace',
    actionKind: 'file-read',
    fingerprint: fp,
    evidenceEpoch: evidenceEpoch(evidence),
    evidence,
    preview: 'read /target',
    status,
    supporterCount: 2,
    revision: 2,
    isCurrent: status !== 'superseded',
    createdAt: '2026-08-18T00:00:00.000Z',
    updatedAt: '2026-08-18T00:00:01.000Z',
  }
}

const supporters: ClaimSupporter[] = [
  { claimId: claimId('claim-a'), principalId: principalId('a'), lastObservedAt: '2026-08-18T00:00:08.000Z' },
  { claimId: claimId('claim-a'), principalId: principalId('b'), lastObservedAt: '2026-08-18T00:00:09.000Z' },
]

function request(overrides: Partial<PolicyRequest> = {}): PolicyRequest {
  return {
    claim: claim('corroborated'),
    supporters,
    currentEvidence: matchingEvidence,
    principalId: principalId('requester'),
    now,
    observationTtlMs: 5_000,
    minIndependentSupporters: 2,
    ...overrides,
  }
}

describe('pure policy recommendation', () => {
  it.each([
    [{ claim: undefined }, { kind: 'allow', reason: 'no-claim' }],
    [{ claim: claim('suspected') }, { kind: 'warn', reason: 'suspected', claimId: 'claim-a' }],
    [{ claim: claim('corroborated') }, { kind: 'deny', reason: 'corroborated', claimId: 'claim-a' }],
    [{ claim: claim('contradicted') }, { kind: 'allow', reason: 'counterexample', claimId: 'claim-a' }],
    [{ claim: claim('resolved') }, { kind: 'allow', reason: 'counterexample', claimId: 'claim-a' }],
  ])('maps a Claim state to its unique recommendation %#', (overrides, expected) => {
    expect(recommendPolicy(request(overrides as Partial<PolicyRequest>))).toEqual(expected)
  })

  it('caps an evidence-free corroborated Claim at warn/evidence-unavailable', () => {
    expect(recommendPolicy(request({ claim: claim('corroborated', []), currentEvidence: [] }))).toEqual({
      kind: 'warn',
      reason: 'evidence-unavailable',
      claimId: 'claim-a',
    })
  })

  it('treats missing current Evidence as unavailable rather than changed', () => {
    expect(recommendPolicy(request({ currentEvidence: [] }))).toMatchObject({
      kind: 'warn',
      reason: 'evidence-unavailable',
    })
  })

  it('recommends verification when Evidence changed and wait for another active owner', () => {
    expect(recommendPolicy(request({ currentEvidence: changedEvidence }))).toMatchObject({
      kind: 'verify',
      reason: 'evidence-changed',
    })

    const lease: VerificationLease = {
      id: leaseId('lease-a'),
      claimId: claimId('claim-a'),
      ownerPrincipalId: principalId('owner'),
      evidenceEpoch: evidenceEpoch(changedEvidence),
      expiresAt: '2026-08-18T00:01:00.000Z',
    }
    expect(recommendPolicy(request({ claim: claim('verifying'), currentEvidence: changedEvidence, activeLease: lease }))).toEqual({
      kind: 'wait',
      reason: 'verification-in-progress',
      claimId: 'claim-a',
      owner: 'owner',
      expiresAt: lease.expiresAt,
    })
    expect(
      recommendPolicy(
        request({
          claim: claim('verifying'),
          currentEvidence: changedEvidence,
          activeLease: lease,
          principalId: principalId('owner'),
        }),
      ),
    ).toEqual({ kind: 'verify', reason: 'evidence-changed', claimId: 'claim-a', leaseId: 'lease-a' })
  })

  it('excludes TTL-expired supporters from a corroborated enforcement decision', () => {
    expect(
      recommendPolicy(
        request({
          supporters: supporters.map((supporter) => ({
            ...supporter,
            lastObservedAt: '2026-08-18T00:00:05.000Z',
          })),
        }),
      ),
    ).toEqual({ kind: 'warn', reason: 'suspected', claimId: 'claim-a' })
  })
})

describe('deployment mapping', () => {
  const deny: PolicyRecommendation = { kind: 'deny', reason: 'corroborated', claimId: claimId('claim-a') }
  const wait: PolicyRecommendation = {
    kind: 'wait',
    reason: 'verification-in-progress',
    claimId: claimId('claim-a'),
    owner: principalId('owner'),
    expiresAt: '2026-08-18T00:01:00.000Z',
  }

  it('observe executes every recommendation and never acquires a policy lease', () => {
    expect(
      mapDeploymentPolicy(
        { kind: 'verify', reason: 'evidence-changed', claimId: claimId('claim-a') },
        { mode: 'observe', actionKind: 'file-read', enforce: true },
      ),
    ).toMatchObject({ decision: { kind: 'allow', reason: 'observe-mode' }, shouldAcquireLease: false })
  })

  it('warn executes deny and wait recommendations as stable warnings', () => {
    expect(mapDeploymentPolicy(deny, { mode: 'warn', actionKind: 'file-read', enforce: true }).decision).toEqual({
      kind: 'warn',
      reason: 'corroborated',
      claimId: 'claim-a',
    })
    expect(mapDeploymentPolicy(wait, { mode: 'warn', actionKind: 'file-read', enforce: true }).decision).toEqual({
      kind: 'warn',
      reason: 'verification-in-progress',
      claimId: 'claim-a',
    })
  })

  it('enforce keeps corroborated denial and verification wait semantically distinct', () => {
    const denied = mapDeploymentPolicy(deny, { mode: 'enforce', actionKind: 'file-read', enforce: true })
    const waiting = mapDeploymentPolicy(wait, { mode: 'enforce', actionKind: 'file-read', enforce: true })
    expect(denied.decision.kind).toBe('deny')
    expect(waiting.decision.kind).toBe('wait')
    expect(denied.decision.kind).not.toBe(waiting.decision.kind)
  })

  it('maps a non-enforced action kind exactly like warn mode', () => {
    expect(mapDeploymentPolicy(deny, { mode: 'enforce', actionKind: 'command', enforce: false }).decision.kind).toBe(
      'warn',
    )
  })

  it('requests a lease before enforce verification and allows its owner after grant', () => {
    const verify: PolicyRecommendation = { kind: 'verify', reason: 'evidence-changed', claimId: claimId('claim-a') }
    expect(
      mapDeploymentPolicy(verify, { mode: 'enforce', actionKind: 'file-read', enforce: true }),
    ).toMatchObject({ decision: { kind: 'warn', reason: 'evidence-changed' }, shouldAcquireLease: true })
    expect(
      mapDeploymentPolicy(verify, {
        mode: 'enforce',
        actionKind: 'file-read',
        enforce: true,
        grantedLeaseId: leaseId('lease-a'),
      }).decision,
    ).toEqual({ kind: 'verify', reason: 'evidence-changed', claimId: 'claim-a', leaseId: 'lease-a' })
  })

  it('reads action enforcement flags symmetrically', () => {
    const config = { policies: { command: { enforce: false }, 'file-read': { enforce: true } } }
    expect(actionPolicyEnforced(config, 'command')).toBe(false)
    expect(actionPolicyEnforced(config, 'file-read')).toBe(true)
  })
})

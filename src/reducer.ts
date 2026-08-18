import { canonicalizeEvidence, compareEvidence, evidenceEpoch } from './evidence.ts'
import type {
  ClaimSupporter,
  FirewallState,
  GrantLeaseCommand,
  PureAuditEvent,
  RecordObservationCommand,
  ReducerCommand,
  ReducerResult,
  ReleaseLeaseCommand,
  SettleLeaseCommand,
} from './store.ts'
import type { Claim, ClaimId, Observation, VerificationLease } from './types/domain.ts'
import { assertNever, FirewallError } from './types/errors.ts'
import { parseUtcIso } from './types/time.ts'

function rejected(state: FirewallState, code: ConstructorParameters<typeof FirewallError>[0], message: string): ReducerResult {
  return { kind: 'rejected', state, events: [], error: new FirewallError(code, message) }
}

function withEvents(
  state: FirewallState,
  events: PureAuditEvent[],
  extras: { claim?: Claim; lease?: VerificationLease } = {},
): ReducerResult {
  return {
    kind: 'applied',
    state: { ...state, events: [...state.events, ...events] },
    events,
    ...extras,
  }
}

function currentClaim(state: FirewallState, scope: string, fingerprint: string): Claim | undefined {
  return state.claims.find((claim) => claim.isCurrent && claim.scope === scope && claim.fingerprint === fingerprint)
}

function activeLeaseForClaim(state: FirewallState, claimId: ClaimId): VerificationLease | undefined {
  return state.leases.find((lease) => lease.claimId === claimId && lease.outcome === undefined)
}

function replaceClaim(state: FirewallState, replacement: Claim): FirewallState {
  return {
    ...state,
    claims: state.claims.map((claim) => (claim.id === replacement.id ? replacement : claim)),
  }
}

function assertObservationEvidence(observation: Observation): void {
  if (evidenceEpoch(observation.evidence) !== observation.evidenceEpoch) {
    throw new FirewallError('INVARIANT_VIOLATION', 'Observation Evidence does not match its epoch.')
  }
}

function observationEvent(observation: Observation, claimId: ClaimId | undefined): PureAuditEvent {
  return {
    kind: 'observation-recorded',
    operationId: observation.operationId,
    observationId: observation.id,
    ...(claimId === undefined ? {} : { claimId }),
    outcome: observation.outcome,
    occurredAt: observation.observedAt,
  }
}

function createClaim(observation: Observation, claimId: ClaimId): Claim {
  return {
    id: claimId,
    scope: observation.scope,
    actionKind: observation.actionKind,
    fingerprint: observation.fingerprint,
    evidenceEpoch: observation.evidenceEpoch,
    evidence: canonicalizeEvidence(observation.evidence),
    preview: observation.preview,
    status: 'suspected',
    supporterCount: 1,
    revision: 1,
    isCurrent: true,
    createdAt: observation.observedAt,
    updatedAt: observation.observedAt,
  }
}

function createClaimEvents(observation: Observation, claim: Claim): PureAuditEvent[] {
  return [
    observationEvent(observation, claim.id),
    {
      kind: 'claim-created',
      operationId: observation.operationId,
      claimId: claim.id,
      to: 'suspected',
      revision: 1,
      occurredAt: observation.observedAt,
    },
  ]
}

function activeSupporterCount(supporters: readonly ClaimSupporter[], claimId: ClaimId, now: string, ttlMs: number): number {
  const nowMs = parseUtcIso(now)
  return supporters.filter(
    (supporter) => supporter.claimId === claimId && parseUtcIso(supporter.lastObservedAt) + ttlMs > nowMs,
  ).length
}

function appendObservation(state: FirewallState, observation: Observation): FirewallState {
  return { ...state, observations: [...state.observations, observation] }
}

function recordObservation(state: FirewallState, command: RecordObservationCommand): ReducerResult {
  const { observation } = command
  if (observation.operationId !== command.operationId) {
    return rejected(state, 'INVARIANT_VIOLATION', 'Observation operation ID must match the reducer command.')
  }
  if (
    state.observations.some(
      (candidate) => candidate.id === observation.id || candidate.operationId === observation.operationId,
    )
  ) {
    return { kind: 'duplicate', state, events: [] }
  }
  try {
    assertObservationEvidence(observation)
    parseUtcIso(command.now)
    parseUtcIso(observation.observedAt)
  } catch (error) {
    return error instanceof FirewallError
      ? { kind: 'rejected', state, events: [], error }
      : rejected(state, 'INVARIANT_VIOLATION', 'Observation validation failed.')
  }

  let next = appendObservation(state, observation)
  const claim = currentClaim(state, observation.scope, observation.fingerprint)

  if (observation.outcome === 'success') {
    if (
      claim !== undefined &&
      claim.evidenceEpoch === observation.evidenceEpoch &&
      (claim.status === 'suspected' || claim.status === 'corroborated')
    ) {
      const updated: Claim = {
        ...claim,
        status: 'contradicted',
        revision: claim.revision + 1,
        updatedAt: command.now,
      }
      next = replaceClaim(next, updated)
      const events: PureAuditEvent[] = [
        observationEvent(observation, claim.id),
        {
          kind: 'claim-transition',
          operationId: command.operationId,
          claimId: claim.id,
          from: claim.status,
          to: 'contradicted',
          revision: updated.revision,
          occurredAt: command.now,
        },
      ]
      return withEvents(next, events, { claim: updated })
    }
    return withEvents(next, [observationEvent(observation, claim?.id)])
  }

  if (observation.failureCode === undefined) {
    return withEvents(next, [observationEvent(observation, claim?.id)])
  }

  if (claim === undefined) {
    const created = createClaim(observation, command.newClaimId)
    next = {
      ...next,
      claims: [...next.claims, created],
      supporters: [
        ...next.supporters,
        { claimId: created.id, principalId: observation.principalId, lastObservedAt: observation.observedAt },
      ],
    }
    return withEvents(next, createClaimEvents(observation, created), { claim: created })
  }

  if (claim.status === 'contradicted' || claim.status === 'resolved') {
    const superseded: Claim = {
      ...claim,
      status: 'superseded',
      revision: claim.revision + 1,
      isCurrent: false,
      updatedAt: command.now,
    }
    const created = createClaim(observation, command.newClaimId)
    next = replaceClaim(next, superseded)
    next = {
      ...next,
      claims: [...next.claims, created],
      supporters: [
        ...next.supporters,
        { claimId: created.id, principalId: observation.principalId, lastObservedAt: observation.observedAt },
      ],
    }
    const events: PureAuditEvent[] = [
      observationEvent(observation, created.id),
      {
        kind: 'claim-transition',
        operationId: command.operationId,
        claimId: claim.id,
        from: claim.status,
        to: 'superseded',
        revision: superseded.revision,
        occurredAt: command.now,
      },
      {
        kind: 'claim-created',
        operationId: command.operationId,
        claimId: created.id,
        to: 'suspected',
        revision: 1,
        occurredAt: command.now,
      },
    ]
    return withEvents(next, events, { claim: created })
  }

  if (claim.evidenceEpoch !== observation.evidenceEpoch) {
    return withEvents(next, [observationEvent(observation, claim.id)], { claim })
  }

  const existingSupporter = next.supporters.find(
    (supporter) => supporter.claimId === claim.id && supporter.principalId === observation.principalId,
  )
  next = {
    ...next,
    supporters:
      existingSupporter === undefined
        ? [
            ...next.supporters,
            { claimId: claim.id, principalId: observation.principalId, lastObservedAt: observation.observedAt },
          ]
        : next.supporters.map((supporter) =>
            supporter === existingSupporter ? { ...supporter, lastObservedAt: observation.observedAt } : supporter,
          ),
  }
  const supporterCount = activeSupporterCount(next.supporters, claim.id, command.now, command.observationTtlMs)
  const status =
    claim.status === 'suspected' && supporterCount >= command.minIndependentSupporters
      ? ('corroborated' as const)
      : claim.status
  const claimChanged = supporterCount !== claim.supporterCount || status !== claim.status
  if (!claimChanged) {
    return withEvents(next, [observationEvent(observation, claim.id)], { claim })
  }

  const updated: Claim = {
    ...claim,
    supporterCount,
    status,
    revision: claim.revision + 1,
    updatedAt: command.now,
  }
  next = replaceClaim(next, updated)
  const events: PureAuditEvent[] = [observationEvent(observation, claim.id)]
  if (status !== claim.status) {
    events.push({
      kind: 'claim-transition',
      operationId: command.operationId,
      claimId: claim.id,
      from: claim.status,
      to: status,
      revision: updated.revision,
      occurredAt: command.now,
    })
  } else {
    events.push({
      kind: 'claim-support-changed',
      operationId: command.operationId,
      claimId: claim.id,
      supporterCount,
      revision: updated.revision,
      occurredAt: command.now,
    })
  }
  return withEvents(next, events, { claim: updated })
}

function invalidateEvidence(state: FirewallState, command: Extract<ReducerCommand, { kind: 'invalidate-evidence' }>): ReducerResult {
  const claim = currentClaim(state, command.scope, command.fingerprint)
  if (claim === undefined || !['suspected', 'corroborated'].includes(claim.status)) {
    return withEvents(state, [])
  }
  try {
    if (compareEvidence(claim.evidence, command.currentEvidence) !== 'changed') return withEvents(state, [])
  } catch (error) {
    return error instanceof FirewallError
      ? { kind: 'rejected', state, events: [], error }
      : rejected(state, 'INVARIANT_VIOLATION', 'Evidence comparison failed.')
  }
  const updated: Claim = {
    ...claim,
    status: 'stale',
    revision: claim.revision + 1,
    updatedAt: command.now,
  }
  const next = replaceClaim(state, updated)
  const event: PureAuditEvent = {
    kind: 'claim-transition',
    operationId: command.operationId,
    claimId: claim.id,
    from: claim.status,
    to: 'stale',
    revision: updated.revision,
    occurredAt: command.now,
  }
  return withEvents(next, [event], { claim: updated })
}

function grantLease(state: FirewallState, command: GrantLeaseCommand): ReducerResult {
  const claim = state.claims.find((candidate) => candidate.id === command.claimId && candidate.isCurrent)
  if (claim === undefined) return rejected(state, 'CLAIM_NOT_FOUND', 'Verification requires a current Claim.')
  if (claim.status !== 'stale') {
    return rejected(state, 'INVARIANT_VIOLATION', 'Only a stale Claim may grant a verification lease.')
  }
  if (command.lease.claimId !== claim.id || command.lease.outcome !== undefined) {
    return rejected(state, 'INVARIANT_VIOLATION', 'A new verification lease must be unsettled and target the Claim.')
  }
  if (activeLeaseForClaim(state, claim.id) !== undefined) {
    return rejected(state, 'REVISION_CONFLICT', 'The Claim already has an active verification lease.')
  }
  if (parseUtcIso(command.lease.expiresAt) <= parseUtcIso(command.now)) {
    return rejected(state, 'LEASE_EXPIRED', 'A verification lease must expire after it is granted.')
  }

  const updated: Claim = {
    ...claim,
    status: 'verifying',
    revision: claim.revision + 1,
    updatedAt: command.now,
  }
  let next = replaceClaim(state, updated)
  next = { ...next, leases: [...next.leases, { ...command.lease }] }
  const events: PureAuditEvent[] = [
    {
      kind: 'claim-transition',
      operationId: command.operationId,
      claimId: claim.id,
      from: 'stale',
      to: 'verifying',
      revision: updated.revision,
      occurredAt: command.now,
    },
    {
      kind: 'lease-granted',
      operationId: command.operationId,
      claimId: claim.id,
      leaseId: command.lease.id,
      ownerPrincipalId: command.lease.ownerPrincipalId,
      occurredAt: command.now,
    },
  ]
  return withEvents(next, events, { claim: updated, lease: command.lease })
}

function settleLease(state: FirewallState, command: SettleLeaseCommand): ReducerResult {
  const lease = state.leases.find((candidate) => candidate.id === command.leaseId && candidate.outcome === undefined)
  if (lease === undefined) return rejected(state, 'INVARIANT_VIOLATION', 'Verification lease is missing or already settled.')
  if (parseUtcIso(lease.expiresAt) <= parseUtcIso(command.now)) {
    return rejected(state, 'LEASE_EXPIRED', 'Verification lease expired before settlement.')
  }
  if (lease.ownerPrincipalId !== command.ownerPrincipalId) {
    return rejected(state, 'LEASE_NOT_OWNER', 'Only the verification lease owner may settle it.')
  }
  const claim = state.claims.find((candidate) => candidate.id === lease.claimId && candidate.isCurrent)
  if (claim === undefined || claim.status !== 'verifying') {
    return rejected(state, 'INVARIANT_VIOLATION', 'Verification settlement requires a current verifying Claim.')
  }
  const { observation } = command
  if (
    observation.operationId !== command.operationId ||
    observation.principalId !== command.ownerPrincipalId ||
    observation.evidenceEpoch !== lease.evidenceEpoch ||
    observation.scope !== claim.scope ||
    observation.fingerprint !== claim.fingerprint
  ) {
    return rejected(state, 'INVARIANT_VIOLATION', 'Verification Observation must match its operation, owner, Claim, and lease Evidence.')
  }
  if (state.observations.some((candidate) => candidate.id === observation.id || candidate.operationId === command.operationId)) {
    return { kind: 'duplicate', state, events: [] }
  }
  try {
    assertObservationEvidence(observation)
  } catch (error) {
    return error instanceof FirewallError
      ? { kind: 'rejected', state, events: [], error }
      : rejected(state, 'INVARIANT_VIOLATION', 'Verification Observation validation failed.')
  }

  const settledLease: VerificationLease = {
    ...lease,
    outcome: observation.outcome,
    settledAt: command.now,
  }
  let next: FirewallState = {
    ...state,
    observations: [...state.observations, observation],
    leases: state.leases.map((candidate) => (candidate.id === lease.id ? settledLease : candidate)),
  }

  if (observation.outcome === 'success') {
    const resolved: Claim = {
      ...claim,
      status: 'resolved',
      revision: claim.revision + 1,
      updatedAt: command.now,
    }
    next = replaceClaim(next, resolved)
    const events: PureAuditEvent[] = [
      observationEvent(observation, claim.id),
      {
        kind: 'lease-settled',
        operationId: command.operationId,
        claimId: claim.id,
        leaseId: lease.id,
        outcome: 'success',
        occurredAt: command.now,
      },
      {
        kind: 'claim-transition',
        operationId: command.operationId,
        claimId: claim.id,
        from: 'verifying',
        to: 'resolved',
        revision: resolved.revision,
        occurredAt: command.now,
      },
    ]
    return withEvents(next, events, { claim: resolved, lease: settledLease })
  }

  if (observation.failureCode === undefined) {
    return rejected(state, 'INVARIANT_VIOLATION', 'Verification failure requires a structured failure code.')
  }
  const superseded: Claim = {
    ...claim,
    status: 'superseded',
    revision: claim.revision + 1,
    isCurrent: false,
    updatedAt: command.now,
  }
  const replacement = createClaim(observation, command.newClaimId)
  next = replaceClaim(next, superseded)
  next = {
    ...next,
    claims: [...next.claims, replacement],
    supporters: [
      ...next.supporters,
      { claimId: replacement.id, principalId: observation.principalId, lastObservedAt: observation.observedAt },
    ],
  }
  const events: PureAuditEvent[] = [
    observationEvent(observation, replacement.id),
    {
      kind: 'lease-settled',
      operationId: command.operationId,
      claimId: claim.id,
      leaseId: lease.id,
      outcome: 'failure',
      occurredAt: command.now,
    },
    {
      kind: 'claim-transition',
      operationId: command.operationId,
      claimId: claim.id,
      from: 'verifying',
      to: 'superseded',
      revision: superseded.revision,
      occurredAt: command.now,
    },
    {
      kind: 'claim-created',
      operationId: command.operationId,
      claimId: replacement.id,
      to: 'suspected',
      revision: 1,
      occurredAt: command.now,
    },
  ]
  return withEvents(next, events, { claim: replacement, lease: settledLease })
}

function releaseLease(state: FirewallState, command: ReleaseLeaseCommand): ReducerResult {
  const lease = state.leases.find((candidate) => candidate.id === command.leaseId && candidate.outcome === undefined)
  if (lease === undefined) return rejected(state, 'INVARIANT_VIOLATION', 'Verification lease is missing or already settled.')
  const nowMs = parseUtcIso(command.now)
  const expiryMs = parseUtcIso(lease.expiresAt)
  if (command.cause === 'expired') {
    if (nowMs < expiryMs) return rejected(state, 'INVARIANT_VIOLATION', 'A live verification lease cannot expire early.')
  } else if (command.ownerPrincipalId !== lease.ownerPrincipalId) {
    return rejected(state, 'LEASE_NOT_OWNER', 'Only the verification lease owner may release it.')
  }
  const claim = state.claims.find((candidate) => candidate.id === lease.claimId && candidate.isCurrent)
  if (claim === undefined || claim.status !== 'verifying') {
    return rejected(state, 'INVARIANT_VIOLATION', 'Lease release requires a current verifying Claim.')
  }
  const settledLease: VerificationLease = { ...lease, outcome: 'released', settledAt: command.now }
  const stale: Claim = {
    ...claim,
    status: 'stale',
    revision: claim.revision + 1,
    updatedAt: command.now,
  }
  let next = replaceClaim(state, stale)
  next = {
    ...next,
    leases: next.leases.map((candidate) => (candidate.id === lease.id ? settledLease : candidate)),
  }
  const events: PureAuditEvent[] = [
    {
      kind: 'lease-settled',
      operationId: command.operationId,
      claimId: claim.id,
      leaseId: lease.id,
      outcome: command.cause,
      occurredAt: command.now,
    },
    {
      kind: 'claim-transition',
      operationId: command.operationId,
      claimId: claim.id,
      from: 'verifying',
      to: 'stale',
      revision: stale.revision,
      occurredAt: command.now,
    },
  ]
  return withEvents(next, events, { claim: stale, lease: settledLease })
}

/**
 * Apply one deterministic state command without I/O, clocks, or ID generation.
 * @param state - Complete prior snapshot.
 * @param command - Explicit transition command.
 * @returns New snapshot, emitted events, or a typed rejected result.
 */
export function reduceFirewall(state: FirewallState, command: ReducerCommand): ReducerResult {
  switch (command.kind) {
    case 'record-observation':
      return recordObservation(state, command)
    case 'invalidate-evidence':
      return invalidateEvidence(state, command)
    case 'grant-lease':
      return grantLease(state, command)
    case 'settle-lease':
      return settleLease(state, command)
    case 'release-lease':
      return releaseLease(state, command)
    default:
      return assertNever(command)
  }
}

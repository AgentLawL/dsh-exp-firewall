import type { Config, DeploymentMode } from './config.ts'
import { compareEvidence } from './evidence.ts'
import type { ClaimSupporter, PolicyRequest } from './store.ts'
import type {
  ActionKind,
  ClaimId,
  Decision,
  LeaseId,
  PrincipalId,
} from './types/domain.ts'
import { assertNever, FirewallError } from './types/errors.ts'
import { parseUtcIso } from './types/time.ts'

/** Pure recommendation before deployment mode changes execution behavior. */
export type PolicyRecommendation =
  | { kind: 'allow'; reason: 'no-claim' | 'counterexample'; claimId?: ClaimId }
  | { kind: 'warn'; reason: 'suspected' | 'evidence-unavailable'; claimId: ClaimId }
  | { kind: 'deny'; reason: 'corroborated'; claimId: ClaimId }
  | { kind: 'verify'; reason: 'evidence-changed'; claimId: ClaimId; leaseId?: LeaseId }
  | {
      kind: 'wait'
      reason: 'verification-in-progress'
      claimId: ClaimId
      owner: PrincipalId
      expiresAt: string
    }

/** Deployment mapping output preserving the original recommendation. */
export interface PolicyEvaluation {
  recommendation: PolicyRecommendation
  decision: Decision
  shouldAcquireLease: boolean
}

/** Inputs needed to map a recommendation to an executable Decision. */
export interface DeploymentPolicyInput {
  mode: DeploymentMode
  actionKind: ActionKind
  enforce: boolean
  grantedLeaseId?: LeaseId
}

/**
 * Count non-expired independent supporters at decision time.
 * @param supporters - Deduplicated supporter rows.
 * @param claimId - Claim being evaluated.
 * @param now - Explicit UTC decision time.
 * @param ttlMs - Observation support lifetime.
 * @returns Current independent supporter count.
 */
export function countActiveSupporters(
  supporters: readonly ClaimSupporter[],
  claimId: ClaimId,
  now: string,
  ttlMs: number,
): number {
  const nowMs = parseUtcIso(now)
  return new Set(
    supporters
      .filter((supporter) => supporter.claimId === claimId && parseUtcIso(supporter.lastObservedAt) + ttlMs > nowMs)
      .map((supporter) => supporter.principalId),
  ).size
}

/**
 * Evaluate the normative recommendation table without acquiring a lease.
 * @param request - Claim, Evidence, support, lease, principal, and explicit time.
 * @returns One unique recommendation.
 */
export function recommendPolicy(request: PolicyRequest): PolicyRecommendation {
  const { claim } = request
  if (claim === undefined) return { kind: 'allow', reason: 'no-claim' }
  if (claim.status === 'contradicted' || claim.status === 'resolved' || claim.status === 'superseded') {
    return { kind: 'allow', reason: 'counterexample', claimId: claim.id }
  }

  const evidenceRelation = compareEvidence(claim.evidence, request.currentEvidence)
  if (evidenceRelation === 'unknown') {
    return { kind: 'warn', reason: 'evidence-unavailable', claimId: claim.id }
  }

  const lease = request.activeLease
  const leaseIsActive = lease !== undefined && lease.outcome === undefined && parseUtcIso(lease.expiresAt) > parseUtcIso(request.now)
  const requiresVerification =
    evidenceRelation === 'changed' || claim.status === 'stale' || claim.status === 'verifying'
  if (requiresVerification) {
    if (leaseIsActive && lease.ownerPrincipalId !== request.principalId) {
      return {
        kind: 'wait',
        reason: 'verification-in-progress',
        claimId: claim.id,
        owner: lease.ownerPrincipalId,
        expiresAt: lease.expiresAt,
      }
    }
    return {
      kind: 'verify',
      reason: 'evidence-changed',
      claimId: claim.id,
      ...(leaseIsActive ? { leaseId: lease.id } : {}),
    }
  }

  switch (claim.status) {
    case 'suspected':
      return { kind: 'warn', reason: 'suspected', claimId: claim.id }
    case 'corroborated': {
      const supporterCount = countActiveSupporters(
        request.supporters,
        claim.id,
        request.now,
        request.observationTtlMs,
      )
      return supporterCount >= request.minIndependentSupporters
        ? { kind: 'deny', reason: 'corroborated', claimId: claim.id }
        : { kind: 'warn', reason: 'suspected', claimId: claim.id }
    }
    case 'stale':
    case 'verifying':
      throw new FirewallError('INVARIANT_VIOLATION', 'Verification status must produce a verification recommendation.')
    default:
      return assertNever(claim.status)
  }
}

function effectiveMode(input: DeploymentPolicyInput): DeploymentMode {
  return input.mode === 'enforce' && !input.enforce ? 'warn' : input.mode
}

function warnDecision(recommendation: PolicyRecommendation): Decision {
  switch (recommendation.kind) {
    case 'allow':
      return recommendation
    case 'warn':
      return recommendation
    case 'deny':
      return { kind: 'warn', reason: 'corroborated', claimId: recommendation.claimId }
    case 'verify':
      return { kind: 'warn', reason: 'evidence-changed', claimId: recommendation.claimId }
    case 'wait':
      return { kind: 'warn', reason: 'verification-in-progress', claimId: recommendation.claimId }
    default:
      return assertNever(recommendation)
  }
}

/**
 * Map a recommendation through observe, warn, or enforce deployment behavior.
 * @param recommendation - Normative pure recommendation.
 * @param input - Mode, action policy, and optional newly granted lease.
 * @returns Executable Decision plus lease-acquisition intent.
 */
export function mapDeploymentPolicy(
  recommendation: PolicyRecommendation,
  input: DeploymentPolicyInput,
): PolicyEvaluation {
  const mode = effectiveMode(input)
  if (mode === 'observe') {
    return {
      recommendation,
      decision: {
        kind: 'allow',
        reason: recommendation.kind === 'allow' ? recommendation.reason : 'observe-mode',
        ...('claimId' in recommendation && recommendation.claimId !== undefined
          ? { claimId: recommendation.claimId }
          : {}),
      },
      shouldAcquireLease: false,
    }
  }
  if (mode === 'warn') {
    return { recommendation, decision: warnDecision(recommendation), shouldAcquireLease: false }
  }

  switch (recommendation.kind) {
    case 'allow':
    case 'warn':
    case 'deny':
    case 'wait':
      return { recommendation, decision: recommendation, shouldAcquireLease: false }
    case 'verify': {
      const leaseId = recommendation.leaseId ?? input.grantedLeaseId
      if (leaseId === undefined) {
        return {
          recommendation,
          decision: { kind: 'warn', reason: 'evidence-changed', claimId: recommendation.claimId },
          shouldAcquireLease: true,
        }
      }
      return {
        recommendation,
        decision: {
          kind: 'verify',
          reason: 'evidence-changed',
          claimId: recommendation.claimId,
          leaseId,
        },
        shouldAcquireLease: false,
      }
    }
    default:
      return assertNever(recommendation)
  }
}

/**
 * Read the action-kind enforcement flag from validated configuration.
 * @param config - Fully resolved configuration.
 * @param actionKind - Supported action kind.
 * @returns Whether enforce mode may suppress the action.
 */
export function actionPolicyEnforced(config: Pick<Config, 'policies'>, actionKind: ActionKind): boolean {
  switch (actionKind) {
    case 'command':
      return config.policies.command.enforce
    case 'file-read':
      return config.policies['file-read'].enforce
    default:
      return assertNever(actionKind)
  }
}

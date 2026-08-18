import type { Config } from './config.ts'
import { actionPolicyEnforced, mapDeploymentPolicy, recommendPolicy, type PolicyEvaluation } from './policy.ts'
import { reduceFirewall } from './reducer.ts'
import type {
  DecisionRequest,
  FirewallState,
  PureAuditEvent,
  RecordObservationRequest,
  ReducerCommand,
  ReducerResult,
  SettleLeaseRequest,
} from './store.ts'
import { createEmptyState } from './store.ts'
import type { Claim, VerificationLease } from './types/domain.ts'
import { FirewallError } from './types/errors.ts'

/** Deterministic scenario projection for tests and demos. */
export interface MemoryScenarioSnapshot {
  claims: Claim[]
  decisions: PolicyEvaluation[]
  events: PureAuditEvent[]
}

/**
 * In-memory driver for the pure reducer and policy functions.
 *
 * It is intentionally not the durable Service implementation: it owns no
 * clock, ID generator, retries, or I/O and exists only for M0 tests and demos.
 */
export class MemoryStore {
  readonly #config: Pick<Config, 'mode' | 'minIndependentSupporters' | 'observationTtlMs' | 'policies'>
  #state: FirewallState
  readonly #decisions: PolicyEvaluation[] = []

  /**
   * Create a deterministic memory Store.
   * @param config - Already-resolved policy and support settings.
   * @param initialState - Optional replay starting point.
   */
  constructor(
    config: Pick<Config, 'mode' | 'minIndependentSupporters' | 'observationTtlMs' | 'policies'>,
    initialState: FirewallState = createEmptyState(),
  ) {
    this.#config = structuredClone(config)
    this.#state = structuredClone(initialState)
  }

  /** Return a detached replayable state snapshot. */
  snapshot(): FirewallState {
    return structuredClone(this.#state)
  }

  /**
   * Apply one explicit reducer command.
   * @param command - Deterministic state transition.
   * @returns Reducer result with a detached state snapshot.
   */
  dispatch(command: ReducerCommand): ReducerResult {
    const result = reduceFirewall(this.#state, command)
    if (result.kind === 'applied') this.#state = result.state
    return structuredClone(result)
  }

  /**
   * Record one Observation using Store configuration.
   * @param request - Explicit operation, Observation, Claim ID, and time.
   * @returns Reducer result.
   */
  record(request: RecordObservationRequest): ReducerResult {
    return this.dispatch({
      kind: 'record-observation',
      ...request,
      observationTtlMs: this.#config.observationTtlMs,
      minIndependentSupporters: this.#config.minIndependentSupporters,
    })
  }

  /**
   * Settle one lease using an explicit structured Observation.
   * @param request - Lease owner, result, replacement Claim ID, and time.
   * @returns Reducer result.
   */
  settleLease(request: SettleLeaseRequest): ReducerResult {
    return this.dispatch({ kind: 'settle-lease', ...request })
  }

  /**
   * Evaluate a Decision and acquire an enforce-mode lease when a candidate is supplied.
   * @param request - Current Evidence, principal, action identity, and optional lease candidate.
   * @returns Recommendation and deployment-mapped Decision.
   */
  decide(request: DecisionRequest): PolicyEvaluation {
    const claim = this.#state.claims.find(
      (candidate) =>
        candidate.isCurrent && candidate.scope === request.scope && candidate.fingerprint === request.fingerprint,
    )
    const activeLease = claim === undefined
      ? undefined
      : this.#state.leases.find((lease) => lease.claimId === claim.id && lease.outcome === undefined)
    const recommendation = recommendPolicy({
      ...(claim === undefined ? {} : { claim }),
      supporters: this.#state.supporters,
      ...(activeLease === undefined ? {} : { activeLease }),
      currentEvidence: request.evidence,
      principalId: request.principalId,
      now: request.now,
      observationTtlMs: this.#config.observationTtlMs,
      minIndependentSupporters: this.#config.minIndependentSupporters,
    })
    let evaluation = mapDeploymentPolicy(recommendation, {
      mode: this.#config.mode,
      actionKind: request.actionKind,
      enforce: actionPolicyEnforced(this.#config, request.actionKind),
    })

    if (evaluation.shouldAcquireLease && request.candidateLease !== undefined) {
      if (claim === undefined || (request.candidateLease.claimId !== undefined && request.candidateLease.claimId !== claim.id)) {
        throw new FirewallError('INVARIANT_VIOLATION', 'Candidate verification lease must target the recommended Claim.')
      }
      if (request.candidateLease.ownerPrincipalId !== request.principalId) {
        throw new FirewallError('INVARIANT_VIOLATION', 'Candidate verification lease must be owned by the requesting principal.')
      }
      const result = this.dispatch({
        kind: 'grant-lease',
        operationId: request.operationId,
        claimId: claim.id,
        lease: { ...request.candidateLease, claimId: claim.id },
        now: request.now,
      })
      if (result.kind === 'rejected') throw result.error
      evaluation = mapDeploymentPolicy(recommendation, {
        mode: this.#config.mode,
        actionKind: request.actionKind,
        enforce: actionPolicyEnforced(this.#config, request.actionKind),
        grantedLeaseId: request.candidateLease.id,
      })
    }

    this.#decisions.push(evaluation)
    return structuredClone(evaluation)
  }

  /** Return deterministic Claims, Decisions, and transition events. */
  scenarioSnapshot(): MemoryScenarioSnapshot {
    return structuredClone({
      claims: this.#state.claims,
      decisions: this.#decisions,
      events: this.#state.events,
    })
  }
}

/**
 * Replay commands into a fresh Memory Store.
 * @param config - Resolved pure Store settings.
 * @param commands - Ordered explicit reducer commands.
 * @returns Final deterministic state.
 */
export function replayMemoryScenario(
  config: Pick<Config, 'mode' | 'minIndependentSupporters' | 'observationTtlMs' | 'policies'>,
  commands: readonly ReducerCommand[],
): FirewallState {
  const store = new MemoryStore(config)
  for (const command of commands) {
    const result = store.dispatch(command)
    if (result.kind === 'rejected') throw result.error
  }
  return store.snapshot()
}

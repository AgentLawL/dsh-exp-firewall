import type { Config } from './config.ts'
import type {
  ActionKind,
  Claim,
  ClaimDetail,
  ClaimFilter,
  ClaimId,
  ClaimStatus,
  Decision,
  EvidenceEpoch,
  EvidenceWitness,
  EventFilter,
  Fingerprint,
  FirewallSummary,
  LeaseId,
  Observation,
  OperationId,
  Page,
  PrincipalId,
  SummaryFilter,
  VerificationLease,
  ClaimView,
} from './types/domain.ts'
import type { FirewallError } from './types/errors.ts'

/** One independent supporter and the most recent qualifying failure time. */
export interface ClaimSupporter {
  claimId: ClaimId
  principalId: PrincipalId
  lastObservedAt: string
}

/** Deterministic transition record produced before durable event IDs are assigned. */
export type PureAuditEvent =
  | {
      kind: 'observation-recorded'
      operationId: OperationId
      observationId: Observation['id']
      claimId?: ClaimId
      outcome: Observation['outcome']
      occurredAt: string
    }
  | {
      kind: 'claim-created'
      operationId: OperationId
      claimId: ClaimId
      to: 'suspected'
      revision: 1
      occurredAt: string
    }
  | {
      kind: 'claim-transition'
      operationId: OperationId
      claimId: ClaimId
      from: ClaimStatus
      to: ClaimStatus
      revision: number
      occurredAt: string
    }
  | {
      kind: 'claim-support-changed'
      operationId: OperationId
      claimId: ClaimId
      supporterCount: number
      revision: number
      occurredAt: string
    }
  | {
      kind: 'lease-granted'
      operationId: OperationId
      claimId: ClaimId
      leaseId: LeaseId
      ownerPrincipalId: PrincipalId
      occurredAt: string
    }
  | {
      kind: 'lease-settled'
      operationId: OperationId
      claimId: ClaimId
      leaseId: LeaseId
      outcome: 'success' | 'failure' | 'released' | 'expired'
      occurredAt: string
    }

/** Complete replayable pure state snapshot. */
export interface FirewallState {
  observations: Observation[]
  claims: Claim[]
  supporters: ClaimSupporter[]
  leases: VerificationLease[]
  events: PureAuditEvent[]
}

/** Create an empty deterministic state snapshot. */
export function createEmptyState(): FirewallState {
  return { observations: [], claims: [], supporters: [], leases: [], events: [] }
}

/** Record one immutable tool result. */
export interface RecordObservationCommand {
  kind: 'record-observation'
  operationId: OperationId
  observation: Observation
  newClaimId: ClaimId
  now: string
  observationTtlMs: number
  minIndependentSupporters: number
}

/** Revoke an active Claim after a proven Evidence change. */
export interface InvalidateEvidenceCommand {
  kind: 'invalidate-evidence'
  operationId: OperationId
  scope: string
  fingerprint: Fingerprint
  currentEvidence: EvidenceWitness[]
  now: string
}

/** Grant one verification lease for a stale Claim. */
export interface GrantLeaseCommand {
  kind: 'grant-lease'
  operationId: OperationId
  claimId: ClaimId
  lease: VerificationLease
  now: string
}

/** Settle an owned lease with a structured verification Observation. */
export interface SettleLeaseCommand {
  kind: 'settle-lease'
  operationId: OperationId
  leaseId: LeaseId
  ownerPrincipalId: PrincipalId
  observation: Observation
  newClaimId: ClaimId
  now: string
}

/** Release an owned lease or expire it at its exact deadline. */
export interface ReleaseLeaseCommand {
  kind: 'release-lease'
  operationId: OperationId
  leaseId: LeaseId
  ownerPrincipalId?: PrincipalId
  cause: 'released' | 'expired'
  now: string
}

/** Closed reducer command set. */
export type ReducerCommand =
  | RecordObservationCommand
  | InvalidateEvidenceCommand
  | GrantLeaseCommand
  | SettleLeaseCommand
  | ReleaseLeaseCommand

/** Deterministic reducer output. */
export type ReducerResult =
  | { kind: 'applied'; state: FirewallState; events: PureAuditEvent[]; claim?: Claim; lease?: VerificationLease }
  | { kind: 'duplicate'; state: FirewallState; events: [] }
  | { kind: 'rejected'; state: FirewallState; events: []; error: FirewallError }

/** Pure policy request with all time and Evidence inputs explicit. */
export interface PolicyRequest {
  claim?: Claim
  supporters: ClaimSupporter[]
  activeLease?: VerificationLease
  currentEvidence: EvidenceWitness[]
  principalId: PrincipalId
  now: string
  observationTtlMs: number
  minIndependentSupporters: number
}

/** Service decision request; lease identity and expiry are caller-generated. */
export interface DecisionRequest {
  operationId: OperationId
  scope: string
  actionKind: ActionKind
  fingerprint: Fingerprint
  principalId: PrincipalId
  evidence: EvidenceWitness[]
  now: string
  candidateLease?: Omit<VerificationLease, 'claimId'> & { claimId?: ClaimId }
}

/** Service Observation mutation request. */
export interface RecordObservationRequest {
  operationId: OperationId
  observation: Observation
  newClaimId: ClaimId
  now: string
}

/** Service lease-settlement request. */
export interface SettleLeaseRequest {
  operationId: OperationId
  leaseId: LeaseId
  ownerPrincipalId: PrincipalId
  observation: Observation
  newClaimId: ClaimId
  now: string
}

/** Background invalidation request produced from one latest filesystem Witness. */
export interface InvalidateClaimsRequest {
  operationId: OperationId
  evidence: EvidenceWitness[]
  now: string
}

/** Host-only mutation emitted only after a warning reaches a tool result. */
export interface RecordWarningRequest {
  operationId: OperationId
  claimId?: ClaimId
  now: string
}

/** Claims transitioned to stale by one filesystem observation. */
export interface InvalidateClaimsResult {
  claimIds: ClaimId[]
}

/** One revision-guarded Claim state transition caused by a mutation. */
export interface ClaimTransition {
  claimId: ClaimId
  from: ClaimStatus
  to: ClaimStatus
  revision: number
}

/** Bounded mutation notification for optional read-only surfaces. */
export interface FirewallChangeNotification {
  kind: 'decision' | 'observation' | 'warning' | 'lease-settlement' | 'evidence-invalidation' | 'lease-release'
  operationId: OperationId
}

/** Result of an Observation mutation. */
export interface RecordResult {
  observation: Observation
  claim?: Claim
  duplicate: boolean
  transitions: ClaimTransition[]
}

/** Result of settling a verification lease. */
export interface SettleResult {
  lease: VerificationLease
  claim: Claim
  replacementClaim?: Claim
  transitions: ClaimTransition[]
}

/** Durable audit event DTO; event IDs are assigned by the Store layer. */
export interface FirewallEvent {
  id: string
  operationId: OperationId
  claimId?: ClaimId
  kind: string
  body: Record<string, unknown>
  occurredAt: string
}

/** Storage operations needed by Provider, Consumer, CLI, HTTP, and browser clients. */
export interface ExperienceFirewallStore {
  decide(request: DecisionRequest): Promise<Decision>
  record(request: RecordObservationRequest): Promise<RecordResult>
  settleLease(request: SettleLeaseRequest): Promise<SettleResult>
  summary(filter?: SummaryFilter): Promise<FirewallSummary>
  listClaims(filter?: ClaimFilter): Promise<Page<ClaimView>>
  getClaim(id: ClaimId, signal?: AbortSignal): Promise<ClaimDetail | undefined>
  listEvents(filter?: EventFilter): Promise<Page<FirewallEvent>>
  shutdown(): Promise<void>
}

/** Public service definition intentionally identical to the Store seam. */
export interface ExperienceFirewallService extends ExperienceFirewallStore {}

/** Host-only extension consumed by the filesystem invalidation queue. */
export interface ExperienceFirewallRuntimeService extends ExperienceFirewallService {
  invalidateClaims(request: InvalidateClaimsRequest): Promise<InvalidateClaimsResult>
  releaseLease(request: ReleaseLeaseCommand): Promise<{ lease: VerificationLease; claim: Claim }>
  recordWarning(request: RecordWarningRequest): Promise<{ recorded: true }>
  subscribe(listener: (notification: FirewallChangeNotification) => void): () => void
  closeSubscriptions(): void
}

/** Configuration subset the deterministic in-memory Store consumes. */
export type PureStoreConfig = Pick<
  Config,
  'mode' | 'minIndependentSupporters' | 'observationTtlMs' | 'policies'
>

/** Exact scope and action identity used to find one current Claim. */
export interface ClaimKey {
  scope: string
  fingerprint: Fingerprint
}

/** Lease creation fields supplied explicitly to deterministic code. */
export interface LeaseCandidate {
  id: LeaseId
  evidenceEpoch: EvidenceEpoch
  expiresAt: string
}

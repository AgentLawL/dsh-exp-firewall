/** Opaque string with a compile-time identity. */
declare const brand: unique symbol

/**
 * Brand a string so identifiers from different domains cannot be mixed.
 * @typeParam Name - Identifier domain name.
 */
export type Branded<Name extends string> = string & { readonly [brand]: Name }

/** Immutable Observation identifier. */
export type ObservationId = Branded<'ObservationId'>
/** Revocable Claim identifier. */
export type ClaimId = Branded<'ClaimId'>
/** Verification lease identifier. */
export type LeaseId = Branded<'LeaseId'>
/** Idempotent mutation identifier. */
export type OperationId = Branded<'OperationId'>
/** SHA-256 action identity. */
export type Fingerprint = Branded<'Fingerprint'>
/** SHA-256 Evidence-set identity. */
export type EvidenceEpoch = Branded<'EvidenceEpoch'>
/** Independent supporter identity. */
export type PrincipalId = Branded<'PrincipalId'>
/** Deterministic audit event identifier. */
export type EventId = Branded<'EventId'>

/** Tool action kinds supported by the MVP. */
export type ActionKind = 'command' | 'file-read'

/** File-state evidence supplied by the filesystem provider. */
export type EvidenceWitness =
  | { kind: 'file-state'; key: string; state: 'absent' }
  | { kind: 'file-state'; key: string; state: 'present'; version: string }

/** Immutable result of one supported tool execution. */
export interface Observation {
  id: ObservationId
  operationId: OperationId
  sessionId: string
  principalId: PrincipalId
  toolCallId?: string
  scope: string
  actionKind: ActionKind
  fingerprint: Fingerprint
  preview: string
  outcome: 'success' | 'failure'
  failureCode?: string
  evidenceEpoch: EvidenceEpoch
  evidence: EvidenceWitness[]
  observedAt: string
}

/** Lifecycle status of a revocable failure Claim. */
export type ClaimStatus =
  | 'suspected'
  | 'corroborated'
  | 'stale'
  | 'verifying'
  | 'contradicted'
  | 'resolved'
  | 'superseded'

/** Derived, revision-guarded conclusion about a repeated tool failure. */
export interface Claim {
  id: ClaimId
  scope: string
  actionKind: ActionKind
  fingerprint: Fingerprint
  evidenceEpoch: EvidenceEpoch
  evidence: EvidenceWitness[]
  preview: string
  status: ClaimStatus
  supporterCount: number
  revision: number
  isCurrent: boolean
  createdAt: string
  updatedAt: string
}

/** Single-principal authorization to verify a stale Claim. */
export interface VerificationLease {
  id: LeaseId
  claimId: ClaimId
  ownerPrincipalId: PrincipalId
  evidenceEpoch: EvidenceEpoch
  expiresAt: string
  outcome?: 'success' | 'failure' | 'released'
  settledAt?: string
}

/** Stable recommendation reasons produced before deployment-mode mapping. */
export type DecisionReason =
  | 'no-claim'
  | 'counterexample'
  | 'suspected'
  | 'corroborated'
  | 'evidence-changed'
  | 'evidence-unavailable'
  | 'verification-in-progress'
  | 'observe-mode'

/** Explainable action returned by the policy service. */
export type Decision =
  | { kind: 'allow'; reason: 'no-claim' | 'counterexample' | 'observe-mode'; claimId?: ClaimId }
  | {
      kind: 'warn'
      reason: 'suspected' | 'corroborated' | 'evidence-unavailable' | 'evidence-changed' | 'verification-in-progress'
      claimId: ClaimId
    }
  | { kind: 'deny'; reason: 'corroborated'; claimId: ClaimId }
  | { kind: 'verify'; reason: 'evidence-changed'; claimId: ClaimId; leaseId: LeaseId }
  | {
      kind: 'wait'
      reason: 'verification-in-progress'
      claimId: ClaimId
      owner: PrincipalId
      expiresAt: string
    }

/** Independently meaningful persisted product counters. */
export interface FirewallSummary {
  suspectedClaims: number
  corroboratedClaims: number
  staleClaims: number
  resolvedClaims: number
  warningsEmitted: number
  callsDenied: number
  verificationWaits: number
  leasesGranted: number
  crossAgentHits: number
}

/** Page of stable read DTOs. */
export interface Page<Value> {
  items: Value[]
  nextCursor?: string
}

/** Public Claim list projection without raw action data. */
export type ClaimView = Pick<
  Claim,
  | 'id'
  | 'scope'
  | 'actionKind'
  | 'fingerprint'
  | 'preview'
  | 'status'
  | 'supporterCount'
  | 'revision'
  | 'isCurrent'
  | 'createdAt'
  | 'updatedAt'
>

/** Public Claim detail projection with structured provenance. */
export interface ClaimDetail extends ClaimView {
  evidenceEpoch: EvidenceEpoch
  evidence: EvidenceWitness[]
  observations: Observation[]
  lease?: VerificationLease
}

/** Read-side Claim filters. */
export interface ClaimFilter {
  scope?: string
  status?: ClaimStatus
  cursor?: string
  limit?: number
  signal?: AbortSignal
}

/** Read-side event filters. */
export interface EventFilter {
  claimId?: ClaimId
  cursor?: string
  limit?: number
  signal?: AbortSignal
}

/** Read-side summary filters. */
export interface SummaryFilter {
  scope?: string
  signal?: AbortSignal
}

import { evidenceEpoch } from '../src/evidence.ts'
import type {
  ClaimId,
  EvidenceWitness,
  Fingerprint,
  LeaseId,
  Observation,
  ObservationId,
  OperationId,
  PrincipalId,
} from '../src/types/domain.ts'

export const fp = 'a'.repeat(64) as Fingerprint

export function claimId(value: string): ClaimId {
  return value as ClaimId
}

export function leaseId(value: string): LeaseId {
  return value as LeaseId
}

export function operationId(value: string): OperationId {
  return value as OperationId
}

export function principalId(value: string): PrincipalId {
  return value as PrincipalId
}

export function observationId(value: string): ObservationId {
  return value as ObservationId
}

export function observation(input: {
  id: string
  principal: string
  at: string
  outcome: Observation['outcome']
  evidence?: EvidenceWitness[]
  failureCode?: string
}): Observation {
  const evidence = input.evidence ?? [{ kind: 'file-state', key: '/target', state: 'absent' }]
  return {
    id: observationId(input.id),
    operationId: operationId(`op-${input.id}`),
    sessionId: `session-${input.principal}`,
    principalId: principalId(input.principal),
    scope: '/workspace',
    actionKind: 'file-read',
    fingerprint: fp,
    preview: 'read /target',
    outcome: input.outcome,
    ...(input.failureCode === undefined ? {} : { failureCode: input.failureCode }),
    evidenceEpoch: evidenceEpoch(evidence),
    evidence,
    observedAt: input.at,
  }
}

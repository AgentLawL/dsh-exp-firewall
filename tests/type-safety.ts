import type { ClaimId, LeaseId, ObservationId } from '../src/types/index.ts'

declare const claimId: ClaimId
declare const observationId: ObservationId
declare const leaseId: LeaseId

function acceptsClaimId(_id: ClaimId): void {}

acceptsClaimId(claimId)
// @ts-expect-error Observation and Claim identifiers are intentionally incompatible.
acceptsClaimId(observationId)
// @ts-expect-error Lease and Claim identifiers are intentionally incompatible.
acceptsClaimId(leaseId)

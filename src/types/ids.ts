import { randomBytes } from 'node:crypto'

import { FirewallError } from './errors.ts'
import type {
  ClaimId,
  LeaseId,
  ObservationId,
  OperationId,
  PrincipalId,
} from './domain.ts'

const UUID_V7_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

/**
 * Create a UUIDv7 string using an explicit millisecond timestamp.
 * @param unixMilliseconds - UTC Unix timestamp in milliseconds.
 * @returns Lowercase UUIDv7.
 */
export function createUuidV7(unixMilliseconds = Date.now()): string {
  if (!Number.isSafeInteger(unixMilliseconds) || unixMilliseconds < 0 || unixMilliseconds > 0xffffffffffff) {
    throw new FirewallError('INVARIANT_VIOLATION', 'UUIDv7 time must be a non-negative 48-bit safe integer.')
  }

  const bytes = randomBytes(16)
  let timestamp = BigInt(unixMilliseconds)
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(timestamp & 0xffn)
    timestamp >>= 8n
  }
  bytes[6] = (bytes[6]! & 0x0f) | 0x70
  bytes[8] = (bytes[8]! & 0x3f) | 0x80

  const hex = bytes.toString('hex')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

/**
 * Report whether a string is a lowercase UUIDv7.
 * @param value - Candidate string.
 * @returns Whether the candidate has UUIDv7 version and variant bits.
 */
export function isUuidV7(value: string): boolean {
  return UUID_V7_PATTERN.test(value)
}

/** Create an Observation identifier. */
export function createObservationId(unixMilliseconds?: number): ObservationId {
  return createUuidV7(unixMilliseconds) as ObservationId
}

/** Create a Claim identifier. */
export function createClaimId(unixMilliseconds?: number): ClaimId {
  return createUuidV7(unixMilliseconds) as ClaimId
}

/** Create a Lease identifier. */
export function createLeaseId(unixMilliseconds?: number): LeaseId {
  return createUuidV7(unixMilliseconds) as LeaseId
}

/** Create an Operation identifier. */
export function createOperationId(unixMilliseconds?: number): OperationId {
  return createUuidV7(unixMilliseconds) as OperationId
}

/**
 * Derive the independent-support identity.
 * @param stableAgentId - Stable agent identity when available.
 * @param sessionId - Durable session fallback.
 * @returns Branded principal identity.
 */
export function derivePrincipalId(stableAgentId: string | undefined, sessionId: string): PrincipalId {
  const value = stableAgentId ?? sessionId
  if (value.length === 0) {
    throw new FirewallError('INVARIANT_VIOLATION', 'A principal requires a stable agent ID or non-empty session ID.')
  }
  return value as PrincipalId
}

import { describe, expect, it } from 'vitest'

import {
  compareUtcIso,
  createClaimId,
  createLeaseId,
  createObservationId,
  createOperationId,
  derivePrincipalId,
  FirewallError,
  isUuidV7,
  parseUtcIso,
  sanitizeErrorMessage,
  toUtcIso,
} from '../src/types/index.ts'

describe('opaque identifiers and time', () => {
  it('creates UUIDv7 entity identifiers', () => {
    for (const id of [createObservationId(0), createClaimId(1), createLeaseId(2), createOperationId(3)]) {
      expect(isUuidV7(id)).toBe(true)
    }
  })

  it('rejects timestamps outside UUIDv7 range', () => {
    expect(() => createClaimId(-1)).toThrowError(FirewallError)
    expect(() => createClaimId(0x1_0000_0000_0000)).toThrowError(FirewallError)
  })

  it('uses stable agent identity before the session fallback', () => {
    expect(derivePrincipalId('agent-a', 'session-a')).toBe('agent-a')
    expect(derivePrincipalId(undefined, 'session-a')).toBe('session-a')
    expect(() => derivePrincipalId(undefined, '')).toThrowError(FirewallError)
  })

  it('serializes, parses, and compares UTC timestamps by time', () => {
    expect(toUtcIso(0)).toBe('1970-01-01T00:00:00.000Z')
    expect(parseUtcIso('1970-01-01T00:00:01.000Z')).toBe(1_000)
    expect(compareUtcIso('2026-08-18T00:00:00.000Z', '2026-08-18T00:00:01.000Z')).toBeLessThan(0)
    expect(() => parseUtcIso('2026-08-18T08:00:00+08:00')).toThrowError(FirewallError)
  })

  it('sanitizes and caps diagnostics by Unicode code point', () => {
    const result = sanitizeErrorMessage(`bad\n${'界'.repeat(300)}`)
    expect(result).not.toContain('\n')
    expect([...result]).toHaveLength(240)
  })
})

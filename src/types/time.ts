import { FirewallError } from './errors.ts'

/**
 * Serialize a Unix millisecond timestamp as UTC ISO 8601.
 * @param unixMilliseconds - UTC Unix timestamp in milliseconds.
 * @returns Canonical UTC ISO 8601 string.
 */
export function toUtcIso(unixMilliseconds: number): string {
  if (!Number.isFinite(unixMilliseconds)) {
    throw new FirewallError('INVARIANT_VIOLATION', 'Timestamp must be finite.')
  }
  return new Date(unixMilliseconds).toISOString()
}

/**
 * Parse a persisted UTC ISO 8601 timestamp.
 * @param value - Timestamp ending in `Z`.
 * @returns Unix timestamp in milliseconds.
 */
export function parseUtcIso(value: string): number {
  const parsed = Date.parse(value)
  if (!value.endsWith('Z') || !Number.isFinite(parsed)) {
    throw new FirewallError('INVARIANT_VIOLATION', 'Persisted timestamps must be valid UTC ISO 8601 strings.')
  }
  return parsed
}

/**
 * Compare persisted timestamps by parsed time.
 * @param left - First UTC ISO timestamp.
 * @param right - Second UTC ISO timestamp.
 * @returns Negative, zero, or positive according to temporal order.
 */
export function compareUtcIso(left: string, right: string): number {
  return parseUtcIso(left) - parseUtcIso(right)
}

/** Stable boundary error codes. */
export type FirewallErrorCode =
  | 'INVALID_CONFIG'
  | 'INVALID_ACTION'
  | 'CLAIM_NOT_FOUND'
  | 'STORE_BUSY'
  | 'STORE_CORRUPT'
  | 'OPERATION_REPLAY_CONFLICT'
  | 'REVISION_CONFLICT'
  | 'LEASE_NOT_OWNER'
  | 'LEASE_EXPIRED'
  | 'INVARIANT_VIOLATION'

const MAX_ERROR_MESSAGE_CODE_POINTS = 240

/**
 * Remove control characters and cap a boundary-safe diagnostic.
 * @param message - Untrusted diagnostic text.
 * @returns Sanitized text suitable for logs and model-visible results.
 */
export function sanitizeErrorMessage(message: string): string {
  return [...message.replace(/[\u0000-\u001f\u007f]/g, ' ')].slice(0, MAX_ERROR_MESSAGE_CODE_POINTS).join('')
}

/** Typed failure carrying a stable, non-secret error code. */
export class FirewallError extends Error {
  /** Stable programmatic failure identity. */
  readonly code: FirewallErrorCode

  /**
   * Create a typed boundary failure.
   * @param code - Stable programmatic failure identity.
   * @param message - Corrective diagnostic that does not contain raw actions.
   */
  constructor(code: FirewallErrorCode, message: string) {
    super(sanitizeErrorMessage(message))
    this.name = 'FirewallError'
    this.code = code
  }
}

/**
 * Prove that a closed union was handled exhaustively.
 * @param value - Unreachable union member.
 * @returns Never returns.
 */
export function assertNever(value: never): never {
  throw new FirewallError('INVARIANT_VIOLATION', `Unhandled closed-union member: ${String(value)}`)
}

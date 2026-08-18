const DEFAULT_CREDENTIAL_FLAGS = [
  '--api-key',
  '--apikey',
  '--access-key',
  '--auth-token',
  '--password',
  '--secret',
  '--token',
] as const

const REDACTED = '[REDACTED]'

function escapeRegularExpression(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * Produce presentation-only text with credential classes removed.
 * @param value - Raw preview candidate; it is never persisted separately.
 * @param maxPreviewChars - Maximum Unicode code points in the final preview.
 * @param credentialFlags - CLI flags whose following or assigned values are credentials.
 * @returns Control-free, redacted, capped preview.
 */
export function createPreview(
  value: string,
  maxPreviewChars: number,
  credentialFlags: readonly string[] = DEFAULT_CREDENTIAL_FLAGS,
): string {
  let preview = value.replace(/[\u0000-\u001f\u007f]/g, ' ')

  preview = preview.replace(
    /\b([A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)[A-Za-z0-9_]*)\s*=\s*(?:"[^"]*"|'[^']*'|[^\s]+)/gi,
    `$1=${REDACTED}`,
  )
  preview = preview.replace(/\bBearer\s+[^\s,;]+/gi, `Bearer ${REDACTED}`)
  preview = preview.replace(/\b([A-Za-z][A-Za-z0-9+.-]*:\/\/)([^/@\s]+)@/g, `$1${REDACTED}@`)

  if (credentialFlags.length > 0) {
    const flags = credentialFlags.map(escapeRegularExpression).join('|')
    const flagPattern = new RegExp(`(${flags})(?:\\s*=\\s*|\\s+)("[^"]*"|'[^']*'|[^\\s]+)`, 'gi')
    preview = preview.replace(flagPattern, `$1 ${REDACTED}`)
  }

  return [...preview].slice(0, maxPreviewChars).join('')
}

/** Common credential-bearing CLI flags redacted by default. */
export const DEFAULT_REDACTED_CREDENTIAL_FLAGS: readonly string[] = DEFAULT_CREDENTIAL_FLAGS

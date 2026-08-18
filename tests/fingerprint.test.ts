import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'

import {
  canonicalizeCommandAction,
  canonicalizeFileReadAction,
  fingerprintAction,
  stableJson,
} from '../src/fingerprint.ts'
import { FirewallError } from '../src/types/errors.ts'

describe('stableJson', () => {
  it('sorts nested object keys, omits object undefined, and preserves arrays', () => {
    expect(stableJson({ z: 1, a: { y: undefined, b: 2, a: 1 }, list: [3, 2, 1] })).toBe(
      '{"a":{"a":1,"b":2},"list":[3,2,1],"z":1}',
    )
  })

  it.each([undefined, Number.NaN, Number.POSITIVE_INFINITY, 1n, () => undefined, new Date()])(
    'rejects non-JSON value %s',
    (value) => {
      expect(() => stableJson(value)).toThrowError(FirewallError)
    },
  )

  it('rejects undefined array entries and cycles', () => {
    expect(() => stableJson([undefined])).toThrowError(FirewallError)
    const cycle: Record<string, unknown> = {}
    cycle.self = cycle
    expect(() => stableJson(cycle)).toThrowError(FirewallError)
  })
})

describe('action fingerprints', () => {
  it('trims only command edges and follows workdir precedence', () => {
    expect(
      canonicalizeCommandAction({ tool: 'bash', command: '  echo   hello\n', workdir: '/tool', sessionCwd: '/session' }),
    ).toEqual({ kind: 'command', tool: 'bash', cwd: '/tool', command: 'echo   hello' })
    expect(canonicalizeCommandAction({ tool: 'bash', command: 'pwd', sessionCwd: '/session' }).cwd).toBe('/session')
    expect(canonicalizeCommandAction({ tool: 'bash', command: 'pwd' }).cwd).toBe('')
  })

  it('keeps internal whitespace, tool, and cwd identity distinct', () => {
    const base = canonicalizeCommandAction({ tool: 'bash', command: 'echo x', workdir: '/w' })
    expect(fingerprintAction(base)).not.toBe(fingerprintAction({ ...base, command: 'echo  x' }))
    expect(fingerprintAction(base)).not.toBe(fingerprintAction({ ...base, tool: 'pwsh' }))
    expect(fingerprintAction(base)).not.toBe(fingerprintAction({ ...base, cwd: '/other' }))
  })

  it('matches the specified full lowercase SHA-256 digest', () => {
    const action = canonicalizeCommandAction({ tool: 'bash', command: 'true' })
    expect(fingerprintAction(action)).toBe(createHash('sha256').update(stableJson(action), 'utf8').digest('hex'))
    expect(fingerprintAction(action)).toMatch(/^[0-9a-f]{64}$/)
  })

  it('removes controls and prefers the Provider display path without resolving it', () => {
    expect(
      canonicalizeFileReadAction({
        tool: 'read',
        path: './secret\u0000.txt',
        sessionCwd: '/workspace',
        providerDisplayPath: '/workspace/link/../secret.txt',
      }),
    ).toEqual({
      kind: 'file-read',
      tool: 'read',
      cwd: '/workspace',
      path: '/workspace/link/../secret.txt',
    })
    expect(canonicalizeFileReadAction({ tool: 'read', path: 'a\u0007b', workdir: '/tool' })).toEqual({
      kind: 'file-read',
      tool: 'read',
      cwd: '/tool',
      path: 'ab',
    })
  })

  it.each([
    () => canonicalizeCommandAction({ tool: 'bash', command: '  ' }),
    () => canonicalizeCommandAction({ tool: 'bash', command: 1 }),
    () => canonicalizeCommandAction({ tool: 'bash', command: 'x', workdir: 1 }),
    () => canonicalizeFileReadAction({ tool: 'read', path: '\u0000' }),
    () => canonicalizeFileReadAction({ tool: 'read', path: 1 }),
  ])('rejects invalid supported action input', (run) => {
    expect(run).toThrowError(FirewallError)
  })
})

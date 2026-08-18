import { describe, expect, it } from 'vitest'

import { DEFAULT_CONFIG, resolveConfig } from '../src/config.ts'
import { FirewallError } from '../src/types/errors.ts'

function expectInvalid(input: Parameters<typeof resolveConfig>[0]): void {
  try {
    resolveConfig(input)
    throw new Error('Expected invalid configuration')
  } catch (error) {
    expect(error).toBeInstanceOf(FirewallError)
    expect((error as FirewallError).code).toBe('INVALID_CONFIG')
  }
}

describe('configuration', () => {
  it('resolves every normative default into owned arrays', () => {
    const first = resolveConfig()
    const second = resolveConfig()

    expect(first).toEqual(DEFAULT_CONFIG)
    expect(first.commandTools).not.toBe(DEFAULT_CONFIG.commandTools)
    expect(first.commandTools).not.toBe(second.commandTools)
    expect(first.dashboard.host).toBe('127.0.0.1')
  })

  it('deeply applies explicit overrides including non-loopback hosts', () => {
    expect(
      resolveConfig({
        mode: 'enforce',
        dashboard: { host: '192.0.2.10' },
        policies: { 'file-read': { enforce: false } },
      }),
    ).toMatchObject({
      mode: 'enforce',
      dashboard: { host: '192.0.2.10', enabled: true, pollIntervalMs: 1_000 },
      policies: { command: { enforce: true }, 'file-read': { enforce: false } },
    })
  })

  it.each([
    { observationTtlMs: 0 },
    { verificationLeaseTtlMs: Number.NaN },
    { storeBusyDeadlineMs: Number.MAX_SAFE_INTEGER + 1 },
    { dashboard: { pollIntervalMs: -1 } },
    { minIndependentSupporters: 1 },
    { minIndependentSupporters: 2.5 },
    { redaction: { maxPreviewChars: 39 } },
    { redaction: { maxPreviewChars: 1_001 } },
    { dataDir: '  ' },
    { dashboard: { host: '' } },
    { commandTools: ['bash', 'bash'] },
    { commandTools: [' '] },
    { commandTools: ['read'], readTools: ['read'] },
  ])('rejects invalid self-contained input %#', (input) => {
    expectInvalid(input as Parameters<typeof resolveConfig>[0])
  })

  it('accepts exact integer and preview boundaries', () => {
    expect(resolveConfig({ minIndependentSupporters: 2, redaction: { maxPreviewChars: 40 } })).toMatchObject({
      minIndependentSupporters: 2,
      redaction: { maxPreviewChars: 40 },
    })
    expect(resolveConfig({ redaction: { maxPreviewChars: 1_000 } }).redaction.maxPreviewChars).toBe(1_000)
  })
})

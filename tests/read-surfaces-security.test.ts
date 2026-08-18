import { describe, expect, it } from 'vitest'

import { claimDetailModel, claimExplorerRow } from '../client/index.ts'
import { createPreview } from '../src/redaction.ts'

describe('shared read-surface security boundary', () => {
  it('keeps credentials and control characters out of final view models and exposes only provenance DTO fields', () => {
    const secret = 'ultra-secret-value'
    const preview = createPreview(`TOKEN=${secret}\u0000 read /target`, 80)
    const claim = {
      id: 'claim-safe', scope: '/workspace', actionKind: 'command', fingerprint: 'a'.repeat(64),
      preview, status: 'corroborated', supporterCount: 2, revision: 2, isCurrent: true,
      createdAt: '2026-08-18T00:00:00.000Z', updatedAt: '2026-08-18T00:00:01.000Z',
      evidenceEpoch: 'b'.repeat(64), evidence: [], observations: [],
    } as never
    const row = claimExplorerRow(claim)
    const detail = claimDetailModel(claim, [])
    const serialized = JSON.stringify({ row, detail })
    expect(serialized).not.toContain(secret)
    expect(serialized).not.toContain('\u0000')
    expect(serialized).not.toContain('command":')
    expect(Object.keys(row).sort()).toEqual(['id', 'preview', 'scope', 'status', 'supporterCount', 'updatedAt'])
  })
})

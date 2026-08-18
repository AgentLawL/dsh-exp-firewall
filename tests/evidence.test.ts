import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'

import {
  canonicalizeEvidence,
  compareEvidence,
  evidenceChanged,
  evidenceEpoch,
  evidenceMatches,
} from '../src/evidence.ts'
import { stableJson } from '../src/fingerprint.ts'
import type { EvidenceWitness } from '../src/types/domain.ts'
import { FirewallError } from '../src/types/errors.ts'

const absent: EvidenceWitness = { kind: 'file-state', key: '/a', state: 'absent' }
const present: EvidenceWitness = { kind: 'file-state', key: '/b', state: 'present', version: 'opaque:v1' }

describe('Evidence identity and comparison', () => {
  it('sorts by kind and key and makes input order irrelevant', () => {
    expect(canonicalizeEvidence([present, absent])).toEqual([absent, present])
    expect(evidenceEpoch([present, absent])).toBe(evidenceEpoch([absent, present]))
  })

  it('uses the complete stable-JSON SHA-256 digest, including empty Evidence', () => {
    expect(evidenceEpoch([])).toBe(createHash('sha256').update('[]', 'utf8').digest('hex'))
    const sorted = canonicalizeEvidence([present, absent])
    expect(evidenceEpoch(sorted)).toBe(createHash('sha256').update(stableJson(sorted), 'utf8').digest('hex'))
  })

  it('matches complete sets and detects a comparable changed witness', () => {
    expect(compareEvidence([absent, present], [present, absent])).toBe('matching')
    expect(evidenceMatches([absent], [absent])).toBe(true)
    expect(
      compareEvidence([present], [{ kind: 'file-state', key: '/b', state: 'present', version: 'opaque:v2' }]),
    ).toBe('changed')
    expect(evidenceChanged([absent], [{ kind: 'file-state', key: '/a', state: 'present', version: '1' }])).toBe(true)
  })

  it('treats missing, extra-only, partial, and empty current Evidence as unknown', () => {
    expect(compareEvidence([absent], [])).toBe('unknown')
    expect(compareEvidence([absent], [{ kind: 'file-state', key: '/other', state: 'absent' }])).toBe('unknown')
    expect(compareEvidence([absent, present], [absent])).toBe('unknown')
    expect(compareEvidence([], [])).toBe('unknown')
  })

  it('keeps opaque versions byte-sensitive', () => {
    expect(
      evidenceEpoch([{ kind: 'file-state', key: '/a', state: 'present', version: 'V1' }]),
    ).not.toBe(evidenceEpoch([{ kind: 'file-state', key: '/a', state: 'present', version: 'v1' }]))
  })

  it('fails loudly on duplicate or malformed keys', () => {
    expect(() => canonicalizeEvidence([absent, absent])).toThrowError(FirewallError)
    expect(() => canonicalizeEvidence([{ kind: 'file-state', key: '', state: 'absent' }])).toThrowError(FirewallError)
  })
})

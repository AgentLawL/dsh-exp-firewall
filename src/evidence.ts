import { createHash } from 'node:crypto'

import { stableJson } from './fingerprint.ts'
import type { EvidenceEpoch, EvidenceWitness } from './types/domain.ts'
import { FirewallError } from './types/errors.ts'

/** Evidence relation used by invalidation and policy evaluation. */
export type EvidenceComparison = 'matching' | 'changed' | 'unknown'

function witnessIdentity(witness: EvidenceWitness): string {
  return stableJson(witness)
}

/**
 * Validate and sort Evidence witnesses without interpreting opaque versions.
 * @param witnesses - Filesystem Provider observations.
 * @returns Fresh array sorted by kind then key.
 */
export function canonicalizeEvidence(witnesses: readonly EvidenceWitness[]): EvidenceWitness[] {
  const keys = new Set<string>()
  const result = witnesses.map((witness) => {
    if (witness.kind !== 'file-state' || witness.key.length === 0) {
      throw new FirewallError('INVARIANT_VIOLATION', 'Evidence requires a supported kind and non-empty key.')
    }
    if (keys.has(witness.key)) {
      throw new FirewallError('INVARIANT_VIOLATION', 'Evidence contains a duplicate key.')
    }
    keys.add(witness.key)
    if (witness.state === 'present' && typeof witness.version !== 'string') {
      throw new FirewallError('INVARIANT_VIOLATION', 'Present file evidence requires an opaque string version.')
    }
    return { ...witness }
  })
  result.sort((left, right) => left.kind.localeCompare(right.kind) || left.key.localeCompare(right.key))
  return result
}

/**
 * Compute a complete Evidence-set epoch.
 * @param witnesses - Evidence set in any order.
 * @returns Branded lowercase SHA-256 digest.
 */
export function evidenceEpoch(witnesses: readonly EvidenceWitness[]): EvidenceEpoch {
  return createHash('sha256').update(stableJson(canonicalizeEvidence(witnesses)), 'utf8').digest('hex') as EvidenceEpoch
}

/**
 * Compare persisted Claim evidence with currently known evidence.
 * @param expected - Complete Evidence set stored on the Claim.
 * @param current - Latest known Evidence set.
 * @returns Matching, changed, or unknown when required current witnesses are absent.
 */
export function compareEvidence(
  expected: readonly EvidenceWitness[],
  current: readonly EvidenceWitness[],
): EvidenceComparison {
  const canonicalExpected = canonicalizeEvidence(expected)
  const canonicalCurrent = canonicalizeEvidence(current)
  if (canonicalExpected.length === 0) return 'unknown'
  if (evidenceEpoch(canonicalExpected) === evidenceEpoch(canonicalCurrent)) return 'matching'

  const currentByKey = new Map(canonicalCurrent.map((witness) => [witness.key, witness]))
  for (const witness of canonicalExpected) {
    const candidate = currentByKey.get(witness.key)
    if (candidate !== undefined && witnessIdentity(candidate) !== witnessIdentity(witness)) {
      return 'changed'
    }
  }
  return 'unknown'
}

/** Return whether complete Evidence sets match. */
export function evidenceMatches(expected: readonly EvidenceWitness[], current: readonly EvidenceWitness[]): boolean {
  return compareEvidence(expected, current) === 'matching'
}

/** Return whether a comparable current Witness proves a change. */
export function evidenceChanged(expected: readonly EvidenceWitness[], current: readonly EvidenceWitness[]): boolean {
  return compareEvidence(expected, current) === 'changed'
}

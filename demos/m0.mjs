import { strict as assert } from 'node:assert'
import { readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { resolveConfig } from '../lib/index.js'
import { evidenceEpoch, MemoryStore } from '../lib/pure/index.js'

const here = dirname(fileURLToPath(import.meta.url))
const scope = '/workspace'
const fingerprint = 'a'.repeat(64)
const oldEvidence = [{ kind: 'file-state', key: '/target', state: 'absent' }]

function failedObservation(id, principalId, observedAt) {
  return {
    id,
    operationId: `op-${id}`,
    sessionId: `session-${principalId}`,
    principalId,
    scope,
    actionKind: 'file-read',
    fingerprint,
    preview: 'read /target',
    outcome: 'failure',
    failureCode: 'FS_NOT_FOUND',
    evidenceEpoch: evidenceEpoch(oldEvidence),
    evidence: oldEvidence,
    observedAt,
  }
}

const store = new MemoryStore(resolveConfig({ mode: 'enforce' }))
const first = failedObservation('observation-a', 'principal-a', '2026-08-18T00:00:00.000Z')
const second = failedObservation('observation-b', 'principal-b', '2026-08-18T00:00:01.000Z')

const firstResult = store.record({ operationId: first.operationId, observation: first, newClaimId: 'claim-a', now: first.observedAt })
const secondResult = store.record({ operationId: second.operationId, observation: second, newClaimId: 'unused', now: second.observedAt })
const denial = store.decide({
  operationId: 'op-denial',
  scope,
  actionKind: 'file-read',
  fingerprint,
  principalId: 'principal-c',
  evidence: oldEvidence,
  now: '2026-08-18T00:00:02.000Z',
})
const output = [
  `principal-a | outcome=failure:FS_NOT_FOUND | claim=${firstResult.claim?.status} | supporters=${String(firstResult.claim?.supporterCount)}`,
  `principal-b | outcome=failure:FS_NOT_FOUND | claim=${secondResult.claim?.status} | supporters=${String(secondResult.claim?.supporterCount)}`,
  `principal-c | decision=${denial.decision.kind} | reason=${denial.decision.reason} | dispatched=false`,
  '',
].join('\n')
if (process.argv.includes('--verify')) {
  assert.equal(output, await readFile(join(here, 'consensus.snapshot.txt'), 'utf8'))
}
process.stdout.write(output)

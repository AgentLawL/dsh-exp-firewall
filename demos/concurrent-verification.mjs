import { strict as assert } from 'node:assert'
import { readFile, mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { resolveConfig, SqliteExperienceFirewallStore } from '../lib/index.js'
import { evidenceEpoch } from '../lib/evidence.js'

const here = dirname(fileURLToPath(import.meta.url))
const root = await mkdtemp(join(tmpdir(), 'exp-firewall-concurrent-'))
const store = new SqliteExperienceFirewallStore(resolveConfig({ mode: 'enforce', dataDir: root }))
const absent = [{ kind: 'file-state', key: '/target', state: 'absent' }]
const present = [{ kind: 'file-state', key: '/target', state: 'present', version: 'v2' }]
const fingerprint = 'a'.repeat(64)

function observation(id, principal, at) {
  return {
    id: `observation-${id}`,
    operationId: `operation-${id}`,
    sessionId: `session-${principal}`,
    principalId: principal,
    toolCallId: `call-${id}`,
    scope: '/workspace',
    actionKind: 'file-read',
    fingerprint,
    preview: 'read /target',
    outcome: 'failure',
    failureCode: 'FS_NOT_FOUND',
    evidenceEpoch: evidenceEpoch(absent),
    evidence: absent,
    observedAt: at,
  }
}

try {
  for (const [id, principal, time, claim] of [
    ['a', 'principal-a', '2026-08-18T00:00:00.000Z', 'claim-a'],
    ['b', 'principal-b', '2026-08-18T00:00:01.000Z', 'claim-unused'],
  ]) {
    const seen = observation(id, principal, time)
    await store.record({ operationId: seen.operationId, observation: seen, newClaimId: claim, now: time })
  }
  await store.invalidateClaims({ operationId: 'operation-invalidate', evidence: present, now: '2026-08-18T00:00:02.000Z' })

  const principals = ['principal-c', 'principal-d', 'principal-e']
  const results = await Promise.all(principals.map((principal, index) => store.decide({
    operationId: `operation-decide-${String(index)}`,
    scope: '/workspace',
    actionKind: 'file-read',
    fingerprint,
    principalId: principal,
    evidence: present,
    now: '2026-08-18T00:00:03.000Z',
    candidateLease: {
      id: `lease-${principal.at(-1)}`,
      ownerPrincipalId: principal,
      evidenceEpoch: evidenceEpoch(present),
      expiresAt: '2026-08-18T00:01:03.000Z',
    },
  })))
  assert.equal(results.filter((decision) => decision.kind === 'verify').length, 1)
  assert.equal(results.filter((decision) => decision.kind === 'wait').length, 2)
  const lines = results.map((decision, index) => decision.kind === 'verify'
    ? `${principals[index]} | decision=verify | reason=${decision.reason} | lease=${decision.leaseId}`
    : `${principals[index]} | decision=wait | reason=${decision.reason} | owner=${decision.owner}`)
  const summary = await store.summary()
  lines.push(`summary | leasesGranted=${String(summary.leasesGranted)} | verificationWaits=${String(summary.verificationWaits)}`)
  const output = `${lines.join('\n')}\n`
  if (process.argv.includes('--verify')) {
    assert.equal(output, await readFile(join(here, 'concurrent-verification.snapshot.txt'), 'utf8'))
  }
  process.stdout.write(output)
} finally {
  await store.shutdown()
  await rm(root, { recursive: true, force: true })
}

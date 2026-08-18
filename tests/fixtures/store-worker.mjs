import { DatabaseSync } from 'node:sqlite'

import { resolveConfig } from '../../src/config.ts'
import { evidenceEpoch } from '../../src/evidence.ts'
import { SqliteExperienceFirewallStore } from '../../src/store-service.ts'
import { DATABASE_FILENAME } from '../../src/store-sqlite.ts'

const input = JSON.parse(process.argv[2])
const oldEvidence = [{ kind: 'file-state', key: '/target', state: 'absent' }]
const newEvidence = [{ kind: 'file-state', key: '/target', state: 'present', version: 'v1' }]
const fingerprint = 'a'.repeat(64)

if (input.action === 'crash') {
  const database = new DatabaseSync(`${input.dataDir}/${DATABASE_FILENAME}`)
  database.exec('BEGIN IMMEDIATE')
  database
    .prepare('INSERT INTO operations(id, request_hash, result_json, created_at) VALUES (?, ?, NULL, ?)')
    .run('crash-operation', 'uncommitted', '2026-08-18T00:00:00.000Z')
  process.exit(17)
}

const store = new SqliteExperienceFirewallStore(
  resolveConfig({ mode: 'enforce', dataDir: input.dataDir, storeBusyDeadlineMs: 2_000 }),
)
try {
  if (input.action === 'record') {
    const observation = {
      id: input.observationId,
      operationId: input.operationId,
      sessionId: `session-${input.principalId}`,
      principalId: input.principalId,
      scope: '/workspace',
      actionKind: 'file-read',
      fingerprint,
      preview: 'read /target',
      outcome: 'failure',
      failureCode: 'FS_NOT_FOUND',
      evidenceEpoch: evidenceEpoch(oldEvidence),
      evidence: oldEvidence,
      observedAt: input.observedAt,
    }
    const result = await store.record({
      operationId: input.operationId,
      observation,
      newClaimId: input.claimId,
      now: input.observedAt,
    })
    process.stdout.write(`${JSON.stringify(result)}\n`)
  } else if (input.action === 'decide') {
    const result = await store.decide({
      operationId: input.operationId,
      scope: '/workspace',
      actionKind: 'file-read',
      fingerprint,
      principalId: input.principalId,
      evidence: newEvidence,
      now: input.now,
      candidateLease: {
        id: input.leaseId,
        claimId: input.claimId,
        ownerPrincipalId: input.principalId,
        evidenceEpoch: evidenceEpoch(newEvidence),
        expiresAt: input.expiresAt,
      },
    })
    process.stdout.write(`${JSON.stringify(result)}\n`)
  } else {
    throw new Error(`Unknown worker action: ${input.action}`)
  }
} finally {
  await store.shutdown()
}

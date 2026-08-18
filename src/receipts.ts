import { createHash } from 'node:crypto'
import type { DatabaseSync } from 'node:sqlite'

import { stableJson, type JsonValue } from './fingerprint.ts'
import type { ClaimId, EventId, OperationId } from './types/domain.ts'
import { FirewallError } from './types/errors.ts'

/** Result of an idempotent operation receipt execution. */
export interface OperationReceiptResult<Result> {
  result: Result
  replayed: boolean
}

/** Safe audit event insertion fields. */
export interface AuditEventInput {
  operationId: OperationId
  claimId?: ClaimId
  kind: string
  body: Record<string, JsonValue | undefined>
  occurredAt: string
}

/**
 * Hash a JSON request for operation replay identity.
 * @param request - Complete mutation request.
 * @returns Full lowercase SHA-256 digest.
 */
export function requestHash(request: unknown): string {
  return createHash('sha256').update(stableJson(request), 'utf8').digest('hex')
}

/**
 * Derive the normative deterministic audit event ID.
 * @param operationId - Owning mutation operation.
 * @param claimId - Related Claim, or undefined for Claim-free events.
 * @param eventKind - Stable event kind.
 * @returns `ev_`-prefixed SHA-256 identity.
 */
export function createEventId(
  operationId: OperationId,
  claimId: ClaimId | undefined,
  eventKind: string,
): EventId {
  const digest = createHash('sha256')
    .update(`${operationId}|${claimId ?? ''}|${eventKind}`, 'utf8')
    .digest('hex')
  return `ev_${digest}` as EventId
}

/**
 * Insert one deterministic audit event inside the caller's transaction.
 * @param database - Open Store connection with an active write transaction.
 * @param event - Safe event fields.
 * @returns Deterministic event ID.
 */
export function insertAuditEvent(database: DatabaseSync, event: AuditEventInput): EventId {
  const id = createEventId(event.operationId, event.claimId, event.kind)
  database
    .prepare(
      `INSERT INTO events(id, operation_id, claim_id, kind, body_json, occurred_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .run(
      id,
      event.operationId,
      event.claimId ?? null,
      event.kind,
      stableJson(event.body),
      event.occurredAt,
    )
  return id
}

function rollback(database: DatabaseSync): void {
  try {
    database.exec('ROLLBACK')
  } catch {
    // SQLite can auto-rollback a failed transaction; preserve the owning error.
  }
}

function mapTransactionError(error: unknown): never {
  if (error instanceof FirewallError) throw error
  const message = error instanceof Error ? error.message : String(error)
  if (/busy|locked/i.test(message)) {
    throw new FirewallError('STORE_BUSY', 'The Exp Firewall Store remained busy; retry the operation.')
  }
  if (/unique constraint failed/i.test(message)) {
    throw new FirewallError('REVISION_CONFLICT', 'A concurrent Store mutation won a uniqueness race; reread and retry.')
  }
  if (/constraint failed/i.test(message)) {
    throw new FirewallError('INVARIANT_VIOLATION', 'A Store mutation violated a persisted invariant.')
  }
  throw new FirewallError('STORE_CORRUPT', 'The Exp Firewall Store transaction failed; inspect database integrity.')
}

/**
 * Execute a mutation exactly once and persist its original JSON result.
 *
 * The receipt insert, callback side effects, and stored result share one
 * `BEGIN IMMEDIATE` transaction. A competing connection therefore observes
 * either no receipt or the complete committed result, never an in-progress row.
 *
 * @param database - Open Store connection.
 * @param operationId - Caller-owned idempotency identity.
 * @param request - Complete JSON mutation request.
 * @param createdAt - Explicit UTC receipt time.
 * @param mutate - Transactional side effects returning a JSON result.
 * @returns Original or newly committed result and replay indicator.
 */
export function withOperationReceipt<Result>(
  database: DatabaseSync,
  operationId: OperationId,
  request: unknown,
  createdAt: string,
  mutate: (database: DatabaseSync) => Result,
): OperationReceiptResult<Result> {
  const hash = requestHash(request)
  try {
    database.exec('BEGIN IMMEDIATE')
    const existing = database
      .prepare('SELECT request_hash, result_json FROM operations WHERE id = ?')
      .get(operationId) as { request_hash: string; result_json: string | null } | undefined
    if (existing !== undefined) {
      if (existing.request_hash !== hash) {
        rollback(database)
        throw new FirewallError(
          'OPERATION_REPLAY_CONFLICT',
          'The operation ID was already used for a different request; generate a new operation ID.',
        )
      }
      if (existing.result_json === null) {
        rollback(database)
        throw new FirewallError('INVARIANT_VIOLATION', 'A committed operation receipt is missing its result.')
      }
      const result = JSON.parse(existing.result_json) as Result
      database.exec('COMMIT')
      return { result, replayed: true }
    }

    database
      .prepare('INSERT INTO operations(id, request_hash, result_json, created_at) VALUES (?, ?, NULL, ?)')
      .run(operationId, hash, createdAt)
    const result = mutate(database)
    const resultJson = stableJson(result)
    database.prepare('UPDATE operations SET result_json = ? WHERE id = ?').run(resultJson, operationId)
    database.exec('COMMIT')
    return { result: JSON.parse(resultJson) as Result, replayed: false }
  } catch (error) {
    rollback(database)
    return mapTransactionError(error)
  }
}

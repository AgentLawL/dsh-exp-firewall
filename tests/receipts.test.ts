import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'

import { createEventId, insertAuditEvent, requestHash, withOperationReceipt } from '../src/receipts.ts'
import { openSqliteDatabase } from '../src/store-sqlite.ts'
import type { ClaimId } from '../src/types/domain.ts'
import { FirewallError } from '../src/types/errors.ts'
import { operationId } from './helpers.ts'

const temporaryDirectories: string[] = []

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'exp-firewall-receipt-'))
  temporaryDirectories.push(directory)
  return directory
}

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })))
})

describe('operation receipts and deterministic events', () => {
  it('hashes stable JSON independent of object field order', () => {
    expect(requestHash({ b: 2, a: 1 })).toBe(requestHash({ a: 1, b: 2 }))
  })

  it('derives event identity exactly from operation, optional Claim, and kind', () => {
    expect(createEventId(operationId('op-a'), undefined, 'decision')).toMatch(/^ev_[0-9a-f]{64}$/)
    expect(createEventId(operationId('op-a'), undefined, 'decision')).toBe(
      createEventId(operationId('op-a'), undefined, 'decision'),
    )
    expect(createEventId(operationId('op-a'), undefined, 'decision')).not.toBe(
      createEventId(operationId('op-a'), 'claim-a' as ClaimId, 'decision'),
    )
  })

  it('returns the original result and performs side effects once on replay', async () => {
    const directory = await temporaryDirectory()
    const store = openSqliteDatabase(directory)
    let mutationCalls = 0
    try {
      const execute = () =>
        withOperationReceipt(
          store.connection,
          operationId('op-once'),
          { action: 'record', value: 1 },
          '2026-08-18T00:00:00.000Z',
          (database) => {
            mutationCalls += 1
            insertAuditEvent(database, {
              operationId: operationId('op-once'),
              kind: 'decision',
              body: { decision: 'allow' },
              occurredAt: '2026-08-18T00:00:00.000Z',
            })
            return { decision: 'allow', sequence: mutationCalls }
          },
        )

      expect(execute()).toEqual({ result: { decision: 'allow', sequence: 1 }, replayed: false })
      expect(execute()).toEqual({ result: { decision: 'allow', sequence: 1 }, replayed: true })
      expect(mutationCalls).toBe(1)
      expect(store.connection.prepare('SELECT COUNT(*) AS count FROM events').get()).toMatchObject({ count: 1 })
      expect(store.connection.prepare('SELECT COUNT(*) AS count FROM operations').get()).toMatchObject({ count: 1 })
    } finally {
      store.close()
    }
  })

  it('shares replay receipts across two database connections', async () => {
    const directory = await temporaryDirectory()
    const first = openSqliteDatabase(directory)
    const second = openSqliteDatabase(directory)
    try {
      const initial = withOperationReceipt(
        first.connection,
        operationId('op-shared'),
        { value: 1 },
        '2026-08-18T00:00:00.000Z',
        () => ({ owner: 'first' }),
      )
      const replay = withOperationReceipt(
        second.connection,
        operationId('op-shared'),
        { value: 1 },
        '2026-08-18T00:00:01.000Z',
        () => ({ owner: 'second' }),
      )
      expect(initial).toEqual({ result: { owner: 'first' }, replayed: false })
      expect(replay).toEqual({ result: { owner: 'first' }, replayed: true })
    } finally {
      first.close()
      second.close()
    }
  })

  it('rejects an operation ID reused with a different request hash', async () => {
    const directory = await temporaryDirectory()
    const store = openSqliteDatabase(directory)
    try {
      withOperationReceipt(
        store.connection,
        operationId('op-conflict'),
        { value: 1 },
        '2026-08-18T00:00:00.000Z',
        () => ({ ok: true }),
      )
      try {
        withOperationReceipt(
          store.connection,
          operationId('op-conflict'),
          { value: 2 },
          '2026-08-18T00:00:01.000Z',
          () => ({ ok: false }),
        )
        throw new Error('expected replay conflict')
      } catch (error) {
        expect(error).toBeInstanceOf(FirewallError)
        expect((error as FirewallError).code).toBe('OPERATION_REPLAY_CONFLICT')
      }
    } finally {
      store.close()
    }
  })

  it('rolls back the receipt and every callback side effect on failure', async () => {
    const directory = await temporaryDirectory()
    const store = openSqliteDatabase(directory)
    try {
      expect(() =>
        withOperationReceipt(
          store.connection,
          operationId('op-rollback'),
          { value: 1 },
          '2026-08-18T00:00:00.000Z',
          (database) => {
            insertAuditEvent(database, {
              operationId: operationId('op-rollback'),
              kind: 'decision',
              body: { decision: 'allow' },
              occurredAt: '2026-08-18T00:00:00.000Z',
            })
            throw new FirewallError('INVARIANT_VIOLATION', 'Injected transactional failure.')
          },
        ),
      ).toThrowError(FirewallError)
      expect(store.connection.prepare('SELECT COUNT(*) AS count FROM operations').get()).toMatchObject({ count: 0 })
      expect(store.connection.prepare('SELECT COUNT(*) AS count FROM events').get()).toMatchObject({ count: 0 })
    } finally {
      store.close()
    }
  })
})

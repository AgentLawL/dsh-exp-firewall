import { Context } from '@deepseek-ai/cordis'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

import * as ServicePlugin from '../src/service.ts'
import { FirewallNotificationBus } from '../src/service.ts'
import { openSqliteDatabase } from '../src/store-sqlite.ts'

describe('Cordis Service Provider lifecycle', () => {
  it('isolates throwing and rejecting read-surface subscribers and suppresses late publications', async () => {
    const errors: unknown[] = []
    const bus = new FirewallNotificationBus((error) => errors.push(error))
    const received: string[] = []
    bus.subscribe(() => {
      throw new Error('broken sync subscriber')
    })
    bus.subscribe((notification) => {
      received.push(notification.kind)
    })
    bus.subscribe((async () => {
      throw new Error('broken async subscriber')
    }) as never)
    bus.publish({ kind: 'decision', operationId: 'op-notify' as never })
    await Promise.resolve()
    expect(received).toEqual(['decision'])
    expect(errors).toHaveLength(2)
    bus.close()
    bus.publish({ kind: 'observation', operationId: 'op-late' as never })
    expect(received).toEqual(['decision'])
  })

  it('registers ctx.expFirewall before consumers and closes SQLite on effect disposal', async () => {
    const dataDir = await mkdtemp(join(tmpdir(), 'exp-firewall-provider-'))
    const ctx = new Context()
    try {
      const fiber = await ctx.plugin(ServicePlugin, { dataDir })
      await expect(ctx.expFirewall.summary()).resolves.toMatchObject({ suspectedClaims: 0, callsDenied: 0 })
      await fiber.dispose()
      const reloaded = await ctx.plugin(ServicePlugin, { dataDir })
      await expect(ctx.expFirewall.summary()).resolves.toMatchObject({ suspectedClaims: 0, callsDenied: 0 })
      await reloaded.dispose()
      const reopened = openSqliteDatabase(dataDir)
      expect(reopened.connection.prepare('PRAGMA quick_check').get()).toMatchObject({ quick_check: 'ok' })
      reopened.close()
    } finally {
      await ctx.fiber.dispose()
      await rm(dataDir, { recursive: true, force: true })
    }
  })
})

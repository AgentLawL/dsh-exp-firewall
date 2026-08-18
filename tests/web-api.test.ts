import { Context } from '@deepseek-ai/cordis'
import WebServer from '@deepseek-ai/dsh-host-webserver'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'

import * as ServicePlugin from '../src/service.ts'
import * as DashboardPlugin from '../src/web-api.ts'
import { claimId, observation, operationId } from './helpers.ts'

let context: Context | undefined
let dataDir: string | undefined

afterEach(async () => {
  await context?.fiber.dispose()
  context = undefined
  if (dataDir !== undefined) await rm(dataDir, { recursive: true, force: true })
  dataDir = undefined
})

async function setup() {
  dataDir = await mkdtemp(join(tmpdir(), 'exp-firewall-http-'))
  context = new Context()
  await context.plugin(WebServer, { host: '127.0.0.1', port: 0 })
  await context.plugin(ServicePlugin, { dataDir })
  await context.plugin(DashboardPlugin, { dataDir, dashboard: { enabled: true, host: '127.0.0.1' } })
  const base = `http://127.0.0.1:${context.webServer.port}/plugins/exp-firewall/api`
  return { ctx: context, base }
}

describe('read-only HTTP API', () => {
  it('serves summary, filtered pages, detail, events, and stable boundary errors', async () => {
    const { ctx, base } = await setup()
    const seen = observation({
      id: 'http-observation', principal: 'http-agent', at: '2026-08-18T00:00:00.000Z',
      outcome: 'failure', failureCode: 'FS_NOT_FOUND',
    })
    await ctx.expFirewall.record({
      operationId: seen.operationId,
      observation: seen,
      newClaimId: claimId('claim-http'),
      now: seen.observedAt,
    })

    const summary = await fetch(`${base}/summary?scope=${encodeURIComponent('/workspace')}`)
    expect(summary.status).toBe(200)
    expect(await summary.json()).toMatchObject({ suspectedClaims: 1, callsDenied: 0 })

    const claims = await fetch(`${base}/claims?status=suspected&limit=1`)
    expect(await claims.json()).toMatchObject({ items: [{ id: 'claim-http', preview: 'read /target' }] })
    const detail = await fetch(`${base}/claims/claim-http`)
    expect(await detail.json()).toMatchObject({ id: 'claim-http', observations: [{ failureCode: 'FS_NOT_FOUND' }] })
    const events = await fetch(`${base}/events?claim=claim-http&limit=10`)
    expect(await events.json()).toMatchObject({ items: expect.arrayContaining([expect.objectContaining({ claimId: 'claim-http' })]) })

    const invalid = await fetch(`${base}/claims?limit=201`)
    expect(invalid.status).toBe(400)
    expect(await invalid.json()).toMatchObject({ code: 'INVALID_ACTION' })
    const missing = await fetch(`${base}/claims/claim-missing`)
    expect(missing.status).toBe(404)
    expect(await missing.json()).toMatchObject({ code: 'CLAIM_NOT_FOUND' })
    const method = await fetch(`${base}/summary`, { method: 'POST' })
    expect(method.status).toBe(405)

    const later = observation({
      id: 'http-later', principal: 'other-agent', at: '2026-08-18T00:00:01.000Z',
      outcome: 'success',
    })
    await expect(ctx.expFirewall.record({
      operationId: operationId('op-http-later'),
      observation: { ...later, operationId: operationId('op-http-later') },
      newClaimId: claimId('unused-http'),
      now: later.observedAt,
    })).resolves.toMatchObject({ duplicate: false })
  })

  it('keeps the dashboard optional and rejects a host mismatch at load time', async () => {
    dataDir = await mkdtemp(join(tmpdir(), 'exp-firewall-http-disabled-'))
    context = new Context()
    await context.plugin(WebServer, { host: '127.0.0.1', port: 0 })
    await context.plugin(ServicePlugin, { dataDir })
    await context.plugin(DashboardPlugin, { dataDir, dashboard: { enabled: false } })
    expect((await fetch(`http://127.0.0.1:${context.webServer.port}/plugins/exp-firewall/api/summary`)).status).toBe(404)
    await expect(context.plugin(DashboardPlugin, {
      dataDir,
      dashboard: { enabled: true, host: '0.0.0.0' },
    })).rejects.toThrow(/dashboard\.host/)
  })
})

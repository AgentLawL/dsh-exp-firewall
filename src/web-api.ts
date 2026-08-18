import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-host-webserver'
import type { IncomingMessage, ServerResponse } from 'node:http'

import { resolveConfig, type ConfigInput } from './config.ts'
import type { ClaimStatus } from './types/domain.ts'
import { FirewallError } from './types/errors.ts'

/** Optional read-only dashboard plugin entry name. */
export const dashboardPluginName = 'exp-firewall-dashboard'
/** Dashboard dependencies are explicit so it remains separately optional. */
export const inject = ['expFirewall', 'webServer']

const API_PREFIX = '/plugins/exp-firewall/api'
const CLAIM_STATUSES = new Set<ClaimStatus>([
  'suspected',
  'corroborated',
  'stale',
  'verifying',
  'contradicted',
  'resolved',
  'superseded',
])

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
  res.end(JSON.stringify(body))
}

function one(query: URLSearchParams, name: string): string | undefined {
  const values = query.getAll(name)
  if (values.length > 1) throw new FirewallError('INVALID_ACTION', `Query parameter ${name} must appear at most once.`)
  const value = values[0]
  return value === undefined || value.length === 0 ? undefined : value
}

function page(query: URLSearchParams): { cursor?: string; limit?: number } {
  const cursor = one(query, 'cursor')
  const rawLimit = one(query, 'limit')
  const limit = rawLimit === undefined ? undefined : Number(rawLimit)
  if (limit !== undefined && (!Number.isSafeInteger(limit) || limit < 1 || limit > 200)) {
    throw new FirewallError('INVALID_ACTION', 'Query parameter limit must be an integer from 1 to 200.')
  }
  return { ...(cursor === undefined ? {} : { cursor }), ...(limit === undefined ? {} : { limit }) }
}

function allowOnly(query: URLSearchParams, names: readonly string[]): void {
  const allowed = new Set(names)
  for (const name of query.keys()) {
    if (!allowed.has(name)) throw new FirewallError('INVALID_ACTION', `Unknown query parameter ${name}.`)
  }
}

function errorResponse(error: unknown): { status: number; body: { code: string; message: string } } {
  if (error instanceof FirewallError) {
    return {
      status: error.code === 'CLAIM_NOT_FOUND' ? 404 : error.code === 'INVALID_ACTION' ? 400 : 503,
      body: { code: error.code, message: error.message },
    }
  }
  return { status: 503, body: { code: 'STORE_CORRUPT', message: 'The read-only Exp Firewall API is unavailable.' } }
}

async function route(ctx: Context, req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (req.method !== 'GET') {
    json(res, 405, { code: 'INVALID_ACTION', message: 'This API accepts GET requests only.' })
    return
  }
  const url = new URL(req.url ?? '/', 'http://exp-firewall.local')
  const signal = new AbortController()
  req.once('aborted', () => signal.abort())
  try {
    if (url.pathname === `${API_PREFIX}/summary`) {
      allowOnly(url.searchParams, ['scope'])
      const scope = one(url.searchParams, 'scope')
      json(res, 200, await ctx.expFirewall.summary({ ...(scope === undefined ? {} : { scope }), signal: signal.signal }))
      return
    }
    if (url.pathname === `${API_PREFIX}/claims`) {
      allowOnly(url.searchParams, ['scope', 'status', 'cursor', 'limit'])
      const scope = one(url.searchParams, 'scope')
      const status = one(url.searchParams, 'status')
      if (status !== undefined && !CLAIM_STATUSES.has(status as ClaimStatus)) {
        throw new FirewallError('INVALID_ACTION', 'Query parameter status is not a known Claim status.')
      }
      json(res, 200, await ctx.expFirewall.listClaims({
        ...page(url.searchParams),
        ...(scope === undefined ? {} : { scope }),
        ...(status === undefined ? {} : { status: status as ClaimStatus }),
        signal: signal.signal,
      }))
      return
    }
    if (url.pathname.startsWith(`${API_PREFIX}/claims/`)) {
      allowOnly(url.searchParams, [])
      const id = decodeURIComponent(url.pathname.slice(`${API_PREFIX}/claims/`.length))
      if (id.length === 0 || id.includes('/')) throw new FirewallError('INVALID_ACTION', 'A single Claim ID is required.')
      const claim = await ctx.expFirewall.getClaim(id as never, signal.signal)
      if (claim === undefined) throw new FirewallError('CLAIM_NOT_FOUND', 'The requested Claim does not exist.')
      json(res, 200, claim)
      return
    }
    if (url.pathname === `${API_PREFIX}/events`) {
      allowOnly(url.searchParams, ['claim', 'cursor', 'limit'])
      const claimId = one(url.searchParams, 'claim')
      json(res, 200, await ctx.expFirewall.listEvents({
        ...page(url.searchParams),
        ...(claimId === undefined ? {} : { claimId: claimId as never }),
        signal: signal.signal,
      }))
      return
    }
    json(res, 404, { code: 'CLAIM_NOT_FOUND', message: 'The requested read-only endpoint does not exist.' })
  } catch (error) {
    const mapped = errorResponse(error)
    json(res, mapped.status, mapped.body)
  }
}

/** Register the optional read-only HTTP routes on the shared host WebServer. */
export function apply(ctx: Context, input: ConfigInput = {}): void {
  const config = resolveConfig(input)
  if (!config.dashboard.enabled) return
  if (ctx.webServer.host !== config.dashboard.host) {
    throw new FirewallError('INVALID_CONFIG', 'dashboard.host must match the configured WebServer host.')
  }
  ctx.effect(
    () => ctx.webServer.register({
      kind: 'prefix',
      path: API_PREFIX,
      handler: (req: IncomingMessage, res: ServerResponse) => route(ctx, req, res),
    }),
    'exp-firewall read-only HTTP API',
  )
}

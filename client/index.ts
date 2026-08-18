/** Optional read-only browser client and framework-neutral view models. */
import type { ClientContext } from '@deepseek-ai/dsh-client-runtime/client'
import type {} from '@deepseek-ai/dsh-client-ui-settings/client'
import type {
  ClaimDetail,
  ClaimStatus,
  ClaimView,
  FirewallSummary,
  Page,
} from 'exp-firewall/types'

import { FirewallDashboard } from './FirewallDashboard.tsx'

export { FirewallDashboard } from './FirewallDashboard.tsx'

/** Public read-only audit event shape returned by the HTTP API. */
export interface FirewallEventDto {
  id: string
  operationId: string
  claimId?: string
  kind: string
  body: Record<string, unknown>
  occurredAt: string
}

/** Browser plugin name. */
export const name = 'exp-firewall-client'
/** Browser services required to register the optional Settings tab. */
export const inject = ['slots']

/** Fetch-compatible function accepted by the API client. */
export type FirewallFetch = (input: string, init?: RequestInit) => Promise<Response>

/** Stable API failure carrying the server's public error code. */
export class FirewallApiError extends Error {
  constructor(readonly code: string, message: string, readonly status: number) {
    super(message)
    this.name = 'FirewallApiError'
  }
}

function query(input: Record<string, string | number | undefined>): string {
  const values = new URLSearchParams()
  for (const [key, value] of Object.entries(input)) {
    if (value !== undefined) values.set(key, String(value))
  }
  const text = values.toString()
  return text.length === 0 ? '' : `?${text}`
}

/** Read-only HTTP client used by the optional browser plugin. */
export class ExperienceFirewallClient {
  constructor(
    readonly baseUrl = '/plugins/exp-firewall/api',
    readonly fetcher: FirewallFetch = globalThis.fetch.bind(globalThis),
  ) {}

  async #get<Value>(path: string, signal?: AbortSignal): Promise<Value> {
    const response = await this.fetcher(`${this.baseUrl}${path}`, {
      method: 'GET',
      ...(signal === undefined ? {} : { signal }),
    })
    const body = await response.json() as unknown
    if (!response.ok) {
      const error = body as { code?: unknown; message?: unknown }
      throw new FirewallApiError(
        typeof error.code === 'string' ? error.code : 'STORE_CORRUPT',
        typeof error.message === 'string' ? error.message : 'The read-only API request failed.',
        response.status,
      )
    }
    return body as Value
  }

  summary(scope?: string, signal?: AbortSignal): Promise<FirewallSummary> {
    return this.#get(`/summary${query({ scope })}`, signal)
  }

  claims(filter: { scope?: string; status?: ClaimStatus; cursor?: string; limit?: number } = {}, signal?: AbortSignal): Promise<Page<ClaimView>> {
    return this.#get(`/claims${query(filter)}`, signal)
  }

  claim(id: string, signal?: AbortSignal): Promise<ClaimDetail> {
    return this.#get(`/claims/${encodeURIComponent(id)}`, signal)
  }

  events(filter: { claim?: string; cursor?: string; limit?: number } = {}, signal?: AbortSignal): Promise<Page<FirewallEventDto>> {
    return this.#get(`/events${query(filter)}`, signal)
  }
}

/** Overview state emitted by the one-second read-only poller. */
export type OverviewState =
  | { kind: 'loading' }
  | { kind: 'ready'; metrics: ReturnType<typeof overviewMetrics> }
  | { kind: 'unavailable'; message: string }
  | { kind: 'stopped' }

/** Product metrics proven directly by Store counters. */
export function overviewMetrics(summary: FirewallSummary) {
  return {
    suspectedClaims: summary.suspectedClaims,
    corroboratedClaims: summary.corroboratedClaims,
    warningsEmitted: summary.warningsEmitted,
    callsDenied: summary.callsDenied,
    leasesGranted: summary.leasesGranted,
    resolvedClaims: summary.resolvedClaims,
    crossAgentHits: summary.crossAgentHits,
  }
}

/** Cancellation-safe periodic Overview reader. */
export class OverviewPoller {
  #timer?: ReturnType<typeof setTimeout>
  #controller?: AbortController
  #running = false

  constructor(
    readonly client: ExperienceFirewallClient,
    readonly intervalMs: number,
    readonly publish: (state: OverviewState) => void,
  ) {
    if (!Number.isSafeInteger(intervalMs) || intervalMs <= 0) throw new TypeError('poll interval must be positive')
  }

  start(): void {
    if (this.#running) return
    this.#running = true
    this.publish({ kind: 'loading' })
    void this.#poll()
  }

  async #poll(): Promise<void> {
    if (!this.#running) return
    this.#controller = new AbortController()
    try {
      const summary = await this.client.summary(undefined, this.#controller.signal)
      if (this.#running) this.publish({ kind: 'ready', metrics: overviewMetrics(summary) })
    } catch (error) {
      if (this.#running) this.publish({ kind: 'unavailable', message: error instanceof Error ? error.message : 'Unavailable' })
    }
    if (this.#running) this.#timer = setTimeout(() => void this.#poll(), this.intervalMs)
  }

  stop(): void {
    if (!this.#running) return
    this.#running = false
    this.#controller?.abort()
    if (this.#timer !== undefined) clearTimeout(this.#timer)
    this.publish({ kind: 'stopped' })
  }
}

/** Framework-neutral Claim Explorer row; every string is treated as quoted data. */
export function claimExplorerRow(claim: ClaimView) {
  return {
    id: claim.id,
    status: claim.status,
    preview: JSON.stringify(claim.preview),
    scope: JSON.stringify(claim.scope),
    supporterCount: claim.supporterCount,
    updatedAt: claim.updatedAt,
  }
}

/** Framework-neutral Claim Detail model with provenance and lifecycle history. */
export function claimDetailModel(claim: ClaimDetail, events: readonly FirewallEventDto[]) {
  const decisionEvent = events.find((event) => event.kind === 'decision')
  const verificationObservation = [...claim.observations].reverse().find((observation) => observation.outcome === 'success')
  const priorEvidence = new Map(claim.evidence.map((witness) => [witness.key, witness]))
  const currentEvidence = new Map((verificationObservation?.evidence ?? claim.evidence).map((witness) => [witness.key, witness]))
  const evidenceDiff = [...new Set([...priorEvidence.keys(), ...currentEvidence.keys()])].flatMap((key) => {
    const before = priorEvidence.get(key)
    const after = currentEvidence.get(key)
    return JSON.stringify(before) === JSON.stringify(after) ? [] : [{ key, before, after }]
  })
  return {
    claim: claimExplorerRow(claim),
    fingerprint: claim.fingerprint,
    evidenceEpoch: claim.evidenceEpoch,
    evidence: claim.evidence,
    observations: claim.observations.map((observation) => ({
      id: observation.id,
      source: { sessionId: observation.sessionId, principalId: observation.principalId, toolCallId: observation.toolCallId },
      outcome: observation.outcome,
      failureCode: observation.failureCode,
      observedAt: observation.observedAt,
    })),
    lease: claim.lease,
    currentDecision: decisionEvent === undefined
      ? undefined
      : { decision: decisionEvent.body.kind, reason: decisionEvent.body.reason },
    counts: {
      warnings: events.filter((event) => event.kind === 'warning-emitted').length,
      denials: events.filter((event) => event.kind === 'call-denied').length,
      verifications: events.filter((event) => event.kind === 'lease-granted').length,
    },
    supporters: [...new Set(claim.observations.filter((item) => item.outcome === 'failure').map((item) => item.principalId))],
    counterexamples: claim.observations.filter((item) => item.outcome === 'success').map((item) => item.id),
    evidenceDiff,
    transitions: events.filter((event) => event.kind.startsWith('claim-transition/')),
  }
}

/** Register the read-only Exp Firewall dashboard as a Plugins settings tab. */
export function apply(ctx: ClientContext): void {
  const client = new ExperienceFirewallClient()
  ctx.slots.inject('settings.plugins.tab', () => ctx.slots.register({
    name: 'settings.plugins.tab',
    id: 'exp-firewall',
    order: 20,
    label: () => 'Exp Firewall',
    inject: () => ({ client, pollIntervalMs: 1_000 }),
  }, FirewallDashboard))
}

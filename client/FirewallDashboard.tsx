import { useCallback, useEffect, useMemo, useState, type CSSProperties, type ReactNode } from 'react'
import type { InjectFace, PropsLocale, PropsRuntime, TranslateNS } from '@deepseek-ai/dsh-client-ui-slots'

import type { ClaimDetail, ClaimStatus, ClaimView, Page } from 'exp-firewall/types'
import {
  claimDetailModel,
  claimExplorerRow,
  type ExperienceFirewallClient,
  type FirewallEventDto,
  type OverviewState,
  OverviewPoller,
} from './index.ts'
import { NS } from './locales.ts'

/** Data dependencies injected by the browser plugin registration. */
export interface FirewallDashboardInjected {
  client: ExperienceFirewallClient
  pollIntervalMs: number
}

/** Props composed by the DSH Settings slot renderer. */
export type FirewallDashboardProps = PropsRuntime<'settings.plugins.tab'> & PropsLocale<typeof NS> & InjectFace<FirewallDashboardInjected>

const panel: CSSProperties = { display: 'grid', gap: 16, padding: 16, color: 'inherit' }
const cards: CSSProperties = { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 8 }
const card: CSSProperties = { border: '1px solid currentColor', borderRadius: 8, padding: 10, opacity: 0.9 }
const table: CSSProperties = { borderCollapse: 'collapse', width: '100%', fontSize: 13 }
const cell: CSSProperties = { borderBottom: '1px solid color-mix(in srgb, currentColor 20%, transparent)', padding: 8, textAlign: 'left', verticalAlign: 'top' }
const controls: CSSProperties = { display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }

function Json({ value }: { value: unknown }): ReactNode {
  return <code style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(value)}</code>
}

const CLAIM_STATUSES = ['suspected', 'corroborated', 'stale', 'verifying', 'contradicted', 'resolved', 'superseded'] as const satisfies readonly ClaimStatus[]

function assertNever(value: never): never {
  throw new Error(`Unhandled dashboard value: ${JSON.stringify(value)}`)
}

/** Localized human label for a stable Claim status value. */
export function claimStatusLabel(status: ClaimStatus, t: TranslateNS<typeof NS>): string {
  switch (status) {
    case 'suspected': return t('status.suspected')
    case 'corroborated': return t('status.corroborated')
    case 'stale': return t('status.stale')
    case 'verifying': return t('status.verifying')
    case 'contradicted': return t('status.contradicted')
    case 'resolved': return t('status.resolved')
    case 'superseded': return t('status.superseded')
    default: return assertNever(status)
  }
}

type OverviewMetricKey = keyof Extract<OverviewState, { kind: 'ready' }>['metrics']

/** Localized human label for a stable Overview metric key. */
export function overviewMetricLabel(key: OverviewMetricKey, t: TranslateNS<typeof NS>): string {
  switch (key) {
    case 'suspectedClaims': return t('metric.suspectedClaims')
    case 'corroboratedClaims': return t('metric.corroboratedClaims')
    case 'warningsEmitted': return t('metric.warningsEmitted')
    case 'callsDenied': return t('metric.callsDenied')
    case 'leasesGranted': return t('metric.leasesGranted')
    case 'resolvedClaims': return t('metric.resolvedClaims')
    case 'crossAgentHits': return t('metric.crossAgentHits')
    default: return assertNever(key)
  }
}

function ClaimDetails({ detail, events, t }: { detail: ClaimDetail; events: readonly FirewallEventDto[]; t: TranslateNS<typeof NS> }): ReactNode {
  const model = claimDetailModel(detail, events)
  return (
    <section aria-label={t('detail.aria')} style={panel}>
      <h3>{t('detail.title')}</h3>
      <dl>
        <dt>{t('detail.statusPreview')}</dt><dd>{claimStatusLabel(model.claim.status, t)} · {model.claim.preview}</dd>
        <dt>{t('detail.decision')}</dt><dd>{model.currentDecision === undefined ? t('detail.noDecision') : `${String(model.currentDecision.decision)} / ${String(model.currentDecision.reason)}`}</dd>
        <dt>{t('detail.evidenceEpoch')}</dt><dd><code>{model.evidenceEpoch}</code></dd>
        <dt>{t('detail.supporters')}</dt><dd>{model.supporters.join(', ') || t('detail.none')}</dd>
        <dt>{t('detail.lease')}</dt><dd>{model.lease === undefined ? t('detail.none') : <Json value={model.lease} />}</dd>
        <dt>{t('detail.counts')}</dt><dd>{[
          t('detail.warningCount', { count: model.counts.warnings }),
          t('detail.denialCount', { count: model.counts.denials }),
          t('detail.verificationCount', { count: model.counts.verifications }),
        ].join(' · ')}</dd>
      </dl>
      <h4>{t('detail.evidenceDiff')}</h4>
      <Json value={{ evidence: model.evidence, diff: model.evidenceDiff }} />
      <h4>{t('detail.observations')}</h4>
      {model.observations.length === 0 ? <p>{t('detail.noObservations')}</p> : (
        <ol>{model.observations.map(item => <li key={item.id}><Json value={item} /></li>)}</ol>
      )}
      <h4>{t('detail.counterexamples')}</h4>
      <p>{model.counterexamples.join(', ') || t('detail.none')}</p>
      <h4>{t('detail.transitions')}</h4>
      {model.transitions.length === 0 ? <p>{t('detail.noTransitions')}</p> : (
        <ol>{model.transitions.map(item => <li key={item.id}><Json value={{ kind: item.kind, at: item.occurredAt, body: item.body }} /></li>)}</ol>
      )}
    </section>
  )
}

/** Read-only Overview, Claim Explorer, and Claim Detail dashboard. */
export function FirewallDashboard({ client, pollIntervalMs, t }: FirewallDashboardProps): ReactNode {
  const [overview, setOverview] = useState<OverviewState>({ kind: 'loading' })
  const [status, setStatus] = useState<ClaimStatus | ''>('')
  const [claims, setClaims] = useState<Page<ClaimView>>({ items: [] })
  const [selected, setSelected] = useState<string>()
  const [detail, setDetail] = useState<ClaimDetail>()
  const [events, setEvents] = useState<readonly FirewallEventDto[]>([])
  const [listError, setListError] = useState<string>()

  const loadClaims = useCallback(async (cursor?: string, append = false) => {
    try {
      const page = await client.claims({ ...(status === '' ? {} : { status }), ...(cursor === undefined ? {} : { cursor }), limit: 50 })
      setClaims(previous => ({ ...page, items: append ? [...previous.items, ...page.items] : page.items }))
      setListError(undefined)
    } catch (error) {
      setListError(t('explorer.unavailable', { message: error instanceof Error ? error.message : t('error.unknown') }))
    }
  }, [client, status, t])

  useEffect(() => {
    const poller = new OverviewPoller(client, pollIntervalMs, (state) => {
      setOverview(state)
      if (state.kind === 'ready') void loadClaims()
    })
    poller.start()
    return () => poller.stop()
  }, [client, loadClaims, pollIntervalMs])

  useEffect(() => { void loadClaims() }, [loadClaims])
  useEffect(() => {
    if (selected === undefined) {
      setDetail(undefined)
      setEvents([])
      return
    }
    const controller = new AbortController()
    void Promise.all([
      client.claim(selected, controller.signal),
      client.events({ claim: selected, limit: 200 }, controller.signal),
    ]).then(([nextDetail, nextEvents]) => {
      setDetail(nextDetail)
      setEvents(nextEvents.items)
    }, () => {
      if (!controller.signal.aborted) setDetail(undefined)
    })
    return () => controller.abort()
  }, [client, selected])

  const metrics = useMemo(
    () => overview.kind === 'ready'
      ? Object.entries(overview.metrics) as Array<[OverviewMetricKey, number]>
      : [],
    [overview],
  )
  return (
    <div style={panel} data-exp-firewall-dashboard>
      <header><h2>{t('dashboard.title')}</h2><p>{t('dashboard.intro')}</p></header>
      {overview.kind === 'loading' ? <p aria-live="polite">{t('dashboard.loading')}</p> : null}
      {overview.kind === 'unavailable' ? <p role="alert">{t('dashboard.unavailable', { message: overview.message })}</p> : null}
      {overview.kind === 'stopped' ? <p>{t('dashboard.stopped')}</p> : null}
      {metrics.length > 0 ? <section aria-label={t('overview.aria')} style={cards}>{metrics.map(([key, value]) => <div style={card} key={key}><strong>{overviewMetricLabel(key, t)}</strong><div>{value}</div></div>)}</section> : null}
      <section aria-label={t('explorer.aria')} style={panel}>
        <div style={controls}><h3>{t('explorer.title')}</h3><label>{t('explorer.status')} <select value={status} onChange={event => setStatus(event.currentTarget.value as ClaimStatus | '')}><option value="">{t('explorer.all')}</option>{CLAIM_STATUSES.map(value => <option key={value} value={value}>{claimStatusLabel(value, t)}</option>)}</select></label></div>
        {listError === undefined ? null : <p role="alert">{listError}</p>}
        {claims.items.length === 0 ? <p>{t('explorer.empty')}</p> : <table style={table}><thead><tr><th style={cell}>{t('column.status')}</th><th style={cell}>{t('column.preview')}</th><th style={cell}>{t('column.scope')}</th><th style={cell}>{t('column.supporters')}</th><th style={cell}>{t('column.updated')}</th></tr></thead><tbody>{claims.items.map(claim => { const row = claimExplorerRow(claim); return <tr key={row.id}><td style={cell}><button type="button" onClick={() => setSelected(row.id)}>{claimStatusLabel(row.status, t)}</button></td><td style={cell}>{row.preview}</td><td style={cell}>{row.scope}</td><td style={cell}>{row.supporterCount}</td><td style={cell}>{row.updatedAt}</td></tr> })}</tbody></table>}
        {claims.nextCursor === undefined ? null : <button type="button" onClick={() => void loadClaims(claims.nextCursor, true)}>{t('explorer.loadMore')}</button>}
      </section>
      {detail === undefined ? null : <ClaimDetails detail={detail} events={events} t={t} />}
    </div>
  )
}

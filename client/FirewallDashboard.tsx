import { useCallback, useEffect, useMemo, useState, type CSSProperties, type ReactNode } from 'react'
import type { InjectFace, PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'

import type { ClaimDetail, ClaimStatus, ClaimView, Page } from 'exp-firewall/types'
import {
  claimDetailModel,
  claimExplorerRow,
  type ExperienceFirewallClient,
  type FirewallEventDto,
  type OverviewState,
  OverviewPoller,
} from './index.ts'

/** Data dependencies injected by the browser plugin registration. */
export interface FirewallDashboardInjected {
  client: ExperienceFirewallClient
  pollIntervalMs: number
}

/** Props composed by the DSH Settings slot renderer. */
export type FirewallDashboardProps = PropsRuntime<'settings.plugins.tab'> & InjectFace<FirewallDashboardInjected>

const panel: CSSProperties = { display: 'grid', gap: 16, padding: 16, color: 'inherit' }
const cards: CSSProperties = { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 8 }
const card: CSSProperties = { border: '1px solid currentColor', borderRadius: 8, padding: 10, opacity: 0.9 }
const table: CSSProperties = { borderCollapse: 'collapse', width: '100%', fontSize: 13 }
const cell: CSSProperties = { borderBottom: '1px solid color-mix(in srgb, currentColor 20%, transparent)', padding: 8, textAlign: 'left', verticalAlign: 'top' }
const controls: CSSProperties = { display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }

function Json({ value }: { value: unknown }): ReactNode {
  return <code style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(value)}</code>
}

function ClaimDetails({ detail, events }: { detail: ClaimDetail; events: readonly FirewallEventDto[] }): ReactNode {
  const model = claimDetailModel(detail, events)
  return (
    <section aria-label="Claim detail" style={panel}>
      <h3>Claim detail</h3>
      <dl>
        <dt>Status / preview</dt><dd>{model.claim.status} · {model.claim.preview}</dd>
        <dt>Decision</dt><dd>{model.currentDecision === undefined ? 'No visible decision' : `${String(model.currentDecision.decision)} / ${String(model.currentDecision.reason)}`}</dd>
        <dt>Evidence epoch</dt><dd><code>{model.evidenceEpoch}</code></dd>
        <dt>Supporters</dt><dd>{model.supporters.join(', ') || 'None'}</dd>
        <dt>Lease</dt><dd>{model.lease === undefined ? 'None' : <Json value={model.lease} />}</dd>
        <dt>Counts</dt><dd><Json value={model.counts} /></dd>
      </dl>
      <h4>Evidence and diff</h4>
      <Json value={{ evidence: model.evidence, diff: model.evidenceDiff }} />
      <h4>Observation timeline</h4>
      {model.observations.length === 0 ? <p>No observations.</p> : (
        <ol>{model.observations.map(item => <li key={item.id}><Json value={item} /></li>)}</ol>
      )}
      <h4>Counterexamples</h4>
      <p>{model.counterexamples.join(', ') || 'None'}</p>
      <h4>Transitions</h4>
      {model.transitions.length === 0 ? <p>No transitions.</p> : (
        <ol>{model.transitions.map(item => <li key={item.id}><Json value={{ kind: item.kind, at: item.occurredAt, body: item.body }} /></li>)}</ol>
      )}
    </section>
  )
}

/** Read-only Overview, Claim Explorer, and Claim Detail dashboard. */
export function FirewallDashboard({ client, pollIntervalMs }: FirewallDashboardProps): ReactNode {
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
      setListError(error instanceof Error ? error.message : 'Claim Explorer unavailable')
    }
  }, [client, status])

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

  const metrics = useMemo(() => overview.kind === 'ready' ? Object.entries(overview.metrics) : [], [overview])
  return (
    <div style={panel} data-exp-firewall-dashboard>
      <header><h2>Exp Firewall</h2><p>Read-only policy provenance and Evidence lifecycle.</p></header>
      {overview.kind === 'loading' ? <p aria-live="polite">Loading overview…</p> : null}
      {overview.kind === 'unavailable' ? <p role="alert">Dashboard unavailable: {overview.message}</p> : null}
      {overview.kind === 'stopped' ? <p>Dashboard stopped.</p> : null}
      {metrics.length > 0 ? <section aria-label="Overview" style={cards}>{metrics.map(([key, value]) => <div style={card} key={key}><strong>{key}</strong><div>{value}</div></div>)}</section> : null}
      <section aria-label="Claim Explorer" style={panel}>
        <div style={controls}><h3>Claim Explorer</h3><label>Status <select value={status} onChange={event => setStatus(event.currentTarget.value as ClaimStatus | '')}><option value="">All</option>{['suspected', 'corroborated', 'stale', 'verifying', 'contradicted', 'resolved', 'superseded'].map(value => <option key={value} value={value}>{value}</option>)}</select></label></div>
        {listError === undefined ? null : <p role="alert">{listError}</p>}
        {claims.items.length === 0 ? <p>No Claims.</p> : <table style={table}><thead><tr><th style={cell}>Status</th><th style={cell}>Preview</th><th style={cell}>Scope</th><th style={cell}>Supporters</th><th style={cell}>Updated</th></tr></thead><tbody>{claims.items.map(claim => { const row = claimExplorerRow(claim); return <tr key={row.id}><td style={cell}><button type="button" onClick={() => setSelected(row.id)}>{row.status}</button></td><td style={cell}>{row.preview}</td><td style={cell}>{row.scope}</td><td style={cell}>{row.supporterCount}</td><td style={cell}>{row.updatedAt}</td></tr> })}</tbody></table>}
        {claims.nextCursor === undefined ? null : <button type="button" onClick={() => void loadClaims(claims.nextCursor, true)}>Load more</button>}
      </section>
      {detail === undefined ? null : <ClaimDetails detail={detail} events={events} />}
    </div>
  )
}

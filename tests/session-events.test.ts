import { describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import SessionStore, { SessionId } from '@deepseek-ai/dsh-session'

import {
  appendFirewallSessionEvent,
  projectFirewallDecisionNotice,
  replayFirewallSessionEvents,
  type ExperienceFirewallSessionEvents,
} from '../src/session-events.ts'
import { claimId, observationId, operationId } from './helpers.ts'
import { fp } from './helpers.ts'

describe('Exp Firewall Session events', () => {
  it('appends JSON-serializable observation, decision, and transition payloads in order', () => {
    const events: Array<{ type: string; data: unknown }> = []
    const session = { append: (type: string, data: unknown) => events.push({ type, data }) }
    const observation: ExperienceFirewallSessionEvents['exp-firewall/observation'] = {
      operationId: operationId('op-observation'),
      observationId: observationId('observation-a'),
      claimId: claimId('claim-a'),
      outcome: 'failure',
      fingerprint: fp,
    }
    appendFirewallSessionEvent(session, 'exp-firewall/observation', observation)
    appendFirewallSessionEvent(session, 'exp-firewall/decision', {
      operationId: operationId('op-decision'),
      claimId: claimId('claim-a'),
      decision: 'deny',
      reason: 'corroborated',
      revision: 2,
    })
    appendFirewallSessionEvent(session, 'exp-firewall/transition', {
      operationId: operationId('op-observation'),
      claimId: claimId('claim-a'),
      from: 'suspected',
      to: 'corroborated',
      revision: 2,
    })

    expect(() => JSON.stringify(events)).not.toThrow()
    expect(replayFirewallSessionEvents(events)).toEqual(events)
  })

  it('ignores unrelated replay events and retains correlation IDs', () => {
    const events = replayFirewallSessionEvents([
      { type: 'turn/start', data: { turn: 1 } },
      {
        type: 'exp-firewall/decision',
        data: { operationId: 'op-a', decision: 'warn', reason: 'suspected' },
      },
    ])
    expect(events).toEqual([
      {
        type: 'exp-firewall/decision',
        data: { operationId: 'op-a', decision: 'warn', reason: 'suspected' },
      },
    ])
  })

  it('projects model-visible text only from an already logged Decision payload', () => {
    expect(
      projectFirewallDecisionNotice(
        {
          operationId: operationId('op-a'),
          claimId: claimId('claim-a'),
          decision: 'wait',
          reason: 'verification-in-progress',
        },
        160,
      ),
    ).toBe('[exp-firewall] decision=wait reason=verification-in-progress claim=claim-a operation=op-a')
    expect(
      projectFirewallDecisionNotice(
        { operationId: operationId('op-allow'), decision: 'allow', reason: 'no-claim' },
        160,
      ),
    ).toBeUndefined()
  })

  it('appends and replays through the real DSH Session event log', async () => {
    const ctx = new Context()
    try {
      await ctx.plugin(SessionStore)
      const session = (ctx.sessions as unknown as {
        create(id: never, options: unknown): {
          append(event: unknown): void
          deriveMessages(): unknown[]
          events: import('../src/session-events.ts').FirewallReplayEvent[]
        }
      }).create(SessionId('firewall-events') as never, { meta: { cwd: '/workspace' } })
      appendFirewallSessionEvent(session as unknown as import('../src/session-events.ts').FirewallSessionAppender, 'exp-firewall/decision', {
        operationId: operationId('op-real'),
        claimId: claimId('claim-real'),
        decision: 'deny',
        reason: 'corroborated',
        revision: 2,
      })
      expect(replayFirewallSessionEvents(session.events)).toMatchObject([
        { type: 'exp-firewall/decision', data: { operationId: 'op-real', claimId: 'claim-real', decision: 'deny' } },
      ])
      expect(session.deriveMessages()).toEqual([])
    } finally {
      await ctx.fiber.dispose()
    }
  })
})

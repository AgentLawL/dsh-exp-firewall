import type { Context } from '@deepseek-ai/cordis'
import type { ToolExecution, ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import { describe, expect, it, vi } from 'vitest'

import { resolveConfig } from '../src/config.ts'
import { ExperienceFirewallConsumer } from '../src/consumer.ts'
import type { ExperienceFirewallRuntimeService, ExperienceFirewallService } from '../src/store.ts'

function fixture(decision: Awaited<ReturnType<ExperienceFirewallService['decide']>> = { kind: 'allow', reason: 'no-claim' }) {
  const events: Array<{ type: string; data: unknown }> = []
  const decideMock = vi.fn(async (_request: Parameters<ExperienceFirewallService['decide']>[0]) => decision)
  const recordMock = vi.fn(async (request: Parameters<ExperienceFirewallService['record']>[0]) => ({
    observation: request.observation,
    duplicate: false,
    transitions: [],
  }))
  const invalidateMock = vi.fn(async () => ({ claimIds: [] }))
  const releaseMock = vi.fn(async () => ({}))
  const closeSubscriptionsMock = vi.fn()
  const warningMock = vi.fn(async () => ({ recorded: true as const }))
  const service = {
    decide: decideMock,
    record: recordMock,
    settleLease: vi.fn(),
    invalidateClaims: invalidateMock,
    releaseLease: releaseMock,
    closeSubscriptions: closeSubscriptionsMock,
    subscribe: vi.fn(() => () => undefined),
    recordWarning: warningMock,
  } as unknown as ExperienceFirewallRuntimeService
  const warnMock = vi.fn()
  const context = {
    expFirewall: service,
    logger: () => ({ warn: warnMock }),
  } as unknown as Context
  const session = {
    id: 'session-a',
    header: { id: 'session-a', cwd: '/workspace' },
    append: (type: string, data: unknown) => events.push({ type, data }),
  }
  return {
    context,
    service,
    decideMock,
    recordMock,
    invalidateMock,
    releaseMock,
    closeSubscriptionsMock,
    warnMock,
    warningMock,
    session,
    events,
  }
}

function execution(
  session: ReturnType<typeof fixture>['session'],
  name: string,
  args: Record<string, unknown>,
): ToolExecution {
  return {
    callId: `call-${name}`,
    rootCallId: `call-${name}`,
    name,
    arguments: args,
    agent: { id: 'agent-a', session },
    signal: new AbortController().signal,
    token: Symbol('execution'),
  } as unknown as ToolExecution
}

const accepted = async () => ({ kind: 'accept' as const })

describe('DSH tool-policy Consumer', () => {
  it('delegates unknown tools without asking the Service', async () => {
    const test = fixture()
    const consumer = new ExperienceFirewallConsumer(test.context, resolveConfig())
    const next = vi.fn(async () => ({ kind: 'allow' as const }))
    await expect(consumer.preExecute(execution(test.session, 'other', {}), next)).resolves.toEqual({ kind: 'allow' })
    expect(next).toHaveBeenCalledOnce()
    expect(test.service.decide).not.toHaveBeenCalled()
  })

  it('logs warn before delegation and appends its stable notice after the result', async () => {
    const test = fixture({ kind: 'warn', reason: 'suspected', claimId: 'claim-a' as never })
    const consumer = new ExperienceFirewallConsumer(test.context, resolveConfig({ mode: 'warn' }))
    const exec = execution(test.session, 'read', { path: 'missing.txt' })
    const next = vi.fn(async () => ({ kind: 'allow' as const }))
    await expect(consumer.preExecute(exec, next)).resolves.toEqual({ kind: 'allow' })
    expect(test.events[0]).toMatchObject({
      type: 'exp-firewall/decision',
      data: { decision: 'warn', reason: 'suspected', claimId: 'claim-a' },
    })
    const post = await consumer.postExecute(
      exec,
      {
        isError: true,
        error: { message: 'not found', info: { name: 'FsError', code: 'FS_NOT_FOUND' } },
        content: [{ type: 'text', text: 'not found' }],
      },
      accepted,
    )
    expect(test.service.record).toHaveBeenCalledOnce()
    expect(test.recordMock.mock.calls[0]?.[0].observation).toMatchObject({
      outcome: 'failure',
      failureCode: 'FS_NOT_FOUND',
    })
    expect(post).toMatchObject({ kind: 'accept', content: [{ text: 'not found' }, { text: expect.stringContaining('reason=suspected') }] })
    expect(test.warningMock).toHaveBeenCalledOnce()
    expect(test.events.at(-1)?.type).toBe('exp-firewall/observation')
  })

  it('short-circuits enforce deny and wait without dispatching the underlying tool', async () => {
    for (const decision of [
      { kind: 'deny' as const, reason: 'corroborated' as const, claimId: 'claim-a' as never },
      {
        kind: 'wait' as const,
        reason: 'verification-in-progress' as const,
        claimId: 'claim-a' as never,
        owner: 'agent-b' as never,
        expiresAt: '2026-08-18T00:01:00.000Z',
      },
    ]) {
      const test = fixture(decision)
      const consumer = new ExperienceFirewallConsumer(test.context, resolveConfig({ mode: 'enforce' }))
      const next = vi.fn(async () => ({ kind: 'allow' as const }))
      const result = await consumer.preExecute(execution(test.session, 'read', { path: 'missing.txt' }), next)
      expect(result.kind).toBe('deny')
      expect(next).not.toHaveBeenCalled()
      expect(test.events[0]).toMatchObject({ type: 'exp-firewall/decision', data: { decision: decision.kind } })
    }
  })

  it('classifies command failure only from a structured exitCode value, never output text', async () => {
    const test = fixture()
    const consumer = new ExperienceFirewallConsumer(test.context, resolveConfig())
    const failedExec = execution(test.session, 'bash', { command: 'false' })
    await consumer.preExecute(failedExec, async () => ({ kind: 'allow' }))
    await consumer.postExecute(
      failedExec,
      { isError: false, value: { exitCode: 7 }, content: [{ type: 'text', text: 'anything' }] },
      accepted,
    )
    expect(test.recordMock.mock.calls[0]?.[0].observation).toMatchObject({ outcome: 'failure', failureCode: 'EXIT_7' })

    const successExec = execution(test.session, 'bash', { command: 'printf error' })
    await consumer.preExecute(successExec, async () => ({ kind: 'allow' }))
    await consumer.postExecute(
      successExec,
      { isError: false, value: { exitCode: 0 }, content: [{ type: 'text', text: 'ERROR FS_NOT_FOUND' }] },
      accepted,
    )
    expect(test.recordMock.mock.calls[1]?.[0].observation).toMatchObject({ outcome: 'success' })
  })

  it('appends Store-returned Claim transitions after the correlated Observation', async () => {
    const test = fixture()
    test.service.record = vi.fn(async (request) => ({
      observation: request.observation,
      duplicate: false,
      transitions: [
        {
          claimId: 'claim-a' as never,
          from: 'suspected' as const,
          to: 'corroborated' as const,
          revision: 2,
        },
      ],
    }))
    const consumer = new ExperienceFirewallConsumer(test.context, resolveConfig())
    const exec = execution(test.session, 'bash', { command: 'false' })
    await consumer.preExecute(exec, async () => ({ kind: 'allow' }))
    await consumer.postExecute(
      exec,
      { isError: false, value: { exitCode: 1 }, content: [] },
      accepted,
    )
    expect(test.events.slice(-2)).toEqual([
      expect.objectContaining({ type: 'exp-firewall/observation' }),
      expect.objectContaining({
        type: 'exp-firewall/transition',
        data: expect.objectContaining({ claimId: 'claim-a', from: 'suspected', to: 'corroborated', revision: 2 }),
      }),
    ])
  })

  it('correlates the Provider display path and latest Evidence without blocking fs/observed', async () => {
    const test = fixture()
    const consumer = new ExperienceFirewallConsumer(test.context, resolveConfig())
    const first = execution(test.session, 'read', { path: 'target.txt' })
    await consumer.preExecute(first, async () => ({ kind: 'allow' }))
    consumer.observeFile(
      { targetKey: 'target-key' as never, displayPath: '/workspace/target.txt' },
      { kind: 'present', version: 'v1' as never },
      first,
    )
    await consumer.postExecute(
      first,
      { isError: false, value: { text: 'ok' }, content: [{ type: 'text', text: 'ok' }] },
      accepted,
    )
    const recorded = test.recordMock.mock.calls[0]?.[0].observation
    if (recorded === undefined) throw new Error('expected recorded Observation')
    expect(recorded.evidence).toEqual([
      { kind: 'file-state', key: '/workspace/target.txt', state: 'present', version: 'v1' },
    ])

    const second = execution(test.session, 'read', { path: 'target.txt' })
    await consumer.preExecute(second, async () => ({ kind: 'allow' }))
    expect(test.decideMock.mock.calls[1]?.[0]).toMatchObject({ evidence: recorded.evidence, fingerprint: recorded.fingerprint })
    await consumer.stop()
    expect(test.invalidateMock).toHaveBeenCalledWith(expect.objectContaining({ evidence: recorded.evidence }))
  })

  it('maps Store failure fail-open except explicit enforce deny', async () => {
    const open = fixture()
    open.service.decide = vi.fn(async () => {
      throw new Error('store down')
    })
    const openConsumer = new ExperienceFirewallConsumer(open.context, resolveConfig({ mode: 'warn' }))
    const openNext = vi.fn(async () => ({ kind: 'allow' as const }))
    await expect(openConsumer.preExecute(execution(open.session, 'read', { path: 'a' }), openNext)).resolves.toEqual({ kind: 'allow' })
    expect(openNext).toHaveBeenCalledOnce()
    expect(open.warnMock).toHaveBeenCalledWith('pre-execution Store decision failed')

    const closed = fixture()
    closed.service.decide = open.service.decide
    const closedConsumer = new ExperienceFirewallConsumer(
      closed.context,
      resolveConfig({ mode: 'enforce', enforceStoreFailure: 'deny' }),
    )
    const closedNext = vi.fn(async () => ({ kind: 'allow' as const }))
    await expect(closedConsumer.preExecute(execution(closed.session, 'read', { path: 'a' }), closedNext)).resolves.toMatchObject({ kind: 'deny' })
    expect(closedNext).not.toHaveBeenCalled()
  })

  it('closes notifications, drains invalidations, and releases process-owned leases once', async () => {
    const test = fixture({
      kind: 'verify',
      reason: 'evidence-changed',
      claimId: 'claim-a' as never,
      leaseId: 'lease-a' as never,
    })
    const consumer = new ExperienceFirewallConsumer(test.context, resolveConfig({ mode: 'enforce' }))
    await consumer.preExecute(execution(test.session, 'read', { path: 'target.txt' }), async () => ({ kind: 'allow' }))
    await Promise.all([consumer.stop(), consumer.stop()])
    expect(test.closeSubscriptionsMock).toHaveBeenCalledOnce()
    expect(test.releaseMock).toHaveBeenCalledOnce()
    expect(test.releaseMock).toHaveBeenCalledWith(expect.objectContaining({
      kind: 'release-lease',
      leaseId: 'lease-a',
      ownerPrincipalId: 'agent-a',
      cause: 'released',
    }))
  })

  it('orders notification closure before queue drain and owned lease release', async () => {
    const order: string[] = []
    let finishInvalidation!: () => void
    const invalidationGate = new Promise<void>((resolve) => {
      finishInvalidation = resolve
    })
    const test = fixture({
      kind: 'verify',
      reason: 'evidence-changed',
      claimId: 'claim-a' as never,
      leaseId: 'lease-a' as never,
    })
    test.service.closeSubscriptions = vi.fn(() => order.push('subscriptions-closed'))
    test.service.invalidateClaims = vi.fn(async () => {
      order.push('invalidation-started')
      await invalidationGate
      order.push('invalidation-finished')
      return { claimIds: [] }
    })
    test.service.releaseLease = vi.fn(async () => {
      order.push('lease-released')
      return {} as never
    })
    const consumer = new ExperienceFirewallConsumer(test.context, resolveConfig({ mode: 'enforce' }))
    const exec = execution(test.session, 'read', { path: 'target.txt' })
    await consumer.preExecute(exec, async () => ({ kind: 'allow' }))
    consumer.observeFile(
      { targetKey: 'target-key' as never, displayPath: '/workspace/target.txt' },
      { kind: 'present', version: 'v1' as never },
      exec,
    )
    const stopping = consumer.stop()
    await Promise.resolve()
    expect(order).toEqual(['subscriptions-closed', 'invalidation-started'])
    finishInvalidation()
    await stopping
    expect(order).toEqual([
      'subscriptions-closed',
      'invalidation-started',
      'invalidation-finished',
      'lease-released',
    ])
  })
})

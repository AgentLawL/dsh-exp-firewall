import { Context } from '@deepseek-ai/cordis'
import Include from '@deepseek-ai/cordis-plugin-include'
import Loader from '@deepseek-ai/cordis-plugin-loader'
import type { Agent } from '@deepseek-ai/dsh-agent'
import { HarnessError } from '@deepseek-ai/dsh-llm'
import SessionStore from '@deepseek-ai/dsh-session'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime, { defineTool, type ToolRunContext } from '@deepseek-ai/dsh-tools'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { afterEach, describe, expect, it } from 'vitest'

import * as ConsumerPlugin from '../src/index.ts'
import * as ServicePlugin from '../src/service.ts'
import { openSqliteDatabase } from '../src/store-sqlite.ts'

interface FixtureState {
  exists: boolean
  version: string
  dispatches: string[]
  hold?: Promise<void>
  bodyStarted?: () => void
}

let fixtureRoot: string | undefined
let context: Context | undefined

afterEach(async () => {
  await context?.fiber.dispose()
  context = undefined
  if (fixtureRoot !== undefined) await rm(fixtureRoot, { recursive: true, force: true })
  fixtureRoot = undefined
})

function toolFixture(state: FixtureState) {
  return {
    name: 'exp-firewall-runtime-fixture',
    inject: ['tools'],
    apply(ctx: Context): void {
      ctx.tools.register(defineTool({
        name: 'read',
        description: 'Read one deterministic fixture path.',
        parameters: { path: { type: 'string', required: true } },
        output: {
          schema: { type: 'string' },
          render: (_args, value) => [{ type: 'text', text: value }],
        },
        async execute(_args, exec: ToolRunContext) {
          state.dispatches.push(String(exec.agent?.id))
          ctx.emit(
            'fs/observed',
            { targetKey: 'fixture-target' as never, displayPath: '/workspace/target.txt' },
            state.exists
              ? { kind: 'present', version: state.version as never }
              : { kind: 'absent' },
            exec,
          )
          state.bodyStarted?.()
          if (state.hold !== undefined) await state.hold
          if (!state.exists) throw new HarnessError('fixture path is absent', 'FS_NOT_FOUND')
          return 'verified contents'
        },
      }))
    },
  }
}

function agent(ctx: Context, name: string): Agent {
  const id = `session-${name}` as never
  const session = (ctx.sessions as unknown as { create(id: never, options: unknown): Agent['session'] })
    .create(id, { meta: { cwd: '/workspace' } })
  return {
    id,
    session,
    ctx,
    options: {},
    status: 'idle',
  } as unknown as Agent
}

async function loadComposition(state: FixtureState): Promise<{ ctx: Context; dataDir: string }> {
  fixtureRoot = await mkdtemp(join(tmpdir(), 'exp-firewall-loader-'))
  const dataDir = join(fixtureRoot, 'data')
  const configPath = join(fixtureRoot, 'cordis.yml')
  await writeFile(configPath, [
    "- name: '@deepseek-ai/dsh-system-prompt'",
    "- name: '@deepseek-ai/dsh-session'",
    "- name: '@deepseek-ai/dsh-tools'",
    "- name: 'exp-firewall/service'",
    '  config: &firewall',
    "    mode: 'enforce'",
    `    dataDir: '${dataDir}'`,
    '    minIndependentSupporters: 2',
    "- name: 'exp-firewall'",
    '  inject: [expFirewall]',
    '  config: *firewall',
    "- name: '@fixture/structured-read'",
    '  inject: [tools]',
    '',
  ].join('\n'))

  context = new Context()
  context.baseUrl = pathToFileURL(fixtureRoot).href + '/'
  await context.plugin(Loader)
  context.loader.builtins.include = Include
  const modules = new Map<string, unknown>([
    ['@deepseek-ai/dsh-system-prompt', SystemPrompt],
    ['@deepseek-ai/dsh-session', SessionStore],
    ['@deepseek-ai/dsh-tools', ToolRuntime],
    ['exp-firewall/service', ServicePlugin],
    ['exp-firewall', ConsumerPlugin],
    ['@fixture/structured-read', toolFixture(state)],
  ])
  context.loader.internal = {
    version: 'v2',
    async import(specifier: string) {
      if (!modules.has(specifier)) throw new Error(`unexpected Loader import: ${specifier}`)
      return modules.get(specifier)
    },
  } as unknown as NonNullable<typeof context.loader.internal>
  await context.loader.create({
    name: 'cordis:include',
    config: { path: pathToFileURL(configPath).href },
  })
  await context.loader.await()
  return { ctx: context, dataDir }
}

async function read(ctx: Context, owner: Agent, callId: string) {
  return ctx.tools.execute({
    signal: new AbortController().signal,
    callId: callId as never,
    name: 'read',
    arguments: { path: 'target.txt' },
    agent: owner,
  })
}

describe('real Loader and DSH runtime composition', () => {
  it('runs consensus, deny, Evidence invalidation, wait, verification, replay, and clean unload', { timeout: 30_000 }, async () => {
    const state: FixtureState = { exists: false, version: 'v1', dispatches: [] }
    const loaded = await loadComposition(state)
    const unloaded = [...loaded.ctx.loader.entries()]
      .filter((entry) => entry.fiber === undefined && !entry.disabled)
      .map((entry) => entry.options.name)
    expect(unloaded).toEqual([])

    const principalA = agent(loaded.ctx, 'a')
    const principalB = agent(loaded.ctx, 'b')
    const principalC = agent(loaded.ctx, 'c')
    const principalD = agent(loaded.ctx, 'd')

    expect((await read(loaded.ctx, principalA, 'call-a')).error?.info?.code).toBe('FS_NOT_FOUND')
    expect((await read(loaded.ctx, principalB, 'call-b')).error?.info?.code).toBe('FS_NOT_FOUND')
    await expect.poll(async () => (await loaded.ctx.expFirewall.summary()).corroboratedClaims).toBe(1)

    const denied = await read(loaded.ctx, principalC, 'call-c-denied')
    expect(denied.isError).toBe(true)
    expect(denied.error?.message).toContain('decision=deny')
    expect(state.dispatches).toEqual(['session-a', 'session-b'])
    expect(principalC.session.events.at(-1)).toMatchObject({
      type: 'exp-firewall/decision',
      data: { decision: 'deny', reason: 'corroborated' },
    })

    state.exists = true
    state.version = 'v2'
    loaded.ctx.emit(
      'fs/observed',
      { targetKey: 'fixture-target' as never, displayPath: '/workspace/target.txt' },
      { kind: 'present', version: 'v2' as never },
      undefined,
    )
    await expect.poll(async () => (await loaded.ctx.expFirewall.summary()).staleClaims).toBe(1)

    let releaseBody!: () => void
    state.hold = new Promise<void>((resolve) => {
      releaseBody = resolve
    })
    let bodyStarted!: () => void
    const bodyStart = new Promise<void>((resolve) => {
      bodyStarted = resolve
    })
    state.bodyStarted = bodyStarted
    const verification = read(loaded.ctx, principalC, 'call-c-verify')
    await bodyStart
    const waiting = await read(loaded.ctx, principalD, 'call-d-wait')
    expect(waiting.isError).toBe(true)
    expect(waiting.error?.message).toContain('decision=wait')
    expect(state.dispatches).toEqual(['session-a', 'session-b', 'session-c'])
    releaseBody()
    await expect(verification).resolves.toMatchObject({ isError: false, value: 'verified contents' })
    await expect.poll(async () => (await loaded.ctx.expFirewall.summary()).resolvedClaims).toBe(1)

    expect(principalC.session.events.map((event) => event.type)).toEqual(expect.arrayContaining([
      'exp-firewall/decision',
      'exp-firewall/observation',
      'exp-firewall/transition',
    ]))
    expect(principalD.session.events.at(-1)).toMatchObject({
      type: 'exp-firewall/decision',
      data: { decision: 'wait', reason: 'verification-in-progress' },
    })

    await loaded.ctx.fiber.dispose()
    context = undefined
    const reopened = openSqliteDatabase(loaded.dataDir)
    expect(reopened.connection.prepare('PRAGMA quick_check').get()).toMatchObject({ quick_check: 'ok' })
    reopened.close()
  })
})

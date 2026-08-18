import { strict as assert } from 'node:assert'
import { readFile, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

import { Context } from '@deepseek-ai/cordis'
import Include from '@deepseek-ai/cordis-plugin-include'
import Loader from '@deepseek-ai/cordis-plugin-loader'
import { HarnessError } from '@deepseek-ai/dsh-llm'
import SessionStore from '@deepseek-ai/dsh-session'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime, { defineTool } from '@deepseek-ai/dsh-tools'

const here = dirname(fileURLToPath(import.meta.url))
const installedRoot = process.env.EXP_FIREWALL_PACKAGE_ROOT
const ConsumerPlugin = await import(installedRoot === undefined
  ? '../lib/index.js'
  : pathToFileURL(join(installedRoot, 'lib', 'index.js')).href)
const ServicePlugin = await import(installedRoot === undefined
  ? '../lib/service.js'
  : pathToFileURL(join(installedRoot, 'lib', 'service.js')).href)
const transcript = []
const state = { exists: false, version: 'v1', dispatches: [] }
let root
let ctx

function fixtureTool() {
  return {
    name: 'exp-firewall-keyless-fixture',
    inject: ['tools'],
    apply(context) {
      context.tools.register(defineTool({
        name: 'read',
        description: 'Read one deterministic fixture path.',
        parameters: { path: { type: 'string', required: true } },
        output: {
          schema: { type: 'string' },
          render: (_args, value) => [{ type: 'text', text: value }],
        },
        async execute(_args, exec) {
          state.dispatches.push(String(exec.agent?.id))
          context.emit(
            'fs/observed',
            { targetKey: 'fixture-target', displayPath: '/workspace/target.txt' },
            state.exists ? { kind: 'present', version: state.version } : { kind: 'absent' },
            exec,
          )
          if (!state.exists) throw new HarnessError('fixture path is absent', 'FS_NOT_FOUND')
          return 'verified contents'
        },
      }))
    },
  }
}

function makeAgent(context, suffix) {
  const id = `session-${suffix}`
  return {
    id,
    session: context.sessions.create(id, { meta: { cwd: '/workspace' } }),
    ctx: context,
    options: {},
    status: 'idle',
  }
}

async function read(context, owner, callId) {
  return context.tools.execute({
    signal: new AbortController().signal,
    callId,
    name: 'read',
    arguments: { path: 'target.txt' },
    agent: owner,
  })
}

async function waitFor(project, expected) {
  const deadline = Date.now() + 5_000
  while (Date.now() < deadline) {
    if (await project() === expected) return
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
  assert.equal(await project(), expected)
}

function lastDecision(owner, kind) {
  return owner.session.events.findLast((event) =>
    event.type === 'exp-firewall/decision' && event.data.decision === kind)
}

try {
  root = await mkdtemp(join(tmpdir(), 'exp-firewall-keyless-'))
  const dataDir = join(root, 'data')
  const configPath = join(root, 'cordis.yml')
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

  ctx = new Context()
  ctx.baseUrl = pathToFileURL(root).href + '/'
  await ctx.plugin(Loader)
  ctx.loader.builtins.include = Include
  const modules = new Map([
    ['@deepseek-ai/dsh-system-prompt', SystemPrompt],
    ['@deepseek-ai/dsh-session', SessionStore],
    ['@deepseek-ai/dsh-tools', ToolRuntime],
    ['exp-firewall/service', ServicePlugin],
    ['exp-firewall', ConsumerPlugin],
    ['@fixture/structured-read', fixtureTool()],
  ])
  ctx.loader.internal = {
    version: 'v2',
    async import(specifier) {
      assert(modules.has(specifier), `unexpected Loader import: ${specifier}`)
      return modules.get(specifier)
    },
  }
  await ctx.loader.create({ name: 'cordis:include', config: { path: pathToFileURL(configPath).href } })
  await ctx.loader.await()

  const principalA = makeAgent(ctx, 'a')
  const principalB = makeAgent(ctx, 'b')
  const principalC = makeAgent(ctx, 'c')

  const a = await read(ctx, principalA, 'call-a')
  assert.equal(a.error?.info?.code, 'FS_NOT_FOUND')
  let claim = (await ctx.expFirewall.listClaims({ limit: 10 })).items[0]
  assert.equal(claim.status, 'suspected')
  transcript.push('A | source=session-a/call-a | outcome=failure:FS_NOT_FOUND | claim=suspected | supporters=1')

  const b = await read(ctx, principalB, 'call-b')
  assert.equal(b.error?.info?.code, 'FS_NOT_FOUND')
  claim = (await ctx.expFirewall.listClaims({ limit: 10 })).items[0]
  assert.equal(claim.status, 'corroborated')
  assert.equal(claim.supporterCount, 2)
  transcript.push('B | source=session-b/call-b | outcome=failure:FS_NOT_FOUND | transition=suspected->corroborated | supporters=2')

  const denied = await read(ctx, principalC, 'call-c-denied')
  assert.equal(denied.isError, true)
  assert.equal(lastDecision(principalC, 'deny')?.data.reason, 'corroborated')
  assert.deepEqual(state.dispatches, ['session-a', 'session-b'])
  transcript.push('C | source=session-c/call-c-denied | decision=deny | reason=corroborated | dispatched=false')

  state.exists = true
  state.version = 'v2'
  ctx.emit(
    'fs/observed',
    { targetKey: 'fixture-target', displayPath: '/workspace/target.txt' },
    { kind: 'present', version: 'v2' },
    undefined,
  )
  await waitFor(async () => (await ctx.expFirewall.summary()).staleClaims, 1)
  transcript.push('SYSTEM | evidence=/workspace/target.txt | change=absent->present:v2 | transition=corroborated->stale')

  const verified = await read(ctx, principalC, 'call-c-verify')
  assert.equal(verified.isError, false)
  assert.equal(lastDecision(principalC, 'verify')?.data.reason, 'evidence-changed')
  assert.deepEqual(state.dispatches, ['session-a', 'session-b', 'session-c'])
  transcript.push('C | source=session-c/call-c-verify | decision=verify | reason=evidence-changed | lease=granted | dispatched=true')
  await waitFor(async () => (await ctx.expFirewall.summary()).resolvedClaims, 1)
  const events = (await ctx.expFirewall.listEvents({ limit: 200 })).items.map((event) => event.kind)
  assert(events.includes('claim-transition/verifying'))
  assert(events.includes('claim-transition/resolved'))
  transcript.push('C | outcome=success | transitions=stale->verifying,verifying->resolved | claim=resolved')

  const output = `${transcript.join('\n')}\n`
  if (process.argv.includes('--verify')) {
    const expected = await readFile(join(here, 'm2-keyless.snapshot.txt'), 'utf8')
    assert.equal(output, expected)
  }
  process.stdout.write(output)
} finally {
  await ctx?.fiber.dispose()
  if (root !== undefined) await rm(root, { recursive: true, force: true })
}
